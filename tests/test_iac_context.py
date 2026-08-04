from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from bluearch_aws_steward.iac_context import (
    CLOUDFORMATION_TYPES,
    TERRAFORM_TYPES,
    IacContextError,
    parse_iac_context,
)


class IacContextTests(unittest.TestCase):
    def test_terraform_parses_all_runtime_scopes_and_redacts_sensitive_values(self) -> None:
        representatives: dict[str, str] = {}
        for terraform_type, (service, _) in TERRAFORM_TYPES.items():
            representatives.setdefault(service, terraform_type)
        blocks = []
        for index, (service, terraform_type) in enumerate(sorted(representatives.items())):
            extra = (
                '  bucket = "contextual-bucket"\n'
                if service == "s3"
                else '  name = "contextual-resource"\n'
            )
            if service == "lambda":
                extra += '  environment { variables = { TOKEN = "must-not-leak" } }\n'
            blocks.append(f'resource "{terraform_type}" "fixture_{index}" {{\n{extra}}}\n')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "main.tf"
            source.write_text("\n".join(blocks), encoding="utf-8")

            result = parse_iac_context(
                {"workspace_root": str(root), "paths": ["main.tf"], "format": "terraform"}
            )

        self.assertEqual({item["service"] for item in result["resources"]}, set(representatives))
        self.assertNotIn("must-not-leak", json.dumps(result))
        self.assertFalse(result["files_modified"])
        self.assertFalse(result["terraform_plan_executed"])

    def test_cloudformation_parses_all_runtime_scopes_and_marks_intrinsics_unknown(self) -> None:
        representatives: dict[str, str] = {}
        for cloudformation_type, (service, _) in CLOUDFORMATION_TYPES.items():
            representatives.setdefault(service, cloudformation_type)
        resources = {
            f"Fixture{index}": {
                "Type": cloudformation_type,
                "Properties": {"Name": {"Ref": "DynamicName"}},
            }
            for index, (_, cloudformation_type) in enumerate(sorted(representatives.items()))
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "template.json"
            source.write_text(json.dumps({"Resources": resources}), encoding="utf-8")

            result = parse_iac_context(
                {
                    "workspace_root": str(root),
                    "paths": ["template.json"],
                    "format": "cloudformation",
                }
            )

        self.assertEqual({item["service"] for item in result["resources"]}, set(representatives))
        self.assertTrue(all(item["unresolved_fields"] for item in result["resources"]))
        self.assertFalse(result["transforms_executed"])

    def test_terraform_plan_uses_only_changed_resources(self) -> None:
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.changed",
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["create"], "after": {"bucket": "changed"}},
                },
                {
                    "address": "aws_s3_bucket.unchanged",
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["no-op"], "after": {"bucket": "unchanged"}},
                },
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "plan.json"
            source.write_text(json.dumps(plan), encoding="utf-8")

            result = parse_iac_context(
                {"workspace_root": str(root), "terraform_plan_json_path": "plan.json"}
            )

        self.assertEqual([item["resource_id"] for item in result["resources"]], ["changed"])

    def test_rejects_state_secret_and_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            (root / "terraform.tfstate").write_text("{}", encoding="utf-8")
            (root / ".env").write_text("TOKEN=secret", encoding="utf-8")
            external = Path(outside) / "main.tf"
            external.write_text('resource "aws_s3_bucket" "x" {}', encoding="utf-8")
            link = root / "escape.tf"
            os.symlink(external, link)

            for path in ("terraform.tfstate", ".env", "escape.tf"):
                with self.subTest(path=path), self.assertRaises(IacContextError):
                    parse_iac_context(
                        {"workspace_root": str(root), "paths": [path], "format": "terraform"}
                    )

    def test_iac_references_create_typed_relationships(self) -> None:
        source_text = """
resource "aws_kms_key" "data" {
  description = "fixture"
}
resource "aws_s3_bucket" "data" {
  bucket = "contextual-bucket"
  kms_key = aws_kms_key.data.arn
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.tf").write_text(source_text, encoding="utf-8")
            result = parse_iac_context(
                {"workspace_root": str(root), "paths": ["main.tf"], "format": "terraform"}
            )

        self.assertEqual(result["relationship_count"], 1)
        self.assertEqual(result["relationships"][0]["relationship_type"], "encrypted_by")

    def test_modern_split_terraform_resources_are_included_in_the_review_graph(self) -> None:
        source_text = """
resource "aws_s3_bucket" "data" {
  bucket = "contextual-bucket"
}
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
}
resource "aws_secretsmanager_secret" "application" {
  name = "contextual-secret"
}
resource "aws_secretsmanager_secret_rotation" "application" {
  secret_id           = aws_secretsmanager_secret.application.id
  rotation_lambda_arn = aws_lambda_function.rotation.arn
  rotation_rules { automatically_after_days = 30 }
}
resource "aws_lambda_function" "rotation" {
  function_name = "contextual-rotation"
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.tf").write_text(source_text, encoding="utf-8")
            result = parse_iac_context(
                {"workspace_root": str(root), "paths": ["main.tf"], "format": "terraform"}
            )

        addresses = {item["address"] for item in result["resources"]}
        self.assertIn("aws_s3_bucket_versioning.data", addresses)
        self.assertIn("aws_s3_bucket_server_side_encryption_configuration.data", addresses)
        self.assertIn("aws_secretsmanager_secret_rotation.application", addresses)
        self.assertGreaterEqual(result["relationship_count"], 4)


if __name__ == "__main__":
    unittest.main()
