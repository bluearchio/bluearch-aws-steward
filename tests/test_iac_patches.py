from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from bluearch_aws_steward.iac_patches import (
    IAC_PATCH_FORMATS,
    generate_iac_patch,
    validate_iac_patch,
)


def _cluster_finding() -> dict:
    return {
        "rule_short_id": "eks-public-endpoint-open",
        "service": "eks",
        "resource": "eks://cluster/vulnerable",
        "resource_ref": {
            "resource_type": "aws.eks.cluster",
            "resource_id": "vulnerable",
            "display_name": "vulnerable",
        },
    }


def _workload_finding(rule: str = "k8s-workload-missing-resource-requests") -> dict:
    return {
        "rule_short_id": rule,
        "service": "eks",
        "resource": "k8s://kind-bluearch-eks-lab/bluearch-eks-lab/deployment/example-api",
        "resource_ref": {
            "resource_type": "kubernetes.deployment",
            "resource_id": "bluearch-eks-lab/Deployment/example-api",
            "display_name": "example-api",
        },
        "evidence": {
            "inside_cluster_context": {
                "workload": {
                    "name": "example-api",
                    "containers": [{"name": "api"}],
                }
            }
        },
    }


class IacPatchTests(unittest.TestCase):
    @patch("bluearch_aws_steward.iac_patches.shutil.which", return_value=None)
    def test_all_supported_formats_generate_and_validate_without_writes(
        self, _which: object
    ) -> None:
        for patch_format in IAC_PATCH_FORMATS:
            with self.subTest(patch_format=patch_format):
                finding = (
                    _cluster_finding()
                    if patch_format in {"terraform", "cloudformation", "eksctl"}
                    else _workload_finding()
                )
                generated = generate_iac_patch(finding, patch_format)
                validation = validate_iac_patch(generated)

                self.assertEqual(generated["status"], "generated")
                self.assertTrue(generated["read_only"])
                self.assertFalse(generated["write_actions_applied"])
                self.assertEqual(validation["status"], "valid")
                self.assertTrue(validation["validated_in_temporary_directory"])
                self.assertFalse(validation["source_files_modified"])
                self.assertEqual(validation["cluster_writes_performed"], 0)

    def test_patch_digest_is_deterministic_and_rejects_tampering(self) -> None:
        first = generate_iac_patch(_cluster_finding(), "terraform")
        second = generate_iac_patch(_cluster_finding(), "terraform")
        self.assertEqual(first["patch_digest"], second["patch_digest"])

        first["files"]["bluearch_steward_patch.tf"] += "# changed after review\n"
        with self.assertRaisesRegex(ValueError, "digest does not match"):
            validate_iac_patch(first)

    @patch("bluearch_aws_steward.iac_patches.shutil.which", return_value=None)
    def test_validation_rejects_paths_outside_the_temporary_directory(self, _which: object) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "outside.txt"
            for filename in (
                str(target),
                "../outside.txt",
                "folder/patch.json",
                "folder\\patch.json",
            ):
                with self.subTest(filename=filename):
                    files = {filename: "{}\n"}
                    serialized = json.dumps(files, sort_keys=True, separators=(",", ":"))
                    document = {
                        "status": "generated",
                        "format": "cloudformation",
                        "files": files,
                        "patch_digest": hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
                    }
                    with self.assertRaisesRegex(ValueError, "filenames"):
                        validate_iac_patch(document)
            self.assertFalse(target.exists())

    def test_runtime_finding_requires_a_reviewed_change(self) -> None:
        result = generate_iac_patch(
            _workload_finding("k8s-pod-restart-loop"),
            "kubernetes-yaml",
        )

        self.assertEqual(result["status"], "input_required")
        self.assertEqual(result["required_inputs"], ["approved_change"])
        self.assertGreaterEqual(len(result["possible_responses"]), 3)
        self.assertFalse(result["write_actions_applied"])

    def test_probe_patch_requires_application_specific_input(self) -> None:
        finding = _workload_finding("k8s-workload-missing-probes")
        blocked = generate_iac_patch(finding, "kubernetes-yaml")
        self.assertEqual(blocked["status"], "input_required")
        self.assertIn("probe_port", blocked["required_inputs"])

        generated = generate_iac_patch(
            finding,
            "kubernetes-yaml",
            {"probe_port": 8080, "probe_path": "/healthz"},
        )
        self.assertEqual(generated["status"], "generated")
        content = generated["files"]["patch.json"]
        self.assertIn('"path": "/healthz"', content)
        self.assertIn('"port": 8080', content)


if __name__ == "__main__":
    unittest.main()
