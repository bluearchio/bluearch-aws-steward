from __future__ import annotations

import json
import tempfile
import unittest
from argparse import Namespace
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

from bluearch_aws_steward.catalog_sync import (
    build_catalog_from_misconfig_db,
    build_full_catalog_from_misconfig_db,
    catalog_matches,
    full_catalog_matches,
    write_catalog_from_misconfig_db,
    write_full_catalog_from_misconfig_db,
)
from bluearch_aws_steward.cli import _rules_sync


class CatalogSyncTests(unittest.TestCase):
    def test_cli_reports_missing_source_instead_of_out_of_sync(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_source = Path(tmpdir) / "missing"
            stderr = StringIO()
            args = Namespace(
                source=str(missing_source),
                output=None,
                full_output=None,
                check=True,
            )

            with redirect_stderr(stderr):
                exit_code = _rules_sync(args)

        self.assertEqual(exit_code, 2)
        self.assertIn("Catalog source is unavailable", stderr.getvalue())
        self.assertIn("--source", stderr.getvalue())

    def test_build_catalog_imports_only_executable_rules(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source_catalog(Path(tmpdir))

            payload = build_catalog_from_misconfig_db(source)

        self.assertEqual(payload["source"], "bluearchio/aws-misconfig-db")
        self.assertEqual(payload["sync"]["imported_rules"], 8)
        self.assertEqual(
            payload["sync"]["skipped_unsupported_rules"],
            {
                "alb-elb": 0,
                "api-gateway": 0,
                "cloudtrail": 0,
                "cloudwatch": 1,
                "dynamodb": 0,
                "ebs": 0,
                "ec2": 1,
                "ecs": 0,
                "efs": 0,
                "iam": 0,
                "kms": 0,
                "lambda": 0,
                "networking": 0,
                "rds": 0,
                "s3": 1,
                "secrets-manager": 0,
                "sns": 0,
                "sqs": 0,
            },
        )
        rules = {rule["short_id"]: rule for rule in payload["rules"]}
        self.assertEqual(
            set(rules),
            {
                "cloudwatch-log-retention-missing",
                "cloudtrail-multi-region-logging-disabled",
                "ec2-unattached-ebs-volume",
                "iam-root-mfa-disabled",
                "lambda-xray-tracing-disabled",
                "rds-publicly-accessible",
                "s3-no-lifecycle",
                "s3-public-bucket",
            },
        )
        self.assertEqual(rules["s3-public-bucket"]["severity"], "high")
        self.assertEqual(rules["s3-no-lifecycle"]["detector"], "s3_missing_lifecycle")
        self.assertTrue(rules["s3-no-lifecycle"]["remediation"]["requires_approval"])
        self.assertEqual(rules["cloudwatch-log-retention-missing"]["service"], "cloudwatch")
        self.assertEqual(
            rules["cloudwatch-log-retention-missing"]["parameters"]["recommended_retention_days"],
            30,
        )
        self.assertEqual(
            rules["ec2-unattached-ebs-volume"]["remediation"]["safety_level"], "high_risk"
        )
        self.assertEqual(
            rules["ec2-unattached-ebs-volume"]["parameters"]["minimum_unattached_days"],
            7,
        )

    def test_write_catalog_and_check_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = _write_source_catalog(root / "source")
            output = root / "rules.json"

            write_catalog_from_misconfig_db(source, output)

            self.assertTrue(catalog_matches(source, output))
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["sync"]["imported_rules"], 8)

    def test_full_catalog_preserves_every_row_and_marks_support_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = _write_source_catalog(Path(tmpdir))

            payload = build_full_catalog_from_misconfig_db(source)

        self.assertEqual(payload["sync"]["catalog_rules"], 11)
        self.assertEqual(payload["sync"]["catalog_services"], 7)
        self.assertEqual(
            payload["sync"]["rules_by_evaluation_mode"],
            {
                "native": 8,
                "native_alias": 0,
                "manual_review": 0,
                "metadata_required": 0,
                "signal_required": 0,
                "specification_required": 3,
            },
        )
        rules = {rule["id"]: rule for rule in payload["rules"]}
        native = rules["356570fe-de33-4782-bc81-152cb144fb05"]
        self.assertTrue(native["evaluation"]["automated"])
        self.assertTrue(native["automated"])
        self.assertEqual(native["short_id"], "s3-public-bucket")
        self.assertEqual(native["detector"], "s3_public_bucket")
        self.assertEqual(rules["unsupported"]["evaluation"]["mode"], "specification_required")
        self.assertFalse(rules["unsupported"]["evaluation"]["automated"])

    def test_write_full_catalog_and_check_match(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            source = _write_source_catalog(root / "source")
            output = root / "full_rules.json"

            write_full_catalog_from_misconfig_db(source, output)

            self.assertTrue(full_catalog_matches(source, output))
            data = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(data["sync"]["catalog_rules"], 11)


def _write_source_catalog(root: Path) -> Path:
    data_dir = root / "data" / "by-service"
    data_dir.mkdir(parents=True, exist_ok=True)
    s3_payload = {
        "service": "s3",
        "count": 3,
        "misconfigurations": [
            {
                "id": "e9b21a0d-2fe8-4f5b-8875-52995b4cf2e7",
                "service_name": "s3",
                "scenario": "source lifecycle scenario",
                "risk_detail": "cost, operations",
                "risk_value": 2,
            },
            {
                "id": "356570fe-de33-4782-bc81-152cb144fb05",
                "service_name": "s3",
                "scenario": "source public scenario",
                "risk_detail": "security, operations",
                "risk_value": 3,
            },
            {
                "id": "unsupported",
                "service_name": "s3",
                "scenario": "unsupported scenario",
                "risk_detail": "security",
                "risk_value": 2,
            },
        ],
    }
    cloudwatch_payload = {
        "service": "cloudwatch",
        "count": 2,
        "misconfigurations": [
            {
                "id": "e7b5c9a1-3f2d-4e8b-9c6a-1d5e8f2b4a3c",
                "service_name": "cloudwatch",
                "scenario": "source retention scenario",
                "risk_detail": "cost",
                "risk_value": 1,
            },
            {
                "id": "unsupported-cloudwatch",
                "service_name": "cloudwatch",
                "scenario": "unsupported scenario",
                "risk_detail": "operations",
                "risk_value": 2,
            },
        ],
    }
    ec2_payload = {
        "service": "ec2",
        "count": 2,
        "misconfigurations": [
            {
                "id": "033ae438-4620-4f65-80cd-776fd0102bb0",
                "service_name": "ec2",
                "scenario": "source unattached volume scenario",
                "risk_detail": "cost",
                "risk_value": 0,
            },
            {
                "id": "unsupported-ec2",
                "service_name": "ec2",
                "scenario": "unsupported scenario",
                "risk_detail": "security",
                "risk_value": 2,
            },
        ],
    }
    expanded_payloads = {
        "cloudtrail": {
            "id": "1a48e014-dc5b-4b3d-9e8a-4fa00ebd4223",
            "scenario": "source trail coverage scenario",
            "risk_detail": "operations",
            "risk_value": 3,
        },
        "iam": {
            "id": "314f0d94-7381-454d-915d-45b962d801e3",
            "scenario": "source root MFA scenario",
            "risk_detail": "security",
            "risk_value": 3,
        },
        "lambda": {
            "id": "2cd8897d-8db5-4bde-8476-1edbe7f97894",
            "scenario": "source tracing scenario",
            "risk_detail": "operations",
            "risk_value": 2,
        },
        "rds": {
            "id": "c0764b9f-5241-46c5-af3f-3bcf30721fec",
            "scenario": "source public database scenario",
            "risk_detail": "operations",
            "risk_value": 2,
        },
    }
    (data_dir / "s3.json").write_text(json.dumps(s3_payload), encoding="utf-8")
    (data_dir / "cloudwatch.json").write_text(json.dumps(cloudwatch_payload), encoding="utf-8")
    (data_dir / "ec2.json").write_text(json.dumps(ec2_payload), encoding="utf-8")
    for service, entry in expanded_payloads.items():
        payload = {
            "service": service,
            "count": 1,
            "misconfigurations": [{"service_name": service, **entry}],
        }
        (data_dir / f"{service}.json").write_text(json.dumps(payload), encoding="utf-8")
    return root


if __name__ == "__main__":
    unittest.main()
