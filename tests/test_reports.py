import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from bluearch_aws_steward.reports import build_report_model, render_report, write_report


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = {
            "observed_at": "2026-07-14T12:00:00Z",
            "provider": "aws-sdk",
            "region": "us-east-1",
            "service": "all",
            "summary": {
                "resources_scanned": 12,
                "rules_evaluated": 5,
                "scan_errors": 0,
                "detection_coverage": {"complete_catalog_evaluation": False},
            },
            "opportunities": [
                {
                    "rule": "s3-no-lifecycle",
                    "service": "s3",
                    "resource": "s3://fixture",
                    "severity": "medium",
                    "why": "S3 lifecycle manager is turned off",
                    "risk": "cost, operations",
                    "value": "Older objects may create avoidable storage cost.",
                    "evidence": {
                        "lifecycle_rules": [],
                        "cost_estimate": {
                            "status": "estimated",
                            "estimated_monthly_savings_usd": 12.34,
                            "confidence": "medium",
                            "basis": "Observed storage and current regional pricing.",
                        },
                        "observation": {
                            "observed_at": "2026-07-14T12:00:00Z",
                            "source": "aws_control_plane",
                            "confidence": "high",
                        },
                    },
                    "resource_ref": {
                        "provider": "aws",
                        "account_id": "000000000000",
                        "region": "us-east-1",
                        "service": "s3",
                        "resource_type": "aws.s3.bucket",
                        "resource_id": "fixture",
                        "arn": "arn:aws:s3:::fixture",
                    },
                    "remediation": {
                        "summary": "Add a lifecycle rule for older objects.",
                        "actions": ["Add an approved lifecycle transition or expiration rule."],
                        "verification": "Confirm at least one enabled lifecycle rule exists.",
                        "safety_level": "low_risk",
                        "requires_approval": True,
                    },
                    "apply": {"supported": True},
                }
            ],
        }

    def test_all_renderers_include_finding_and_metadata(self) -> None:
        model = build_report_model(self.result)
        for report_format in ("json", "markdown", "html", "csv", "sarif"):
            content = render_report(model, report_format)
            self.assertIsInstance(content, str)
            self.assertIn("s3-no-lifecycle", content)
            self.assertIn("us-east-1", content)

        sarif = json.loads(render_report(model, "sarif"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "s3-no-lifecycle")

        pdf = render_report(model, "pdf")
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))

    def test_csv_explains_why_each_finding_matched(self) -> None:
        content = render_report(build_report_model(self.result), "csv")
        rows = list(csv.DictReader(io.StringIO(content)))

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["rule_description"], "S3 lifecycle manager is turned off")
        self.assertEqual(row["matching_criteria"], "S3 lifecycle manager is turned off")
        self.assertIn("lifecycle_rules=[]", row["observed_evidence"])
        self.assertEqual(row["evidence_confidence"], "high")
        self.assertEqual(row["cost_estimate_status"], "estimated")
        self.assertEqual(row["estimated_monthly_savings_usd"], "12.34")
        self.assertEqual(row["cost_confidence"], "medium")
        self.assertIn("regional pricing", row["cost_estimate_basis"])
        self.assertEqual(row["resource_arn"], "arn:aws:s3:::fixture")
        self.assertEqual(row["remediation_summary"], "Add a lifecycle rule for older objects.")
        self.assertIn("approved lifecycle", row["remediation_actions"])
        self.assertEqual(row["requires_approval"], "true")
        self.assertEqual(row["apply_supported"], "true")

        model = build_report_model(self.result)
        self.assertEqual(model["summary"]["estimated_monthly_savings_usd"], 12.34)
        self.assertEqual(model["summary"]["cost_estimates_available"], 1)
        markdown = render_report(model, "markdown")
        self.assertIn("Observed storage and current regional pricing.", markdown)
        self.assertIn("Individual approval required: **true**", markdown)

    def test_missing_cost_signal_is_explicit_in_every_report_model(self) -> None:
        result = json.loads(json.dumps(self.result))
        result["opportunities"][0]["evidence"].pop("cost_estimate")

        model = build_report_model(result)
        finding = model["findings"][0]

        self.assertEqual(finding["cost_estimate_status"], "not_estimated")
        self.assertEqual(finding["cost_confidence"], "not_available")
        self.assertIsNone(finding["estimated_monthly_savings_usd"])
        self.assertEqual(model["summary"]["cost_estimates_unavailable"], 1)

    def test_report_context_falls_back_to_resource_reference(self) -> None:
        result = json.loads(json.dumps(self.result))
        result.pop("provider")
        result.pop("region")

        model = build_report_model(result)

        self.assertEqual(model["provider"], "aws")
        self.assertEqual(model["account_id"], "000000000000")
        self.assertEqual(model["region"], "us-east-1")

    def test_write_report_is_local_and_deterministic(self) -> None:
        model = build_report_model(self.result)
        with tempfile.TemporaryDirectory() as directory:
            path = write_report(model, "markdown", str(Path(directory) / "assessment.md"))
            self.assertIsNotNone(path)
            self.assertTrue(Path(path or "").is_file())
            self.assertIn("read-only", Path(path or "").read_text(encoding="utf-8"))

    def test_write_report_never_overwrites_an_existing_file(self) -> None:
        model = build_report_model(self.result)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment.md"
            path.write_text("user content", encoding="utf-8")

            with self.assertRaises(FileExistsError):
                write_report(model, "markdown", str(path))

            self.assertEqual(path.read_text(encoding="utf-8"), "user content")

    def test_write_pdf_report_creates_binary_document(self) -> None:
        model = build_report_model(self.result)
        with tempfile.TemporaryDirectory() as directory:
            path = write_report(model, "pdf", str(Path(directory) / "assessment.pdf"))

            self.assertIsNotNone(path)
            self.assertTrue(Path(path or "").read_bytes().startswith(b"%PDF-"))

    def test_unsupported_format_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            render_report(build_report_model(self.result), "docx")


if __name__ == "__main__":
    unittest.main()
