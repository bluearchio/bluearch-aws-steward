from __future__ import annotations

import unittest

from bluearch_aws_steward import pdf_report, reports

# mcp_server emits these three fields in two shapes on purpose: the summary
# block carries counts beside resources_scanned and rules_evaluated, while the
# payload's top level carries the detail lists. Reading one where the other was
# expected is what raised TypeError from pdf_report on a live account.
COUNTS_SHAPED = {
    "resources_scanned": 12,
    "rules_evaluated": 40,
    "scan_errors": 1,
    "service_errors": 2,
    "capability_errors": 3,
    "rules_skipped": 4,
}

LIST_SHAPED = {
    "resources_scanned": 12,
    "rules_evaluated": 40,
    "scan_errors": 1,
    "service_errors": [{"service": "eks", "error": "no kubeconfig"}],
    "capability_errors": [{"source": "eks", "reason": "unreachable"}],
    "rules_skipped": [{"rule": "eks-nodegroup-ami-outdated", "reason": "unsupported"}],
}

FINDING = {
    "rule": "s3-bucket-public",
    "rule_id": "s3-bucket-public",
    "severity": "high",
    "service": "s3",
    "resource_id": "demo-bucket",
    "title": "Bucket is public",
    "description": "public",
    "evidence": {},
    "remediation": {},
}


def _model(summary: dict) -> dict:
    return reports.build_report_model(
        {
            "assessment_id": "a1",
            "generated_at": "2026-08-05T00:00:00Z",
            "provider": "aws",
            "region": "us-east-1",
            "service": "s3",
            "findings": [FINDING],
            "resources": [{"resource_id": "demo-bucket", "service": "s3"}],
            "summary": summary,
        }
    )


class SummaryShapeTests(unittest.TestCase):
    """An account with capability errors must still be able to export a report.

    An EKS cluster without a kubeconfig is enough to produce them, so this is
    the common case rather than an edge one.
    """

    def test_every_format_renders_from_either_shape(self) -> None:
        for label, summary in (("list", LIST_SHAPED), ("counts", COUNTS_SHAPED)):
            model = _model(summary)
            for report_format in ("markdown", "html", "json", "csv", "sarif"):
                with self.subTest(shape=label, format=report_format):
                    reports.render_report(model, report_format)

    def test_pdf_exports_from_either_shape(self) -> None:
        # The original defect: len() on an int raised TypeError and blocked
        # every PDF export on any account reporting a capability error.
        for label, summary in (("list", LIST_SHAPED), ("counts", COUNTS_SHAPED)):
            with self.subTest(shape=label):
                self.assertGreater(len(pdf_report.render_pdf_report(_model(summary))), 0)

    def test_detail_survives_when_the_producer_supplied_it(self) -> None:
        # summary is the only home for this detail — the model has no top-level
        # capability_errors — so dropping it here drops it from the report.
        summary = _model(LIST_SHAPED)["summary"]
        self.assertEqual(summary["capability_errors"], LIST_SHAPED["capability_errors"])
        self.assertEqual(summary["service_errors"], LIST_SHAPED["service_errors"])
        self.assertEqual(summary["rules_skipped"], LIST_SHAPED["rules_skipped"])


if __name__ == "__main__":
    unittest.main()
