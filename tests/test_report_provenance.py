from __future__ import annotations

import csv
import io
import json
import unittest

from bluearch_aws_steward import reports

FINDING = {
    "rule": "s3-public-bucket",
    "rule_id": "s3-public-bucket",
    "severity": "high",
    "service": "s3",
    "resource_id": "reports-archive",
    "title": "Bucket is public",
    "description": "public",
    "evidence": {},
    "remediation": {},
    # An account-wide scan resolves the resource without a region on the ref.
    "resource_ref": {"service": "s3", "resource_id": "reports-archive", "account_id": "1234"},
}

# Shaped like a stored account-wide assessment: no top-level region, but the
# routing block records the region the scan actually ran against.
ACCOUNT_WIDE = {
    "assessment_id": "a1",
    "observed_at": "2026-08-05T00:00:00Z",
    "service": "all",
    "findings": [FINDING],
    "resources": [{"resource_id": "reports-archive", "service": "s3"}],
    "summary": {"resources_scanned": 1606},
    "routing": {
        "objective": "all",
        "service": "all",
        "provider": "aws-sdk",
        "region": "us-east-1",
    },
}


class ReportProvenanceTests(unittest.TestCase):
    """A report is evidence, so it has to say where it was observed.

    An account-wide assessment reaches build_report_model with no top-level
    region and no region on any resource_ref, which left every export saying
    `unknown` or writing an empty column for all findings.
    """

    def test_region_is_taken_from_routing_when_the_result_omits_it(self) -> None:
        model = reports.build_report_model(ACCOUNT_WIDE)
        self.assertEqual(model["region"], "us-east-1")

    def test_provider_is_taken_from_routing_when_the_result_omits_it(self) -> None:
        model = reports.build_report_model(ACCOUNT_WIDE)
        self.assertEqual(model["provider"], "aws-sdk")

    def test_an_explicit_region_still_wins_over_routing(self) -> None:
        result = {**ACCOUNT_WIDE, "region": "eu-west-1"}
        self.assertEqual(reports.build_report_model(result)["region"], "eu-west-1")

    def test_markdown_names_the_region_instead_of_unknown(self) -> None:
        rendered = reports.render_report(reports.build_report_model(ACCOUNT_WIDE), "markdown")
        text = getattr(rendered, "content", rendered)
        self.assertIn("us-east-1", str(text))
        self.assertNotIn("Region: `unknown`", str(text))

    def test_every_csv_row_carries_the_region(self) -> None:
        rendered = reports.render_report(reports.build_report_model(ACCOUNT_WIDE), "csv")
        text = str(getattr(rendered, "content", rendered))
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertTrue(rows, "csv export produced no rows")
        self.assertEqual({row["region"] for row in rows}, {"us-east-1"})

    def test_json_export_carries_the_region(self) -> None:
        rendered = reports.render_report(reports.build_report_model(ACCOUNT_WIDE), "json")
        text = str(getattr(rendered, "content", rendered))
        self.assertEqual(json.loads(text)["region"], "us-east-1")


if __name__ == "__main__":
    unittest.main()
