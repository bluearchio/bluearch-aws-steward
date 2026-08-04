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


class PdfCountFieldTests(unittest.TestCase):
    def test_pdf_renders_when_capability_errors_is_an_int(self) -> None:
        from bluearch_aws_steward.pdf_report import render_pdf_report

        model = {
            "generated_at": "2026-08-04T00:00:00Z",
            "provider": "aws-sdk",
            "report_profile": "technical",
            "summary": {
                "resources_scanned": 10,
                "complete_findings": 1,
                "capability_errors": 3,
                "service_errors": 0,
                "rules_skipped": 2,
                "detection_coverage": {},
            },
            "findings": [],
            "severity_counts": {},
            "service_counts": {},
        }
        pdf = render_pdf_report(model)
        self.assertTrue(pdf.startswith(b"%PDF-"))


class ReportProfileTests(unittest.TestCase):
    def _result(self) -> dict:
        opportunities = [
            {
                "rule": f"rule-{index:03d}",
                "service": "s3",
                "resource": f"s3://bucket-{index}",
                "severity": "low",
                "priority": {"score": float(index)},
            }
            for index in range(40)
        ]
        return {
            "observed_at": "2026-08-04T00:00:00Z",
            "provider": "aws-sdk",
            "summary": {"resources_scanned": 40},
            "complete_opportunities": opportunities,
            "grouped_solutions": [
                {"rule": "rule-039", "resources": 1, "priority_score": 39.0},
                {"rule": "rule-000", "resources": 39, "priority_score": 0.0},
            ],
        }

    def test_executive_profile_limits_presented_findings_to_ten(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        self.assertEqual(len(model["presented_findings"]), 10)
        self.assertEqual(len(model["findings"]), 40)

    def test_executive_profile_presents_the_highest_priority_findings(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        scores = [item["priority_score"] for item in model["presented_findings"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(scores[0], 39.0)

    def test_technical_profile_keeps_every_finding(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="technical")
        self.assertEqual(len(model["findings"]), 40)

    def test_executive_profile_keeps_summary_totals_truthful(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        technical_model = build_report_model(self._result(), report_profile="technical")
        model = build_report_model(self._result(), report_profile="executive")

        self.assertEqual(len(model["presented_findings"]), 10)
        self.assertTrue(model["findings_truncated"])
        self.assertTrue(model["summary"]["report_truncated"])
        self.assertEqual(model["summary"]["presented_findings"], 10)
        self.assertEqual(model["summary"]["findings"], technical_model["summary"]["findings"])
        self.assertEqual(model["summary"]["findings"], 40)

    def test_technical_profile_is_not_marked_truncated(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="technical")
        self.assertFalse(model["findings_truncated"])

    def test_grouped_solutions_reach_the_model_already_ranked(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        self.assertEqual(len(model["grouped_solutions"]), 2)
        scores = [group["priority_score"] for group in model["grouped_solutions"]]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual(model["grouped_solutions"][0]["rule"], "rule-039")

    def test_markdown_shows_the_grouped_rollup(self) -> None:
        from bluearch_aws_steward.reports import build_report_model, render_report

        model = build_report_model(self._result(), report_profile="executive")
        rendered = render_report(model, "markdown")
        self.assertIn("Grouped Solutions", rendered)
        self.assertIn("rule-039", rendered)

    def test_html_shows_the_grouped_rollup(self) -> None:
        from bluearch_aws_steward.reports import build_report_model, render_report

        model = build_report_model(self._result(), report_profile="executive")
        rendered = render_report(model, "html")
        self.assertIn("Grouped Solutions", rendered)

    def test_executive_pdf_is_far_smaller_than_technical(self) -> None:
        from bluearch_aws_steward.pdf_report import render_pdf_report
        from bluearch_aws_steward.reports import build_report_model

        executive = render_pdf_report(
            build_report_model(self._result(), report_profile="executive")
        )
        technical = render_pdf_report(
            build_report_model(self._result(), report_profile="technical")
        )
        self.assertLess(len(executive), len(technical))

    def test_pdf_renders_the_grouped_section(self) -> None:
        import copy

        from bluearch_aws_steward.pdf_report import render_pdf_report
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result(), report_profile="executive")
        self.assertTrue(model["grouped_solutions"])
        with_groups = render_pdf_report(model)

        without = copy.deepcopy(model)
        without["grouped_solutions"] = []
        without_groups = render_pdf_report(without)

        self.assertGreater(len(with_groups), len(without_groups))

    def test_default_profile_is_executive(self) -> None:
        from bluearch_aws_steward.reports import build_report_model

        model = build_report_model(self._result())
        self.assertEqual(model["report_profile"], "executive")
        self.assertEqual(len(model["presented_findings"]), 10)

    def test_machine_readable_formats_are_never_truncated_by_the_default_profile(self) -> None:
        from bluearch_aws_steward.reports import build_report_model, render_report

        model = build_report_model(self._result())
        self.assertEqual(model["report_profile"], "executive")

        rows = list(csv.DictReader(io.StringIO(str(render_report(model, "csv")))))
        sarif = json.loads(str(render_report(model, "sarif")))
        exported = json.loads(str(render_report(model, "json")))

        # CSV and SARIF feed CI. Handing them 10 of 40 rows without saying so is
        # silent data loss, so they must carry the complete finding set.
        self.assertEqual(len(rows), 40)
        self.assertEqual(len(sarif["runs"][0]["results"]), 40)
        self.assertEqual(len(exported["findings"]), 40)

    def test_document_formats_show_ten_findings_and_say_so(self) -> None:
        from bluearch_aws_steward.reports import build_report_model, render_report

        model = build_report_model(self._result())
        markdown = str(render_report(model, "markdown"))
        rendered_html = str(render_report(model, "html"))

        self.assertEqual(markdown.count("\n### rule-"), 10)
        self.assertIn("Showing 10 of 40 findings.", markdown)
        self.assertIn("Showing 10 of 40 findings.", rendered_html)
        self.assertEqual(rendered_html.count("<td>s3://bucket-"), 10)

        pdf = render_report(model, "pdf")
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(bytes(pdf).startswith(b"%PDF-"))

    def test_mcp_export_defaults_to_executive(self) -> None:
        from bluearch_aws_steward.mcp_server import StewardMcpServer
        from tests.support_triage import call_tool, completed_result

        server = StewardMcpServer()
        submitted = call_tool(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Assess this account.",
                "scan_result": __import__(
                    "tests.support_triage", fromlist=["triage_scan_result"]
                ).triage_scan_result(),
                "objectives": ["all"],
                "services": ["iam"],
            },
        )
        assessment_id = submitted["assessment_id"]
        # wait for completion
        completed_result(server, assessment_id)
        # export without specifying a profile
        exported = call_tool(
            server,
            2,
            "bluearch_export_report",
            {"assessment_id": assessment_id, "format": "json"},
        )
        self.assertEqual(exported["report_profile"], "executive")


class ContextualGroupedRolloutTests(unittest.TestCase):
    """The two grouping shapes must both render.

    _group_solution_cards emits {rule, resources, priority_score, ...}.
    _group_recommendations (contextual reviews) emits {group, count,
    highest_severity, items}. A renderer that knows only the first shape prints
    "`None` - 0 resource(s), priority 0" for every contextual group, which is
    fabricated data in the flagship mode's default report.
    """

    def _model(self) -> dict:
        from bluearch_aws_steward.reports import build_report_model

        return build_report_model(
            {
                "observed_at": "2026-08-04T00:00:00Z",
                "provider": "aws-sdk",
                "assessment_mode": "architectural_review",
                "summary": {"resources_scanned": 4},
                "complete_opportunities": [],
                "grouped_solutions": [
                    {
                        "group": "lambda",
                        "count": 3,
                        "highest_severity": "high",
                        "items": [{"rule": "lambda-tracing-disabled"}],
                    },
                    {
                        "group": "s3",
                        "count": 1,
                        "highest_severity": "medium",
                        "items": [{"rule": "s3-no-lifecycle"}],
                    },
                ],
            },
            report_profile="executive",
        )

    def test_markdown_names_contextual_groups_and_omits_unscored_priority(self) -> None:
        from bluearch_aws_steward.reports import render_report

        rendered = str(render_report(self._model(), "markdown"))

        self.assertIn("`lambda` — 3 resource(s)", rendered)
        self.assertIn("`s3` — 1 resource(s)", rendered)
        self.assertNotIn("`None`", rendered)
        self.assertNotIn("priority 0", rendered)

    def test_html_names_contextual_groups_and_omits_unscored_priority(self) -> None:
        from bluearch_aws_steward.reports import _grouped_html

        rendered = _grouped_html(self._model())

        self.assertIn("<td>lambda</td>", rendered)
        self.assertIn("<td>3</td>", rendered)
        self.assertNotIn("None", rendered)
        self.assertNotIn("<th>Priority</th>", rendered)

    def test_pdf_names_contextual_groups_and_omits_unscored_priority(self) -> None:
        from bluearch_aws_steward.pdf_report import _grouped_summary, _styles

        texts = [
            element.text
            for element in _grouped_summary(self._model(), _styles())
            if hasattr(element, "text")
        ]

        self.assertIn("lambda — 3 resource(s)", texts)
        self.assertIn("s3 — 1 resource(s)", texts)
        self.assertFalse([text for text in texts if "None" in text or "priority 0" in text])

    def test_solution_card_groups_still_render_their_priority(self) -> None:
        from bluearch_aws_steward.reports import _grouped_html, _grouped_markdown

        model = {
            "grouped_solutions": [
                {"rule": "s3-public-bucket", "resources": 4, "priority_score": 71.0}
            ]
        }

        markdown = "\n".join(_grouped_markdown(model))
        self.assertIn("`s3-public-bucket` — 4 resource(s), priority 71.0", markdown)
        self.assertIn("<td>71.0</td>", _grouped_html(model))

    def test_pdf_grouped_section_starts_on_its_own_page(self) -> None:
        from reportlab.platypus import PageBreak

        from bluearch_aws_steward.pdf_report import _grouped_summary, _styles

        story = _grouped_summary(self._model(), _styles())

        # Without a page break the rollup collides with the coverage table.
        self.assertTrue(story)
        self.assertIsInstance(story[0], PageBreak)


if __name__ == "__main__":
    unittest.main()
