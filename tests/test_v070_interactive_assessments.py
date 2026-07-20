from __future__ import annotations

import csv
import io
import tempfile
import time
import unittest
from pathlib import Path

from bluearch_aws_steward.assessments import AssessmentStore
from bluearch_aws_steward.mcp_server import StewardMcpServer, list_mcp_tools


def _finding(index: int) -> dict:
    variants = [
        ("s3-public-bucket", "s3", "critical", "security exposure"),
        ("s3-versioning-disabled", "s3", "high", "reliability operations"),
        ("ec2-unattached-ebs-volume", "ec2", "medium", "cost operations"),
        ("iam-root-mfa-disabled", "iam", "low", "security access control"),
    ]
    rule, service, severity, risk = variants[index % len(variants)]
    return {
        "finding_id": f"finding-{index:04d}",
        "rule_id": rule,
        "rule_short_id": rule,
        "service": service,
        "resource": f"{service}://fixture/{index:04d}",
        "severity": severity,
        "risk_detail": risk,
        "scenario": f"Fixture matching criterion {index}",
        "evidence": {"fixture": index},
        "remediation": {
            "summary": "Apply the reviewed recommendation.",
            "safety_level": "low_risk",
            "requires_approval": True,
            "actions": ["Apply the reviewed recommendation."],
            "verification": "Re-read the resource configuration.",
        },
    }


def _scan_result(count: int) -> dict:
    return {
        "schema_version": "0.2",
        "generated_at": "2026-07-15T12:00:00Z",
        "service": "all",
        "provider": "aws-sdk",
        "region": "us-east-1",
        "findings": [_finding(index) for index in range(count)],
        "summary": {
            "findings": count,
            "resources_scanned": count,
            "rules_evaluated": 4,
            "scan_errors": 0,
            "rules_skipped": [],
            "capability_errors": [],
            "service_errors": [],
            "detection_coverage": {"complete_catalog_evaluation": True},
        },
    }


def _call(server: StewardMcpServer, request_id: int, name: str, arguments: dict) -> dict:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    if response["result"]["isError"]:
        raise AssertionError(response["result"]["content"][0]["text"])
    return response["result"]["structuredContent"]


def _complete(server: StewardMcpServer, assessment_id: str) -> None:
    for index in range(100):
        status = _call(
            server,
            1000 + index,
            "bluearch_get_scan_status",
            {"assessment_id": assessment_id},
        )
        if status["status"] not in {"queued", "running"}:
            return
        time.sleep(0.01)
    raise AssertionError("assessment did not complete")


class InteractiveAssessmentTests(unittest.TestCase):
    def test_more_than_200_findings_are_preserved_while_conversation_stays_concise(self) -> None:
        server = StewardMcpServer()
        started = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Run every active rule and prepare a complete report.",
                "assessment_mode": "full_report",
                "objectives": ["all"],
                "services": ["all"],
                "scan_result": _scan_result(225),
                "max_returned_findings": 20,
            },
        )
        _complete(server, started["assessment_id"])
        results = _call(
            server,
            2,
            "bluearch_get_scan_results",
            {"assessment_id": started["assessment_id"], "generate_pdf_report": False},
        )

        self.assertEqual(results["result"]["summary"]["complete_findings"], 225)
        self.assertEqual(len(results["result"]["opportunities"]), 20)
        self.assertNotIn("complete_opportunities", results["result"])
        self.assertTrue(results["result"]["summary"]["presentation_truncated"])

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "complete.csv"
            exported = _call(
                server,
                3,
                "bluearch_export_report",
                {
                    "assessment_id": started["assessment_id"],
                    "format": "csv",
                    "report_profile": "complete",
                    "include_all_findings": True,
                    "output_path": str(path),
                },
            )
            rows = list(csv.reader(io.StringIO(path.read_text(encoding="utf-8"))))
            self.assertEqual(exported["report_summary"]["findings"], 225)
            self.assertEqual(len(rows) - 1, 225)

    def test_cursor_pagination_has_no_duplicates_or_omissions(self) -> None:
        store = AssessmentStore(
            lambda _: {"complete_opportunities": [_finding(i) for i in range(137)]}
        )
        submitted = store.submit({"prompt": "fixture"})
        store.wait(submitted["assessment_id"], timeout=2)
        server = StewardMcpServer(assessment_store=store)

        cursor = None
        returned = []
        while True:
            arguments = {"assessment_id": submitted["assessment_id"], "page_size": 31}
            if cursor:
                arguments["cursor"] = cursor
            page = _call(server, 10 + len(returned), "bluearch_query_results", arguments)
            returned.extend(item["finding_id"] for item in page["findings"])
            cursor = page["next_cursor"]
            if not cursor:
                break

        self.assertEqual(len(returned), 137)
        self.assertEqual(len(set(returned)), 137)

    def test_filters_cover_service_severity_rule_objective_and_remediation(self) -> None:
        server = StewardMcpServer()
        started = _call(
            server,
            20,
            "bluearch_assess",
            {
                "prompt": "Assess security, reliability, cost, and operations.",
                "objectives": ["security", "reliability", "cost_optimization", "operations"],
                "services": ["s3", "ec2", "iam"],
                "result_preferences": {
                    "severities": ["critical"],
                    "remediation_supported": True,
                },
                "scan_result": _scan_result(40),
            },
        )
        _complete(server, started["assessment_id"])
        presentation = _call(
            server,
            22,
            "bluearch_get_scan_results",
            {"assessment_id": started["assessment_id"], "generate_pdf_report": False},
        )
        self.assertEqual(presentation["result"]["summary"]["complete_findings"], 40)
        self.assertTrue(
            all(item["severity"] == "critical" for item in presentation["result"]["opportunities"])
        )
        queried = _call(
            server,
            21,
            "bluearch_query_results",
            {
                "assessment_id": started["assessment_id"],
                "filters": {
                    "services": ["s3"],
                    "severities": ["critical"],
                    "rules": ["s3-public-bucket"],
                    "objectives": ["security"],
                    "remediation_supported": True,
                },
                "page_size": 100,
            },
        )
        self.assertEqual(queried["summary"]["complete_assessment_findings"], 40)
        self.assertGreater(queried["summary"]["filtered_findings"], 0)
        self.assertTrue(all(item["service"] == "s3" for item in queried["findings"]))
        self.assertTrue(all(item["severity"] == "critical" for item in queried["findings"]))
        self.assertTrue(all(item["rule"] == "s3-public-bucket" for item in queried["findings"]))
        self.assertEqual(queried["aws_reads_performed"], 0)

    def test_plural_and_singular_inputs_normalize_to_assessment_intent(self) -> None:
        store = AssessmentStore(
            lambda request: {"summary": {}, "assessment_intent": request["_assessment_intent"]}
        )
        server = StewardMcpServer(assessment_store=store)
        plural = _call(
            server,
            30,
            "bluearch_assess",
            {
                "prompt": "Assess IAM and S3 security and cost.",
                "objectives": ["security", "cost_optimization"],
                "services": ["iam", "s3"],
                "scan_result": _scan_result(0),
            },
        )
        singular = _call(
            server,
            31,
            "bluearch_assess",
            {
                "prompt": "Assess S3 security.",
                "objective": "security",
                "service": "s3",
                "scan_result": _scan_result(0),
            },
        )
        plural_request = store.get_request(plural["assessment_id"])
        singular_request = store.get_request(singular["assessment_id"])
        self.assertEqual(plural_request["objectives"], ["security", "cost_optimization"])
        self.assertEqual(plural_request["services"], ["iam", "s3"])
        self.assertEqual(plural_request["objective"], "all")
        self.assertEqual(singular_request["objectives"], ["security"])
        self.assertEqual(singular_request["services"], ["s3"])

    def test_generic_prompt_is_guided_and_complete_prompt_infers_full_report(self) -> None:
        server = StewardMcpServer()
        guided = _call(server, 40, "bluearch_assess", {"prompt": "Review my AWS account."})
        self.assertEqual(guided["status"], "input_required")
        self.assertEqual(
            [question["response_type"] for question in guided["questions"]],
            ["multi_select", "multi_select"],
        )

        store = AssessmentStore(
            lambda request: {"summary": {}, "intent": request["_assessment_intent"]}
        )
        full_server = StewardMcpServer(assessment_store=store)
        full = _call(
            full_server,
            41,
            "bluearch_assess",
            {
                "prompt": "Run every active rule and generate a complete technical PDF.",
                "scan_result": _scan_result(0),
            },
        )
        request = store.get_request(full["assessment_id"])
        self.assertEqual(request["assessment_mode"], "full_report")
        self.assertEqual(request["objectives"], ["all"])
        self.assertEqual(request["services"], ["all"])

    def test_memory_guard_is_explicit_and_never_silent(self) -> None:
        store = AssessmentStore(
            lambda _: {"complete_opportunities": [_finding(i) for i in range(7)], "summary": {}},
            max_findings=5,
        )
        submitted = store.submit({"prompt": "fixture"})
        result = store.wait(submitted["assessment_id"], timeout=2)["result"]
        self.assertEqual(len(result["complete_opportunities"]), 5)
        self.assertTrue(result["summary"]["incomplete"])
        self.assertEqual(result["summary"]["incomplete_reason"], "assessment_memory_guard_reached")
        self.assertEqual(result["summary"]["findings_observed_before_guard"], 7)

    def test_query_and_export_do_not_run_assessment_again(self) -> None:
        calls = 0

        def run(_: dict) -> dict:
            nonlocal calls
            calls += 1
            return {"complete_opportunities": [_finding(i) for i in range(3)], "summary": {}}

        store = AssessmentStore(run)
        submitted = store.submit({"prompt": "fixture"})
        store.wait(submitted["assessment_id"], timeout=2)
        server = StewardMcpServer(assessment_store=store)
        _call(server, 50, "bluearch_query_results", {"assessment_id": submitted["assessment_id"]})
        with tempfile.TemporaryDirectory() as directory:
            _call(
                server,
                51,
                "bluearch_export_report",
                {
                    "assessment_id": submitted["assessment_id"],
                    "format": "pdf",
                    "report_profile": "technical",
                    "include_all_findings": True,
                    "output_path": str(Path(directory) / "report.pdf"),
                },
            )
        self.assertEqual(calls, 1)

    def test_mcp_contract_exposes_additive_v070_fields(self) -> None:
        tools = {tool["name"]: tool for tool in list_mcp_tools()}
        self.assertIn("bluearch_query_results", tools)
        assess = tools["bluearch_assess"]["inputSchema"]["properties"]
        self.assertIn("objective", assess)
        self.assertIn("objectives", assess)
        self.assertIn("service", assess)
        self.assertIn("services", assess)
        self.assertIn("assessment_mode", assess)
        export = tools["bluearch_export_report"]["inputSchema"]["properties"]
        self.assertEqual(
            export["report_profile"]["enum"], ["executive", "technical", "remediation", "complete"]
        )


if __name__ == "__main__":
    unittest.main()
