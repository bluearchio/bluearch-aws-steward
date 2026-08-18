from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from bluearch_aws_steward.contextual_review import (
    MAX_GRAPH_NODES,
    MAX_READ_OPERATIONS,
    BudgetedAwsProvider,
    ReadBudgetExceeded,
    _contextual_recommendations,
    prepare_contextual_review,
)
from bluearch_aws_steward.knowledge_packs import (
    knowledge_pack_manifest,
    validate_knowledge_packs,
)
from bluearch_aws_steward.mcp_server import StewardMcpServer, list_mcp_tools
from bluearch_aws_steward.models import ResourceRef
from bluearch_aws_steward.reports import build_report_model, render_report


def _call(server: StewardMcpServer, request_id: int, name: str, arguments: dict) -> dict:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    if response["result"]["isError"]:
        raise AssertionError(response["result"]["content"][0]["text"])
    return json.loads(response["result"]["content"][0]["text"])


def _scan_result() -> dict:
    return {
        "schema_version": "0.2",
        "generated_at": "2026-08-03T12:00:00Z",
        "service": "s3",
        "provider": "aws-sdk",
        "profile": None,
        "region": "us-east-1",
        "findings": [
            {
                "finding_id": "finding-contextual-s3",
                "rule_id": "79c21971-4b21-43f7-aec0-9033147ef385",
                "rule_short_id": "s3-versioning-disabled",
                "service": "s3",
                "resource": "s3://contextual-fixture",
                "resource_ref": {
                    "provider": "aws",
                    "service": "s3",
                    "resource_type": "aws.s3.bucket",
                    "resource_id": "contextual-fixture",
                    "region": "us-east-1",
                    "arn": "arn:aws:s3:::contextual-fixture",
                },
                "severity": "medium",
                "risk_detail": "reliability",
                "scenario": "Bucket versioning is disabled.",
                "evidence": {
                    "versioning_status": None,
                    "observation": {
                        "source": "aws_control_plane",
                        "confidence": "high",
                        "observed_at": "2026-08-03T12:00:00Z",
                    },
                },
                "remediation": {
                    "summary": "Enable versioning after reviewing consumers.",
                    "safety_level": "low_risk",
                    "requires_approval": True,
                    "actions": ["Enable versioning."],
                    "verification": "Re-read bucket versioning.",
                },
            },
            {
                "finding_id": "finding-unrelated-s3",
                "rule_id": "79c21971-4b21-43f7-aec0-9033147ef385",
                "rule_short_id": "s3-versioning-disabled",
                "service": "s3",
                "resource": "s3://unrelated-bucket",
                "severity": "medium",
                "risk_detail": "reliability",
                "scenario": "Bucket versioning is disabled.",
                "evidence": {"versioning_status": None},
                "remediation": {
                    "summary": "Enable versioning.",
                    "safety_level": "low_risk",
                    "requires_approval": True,
                    "actions": ["Enable versioning."],
                    "verification": "Re-read bucket versioning.",
                },
            },
        ],
        "summary": {
            "resources_scanned": 2,
            "findings": 2,
            "rules_evaluated": 14,
            "scan_errors": 0,
            "detection_coverage": {"complete_catalog_evaluation": False},
        },
    }


class _CountingProvider:
    def __init__(self) -> None:
        self.calls = 0

    def capabilities(self) -> set[str]:
        return {"test.read"}

    def read(self, operation: str, **parameters: object) -> dict:
        self.calls += 1
        return {"operation": operation, "parameters": parameters}


class _RecordingProvider(_CountingProvider):
    def __init__(self) -> None:
        super().__init__()
        self.requests: list[tuple[str, dict]] = []

    def read(self, operation: str, **parameters: object) -> dict:
        self.calls += 1
        self.requests.append((operation, dict(parameters)))
        return {"logGroups": []}


def _completed_result(server: StewardMcpServer, assessment_id: str) -> dict:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = _call(server, 90, "bluearch_get_scan_status", {"assessment_id": assessment_id})
        if status["status"] == "completed":
            return _call(
                server,
                91,
                "bluearch_get_scan_results",
                {"assessment_id": assessment_id, "generate_pdf_report": False},
            )["result"]
        if status["status"] == "failed":
            raise AssertionError(status.get("error"))
        time.sleep(0.01)
    raise AssertionError("contextual assessment did not complete")


class KnowledgePackTests(unittest.TestCase):
    def test_packs_cover_all_runtime_scopes_and_native_rules(self) -> None:
        manifest = validate_knowledge_packs()

        self.assertEqual(manifest["runtime_scope_count"], 17)
        self.assertEqual(manifest["native_rule_count"], 121)
        self.assertEqual(len(manifest["rule_mappings"]), 121)
        self.assertEqual(
            manifest["mapped_native_rules"] + manifest["intentionally_unmapped_native_rules"],
            121,
        )
        self.assertGreaterEqual(manifest["waf_catalog_row_count"], 298)
        self.assertTrue(manifest["catalog_revision"].startswith("sha256:"))

    def test_manifest_is_generated_not_hardcoded_in_mcp_coverage(self) -> None:
        expected = knowledge_pack_manifest()
        coverage_tool = next(
            tool for tool in list_mcp_tools() if tool["name"] == "bluearch_get_coverage"
        )

        self.assertIn("inputSchema", coverage_tool)
        self.assertEqual(expected["runtime_scope_count"], 17)


class ContextualPreparationTests(unittest.TestCase):
    def test_vague_resource_review_requests_exact_focus(self) -> None:
        _, refinement = prepare_contextual_review(
            {
                "prompt": "Review the S3 bucket I am deploying.",
                "assessment_mode": "architectural_review",
                "review_context": {"operation": "create"},
            }
        )

        self.assertIsNotNone(refinement)
        self.assertEqual(refinement["reason"], "architectural_review_focus_required")
        self.assertIn("full_assessment", {item["id"] for item in refinement["possible_responses"]})

    def test_context_questions_are_limited_and_resumable(self) -> None:
        _, refinement = prepare_contextual_review(
            {
                "prompt": "Review s3://contextual-fixture before deletion.",
                "assessment_mode": "architectural_review",
                "review_context": {"operation": "delete"},
            }
        )

        self.assertIsNotNone(refinement)
        self.assertEqual(refinement["reason"], "architectural_review_context_required")
        self.assertLessEqual(len(refinement["questions"]), 5)
        self.assertEqual(refinement["resume"]["tool"], "bluearch_assess")

    def test_explicit_unknowns_are_preserved(self) -> None:
        prepared, refinement = prepare_contextual_review(
            {
                "prompt": "Review s3://contextual-fixture.",
                "assessment_mode": "architectural_review",
                "review_context": {
                    "operation": "review",
                    "answers": {
                        "environment": "unknown",
                        "data_classification": "unknown",
                        "access_pattern": "unknown",
                        "retention": "unknown",
                        "consumers": "unknown",
                    },
                },
            }
        )

        self.assertIsNone(refinement)
        self.assertEqual(prepared["_review_intent"]["answers"]["environment"], "unknown")


class BudgetTests(unittest.TestCase):
    def test_reads_are_deduplicated_and_hard_limited(self) -> None:
        provider = _CountingProvider()
        bounded = BudgetedAwsProvider(provider, 2)

        first = bounded.read("test.read", ResourceId="one")
        second = bounded.read("test.read", ResourceId="one")
        bounded.read("test.read", ResourceId="two")

        self.assertEqual(first, second)
        self.assertEqual(provider.calls, 2)
        self.assertEqual(bounded.cache_hits, 1)
        with self.assertRaises(ReadBudgetExceeded):
            bounded.read("test.read", ResourceId="three")
        self.assertTrue(bounded.exhausted)
        self.assertEqual(MAX_READ_OPERATIONS, 50)
        self.assertEqual(MAX_GRAPH_NODES, 25)

    def test_targetable_operations_receive_the_exact_focus(self) -> None:
        provider = _RecordingProvider()
        bounded = BudgetedAwsProvider(
            provider,
            5,
            focus=[
                ResourceRef(
                    provider="aws",
                    service="cloudwatch",
                    resource_type="aws.logs.log-group",
                    resource_id="/aws/lambda/contextual",
                )
            ],
        )

        bounded.read("logs.describe_log_groups")

        self.assertEqual(
            provider.requests,
            [("logs.describe_log_groups", {"logGroupNamePrefix": "/aws/lambda/contextual"})],
        )
        self.assertEqual(bounded.ledger[0]["focus_mode"], "targeted_api")

    def test_exact_focus_can_replace_non_targetable_inventory_discovery(self) -> None:
        provider = _RecordingProvider()
        bounded = BudgetedAwsProvider(
            provider,
            5,
            focus=[
                ResourceRef(
                    provider="aws",
                    service="dynamodb",
                    resource_type="aws.dynamodb.table",
                    resource_id="contextual-table",
                )
            ],
        )

        response = bounded.read("dynamodb.list_tables")

        self.assertEqual(response, {"TableNames": ["contextual-table"]})
        self.assertEqual(provider.calls, 0)
        self.assertFalse(bounded.ledger[0]["aws_call"])


class ContextualMcpTests(unittest.TestCase):
    def test_high_impact_cross_pillar_risk_precedes_requested_objective(self) -> None:
        focus = [
            ResourceRef(
                provider="aws",
                service="s3",
                resource_type="aws.s3.bucket",
                resource_id="contextual-fixture",
            )
        ]
        recommendations = _contextual_recommendations(
            [
                {
                    "opportunity_id": "cost",
                    "rule": "s3-no-lifecycle",
                    "resource": "s3://contextual-fixture",
                    "service": "s3",
                    "severity": "medium",
                    "matched_objectives": ["cost_optimization"],
                    "remediation": {},
                },
                {
                    "opportunity_id": "security",
                    "rule": "s3-public-bucket",
                    "resource": "s3://contextual-fixture",
                    "service": "s3",
                    "severity": "high",
                    "matched_objectives": ["security"],
                    "remediation": {},
                },
            ],
            focus,
            [],
            {"objectives": ["cost_optimization"], "answers": {}, "operation": "optimize"},
        )

        self.assertEqual([item["opportunity_id"] for item in recommendations], ["security", "cost"])
        self.assertFalse(recommendations[0]["ranking"]["requested_objective_match"])
        self.assertTrue(recommendations[0]["ranking"]["cross_pillar_risk_preserved"])

    def test_stdio_contract_lifecycle_filters_unrelated_resources(self) -> None:
        server = StewardMcpServer()
        submitted = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Review s3://contextual-fixture before deleting it.",
                "assessment_mode": "architectural_review",
                "review_context": {
                    "operation": "delete",
                    "answers": {
                        "environment": "production",
                        "data_classification": "confidential",
                        "access_pattern": "private_application",
                        "retention": "multi_year",
                        "consumers": "single_workload",
                    },
                },
                "scan_result": _scan_result(),
            },
        )
        assessment_id = submitted["assessment_id"]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            status = _call(server, 2, "bluearch_get_scan_status", {"assessment_id": assessment_id})
            if status["status"] == "completed":
                break
            time.sleep(0.01)
        else:
            self.fail("contextual assessment did not complete")

        result = _call(
            server,
            3,
            "bluearch_get_scan_results",
            {"assessment_id": assessment_id, "generate_pdf_report": False},
        )["result"]

        self.assertEqual(result["assessment_mode"], "architectural_review")
        self.assertFalse(result["summary"]["full_account_scan"])
        self.assertEqual(result["resources"], ["s3://contextual-fixture"])
        self.assertNotIn("s3://unrelated-bucket", json.dumps(result))
        self.assertEqual(result["evidence_ledger"]["write_operations"], 0)
        self.assertTrue(result["excluded_scope"]["full_account_scan_not_performed"])
        statuses = result["well_architected_review"]["status_counts"]
        self.assertGreaterEqual(statuses["risk"], 1)
        self.assertIn("business_impact", result["opportunities"][0])
        self.assertIn("verification", result["opportunities"][0])

    def test_pure_terraform_review_never_requires_or_calls_aws(self) -> None:
        def fail_provider(_: dict) -> object:
            raise AssertionError("pure IaC review must not create an AWS provider")

        server = StewardMcpServer(aws_provider_factory=fail_provider)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "function.tf").write_text(
                'resource "aws_lambda_function" "api" {\n'
                '  function_name = "contextual-api"\n'
                '  role = "arn:aws:iam::000000000000:role/fixture"\n'
                '  handler = "index.handler"\n'
                '  runtime = "python3.13"\n'
                "}\n",
                encoding="utf-8",
            )
            submitted = _call(
                server,
                10,
                "bluearch_assess",
                {
                    "prompt": "Review the Lambda function I am creating.",
                    "assessment_mode": "architectural_review",
                    "review_context": {
                        "operation": "create",
                        "iac": {
                            "workspace_root": str(root),
                            "paths": ["function.tf"],
                            "format": "terraform",
                        },
                        "answers": {"_continue_with_unknowns": True},
                    },
                },
            )
            result = _completed_result(server, submitted["assessment_id"])

        self.assertEqual(result["provider"], "aws-sdk")
        self.assertEqual(result["evidence_ledger"]["operation_count"], 0)
        self.assertEqual(result["evidence_ledger"]["write_operations"], 0)
        self.assertIn("lambda-xray-tracing-disabled", result["rules"])
        self.assertEqual(result["focus"]["resolution_source"], "iac_changed_resources")
        self.assertTrue(result["mcp"]["read_only"])
        self.assertTrue(
            any(
                edge.get("relationship_type") == "declared_by"
                and edge.get("source") == "iac_live_correlation"
                and edge.get("evidence_provenance", {}).get("source_path") == "function.tf"
                for edge in result["architecture_neighborhood"]["edges"]
            )
        )

    def test_context_can_exclude_an_inapplicable_practice_and_recommendation(self) -> None:
        server = StewardMcpServer()
        submitted = _call(
            server,
            20,
            "bluearch_assess",
            {
                "prompt": "Review s3://contextual-fixture before deleting it.",
                "assessment_mode": "architectural_review",
                "review_context": {
                    "operation": "delete",
                    "answers": {
                        "environment": "sandbox",
                        "data_classification": "internal",
                        "access_pattern": "batch",
                        "retention": "ephemeral",
                        "consumers": "single_workload",
                    },
                },
                "scan_result": _scan_result(),
            },
        )
        result = _completed_result(server, submitted["assessment_id"])
        practices = [
            practice
            for pillar in result["well_architected_review"]["pillars"]
            for practice in pillar["practices"]
            if practice["practice_id"] == "REL09-BP01"
        ]

        self.assertTrue(practices)
        self.assertTrue(all(item["status"] == "not_applicable" for item in practices))
        self.assertNotIn("s3-versioning-disabled", result["rules"])
        self.assertEqual(result["summary"]["contextually_excluded_findings"], 1)

    def test_contextual_data_is_preserved_in_every_report_format(self) -> None:
        server = StewardMcpServer()
        submitted = _call(
            server,
            30,
            "bluearch_assess",
            {
                "prompt": "Review s3://contextual-fixture.",
                "assessment_mode": "architectural_review",
                "review_context": {
                    "operation": "review",
                    "answers": {
                        "environment": "production",
                        "data_classification": "confidential",
                        "access_pattern": "private_application",
                        "retention": "multi_year",
                        "consumers": "single_workload",
                    },
                },
                "scan_result": _scan_result(),
            },
        )
        result = _completed_result(server, submitted["assessment_id"])
        model = build_report_model(result)

        for report_format in ("json", "markdown", "html", "csv", "sarif"):
            rendered = render_report(model, report_format)
            self.assertIn("REL09-BP01", rendered)
            self.assertIn("architectural_review", rendered)
        pdf = render_report(model, "pdf")
        self.assertIsInstance(pdf, bytes)
        self.assertTrue(pdf.startswith(b"%PDF-"))


if __name__ == "__main__":
    unittest.main()
