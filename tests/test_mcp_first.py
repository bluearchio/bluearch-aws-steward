from __future__ import annotations

import json
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from threading import Event

from bluearch_aws_steward.assessments import AssessmentStore
from bluearch_aws_steward.aws_context import discover_aws_context
from bluearch_aws_steward.mcp_server import (
    StewardMcpServer,
    list_mcp_prompts,
    list_mcp_tools,
    mcp_client_config,
    run_mcp_stdio_server,
)
from bluearch_aws_steward.providers.base import AwsProviderError


def _finding() -> dict:
    return {
        "finding_id": "steward-versioning-test",
        "rule_id": "rule-versioning",
        "rule_short_id": "s3-versioning-disabled",
        "service": "s3",
        "resource": "s3://example-bucket",
        "severity": "medium",
        "risk_detail": "operations",
        "scenario": "S3 versioning should support object recovery",
        "evidence": {"versioning_status": None},
        "remediation": {
            "summary": "Enable bucket versioning.",
            "safety_level": "low_risk",
            "requires_approval": True,
            "actions": ["Enable bucket versioning."],
            "verification": "Re-read bucket versioning.",
        },
    }


def _scan_result() -> dict:
    return {
        "schema_version": "0.1",
        "generated_at": "2026-07-13T12:00:00Z",
        "service": "s3",
        "provider": "aws-sdk",
        "profile": "test-profile",
        "region": "us-east-1",
        "findings": [_finding()],
        "summary": {"findings": 1, "resources_scanned": 1, "scan_errors": 0},
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
    return json.loads(response["result"]["content"][0]["text"])


def _aws_context(*profiles: dict, active_profile: str | None = None) -> dict:
    return {
        "profiles": list(profiles),
        "profile_count": len(profiles),
        "active_profile": active_profile,
        "environment_region": None,
        "credential_sources": [],
        "non_profile_credentials_configured": False,
        "discovery_errors": [],
        "secrets_included": False,
    }


class MutableVersioningProvider:
    def __init__(self) -> None:
        self.versioning_status = None
        self.writes: list[str] = []

    def caller_identity(self) -> dict:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/Developer/test",
        }

    def list_buckets(self) -> list[str]:
        return ["example-bucket"]

    def get_bucket_versioning_status(self, bucket: str) -> str | None:
        self.assert_bucket(bucket)
        return self.versioning_status

    def put_versioning(self, bucket: str) -> None:
        self.assert_bucket(bucket)
        self.writes.append("put_versioning")
        self.versioning_status = "Enabled"

    def assert_bucket(self, bucket: str) -> None:
        if bucket != "example-bucket":
            raise AssertionError(f"unexpected bucket: {bucket}")


class AssessmentStoreTests(unittest.TestCase):
    def test_jobs_are_ephemeral_and_return_point_in_time_results(self) -> None:
        def run(request: dict) -> dict:
            request["_progress_callback"](
                {
                    "phase": "scanning",
                    "services_total": 1,
                    "services_completed": 1,
                    "findings_discovered": 1,
                }
            )
            return {
                "observed_at": "2026-07-13T12:00:00Z",
                "summary": {"prompt": request["prompt"]},
            }

        store = AssessmentStore(
            run,
            ttl_seconds=60,
        )

        submitted = store.submit({"prompt": "Find savings", "scan_result": {"findings": []}})
        completed = store.wait(submitted["assessment_id"], timeout=2)

        self.assertEqual(completed["status"], "completed")
        self.assertTrue(completed["ephemeral"])
        self.assertTrue(completed["point_in_time"])
        self.assertTrue(completed["request"]["uses_supplied_scan_result"])
        self.assertEqual(completed["result"]["summary"]["prompt"], "Find savings")
        self.assertEqual(completed["progress"]["services_completed"], 1)
        self.assertEqual(completed["progress"]["findings_discovered"], 1)

    def test_failed_jobs_preserve_a_user_facing_error(self) -> None:
        def fail(_: dict) -> dict:
            raise ValueError("invalid assessment")

        store = AssessmentStore(fail)
        submitted = store.submit({"prompt": "Fail"})
        failed = store.wait(submitted["assessment_id"], timeout=2)

        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["error"], "invalid assessment")

    def test_partial_results_and_cancellation_preserve_completed_reads(self) -> None:
        started = Event()

        def run(request: dict) -> dict:
            request["_partial_callback"](
                {
                    "schema_version": "0.2",
                    "summary": {"resources_scanned": 3, "partial": True},
                    "findings": [],
                }
            )
            started.set()
            request["_cancel_event"].wait(2)
            return {
                "observed_at": "2026-07-14T12:00:00Z",
                "summary": {"resources_scanned": 3, "cancelled": True},
            }

        store = AssessmentStore(run)
        submitted = store.submit({"prompt": "Cancel safely"})
        self.assertTrue(started.wait(2))
        running = store.get(submitted["assessment_id"], include_partial=True)
        self.assertEqual(running["partial_result"]["summary"]["resources_scanned"], 3)
        server = StewardMcpServer(assessment_store=store)
        progress = _call(
            server,
            1,
            "bluearch_get_scan_results",
            {"assessment_id": submitted["assessment_id"], "include_partial": True},
        )
        self.assertFalse(progress["final_response_allowed"])
        self.assertEqual(progress["report_offer_available_after"], ["completed", "cancelled"])

        cancelling = store.cancel(submitted["assessment_id"])
        self.assertTrue(cancelling["cancel_requested"])
        cancelled = store.wait(submitted["assessment_id"], timeout=2)

        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["result"]["summary"]["resources_scanned"], 3)

        offer = _call(
            server,
            2,
            "bluearch_get_scan_results",
            {"assessment_id": submitted["assessment_id"]},
        )
        self.assertEqual(offer["reason"], "pdf_report_offer_required")
        self.assertTrue(offer["report"]["partial"])


class McpPromptTests(unittest.TestCase):
    def test_initialize_advertises_prompt_capability(self) -> None:
        response = StewardMcpServer().handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18", "capabilities": {}},
            }
        )

        self.assertEqual(
            response["result"]["capabilities"]["prompts"],
            {"listChanged": False},
        )

    def test_prompt_list_contains_safe_user_workflows_only(self) -> None:
        prompts = {prompt["name"]: prompt for prompt in list_mcp_prompts()}

        self.assertEqual(
            set(prompts),
            {
                "readiness_and_coverage",
                "comprehensive_assessment",
                "cost_optimization",
                "security_review",
                "catalog_search",
                "remediation_plan",
                "pdf_assessment_report",
            },
        )
        self.assertNotIn("apply", " ".join(prompts).lower())
        query = next(
            argument
            for argument in prompts["catalog_search"]["arguments"]
            if argument["name"] == "query"
        )
        self.assertTrue(query["required"])

    def test_prompt_get_renders_explicit_scope_and_read_only_guard(self) -> None:
        response = StewardMcpServer().handle(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "prompts/get",
                "params": {
                    "name": "cost_optimization",
                    "arguments": {
                        "profile": "engineering-sso",
                        "region": "us-east-1",
                        "service": "ec2",
                        "max_results": "5",
                    },
                },
            }
        )

        text = response["result"]["messages"][0]["content"]["text"]
        self.assertIn('AWS profile "engineering-sso"', text)
        self.assertIn('service scope "ec2"', text)
        self.assertIn("at most 5", text)
        self.assertIn("do not apply changes", text.lower())
        self.assertNotIn("allow_write=true", text)

    def test_pdf_report_prompt_reuses_completed_result_without_aws_reads(self) -> None:
        response = StewardMcpServer().handle(
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "prompts/get",
                "params": {
                    "name": "pdf_assessment_report",
                    "arguments": {
                        "assessment_id": "assessment-123",
                        "output_path": "./reports/assessment-123.pdf",
                    },
                },
            }
        )

        text = response["result"]["messages"][0]["content"]["text"]
        self.assertIn("bluearch_export_report", text)
        self.assertIn("format pdf", text)
        self.assertIn("./reports/assessment-123.pdf", text)
        self.assertIn("do not start another assessment", text.lower())
        self.assertIn("do not", text.lower())
        self.assertIn("query aws again", text.lower())

    def test_prompt_get_rejects_missing_required_and_invalid_arguments(self) -> None:
        server = StewardMcpServer()
        missing = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "prompts/get",
                "params": {"name": "catalog_search", "arguments": {}},
            }
        )
        invalid = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "prompts/get",
                "params": {
                    "name": "comprehensive_assessment",
                    "arguments": {"service": "unsupported"},
                },
            }
        )

        self.assertEqual(missing["error"]["code"], -32602)
        self.assertIn("query", missing["error"]["message"])
        self.assertEqual(invalid["error"]["code"], -32602)
        self.assertIn("service", invalid["error"]["message"])


class McpFirstWorkflowTests(unittest.TestCase):
    def test_mcp_config_fallback_uses_the_locked_synchronized_checkout(self) -> None:
        repository_root = Path("/tmp/bluearch-aws-steward").absolute()
        config = mcp_client_config(
            repository_root=repository_root,
            uv_executable="/usr/local/bin/uv",
        )["mcpServers"]["bluearch-aws-steward"]
        self.assertEqual(config["command"], "/usr/local/bin/uv")
        self.assertEqual(
            config["args"],
            [
                "run",
                "--directory",
                str(repository_root),
                "--locked",
                "--no-sync",
                "python",
                "-m",
                "bluearch_aws_steward.mcp",
            ],
        )
        self.assertEqual(config["env"]["AWS_SDK_LOAD_CONFIG"], "1")
        self.assertNotIn("AWS_PROFILE", config["env"])
        self.assertNotIn("AWS_REGION", config["env"])

    def test_mcp_config_detects_the_source_checkout(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        config = mcp_client_config(uv_executable="/usr/local/bin/uv")["mcpServers"][
            "bluearch-aws-steward"
        ]

        self.assertEqual(
            config["command"],
            str(repository_root / ".venv" / "bin" / "bluearch-steward-mcp"),
        )
        self.assertEqual(config["args"], [])

    def test_public_mcp_config_uses_an_exact_uvx_package_version(self) -> None:
        config = mcp_client_config(
            runtime="uvx",
            uvx_executable="/usr/local/bin/uvx",
            package_version="0.7.0b4",
        )["mcpServers"]["bluearch-aws-steward"]

        self.assertEqual(config["command"], "/usr/local/bin/uvx")
        self.assertEqual(
            config["args"],
            [
                "--from",
                "bluearch-aws-steward==0.7.0b4",
                "bluearch-steward-mcp",
            ],
        )
        self.assertEqual(config["env"]["AWS_SDK_LOAD_CONFIG"], "1")

    def test_mcp_config_rejects_unknown_runtime(self) -> None:
        with self.assertRaisesRegex(ValueError, "runtime must be one of"):
            mcp_client_config(runtime="unknown")

    def test_primary_tool_contract_is_exposed(self) -> None:
        tools = {tool["name"]: tool for tool in list_mcp_tools()}
        expected = {
            "bluearch_assess",
            "bluearch_list_aws_profiles",
            "bluearch_get_scan_status",
            "bluearch_get_scan_results",
            "bluearch_export_report",
            "bluearch_get_resource_details",
            "bluearch_get_coverage",
            "bluearch_status",
        }
        self.assertTrue(expected <= set(tools))
        self.assertEqual(
            tools["bluearch_assess"]["inputSchema"]["properties"]["provider"]["default"],
            "aws-sdk",
        )
        self.assertNotIn(
            "default",
            tools["bluearch_assess"]["inputSchema"]["properties"]["region"],
        )
        self.assertNotIn(
            "default",
            tools["bluearch_assess"]["inputSchema"]["properties"]["service"],
        )
        self.assertNotIn(
            "default",
            tools["bluearch_find_opportunities"]["inputSchema"]["properties"]["objective"],
        )
        self.assertNotIn(
            "default",
            tools["bluearch_find_opportunities"]["inputSchema"]["properties"]["service"],
        )
        self.assertNotIn(
            "default",
            tools["bluearch_scan_aws"]["inputSchema"]["properties"]["service"],
        )
        self.assertIn(
            "assessment_id",
            tools["bluearch_plan_remediation"]["inputSchema"]["properties"],
        )
        self.assertIn(
            "pdf",
            tools["bluearch_export_report"]["inputSchema"]["properties"]["format"]["enum"],
        )
        self.assertIn(
            "generate_pdf_report",
            tools["bluearch_get_scan_results"]["inputSchema"]["properties"],
        )

    def test_pdf_export_writes_binary_without_embedding_it_in_json(self) -> None:
        store = AssessmentStore(lambda _: _scan_result())
        submitted = store.submit({"prompt": "Use the supplied fixture result"})
        completed = store.wait(submitted["assessment_id"], timeout=2)
        self.assertEqual(completed["status"], "completed")
        server = StewardMcpServer(assessment_store=store)

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "assessment.pdf"
            exported = _call(
                server,
                6,
                "bluearch_export_report",
                {
                    "assessment_id": submitted["assessment_id"],
                    "format": "pdf",
                    "output_path": str(output_path),
                },
            )

            self.assertEqual(exported["content_type"], "application/pdf")
            self.assertIsNone(exported["content"])
            self.assertIsNone(exported["report"])
            self.assertEqual(exported["report_summary"]["findings"], 1)
            self.assertEqual(exported["output_path"], str(output_path))
            self.assertEqual(exported["size_bytes"], output_path.stat().st_size)
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-"))

    def test_completed_scan_results_can_generate_pdf_after_user_accepts(self) -> None:
        store = AssessmentStore(lambda _: _scan_result())
        submitted = store.submit({"prompt": "Use the supplied fixture result"})
        completed = store.wait(submitted["assessment_id"], timeout=2)
        self.assertEqual(completed["status"], "completed")
        server = StewardMcpServer(assessment_store=store)

        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "accepted.pdf"
            results = _call(
                server,
                6,
                "bluearch_get_scan_results",
                {
                    "assessment_id": submitted["assessment_id"],
                    "generate_pdf_report": True,
                    "pdf_output_path": str(output_path),
                },
            )

            self.assertTrue(results["ready"])
            self.assertTrue(results["pdf_report_offer"]["accepted"])
            self.assertEqual(results["pdf_report"]["content_type"], "application/pdf")
            self.assertEqual(results["pdf_report"]["output_path"], str(output_path))
            self.assertTrue(output_path.read_bytes().startswith(b"%PDF-"))

    def test_assessment_to_resource_and_plan_flow(self) -> None:
        provider = MutableVersioningProvider()
        server = StewardMcpServer(
            aws_context_loader=lambda: _aws_context(
                {"name": "test-profile", "kind": "sso", "region": "us-east-1"},
                active_profile="test-profile",
            ),
            aws_provider_factory=lambda _: provider,
        )
        started = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Improve S3 operations and versioning",
                "scan_result": _scan_result(),
            },
        )
        assessment_id = started["assessment_id"]
        server._assessments.wait(assessment_id, timeout=2)

        status = _call(server, 2, "bluearch_get_scan_status", {"assessment_id": assessment_id})
        self.assertEqual(status["status"], "completed")
        self.assertEqual(status["next"]["tool"], "bluearch_get_scan_results")

        prompt = _call(server, 3, "bluearch_get_scan_results", {"assessment_id": assessment_id})
        self.assertEqual(prompt["status"], "input_required")
        self.assertEqual(prompt["reason"], "pdf_report_offer_required")
        self.assertEqual(
            [response["arguments"] for response in prompt["possible_responses"]],
            [{"generate_pdf_report": True}, {"generate_pdf_report": False}],
        )
        self.assertEqual(prompt["resume"]["tool"], "bluearch_get_scan_results")

        results = _call(
            server,
            4,
            "bluearch_get_scan_results",
            {"assessment_id": assessment_id, "generate_pdf_report": False},
        )
        self.assertTrue(results["ready"])
        self.assertEqual(results["observed_at"], "2026-07-13T12:00:00Z")
        self.assertFalse(results["freshness"]["persistent_inventory"])
        self.assertFalse(results["pdf_report_offer"]["accepted"])
        cards = results["result"]["solution_cards"]
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["risk"], "operations")
        self.assertEqual(cards[0]["evidence"]["versioning_status"], None)
        self.assertEqual(cards[0]["cost_estimate"]["status"], "not_estimated")
        self.assertEqual(cards[0]["cost_estimate"]["confidence"], "not_available")
        self.assertTrue(cards[0]["requires_approval"])
        finding_id = cards[0]["solution_id"]

        details = _call(
            server,
            5,
            "bluearch_get_resource_details",
            {"assessment_id": assessment_id, "resource": "s3://example-bucket"},
        )
        self.assertEqual(details["status"], "matched")
        self.assertEqual(details["finding_count"], 1)
        self.assertEqual(details["source"], "assessment_snapshot")

        plan = _call(
            server,
            6,
            "bluearch_plan_remediation",
            {"assessment_id": assessment_id, "finding_id": finding_id},
        )
        self.assertEqual(plan["status"], "awaiting_approval")
        self.assertEqual(plan["plan"]["finding"]["source_finding_id"], finding_id)
        self.assertEqual(plan["plan"]["finding"]["resource"], "s3://example-bucket")
        self.assertTrue(plan["apply_supported"])
        self.assertEqual(plan["plan"]["aws_context"]["account_id"], "123456789012")
        self.assertIn("s3:PutBucketVersioning", plan["plan"]["required_iam_actions"])
        self.assertNotIn("cli_equivalent", plan)

        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_apply_remediation",
                    "arguments": {
                        "plan_id": plan["plan_id"],
                        "plan_digest": plan["plan_digest"],
                        "allow_write": False,
                    },
                },
            }
        )
        self.assertTrue(response["result"]["isError"])
        self.assertIn("allow_write=true", response["result"]["content"][0]["text"])
        self.assertEqual(provider.writes, [])

    def test_status_and_coverage_do_not_require_cli(self) -> None:
        server = StewardMcpServer()
        status = _call(server, 1, "bluearch_status", {"check_aws": False})
        coverage = _call(server, 2, "bluearch_get_coverage", {})

        self.assertTrue(status["mcp_first"])
        self.assertEqual(status["default_provider"], "aws-sdk")
        self.assertFalse(status["state"]["persistent_inventory"])
        self.assertEqual(coverage["rule_count"], 100)
        self.assertEqual(coverage["catalog_rule_count"], 631)
        self.assertEqual(coverage["automated_rule_count"], 100)
        self.assertEqual(coverage["unevaluated_rule_count"], 531)
        self.assertEqual(coverage["rules_by_evaluation_mode"]["manual_review"], 117)
        self.assertEqual(status["coverage"]["catalog_rules"], 631)
        self.assertEqual(
            {service["service"] for service in coverage["services"]},
            {
                "iam",
                "cloudtrail",
                "cloudwatch",
                "dynamodb",
                "s3",
                "ec2",
                "rds",
                "lambda",
                "efs",
                "ecs",
                "alb",
                "api-gateway",
                "kms",
                "secrets-manager",
                "sns",
                "sqs",
            },
        )

    def test_rules_search_includes_non_automated_catalog_entries(self) -> None:
        server = StewardMcpServer()

        payload = _call(
            server,
            1,
            "bluearch_rules_search",
            {"service": "well-architected", "query": "COST01-BP02"},
        )

        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["returned"], 1)
        self.assertFalse(payload["rules"][0]["evaluation"]["automated"])
        self.assertEqual(payload["rules"][0]["evaluation"]["mode"], "manual_review")

    def test_profile_discovery_returns_only_non_secret_metadata(self) -> None:
        context = discover_aws_context(
            environ={"AWS_PROFILE": "engineering-sso"},
            full_config={
                "profiles": {
                    "engineering-sso": {
                        "sso_session": "company",
                        "sso_account_id": "123456789012",
                        "sso_role_name": "AdministratorAccess",
                        "region": "eu-west-1",
                    },
                    "automation": {
                        "aws_access_key_id": "must-not-leak",
                        "aws_secret_access_key": "must-not-leak",  # pragma: allowlist secret
                    },
                }
            },
        )

        self.assertEqual(context["active_profile"], "engineering-sso")
        self.assertEqual(
            {profile["name"]: profile["kind"] for profile in context["profiles"]},
            {"automation": "static_credentials", "engineering-sso": "sso"},
        )
        self.assertFalse(context["secrets_included"])
        serialized = json.dumps(context)
        self.assertNotIn("123456789012", serialized)
        self.assertNotIn("must-not-leak", serialized)

    def test_vague_assessment_returns_guided_goal_and_scope_responses(self) -> None:
        def unexpected_context_discovery() -> dict:
            raise AssertionError("AWS context must not be read before request refinement")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {"prompt": "Review my AWS environment"},
        )

        self.assertEqual(payload["status"], "input_required")
        self.assertEqual(payload["reason"], "assessment_refinement_required")
        self.assertIn("objective_security", payload["resume"]["merge_user_input"])
        self.assertIn("objective_cost_optimization", payload["resume"]["merge_user_input"])
        self.assertIn("service_s3", payload["resume"]["merge_user_input"])
        self.assertIn("service_ec2", payload["resume"]["merge_user_input"])
        self.assertEqual(
            [question["id"] for question in payload["questions"]],
            ["objectives", "services"],
        )
        response_ids = {response["id"] for response in payload["possible_responses"]}
        self.assertIn("comprehensive_all", response_ids)
        self.assertIn("cost_all", response_ids)
        self.assertIn("security_s3", response_ids)
        self.assertNotIn("assessment_id", payload)
        properties = payload["input_request"]["requestedSchema"]["properties"]
        self.assertEqual(properties["objective_security"]["type"], "boolean")
        self.assertEqual(properties["objective_cost_optimization"]["type"], "boolean")
        self.assertEqual(properties["service_s3"]["type"], "boolean")
        self.assertEqual(properties["service_ec2"]["type"], "boolean")
        self.assertNotIn("service", properties)
        self.assertNotIn("objective", properties)
        self.assertEqual(payload["questions"][0]["response_type"], "multi_select")
        self.assertEqual(payload["questions"][1]["response_type"], "multi_select")

    def test_broad_compatibility_opportunity_call_returns_guided_responses(self) -> None:
        def unexpected_context_discovery() -> dict:
            raise AssertionError("AWS context must not be read before request refinement")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)

        payload = _call(
            server,
            1,
            "bluearch_find_opportunities",
            {"objective": "all", "service": "all"},
        )

        self.assertEqual(payload["status"], "input_required")
        self.assertEqual(payload["reason"], "assessment_refinement_required")
        self.assertEqual(payload["resume"]["tool"], "bluearch_find_opportunities")
        self.assertTrue(payload["resume"]["arguments"]["scope_confirmed"])
        self.assertIn("objective", payload["resume"]["merge_user_input"])
        self.assertIn("service_s3", payload["resume"]["merge_user_input"])
        self.assertNotIn("_resume_tool", payload["resume"]["arguments"])
        response_ids = {response["id"] for response in payload["possible_responses"]}
        self.assertIn("cost_all", response_ids)
        self.assertIn("security_s3", response_ids)

    def test_scan_compatibility_call_without_service_returns_scope_choices(self) -> None:
        def unexpected_context_discovery() -> dict:
            raise AssertionError("AWS context must not be read before request refinement")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)

        payload = _call(server, 1, "bluearch_scan_aws", {})

        self.assertEqual(payload["status"], "input_required")
        self.assertEqual(payload["reason"], "assessment_refinement_required")
        self.assertEqual(payload["resume"]["tool"], "bluearch_scan_aws")
        self.assertIn("service_s3", payload["resume"]["merge_user_input"])
        self.assertIn("service_ec2", payload["resume"]["merge_user_input"])
        self.assertTrue(payload["resume"]["arguments"]["scope_confirmed"])

    def test_stdio_uses_native_elicitation_and_resumes_assessment(self) -> None:
        store = AssessmentStore(
            lambda request: {
                "observed_at": "2026-07-13T12:00:00Z",
                "summary": {"objective": request["objective"], "service": request["service"]},
                "opportunities": [],
            }
        )
        server = StewardMcpServer(
            assessment_store=store,
            aws_context_loader=lambda: _aws_context(
                {
                    "name": "engineering-sso",
                    "kind": "sso",
                    "region": "us-east-1",
                    "active": False,
                }
            ),
            aws_identity_loader=lambda arguments: {
                "Account": "123456789012",
                "Arn": "arn:aws:sts::123456789012:assumed-role/test/user",
            },
        )
        input_stream = StringIO(
            "\n".join(
                json.dumps(message)
                for message in [
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
                    },
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "bluearch_assess",
                            "arguments": {
                                "prompt": "Review my AWS environment",
                            },
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": "bluearch-elicitation-1",
                        "result": {
                            "action": "accept",
                            "content": {
                                "objective_security": True,
                                "objective_cost_optimization": True,
                                "service_s3": True,
                                "service_ec2": True,
                            },
                        },
                    },
                ]
            )
            + "\n"
        )
        output_stream = StringIO()

        self.assertEqual(run_mcp_stdio_server(input_stream, output_stream, server), 0)

        messages = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual(messages[1]["method"], "elicitation/create")
        self.assertEqual(
            messages[1]["params"]["requestedSchema"]["properties"]["objective_cost_optimization"][
                "title"
            ],
            "Reduce AWS costs",
        )
        final_payload = messages[2]["result"]["structuredContent"]
        self.assertIn(final_payload["status"], {"queued", "running", "completed"})
        request = store.get_request(final_payload["assessment_id"])
        self.assertEqual(request["objective"], "all")
        self.assertEqual(request["objectives"], ["cost_optimization", "security"])
        self.assertEqual(request["service"], ["s3", "ec2"])
        self.assertEqual(request["services"], ["s3", "ec2"])

    def test_stdio_keeps_structured_text_fallback_without_elicitation(self) -> None:
        input_stream = StringIO(
            "\n".join(
                json.dumps(message)
                for message in [
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {}},
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "bluearch_assess",
                            "arguments": {"prompt": "Review my AWS environment"},
                        },
                    },
                ]
            )
            + "\n"
        )
        output_stream = StringIO()

        self.assertEqual(run_mcp_stdio_server(input_stream, output_stream), 0)

        messages = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual(len(messages), 2)
        self.assertEqual(messages[1]["result"]["structuredContent"]["status"], "input_required")

    def test_stdio_uses_native_yes_no_pdf_offer_for_terminal_results(self) -> None:
        store = AssessmentStore(lambda _: _scan_result())
        submitted = store.submit({"prompt": "Review the account"})
        self.assertEqual(store.wait(submitted["assessment_id"], timeout=2)["status"], "completed")
        server = StewardMcpServer(assessment_store=store)
        input_stream = StringIO(
            "\n".join(
                json.dumps(message)
                for message in [
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
                    },
                    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "bluearch_get_scan_results",
                            "arguments": {"assessment_id": submitted["assessment_id"]},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": "bluearch-elicitation-1",
                        "result": {
                            "action": "accept",
                            "content": {"generate_pdf_report": False},
                        },
                    },
                ]
            )
            + "\n"
        )
        output_stream = StringIO()

        self.assertEqual(run_mcp_stdio_server(input_stream, output_stream, server), 0)

        messages = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        self.assertEqual(messages[1]["method"], "elicitation/create")
        pdf_schema = messages[1]["params"]["requestedSchema"]["properties"]
        self.assertEqual(pdf_schema["generate_pdf_report"]["type"], "boolean")
        final_payload = messages[2]["result"]["structuredContent"]
        self.assertTrue(final_payload["ready"])
        self.assertTrue(final_payload["pdf_report_offer"]["asked"])
        self.assertFalse(final_payload["pdf_report_offer"]["accepted"])

    def test_stdio_native_elicitation_progresses_from_intent_to_profile(self) -> None:
        store = AssessmentStore(
            lambda request: {
                "observed_at": "2026-07-13T12:00:00Z",
                "summary": {"profile": request["profile"]},
                "opportunities": [],
            }
        )
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1"},
            {"name": "production-sso", "kind": "sso", "region": "eu-west-1"},
        )
        server = StewardMcpServer(
            assessment_store=store,
            aws_context_loader=lambda: context,
            aws_identity_loader=lambda arguments: {
                "Account": "123456789012",
                "Arn": f"arn:aws:sts::123456789012:assumed-role/{arguments['profile']}/user",
            },
        )
        messages = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"capabilities": {"elicitation": {}}},
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_assess",
                    "arguments": {"prompt": "Review my AWS environment"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": "bluearch-elicitation-1",
                "result": {
                    "action": "accept",
                    "content": {"objective_security": True, "service_s3": True},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": "bluearch-elicitation-2",
                "result": {"action": "accept", "content": {"profile": "engineering-sso"}},
            },
        ]
        input_stream = StringIO("\n".join(json.dumps(message) for message in messages) + "\n")
        output_stream = StringIO()

        self.assertEqual(run_mcp_stdio_server(input_stream, output_stream, server), 0)

        output = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        elicitations = [
            message for message in output if message.get("method") == "elicitation/create"
        ]
        self.assertEqual(len(elicitations), 2)
        profile_schema = elicitations[1]["params"]["requestedSchema"]["properties"]["profile"]
        self.assertEqual(profile_schema["enum"], ["engineering-sso", "production-sso"])
        self.assertEqual(
            profile_schema["enumNames"],
            ["engineering-sso (sso)", "production-sso (sso)"],
        )
        final_payload = output[-1]["result"]["structuredContent"]
        request = store.get_request(final_payload["assessment_id"])
        self.assertEqual(request["profile"], "engineering-sso")

    def test_stdio_native_elicitation_can_be_cancelled_without_aws_calls(self) -> None:
        def unexpected_context_discovery() -> dict:
            raise AssertionError("AWS context must not be read after elicitation cancellation")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)
        input_stream = StringIO(
            "\n".join(
                json.dumps(message)
                for message in [
                    {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {"capabilities": {"elicitation": {}}},
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": 2,
                        "method": "tools/call",
                        "params": {
                            "name": "bluearch_assess",
                            "arguments": {"prompt": "Review my AWS environment"},
                        },
                    },
                    {
                        "jsonrpc": "2.0",
                        "id": "bluearch-elicitation-1",
                        "result": {"action": "cancel"},
                    },
                ]
            )
            + "\n"
        )
        output_stream = StringIO()

        self.assertEqual(run_mcp_stdio_server(input_stream, output_stream, server), 0)

        messages = [json.loads(line) for line in output_stream.getvalue().splitlines()]
        final_payload = messages[2]["result"]["structuredContent"]
        self.assertEqual(final_payload["status"], "cancelled")
        self.assertIn("No AWS request was made", final_payload["message"])

    def test_inferred_cost_goal_asks_only_for_supported_service_scope(self) -> None:
        def unexpected_context_discovery() -> dict:
            raise AssertionError("AWS context must not be read before request refinement")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {"prompt": "Find my highest AWS cost savings"},
        )

        self.assertIn("service_s3", payload["resume"]["merge_user_input"])
        self.assertIn("service_ec2", payload["resume"]["merge_user_input"])
        self.assertEqual(payload["resume"]["arguments"]["objective"], "cost_optimization")
        properties = payload["input_request"]["requestedSchema"]["properties"]
        self.assertEqual(properties["service_s3"]["type"], "boolean")
        self.assertEqual(properties["service_ec2"]["type"], "boolean")
        self.assertNotIn("service", properties)
        self.assertEqual(payload["questions"][0]["response_type"], "multi_select")
        self.assertEqual(payload["possible_responses"][0]["id"], "service_all")
        self.assertTrue(payload["possible_responses"][0]["recommended"])

    def test_comprehensive_prompt_only_asks_for_service_scope(self) -> None:
        def unexpected_context_discovery() -> dict:
            raise AssertionError("AWS context must not be read before request refinement")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {"prompt": "Check all recommendations in my AWS environment"},
        )

        self.assertIn("service_s3", payload["resume"]["merge_user_input"])
        self.assertIn("service_ec2", payload["resume"]["merge_user_input"])
        self.assertEqual(payload["resume"]["arguments"]["objective"], "all")

    def test_refined_request_advances_to_profile_selection(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1", "active": False},
            {"name": "production-sso", "kind": "sso", "region": "eu-west-1", "active": False},
        )
        server = StewardMcpServer(aws_context_loader=lambda: context)

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Review my AWS environment",
                "objective": "security",
                "service": "s3",
            },
        )

        self.assertEqual(payload["reason"], "aws_profile_required")
        self.assertEqual(
            [response["arguments"] for response in payload["possible_responses"]],
            [{"profile": "engineering-sso"}, {"profile": "production-sso"}],
        )

    def test_assessment_asks_user_when_multiple_profiles_are_ambiguous(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1", "active": False},
            {"name": "production-sso", "kind": "sso", "region": "eu-west-1", "active": False},
        )
        server = StewardMcpServer(aws_context_loader=lambda: context)

        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_assess",
                    "arguments": {"prompt": "Find S3 security issues"},
                },
            }
        )
        payload = response["result"]["structuredContent"]

        self.assertFalse(response["result"]["isError"])
        self.assertEqual(payload["status"], "input_required")
        self.assertEqual(payload["reason"], "aws_profile_required")
        self.assertNotIn("assessment_id", payload)
        self.assertEqual(
            payload["input_request"]["requestedSchema"]["properties"]["profile"]["enum"],
            ["engineering-sso", "production-sso"],
        )
        self.assertEqual(payload["resume"]["tool"], "bluearch_assess")
        self.assertEqual(payload["resume"]["merge_user_input"], ["profile"])
        self.assertEqual(
            [response["user_response"] for response in payload["possible_responses"]],
            [
                "Use the engineering-sso AWS profile.",
                "Use the production-sso AWS profile.",
            ],
        )

    def test_selected_profile_is_validated_then_assessment_starts(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1", "active": False},
            {"name": "production-sso", "kind": "sso", "region": "eu-west-1", "active": False},
        )
        store = AssessmentStore(
            lambda request: {
                "observed_at": "2026-07-13T12:00:00Z",
                "summary": {"profile": request["profile"]},
            }
        )
        server = StewardMcpServer(
            assessment_store=store,
            aws_context_loader=lambda: context,
            aws_identity_loader=lambda arguments: {
                "Account": "123456789012",
                "Arn": f"arn:aws:sts::123456789012:assumed-role/{arguments['profile']}/user",
            },
        )

        started = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Find S3 security issues",
                "profile": "engineering-sso",
            },
        )

        self.assertIn("assessment_id", started)
        self.assertEqual(started["aws_context"]["profile"], "engineering-sso")
        self.assertEqual(started["aws_context"]["region"], "us-east-1")
        self.assertEqual(started["aws_context"]["account_id"], "123456789012")
        request = store.get_request(started["assessment_id"])
        self.assertEqual(request["profile"], "engineering-sso")
        self.assertEqual(request["region"], "us-east-1")
        self.assertEqual(request["_account_id"], "123456789012")

    def test_unknown_profile_returns_configured_choices(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1", "active": False},
            {"name": "production-sso", "kind": "sso", "region": "eu-west-1", "active": False},
        )
        server = StewardMcpServer(aws_context_loader=lambda: context)

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Find S3 security issues",
                "profile": "misspelled-profile",
            },
        )

        self.assertEqual(payload["reason"], "aws_profile_not_found")
        self.assertNotIn("profile", payload["resume"]["arguments"])
        self.assertEqual(
            [choice["value"] for choice in payload["choices"]],
            ["engineering-sso", "production-sso"],
        )

    def test_regional_assessment_asks_for_region_when_profile_has_none(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": None, "active": False},
        )
        server = StewardMcpServer(aws_context_loader=lambda: context)

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Find cost savings from unattached EBS volumes",
                "profile": "engineering-sso",
            },
        )

        self.assertEqual(payload["status"], "input_required")
        self.assertEqual(payload["reason"], "aws_region_required")
        self.assertEqual(payload["resume"]["merge_user_input"], ["region"])
        self.assertEqual(payload["possible_responses"][0]["arguments"], {"region": "us-east-1"})
        self.assertTrue(payload["possible_responses"][-1]["requires_free_text"])

    def test_expired_sso_returns_safe_authentication_recovery(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1", "active": False},
        )

        def expired(_: dict) -> dict:
            raise AwsProviderError(
                "AWS SDK operation failed: sts.get_caller_identity",
                detail="UnauthorizedSSOTokenError: The SSO session has expired",
            )

        server = StewardMcpServer(
            aws_context_loader=lambda: context,
            aws_identity_loader=expired,
        )

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Find S3 security issues",
                "profile": "engineering-sso",
            },
        )

        self.assertEqual(payload["status"], "authentication_required")
        self.assertEqual(payload["reason"], "aws_sso_login_required")
        self.assertEqual(
            payload["actions"][0]["command"],
            "aws sso login --profile engineering-sso",
        )
        self.assertEqual(payload["possible_responses"][0]["next_action"], "retry_resume")
        self.assertFalse(payload["security"]["credentials_requested"])

    def test_sso_network_error_is_not_misreported_as_expired_login(self) -> None:
        context = _aws_context(
            {"name": "engineering-sso", "kind": "sso", "region": "us-east-1", "active": False},
        )

        def unavailable(_: dict) -> dict:
            raise AwsProviderError(
                "AWS SDK operation failed: sts.get_caller_identity",
                detail="EndpointConnectionError: Could not connect to the AWS endpoint",
            )

        server = StewardMcpServer(
            aws_context_loader=lambda: context,
            aws_identity_loader=unavailable,
        )
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_assess",
                    "arguments": {
                        "prompt": "Find S3 security issues",
                        "profile": "engineering-sso",
                    },
                },
            }
        )

        self.assertTrue(response["result"]["isError"])
        self.assertIn("EndpointConnectionError", response["result"]["content"][0]["text"])
        self.assertNotIn("aws sso login", response["result"]["content"][0]["text"])

    def test_missing_credentials_requests_external_configuration(self) -> None:
        context = _aws_context()

        def missing(_: dict) -> dict:
            raise AwsProviderError(
                "AWS SDK operation failed: sts.get_caller_identity",
                detail="NoCredentialsError: Unable to locate credentials",
            )

        server = StewardMcpServer(
            aws_context_loader=lambda: context,
            aws_identity_loader=missing,
        )

        payload = _call(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Find S3 security issues",
                "region": "us-east-1",
            },
        )

        self.assertEqual(payload["status"], "authentication_required")
        self.assertEqual(payload["reason"], "aws_credentials_required")
        self.assertEqual(payload["actions"][0]["command"], "aws configure sso")
        self.assertEqual(payload["possible_responses"][0]["next_action"], "list_profiles")
        self.assertFalse(payload["security"]["credentials_requested"])


if __name__ == "__main__":
    unittest.main()
