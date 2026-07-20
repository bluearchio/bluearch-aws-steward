from __future__ import annotations

import unittest
from typing import Any, Dict, List

from bluearch_aws_steward.detectors.cloudtrail import scan_cloudtrail
from bluearch_aws_steward.detectors.iam import scan_iam
from bluearch_aws_steward.detectors.lambda_service import scan_lambda
from bluearch_aws_steward.detectors.rds import scan_rds
from bluearch_aws_steward.mcp_server import StewardMcpServer


class ExtendedServiceFakeProvider:
    def get_iam_account_summary(self) -> Dict[str, Any]:
        return {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}

    def list_cloudtrail_trails(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "incomplete-trail",
                "home_region": "us-east-1",
                "is_multi_region": False,
                "is_organization_trail": False,
                "log_file_validation_enabled": False,
                "kms_key_id": None,
                "cloudwatch_logs_log_group_arn": None,
                "is_logging": False,
            }
        ]

    def list_rds_instances(self) -> List[Dict[str, Any]]:
        return [
            {
                "identifier": "legacy-db",
                "engine": "postgres",
                "engine_version": "16.4",
                "instance_class": "db.t3.medium",
                "status": "available",
                "publicly_accessible": True,
                "storage_encrypted": False,
                "multi_az": False,
                "storage_type": "gp2",
                "allocated_storage_gib": 100,
                "availability_zone": "us-east-1a",
            }
        ]

    def list_lambda_functions(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "untraced-function",
                "runtime": "python3.13",
                "memory_mb": 256,
                "timeout_seconds": 30,
                "last_modified": "2026-07-01T12:00:00Z",
                "tracing_mode": "PassThrough",
            }
        ]


class ExtendedServiceDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = ExtendedServiceFakeProvider()

    def test_iam_account_controls_detect_root_risks(self) -> None:
        result = scan_iam(self.provider, None, None, "us-east-1")

        self.assertEqual(result.summary["resources_scanned"], 1)
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {"iam-root-mfa-disabled", "iam-root-access-key-present"},
        )
        self.assertEqual({finding.resource for finding in result.findings}, {"iam://account/root"})

    def test_cloudtrail_detects_coverage_and_trail_configuration(self) -> None:
        result = scan_cloudtrail(self.provider, None, None, "us-east-1")

        self.assertEqual(result.summary["resources_scanned"], 2)
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {
                "cloudtrail-multi-region-logging-disabled",
                "cloudtrail-log-validation-disabled",
                "cloudtrail-kms-encryption-disabled",
                "cloudtrail-cloudwatch-integration-missing",
            },
        )

    def test_rds_detects_static_security_reliability_and_cost_controls(self) -> None:
        result = scan_rds(self.provider, None, None, "us-east-1")

        self.assertEqual(result.summary["resources_scanned"], 1)
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {
                "rds-publicly-accessible",
                "rds-storage-unencrypted",
                "rds-multi-az-disabled",
                "rds-gp2-storage",
            },
        )
        gp2 = next(
            finding for finding in result.findings if finding.rule_short_id == "rds-gp2-storage"
        )
        self.assertEqual(gp2.evidence["cost_estimate"]["status"], "preventive")

    def test_lambda_detects_functions_without_active_tracing(self) -> None:
        result = scan_lambda(self.provider, None, None, "us-east-1")

        self.assertEqual(result.summary["resources_scanned"], 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_short_id, "lambda-xray-tracing-disabled")
        self.assertEqual(result.findings[0].resource, "lambda://function/untraced-function")

    def test_guided_service_responses_include_expanded_coverage(self) -> None:
        def unexpected_context_discovery() -> Dict[str, Any]:
            raise AssertionError("AWS context must not be read before request refinement")

        server = StewardMcpServer(aws_context_loader=unexpected_context_discovery)
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_assess",
                    "arguments": {"prompt": "Find AWS security risks"},
                },
            }
        )
        payload = response["result"]["structuredContent"]

        self.assertEqual(payload["reason"], "assessment_refinement_required")
        self.assertIn("service_s3", payload["resume"]["merge_user_input"])
        self.assertIn("service_api_gateway", payload["resume"]["merge_user_input"])
        properties = payload["input_request"]["requestedSchema"]["properties"]
        self.assertEqual(properties["service_s3"]["type"], "boolean")
        self.assertEqual(properties["service_api_gateway"]["type"], "boolean")
        self.assertEqual(
            [item["arguments"]["service"] for item in payload["possible_responses"]],
            [
                "all",
                "iam",
                "cloudtrail",
                "cloudwatch",
                "dynamodb",
                "s3",
                "ec2",
                "efs",
                "rds",
                "lambda",
                "ecs",
                "alb",
                "kms",
                "secrets-manager",
                "sns",
                "sqs",
                "api-gateway",
            ],
        )


if __name__ == "__main__":
    unittest.main()
