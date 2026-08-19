from __future__ import annotations

import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, List, Optional

from bluearch_aws_steward.detectors.cloudtrail import scan_cloudtrail
from bluearch_aws_steward.detectors.cloudwatch import scan_cloudwatch
from bluearch_aws_steward.detectors.s3 import scan_s3
from bluearch_aws_steward.mcp_server import StewardMcpServer
from bluearch_aws_steward.providers.operations import READ_OPERATIONS
from bluearch_aws_steward.remediation import build_remediation_document, execute_remediation_plan


class MutableAwsProvider:
    def __init__(self) -> None:
        self.account_id = "123456789012"
        self.versioning_status: Optional[str] = None
        self.log_retention: Optional[int] = None
        self.log_validation = False
        self.writes: List[tuple[str, Any]] = []

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": self.account_id,
            "Arn": f"arn:aws:sts::{self.account_id}:assumed-role/Developer/test",
        }

    def list_buckets(self) -> List[str]:
        return ["demo-bucket"]

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        self._expect(bucket, "demo-bucket")
        return self.versioning_status

    def put_versioning(self, bucket: str) -> None:
        self._expect(bucket, "demo-bucket")
        self.writes.append(("s3:PutBucketVersioning", bucket))
        self.versioning_status = "Enabled"

    def list_log_groups(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "/aws/lambda/demo",
                "retention_days": self.log_retention,
                "stored_bytes": 1024,
                "created_at": "2026-07-01T00:00:00Z",
            }
        ]

    def put_log_retention(self, log_group_name: str, retention_days: int) -> None:
        self._expect(log_group_name, "/aws/lambda/demo")
        self.writes.append(("logs:PutRetentionPolicy", retention_days))
        self.log_retention = retention_days

    def list_cloudtrail_trails(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "audit",
                "arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit",
                "home_region": "us-east-1",
                "is_multi_region": True,
                "is_organization_trail": False,
                "is_logging": True,
                "log_file_validation_enabled": self.log_validation,
                "kms_key_id": "kms-key",
                "cloudwatch_logs_log_group_arn": "log-group",
            }
        ]

    def update_cloudtrail_log_file_validation(self, trail_name: str, *, enabled: bool) -> None:
        self._expect(trail_name, "audit")
        self.writes.append(("cloudtrail:UpdateTrail", enabled))
        self.log_validation = enabled

    @staticmethod
    def _expect(actual: Any, expected: Any) -> None:
        if actual != expected:
            raise AssertionError(f"expected {expected!r}, got {actual!r}")


class PublicBucketProvider(MutableAwsProvider):
    """Public-read bucket policy with an incomplete public access block."""

    def __init__(self) -> None:
        super().__init__()
        self.public_access_block = {
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        }

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        self._expect(bucket, "demo-bucket")
        return dict(self.public_access_block)

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        self._expect(bucket, "demo-bucket")
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AnonymousRead",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::demo-bucket/*",
                }
            ],
        }

    def put_public_access_block(self, bucket: str) -> None:
        self._expect(bucket, "demo-bucket")
        self.writes.append(("s3:PutPublicAccessBlock", bucket))
        self.public_access_block = {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }


class LoggingAwsProvider(MutableAwsProvider):
    def __init__(self) -> None:
        super().__init__()
        self.source_logging_enabled = False
        self.destination_logging_enabled = False
        self.delivery_policy_enabled = True
        self.destination_encryption = "AES256"
        self.policy_account_id = self.account_id

    def capabilities(self) -> set[str]:
        return set(READ_OPERATIONS)

    def list_buckets(self) -> List[str]:
        return ["source-bucket", "log-bucket"]

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "s3.get_bucket_logging":
            if parameters["Bucket"] == "source-bucket":
                if not self.source_logging_enabled:
                    return {}
                return {
                    "LoggingEnabled": {
                        "TargetBucket": "log-bucket",
                        "TargetPrefix": "bluearch/source/",
                    }
                }
            if not self.destination_logging_enabled:
                return {}
            return {
                "LoggingEnabled": {
                    "TargetBucket": "another-log-bucket",
                    "TargetPrefix": "recursive/",
                }
            }
        if operation == "s3.get_bucket_location":
            return {"LocationConstraint": None}
        if operation == "s3.get_bucket_encryption":
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": self.destination_encryption
                            }
                        }
                    ]
                }
            }
        if operation == "s3.get_bucket_policy":
            if not self.delivery_policy_enabled:
                return {}
            return {
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "logging.s3.amazonaws.com"},
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::log-bucket/bluearch/source/*",
                                "Condition": {
                                    "ArnLike": {"aws:SourceArn": "arn:aws:s3:::source-bucket"},
                                    "StringEquals": {"aws:SourceAccount": self.policy_account_id},
                                },
                            }
                        ],
                    }
                )
            }
        raise AssertionError(f"unexpected read operation: {operation}")

    def put_bucket_logging(
        self,
        bucket: str,
        *,
        target_bucket: str,
        target_prefix: str,
    ) -> None:
        self._expect(bucket, "source-bucket")
        self._expect(target_bucket, "log-bucket")
        self._expect(target_prefix, "bluearch/source/")
        self.source_logging_enabled = True
        self.writes.append(("s3:PutBucketLogging", bucket))


class AlbLoggingProvider:
    def __init__(self) -> None:
        self.writes: List[tuple[str, Any]] = []

    def list_buckets(self) -> List[str]:
        return ["log-bucket"]

    def read(self, operation: str, **_: Any) -> Dict[str, Any]:
        if operation == "s3.get_bucket_location":
            return {"LocationConstraint": None}
        if operation == "s3.get_bucket_encryption":
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            }
        if operation == "s3.get_bucket_policy":
            return {
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {
                                    "Service": "logdelivery.elasticloadbalancing.amazonaws.com"
                                },
                                "Action": "s3:PutObject",
                                "Resource": (
                                    "arn:aws:s3:::log-bucket/bluearch/alb/AWSLogs/123456789012/*"
                                ),
                            }
                        ],
                    }
                )
            }
        raise AssertionError(operation)

    def enable_alb_access_logging(
        self,
        load_balancer_arn: str,
        *,
        target_bucket: str,
        target_prefix: str,
    ) -> None:
        self.writes.append(
            (
                "elasticloadbalancing:ModifyLoadBalancerAttributes",
                (load_balancer_arn, target_bucket, target_prefix),
            )
        )


def _context() -> Dict[str, Any]:
    return {
        "profiles": [{"name": "test-sso", "kind": "sso", "region": "us-east-1"}],
        "profile_count": 1,
        "active_profile": "test-sso",
        "environment_region": None,
        "credential_sources": [],
        "non_profile_credentials_configured": False,
        "discovery_errors": [],
        "secrets_included": False,
    }


def _server(provider: MutableAwsProvider) -> StewardMcpServer:
    return StewardMcpServer(
        aws_context_loader=_context,
        aws_provider_factory=lambda _: provider,
    )


def _call(server: StewardMcpServer, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    if response["result"]["isError"]:
        raise AssertionError(response["result"]["content"][0]["text"])
    return json.loads(response["result"]["content"][0]["text"])


def _error(server: StewardMcpServer, name: str, arguments: Dict[str, Any]) -> str:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    if not response["result"]["isError"]:
        raise AssertionError("expected MCP tool error")
    return str(response["result"]["content"][0]["text"])


class GuardedRemediationWorkflowTests(unittest.TestCase):
    def test_s3_plan_apply_verify_and_replay_guard(self) -> None:
        provider = MutableAwsProvider()
        finding = (
            scan_s3(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="s3-versioning-disabled",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)

        planned = _call(server, "bluearch_plan_remediation", {"finding": finding})
        plan = planned["plan"]

        self.assertEqual(planned["status"], "awaiting_approval")
        self.assertEqual(plan["aws_operations"][0]["operation"], "s3.PutBucketVersioning")
        self.assertEqual(
            plan["aws_operations"][0]["parameters"],
            {
                "Bucket": "demo-bucket",
                "VersioningConfiguration": {"Status": "Enabled"},
            },
        )
        self.assertEqual(plan["impact"]["blast_radius"], "single_bucket")
        self.assertFalse(plan["rollback"]["automatic"])
        self.assertNotIn("allow_write", planned["next"]["arguments"])
        self.assertTrue(planned["next"]["requires_explicit_user_approval"])
        self.assertIn("s3:GetBucketVersioning", plan["required_iam_permissions"]["read"])
        self.assertIn("s3:PutBucketVersioning", plan["required_iam_permissions"]["write"])

        digest_error = _error(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": "0" * 64,
                "allow_write": True,
            },
        )
        self.assertIn("digest does not match", digest_error)
        self.assertEqual(provider.writes, [])

        applied = _call(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )

        self.assertEqual(applied["status"], "applied")
        self.assertTrue(applied["verified"])
        self.assertEqual(provider.writes, [("s3:PutBucketVersioning", "demo-bucket")])
        replay_error = _error(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )
        self.assertIn("already applied", replay_error)

    def test_s3_public_bucket_apply_reports_residual_public_policy(self) -> None:
        provider = PublicBucketProvider()
        finding = (
            scan_s3(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="s3-public-bucket",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)
        planned = _call(server, "bluearch_plan_remediation", {"finding": finding})

        applied = _call(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )

        self.assertEqual(applied["status"], "applied_with_residual_risk")
        self.assertTrue(applied["write_actions_applied"])
        self.assertEqual(provider.writes, [("s3:PutPublicAccessBlock", "demo-bucket")])
        residual_rules = {item["rule"] for item in applied["residual_risks"]}
        self.assertIn("s3-policy-public-read", residual_rules)
        self.assertIn("bucket policy", applied["message"])
        # Small models need the next step spelled out, not just described:
        # every residual risk carries its catalog action, and the response
        # ends with an action-first next block plus a verification recipe.
        for item in applied["residual_risks"]:
            self.assertTrue(item["action"])
        next_block = applied["next"]
        self.assertTrue(next_block["remediation"]["requires_review"])
        self.assertIn("bucket policy", next_block["remediation"]["description"].lower())
        verification = next_block["verification"]
        self.assertEqual(verification["tool"], "bluearch_scan_aws")
        self.assertIn(
            "s3-policy-public-read", verification["arguments"]["rule_filter"]
        )
        self.assertEqual(verification["arguments"]["service"], "s3")

    def test_changed_live_state_invalidates_plan_without_writing(self) -> None:
        provider = MutableAwsProvider()
        finding = (
            scan_s3(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="s3-versioning-disabled",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)
        planned = _call(server, "bluearch_plan_remediation", {"finding": finding})
        provider.versioning_status = "Suspended"

        error = _error(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )

        self.assertIn("stale plan was invalidated", error)
        self.assertEqual(provider.writes, [])

    def test_concurrent_apply_claim_allows_only_one_write(self) -> None:
        provider = MutableAwsProvider()
        finding = (
            scan_s3(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="s3-versioning-disabled",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)
        planned = _call(server, "bluearch_plan_remediation", {"finding": finding})
        arguments = {
            "plan_id": planned["plan_id"],
            "plan_digest": planned["plan_digest"],
            "allow_write": True,
        }

        def apply_once() -> bool:
            response = server.handle(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {"name": "bluearch_apply_remediation", "arguments": arguments},
                }
            )
            assert response is not None
            return bool(response["result"]["isError"])

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(lambda _: apply_once(), range(2)))

        self.assertEqual(sorted(outcomes), [False, True])
        self.assertEqual(provider.writes, [("s3:PutBucketVersioning", "demo-bucket")])

    def test_cloudwatch_plan_elicits_retention_then_applies(self) -> None:
        provider = MutableAwsProvider()
        finding = (
            scan_cloudwatch(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="cloudwatch-log-retention-missing",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)

        refinement = _call(server, "bluearch_plan_remediation", {"finding": finding})
        self.assertEqual(refinement["status"], "input_required")
        self.assertEqual(refinement["resume"]["merge_user_input"], ["cloudwatch_retention_days"])

        planned = _call(
            server,
            "bluearch_plan_remediation",
            {"finding": finding, "cloudwatch_retention_days": 30},
        )
        self.assertEqual(planned["plan"]["desired_state"], {"retention_days": 30})
        self.assertEqual(
            planned["plan"]["aws_operations"][0]["parameters"],
            {"logGroupName": "/aws/lambda/demo", "retentionInDays": 30},
        )
        self.assertIn("logs:PutRetentionPolicy", planned["plan"]["required_iam_actions"])

        applied = _call(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )
        self.assertTrue(applied["verified"])
        self.assertEqual(provider.writes, [("logs:PutRetentionPolicy", 30)])

    def test_cloudtrail_log_validation_plan_applies_and_verifies(self) -> None:
        provider = MutableAwsProvider()
        finding = (
            scan_cloudtrail(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="cloudtrail-log-validation-disabled",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)

        planned = _call(server, "bluearch_plan_remediation", {"finding": finding})
        self.assertEqual(
            planned["plan"]["aws_operations"][0]["parameters"],
            {"Name": "audit", "EnableLogFileValidation": True},
        )
        applied = _call(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )

        self.assertTrue(applied["verified"])
        self.assertEqual(provider.writes, [("cloudtrail:UpdateTrail", True)])

    def test_apply_rejects_changed_account(self) -> None:
        provider = MutableAwsProvider()
        finding = (
            scan_cloudtrail(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                rule_filter="cloudtrail-log-validation-disabled",
            )
            .findings[0]
            .to_dict()
        )
        server = _server(provider)
        planned = _call(server, "bluearch_plan_remediation", {"finding": finding})
        provider.account_id = "999999999999"

        error = _error(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )
        self.assertIn("active AWS account does not match", error)
        self.assertEqual(provider.writes, [])

    def test_s3_logging_requires_existing_destination_then_applies_and_verifies(self) -> None:
        provider = LoggingAwsProvider()
        finding = next(
            finding.to_dict()
            for finding in scan_s3(
                provider,
                profile="test-sso",
                endpoint_url=None,
                region="us-east-1",
                provider="aws-sdk",
                bucket_prefix="source-bucket",
                rule_filter="s3-server-access-logging-disabled",
            ).findings
        )
        server = _server(provider)

        refinement = _call(server, "bluearch_plan_remediation", {"finding": finding})
        self.assertEqual(refinement["status"], "input_required")
        self.assertEqual(
            set(refinement["resume"]["merge_user_input"]),
            {"logging_destination_bucket", "logging_destination_prefix"},
        )

        planned = _call(
            server,
            "bluearch_plan_remediation",
            {
                "finding": finding,
                "logging_destination_bucket": "log-bucket",
                "logging_destination_prefix": "bluearch/source",
            },
        )
        validation = planned["plan"]["preconditions"]["destination_validation"]
        self.assertTrue(validation["target_bucket_exists"])
        self.assertTrue(validation["delivery_policy_validated"])
        self.assertEqual(validation["target_bucket_encryption"], ["AES256"])
        self.assertFalse(validation["delivery_policy_managed_by_steward"])

        applied = _call(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": planned["plan_id"],
                "plan_digest": planned["plan_digest"],
                "allow_write": True,
            },
        )
        self.assertTrue(applied["verified"])
        self.assertEqual(provider.writes, [("s3:PutBucketLogging", "source-bucket")])

    def test_s3_logging_rejects_unsafe_destination_without_writing(self) -> None:
        cases = (
            ("delivery_policy_enabled", False, "bucket policy does not contain"),
            ("policy_account_id", "999999999999", "bucket policy does not contain"),
            ("destination_encryption", "aws:kms", "must use SSE-S3"),
            (
                "destination_logging_enabled",
                True,
                "dedicated destination without access logging",
            ),
        )
        for attribute, value, expected_error in cases:
            with self.subTest(attribute=attribute):
                provider = LoggingAwsProvider()
                setattr(provider, attribute, value)
                finding = next(
                    finding.to_dict()
                    for finding in scan_s3(
                        provider,
                        profile="test-sso",
                        endpoint_url=None,
                        region="us-east-1",
                        provider="aws-sdk",
                        bucket_prefix="source-bucket",
                        rule_filter="s3-server-access-logging-disabled",
                    ).findings
                )

                error = _error(
                    _server(provider),
                    "bluearch_plan_remediation",
                    {
                        "finding": finding,
                        "logging_destination_bucket": "log-bucket",
                        "logging_destination_prefix": "bluearch/source",
                    },
                )

                self.assertIn(expected_error, error)
                self.assertEqual(provider.writes, [])

    def test_alb_logging_plan_never_creates_destination_infrastructure(self) -> None:
        provider = AlbLoggingProvider()
        finding = {
            "finding_id": "alb-log-fixture",
            "rule_id": "8ac617e8-5a7a-4da8-8084-7ef5e5cbc74c",
            "rule_short_id": "alb-access-logging-disabled",
            "service": "alb",
            "resource": "alb://load-balancer/fixture",
            "severity": "medium",
            "evidence": {
                "load_balancer_arn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/fixture/1",
                "access_logging_enabled": False,
            },
            "remediation": {
                "summary": "Enable ALB access logging.",
                "safety_level": "low_risk",
                "requires_approval": True,
                "verification": "Re-read ALB attributes.",
            },
        }
        document = build_remediation_document(
            finding,
            aws_context={"region": "us-east-1", "account_id": "123456789012"},
            options={
                "logging_destination_bucket": "log-bucket",
                "logging_destination_prefix": "bluearch/alb",
            },
        )

        actions = execute_remediation_plan(provider, document)

        self.assertEqual(
            actions, ["enabled ALB access logging to the reviewed existing destination"]
        )
        self.assertEqual(len(provider.writes), 1)
        self.assertTrue(document["preconditions"]["destination_bucket_must_exist"])
        self.assertTrue(
            document["preconditions"]["destination_delivery_permissions_must_be_preconfigured"]
        )


if __name__ == "__main__":
    unittest.main()
