from __future__ import annotations

import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict, List, Optional
from unittest.mock import patch

from bluearch_aws_steward.cli import _print_scan_text
from bluearch_aws_steward.detectors.cloudwatch import scan_cloudwatch
from bluearch_aws_steward.detectors.ec2 import scan_ec2
from bluearch_aws_steward.detectors.s3 import scan_s3
from bluearch_aws_steward.mcp_server import (
    _infer_prompt_fields,
    _tool_find_opportunities,
    _tool_plan_remediation,
    list_mcp_tools,
)
from bluearch_aws_steward.policy import ScanPolicy, build_scan_policy
from bluearch_aws_steward.providers.base import AwsProviderError
from bluearch_aws_steward.scanner import run_aws_scan


class MultiServiceFakeProvider:
    def __init__(self) -> None:
        self.calls: List[str] = []

    def capabilities(self) -> set[str]:
        return {
            "s3.list_buckets",
            "s3.get_bucket_lifecycle_configuration",
        }

    def caller_identity(self) -> Dict[str, Any]:
        return {"Account": "123456789012"}

    def list_buckets(self) -> List[str]:
        self.calls.append("list_buckets")
        return ["clean-bucket"]

    def list_log_groups(self) -> List[Dict[str, Any]]:
        self.calls.append("list_log_groups")
        return [
            {
                "name": "/aws/lambda/no-retention",
                "retention_days": None,
                "stored_bytes": 1073741824,
                "created_at": 1234,
            },
            {
                "name": "/aws/lambda/retained",
                "retention_days": 30,
                "stored_bytes": 1024,
                "created_at": 1234,
            },
        ]

    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        self.calls.append("list_ebs_volumes")
        return [
            {
                "volume_id": "vol-unattached",
                "state": "available",
                "size_gib": 100,
                "volume_type": "gp3",
                "availability_zone": "us-east-1a",
                "encrypted": True,
                "created_at": "2026-01-02T00:00:00+00:00",
                "attachments": [],
            },
            {
                "volume_id": "vol-attached",
                "state": "in-use",
                "size_gib": 20,
                "volume_type": "gp3",
                "availability_zone": "us-east-1b",
                "encrypted": True,
                "created_at": "2026-01-01T00:00:00+00:00",
                "attachments": [{"instance_id": "i-123", "state": "attached"}],
            },
            {
                "volume_id": "vol-new-unattached",
                "state": "available",
                "size_gib": 10,
                "volume_type": "gp3",
                "availability_zone": "us-east-1c",
                "encrypted": True,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "attachments": [],
            },
        ]

    def list_elastic_ips(self) -> List[Dict[str, Any]]:
        self.calls.append("list_elastic_ips")
        return []

    def get_iam_account_summary(self) -> Dict[str, Any]:
        self.calls.append("get_iam_account_summary")
        return {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}

    def list_cloudtrail_trails(self) -> List[Dict[str, Any]]:
        self.calls.append("list_cloudtrail_trails")
        return [
            {
                "name": "compliant-trail",
                "home_region": "us-east-1",
                "is_multi_region": True,
                "is_organization_trail": False,
                "log_file_validation_enabled": True,
                "kms_key_id": "configured",
                "cloudwatch_logs_log_group_arn": "configured",
                "is_logging": True,
            }
        ]

    def list_rds_instances(self) -> List[Dict[str, Any]]:
        self.calls.append("list_rds_instances")
        return [
            {
                "identifier": "compliant-db",
                "engine": "postgres",
                "status": "available",
                "publicly_accessible": False,
                "storage_encrypted": True,
                "multi_az": True,
                "storage_type": "gp3",
            }
        ]

    def list_lambda_functions(self) -> List[Dict[str, Any]]:
        self.calls.append("list_lambda_functions")
        return [
            {
                "name": "traced-function",
                "runtime": "python3.13",
                "tracing_mode": "Active",
            }
        ]

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyInsecureTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": [
                        f"arn:aws:s3:::{bucket}",
                        f"arn:aws:s3:::{bucket}/*",
                    ],
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                }
            ],
        }

    def get_bucket_encryption_rules(self, bucket: str) -> List[Dict[str, Any]]:
        return [{"enabled": True}]

    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        return [
            {
                "ID": "transition-old-objects",
                "Status": "Enabled",
                "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
            }
        ]

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        return "Enabled"

    def put_public_access_block(self, bucket: str) -> None:
        raise AssertionError("read-only test")

    def put_default_encryption(self, bucket: str) -> None:
        raise AssertionError("read-only test")

    def put_lifecycle(
        self,
        bucket: str,
        *,
        transition_days: int = 30,
        storage_class: str = "STANDARD_IA",
    ) -> None:
        raise AssertionError("read-only test")

    def put_versioning(self, bucket: str) -> None:
        raise AssertionError("read-only test")


class CloudWatchDeniedProvider(MultiServiceFakeProvider):
    def list_log_groups(self) -> List[Dict[str, Any]]:
        self.calls.append("list_log_groups")
        raise AwsProviderError("CloudWatch access denied", detail="AccessDenied")


class MissingLifecycleProvider(MultiServiceFakeProvider):
    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        return []


class MissingStorageTieringProvider(MultiServiceFakeProvider):
    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        return [
            {
                "ID": "tag-only-lifecycle",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "Expiration": {"Days": 365},
            }
        ]


class UnsafeBucketPolicyProvider(MultiServiceFakeProvider):
    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "PublicWildcard",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": "*",
                }
            ],
        }


class ExemptVolumeProvider(MultiServiceFakeProvider):
    def __init__(self, tags: Dict[str, str]) -> None:
        super().__init__()
        self.tags = tags

    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        volumes = super().list_ebs_volumes()
        volumes[0]["tags"] = self.tags
        return volumes


class RiskyEc2Provider(MultiServiceFakeProvider):
    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        self.calls.append("list_ebs_volumes")
        return [
            {
                "volume_id": "vol-unencrypted",
                "state": "in-use",
                "size_gib": 20,
                "volume_type": "gp3",
                "availability_zone": "us-east-1a",
                "encrypted": False,
                "created_at": "2026-01-01T00:00:00+00:00",
                "attachments": [{"instance_id": "i-123", "state": "attached"}],
                "tags": {},
            }
        ]

    def list_elastic_ips(self) -> List[Dict[str, Any]]:
        self.calls.append("list_elastic_ips")
        return [
            {
                "allocation_id": "eipalloc-unused",
                "association_id": None,
                "public_ip": "192.0.2.10",
                "instance_id": None,
                "network_interface_id": None,
                "domain": "vpc",
                "tags": {},
            },
            {
                "allocation_id": "eipalloc-used",
                "association_id": "eipassoc-used",
                "public_ip": "192.0.2.11",
                "instance_id": "i-123",
                "network_interface_id": "eni-123",
                "domain": "vpc",
                "tags": {},
            },
        ]


class TinyLogGroupProvider(MultiServiceFakeProvider):
    def list_log_groups(self) -> List[Dict[str, Any]]:
        groups = super().list_log_groups()
        groups[0]["stored_bytes"] = 1024
        return groups


class MultiServiceDetectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.provider = MultiServiceFakeProvider()

    def test_cloudwatch_detects_only_groups_without_retention(self) -> None:
        result = scan_cloudwatch(
            self.provider,
            profile=None,
            endpoint_url=None,
            region="us-east-1",
        )

        self.assertEqual(result.summary["resources_scanned"], 2)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_short_id, "cloudwatch-log-retention-missing")
        self.assertEqual(finding.resource, "cloudwatch-logs://log-group/aws/lambda/no-retention")
        self.assertEqual(finding.remediation.safety_level, "review_required")
        self.assertEqual(finding.evidence["recommended_retention_days"], 30)
        self.assertEqual(finding.evidence["cost_estimate"]["estimated_monthly_savings_usd"], 0.03)

    def test_ec2_detects_only_unattached_ebs_volumes(self) -> None:
        result = scan_ec2(
            self.provider,
            profile=None,
            endpoint_url=None,
            region="us-east-1",
        )

        self.assertEqual(result.summary["resources_scanned"], 3)
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_short_id, "ec2-unattached-ebs-volume")
        self.assertEqual(finding.resource, "ebs://vol-unattached")
        self.assertEqual(finding.remediation.safety_level, "high_risk")
        self.assertGreaterEqual(finding.evidence["age_days"], 7)
        self.assertEqual(finding.evidence["minimum_age_days"], 7)
        self.assertEqual(finding.evidence["cost_estimate"]["estimated_monthly_savings_usd"], 8.0)

    def test_policy_overrides_thresholds_and_tag_exemptions(self) -> None:
        threshold_result = scan_ec2(
            self.provider,
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            policy=ScanPolicy(ebs_min_unattached_days=0),
        )
        self.assertEqual(
            {finding.resource for finding in threshold_result.findings},
            {"ebs://vol-unattached", "ebs://vol-new-unattached"},
        )

        custom_exempt = scan_ec2(
            ExemptVolumeProvider({"owner": "platform"}),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            policy=ScanPolicy(exclude_tags={"owner": "platform"}),
        )
        self.assertEqual(custom_exempt.findings, [])

        catalog_exempt = scan_ec2(
            ExemptVolumeProvider({"bluearch:steward-exempt": "true"}),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
        )
        self.assertEqual(catalog_exempt.findings, [])

    def test_ec2_detects_unencrypted_volumes_and_unassociated_elastic_ips(self) -> None:
        provider = RiskyEc2Provider()
        result = scan_ec2(
            provider,
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="ec2-ebs-volume-unencrypted,ec2-unassociated-elastic-ip",
        )

        self.assertEqual(result.summary["resources_scanned"], 3)
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {"ec2-ebs-volume-unencrypted", "ec2-unassociated-elastic-ip"},
        )
        eip = next(
            finding
            for finding in result.findings
            if finding.rule_short_id == "ec2-unassociated-elastic-ip"
        )
        self.assertEqual(eip.resource, "eip://eipalloc-unused")
        self.assertEqual(eip.evidence["cost_estimate"]["status"], "preventive")
        self.assertEqual(provider.calls, ["list_ebs_volumes", "list_elastic_ips"])

    def test_small_cloudwatch_group_is_a_preventive_cost_opportunity(self) -> None:
        result = scan_cloudwatch(
            TinyLogGroupProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
        )
        finding = result.findings[0]
        self.assertEqual(finding.evidence["cost_estimate"]["status"], "preventive")

        opportunities = _tool_find_opportunities(
            {
                "objective": "cost_optimization",
                "scan_result": {"service": "cloudwatch", "findings": [finding.to_dict()]},
            }
        )
        self.assertEqual(opportunities["summary"]["opportunities"], 1)

    def test_s3_lifecycle_without_cost_evidence_is_advisory(self) -> None:
        result = scan_s3(
            MissingLifecycleProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="s3-no-lifecycle",
        )

        self.assertEqual(len(result.findings), 1)
        evidence = result.findings[0].evidence
        self.assertEqual(evidence["assessment"], "advisory")
        self.assertEqual(evidence["cost_estimate"]["status"], "insufficient")

    def test_s3_detects_lifecycle_without_storage_tiering_actions(self) -> None:
        result = scan_s3(
            MissingStorageTieringProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="s3-intelligent-tiering-missing",
        )

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_short_id, "s3-intelligent-tiering-missing")
        self.assertEqual(finding.evidence["assessment"], "advisory")
        self.assertFalse(finding.evidence["storage_tiering_present"])
        self.assertEqual(finding.evidence["lifecycle_rules"][0]["id"], "tag-only-lifecycle")
        self.assertEqual(finding.evidence["cost_estimate"]["status"], "insufficient")

    def test_s3_detects_public_wildcards_delete_access_and_missing_tls_policy(self) -> None:
        result = scan_s3(
            UnsafeBucketPolicyProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter=(
                "s3-policy-all-actions-public,s3-policy-public-delete,s3-tls-enforcement-missing"
            ),
        )

        self.assertEqual(result.summary["resources_scanned"], 1)
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {
                "s3-policy-all-actions-public",
                "s3-policy-public-delete",
                "s3-tls-enforcement-missing",
            },
        )
        wildcard = next(
            finding
            for finding in result.findings
            if finding.rule_short_id == "s3-policy-all-actions-public"
        )
        self.assertEqual(
            wildcard.evidence["public_wildcard_actions"][0]["statement_id"],
            "PublicWildcard",
        )

    def test_s3_tls_detector_accepts_complete_insecure_transport_deny(self) -> None:
        result = scan_s3(
            self.provider,
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="s3-tls-enforcement-missing",
        )

        self.assertEqual(result.findings, [])

    def test_all_service_scan_combines_findings_and_summaries(self) -> None:
        progress = []
        result = run_aws_scan(
            self.provider,
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-cli",
            progress_callback=progress.append,
        )

        self.assertEqual(result.service, "all")
        self.assertEqual(result.summary["resources_scanned"], 11)
        self.assertEqual(result.summary["rules_evaluated"], 24)
        self.assertEqual(
            result.summary["services_scanned"],
            [
                "iam",
                "cloudtrail",
                "cloudwatch",
                "dynamodb",
                "s3",
                "ec2",
                "rds",
                "lambda",
                "efs",
                "eks",
                "ecs",
                "alb",
                "kms",
                "secrets-manager",
                "sns",
                "sqs",
                "api-gateway",
            ],
        )
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {"cloudwatch-log-retention-missing", "ec2-unattached-ebs-volume"},
        )
        self.assertEqual(progress[-1]["services_completed"], 17)
        self.assertEqual(progress[-1]["findings_discovered"], 2)
        self.assertEqual(progress[-1]["resources_scanned"], 11)
        coverage = result.summary["detection_coverage"]
        self.assertEqual(coverage["catalog_rules_in_scope"], 650)
        self.assertEqual(coverage["automated_rules_available"], 121)
        self.assertEqual(coverage["automated_rules_evaluated"], 24)
        self.assertEqual(coverage["unevaluated_catalog_rules"], 626)
        self.assertFalse(coverage["complete_catalog_evaluation"])

    def test_all_service_rule_filter_skips_unrelated_provider_calls(self) -> None:
        result = run_aws_scan(
            self.provider,
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-cli",
            rule_filter="ec2-unattached-ebs-volume",
        )

        self.assertEqual(result.service, "ec2")
        self.assertEqual(self.provider.calls, ["list_ebs_volumes"])
        coverage = result.summary["detection_coverage"]
        self.assertEqual(coverage["scope"], "executable_rule_filter")
        self.assertEqual(coverage["catalog_rules_in_scope"], 1)
        self.assertTrue(coverage["complete_catalog_evaluation"])

    def test_all_service_scan_returns_partial_results_on_provider_error(self) -> None:
        result = run_aws_scan(
            CloudWatchDeniedProvider(),
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-cli",
        )

        self.assertEqual(result.summary["scan_errors"], 1)
        self.assertEqual(
            result.summary["services_scanned"],
            [
                "iam",
                "cloudtrail",
                "dynamodb",
                "s3",
                "ec2",
                "rds",
                "lambda",
                "efs",
                "eks",
                "ecs",
                "alb",
                "kms",
                "secrets-manager",
                "sns",
                "sqs",
                "api-gateway",
            ],
        )
        self.assertEqual(result.summary["service_errors"][0]["service"], "cloudwatch")
        coverage = result.summary["detection_coverage"]
        self.assertEqual(coverage["automated_rules_available"], 121)
        self.assertEqual(coverage["automated_rules_evaluated"], 23)
        self.assertEqual(coverage["automated_rules_not_evaluated"], 98)
        self.assertFalse(coverage["complete_catalog_evaluation"])
        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {"ec2-unattached-ebs-volume"},
        )

    def test_cli_does_not_describe_incomplete_empty_scan_as_clean(self) -> None:
        payload = run_aws_scan(
            CloudWatchDeniedProvider(),
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-cli",
            rule_filter="cloudwatch-log-retention-missing,ec2-unattached-ebs-volume",
        ).to_dict()
        payload["findings"] = []
        payload["summary"]["findings"] = 0
        output = StringIO()

        with redirect_stdout(output):
            _print_scan_text(payload)

        self.assertIn("scan was incomplete", output.getvalue())
        self.assertNotIn("No findings detected", output.getvalue())

    def test_cli_reports_unevaluated_catalog_rules_for_zero_findings(self) -> None:
        payload = run_aws_scan(
            self.provider,
            service="s3",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
        ).to_dict()
        output = StringIO()

        with redirect_stdout(output):
            _print_scan_text(payload)

        rendered = output.getvalue()
        self.assertIn("9/25 evaluated; 16 unevaluated", rendered)
        self.assertIn("No findings among the evaluated native rules", rendered)
        self.assertNotIn("No findings detected", rendered)


class MultiServiceMcpTests(unittest.TestCase):
    def test_prompt_routing_selects_all_or_specific_services(self) -> None:
        broad = _infer_prompt_fields("Find top 10 AWS cost savings in us-east-1")
        self.assertEqual(broad["service"], "all")
        self.assertEqual(
            set(broad["rule_filter"].split(",")),
            {
                "alb-idle-load-balancer",
                "cloudwatch-log-retention-missing",
                "dynamodb-inactive-table",
                "dynamodb-on-demand-low-utilization",
                "dynamodb-read-capacity-underutilized",
                "dynamodb-standard-ia-candidate",
                "dynamodb-write-capacity-underutilized",
                "ebs-orphaned-snapshot-or-ami",
                "ec2-dev-schedule-missing",
                "ec2-ebs-delete-on-termination-disabled",
                "ec2-gp2-volume-candidate",
                "ec2-idle-instance",
                "ec2-low-cpu-rightsizing",
                "ec2-previous-generation-instance",
                "ec2-unattached-ebs-volume",
                "ec2-unassociated-elastic-ip",
                "efs-inactive-unmounted",
                "efs-lifecycle-policy-missing",
                "efs-throughput-overprovisioned",
                "eks-workload-overprovisioned",
                "k8s-workload-missing-resource-requests",
                "lambda-high-error-rate",
                "lambda-memory-underutilized",
                "lambda-provisioned-concurrency-underused",
                "lambda-timeout-rate-high",
                "lambda-unused-function",
                "rds-gp2-storage",
                "rds-idle-instance",
                "rds-low-cpu-rightsizing",
                "rds-previous-generation-instance",
                "rds-storage-autoscaling-disabled",
                "s3-intelligent-tiering-missing",
            },
        )
        self.assertEqual(
            _infer_prompt_fields("Find CloudWatch log retention waste")["service"], "cloudwatch"
        )
        self.assertEqual(_infer_prompt_fields("Find unattached EBS volumes")["service"], "ec2")
        mixed = _infer_prompt_fields("Find CloudWatch log retention and unattached EBS waste")
        self.assertEqual(mixed["service"], "all")
        self.assertEqual(
            set(mixed["rule_filter"].split(",")),
            {"cloudwatch-log-retention-missing", "ec2-unattached-ebs-volume"},
        )

    def test_mcp_schemas_expose_multi_service_scans(self) -> None:
        tools = {tool["name"]: tool for tool in list_mcp_tools()}
        advise_service = tools["bluearch_advise"]["inputSchema"]["properties"]["service"]
        scan_service = tools["bluearch_scan_aws"]["inputSchema"]["properties"]["service"]

        self.assertEqual(advise_service["default"], "all")
        self.assertEqual(
            scan_service["enum"],
            [
                "all",
                "iam",
                "cloudtrail",
                "cloudwatch",
                "dynamodb",
                "s3",
                "ec2",
                "rds",
                "lambda",
                "efs",
                "eks",
                "ecs",
                "alb",
                "kms",
                "secrets-manager",
                "sns",
                "sqs",
                "api-gateway",
                "ebs",
                "networking",
            ],
        )

    def test_find_opportunities_defaults_to_all_services_at_runtime(self) -> None:
        with patch(
            "bluearch_aws_steward.mcp_server._client",
            return_value=MultiServiceFakeProvider(),
        ):
            payload = _tool_find_opportunities(
                {
                    "objective": "cost_optimization",
                    "max_returned_resources": 10,
                    "max_returned_findings": 10,
                }
            )

        self.assertEqual(payload["service"], "all")
        self.assertEqual(payload["summary"]["opportunities"], 2)
        self.assertEqual(
            {opportunity["service"] for opportunity in payload["opportunities"]},
            {"cloudwatch", "ec2"},
        )
        self.assertEqual(payload["opportunities"][0]["service"], "ec2")
        self.assertEqual(payload["summary"]["returned_rules"], 2)
        self.assertEqual(
            payload["summary"]["services_scanned"],
            ["cloudwatch", "dynamodb", "s3", "ec2", "rds", "lambda", "efs", "eks", "alb"],
        )
        self.assertTrue(payload["summary"]["incomplete"])
        self.assertGreater(len(payload["rules_skipped"]), 0)

    def test_find_opportunities_accepts_multi_selected_services(self) -> None:
        with patch(
            "bluearch_aws_steward.mcp_server._client",
            return_value=MultiServiceFakeProvider(),
        ):
            payload = _tool_find_opportunities(
                {
                    "objective": "cost_optimization",
                    "service": ["cloudwatch", "ec2"],
                    "max_returned_resources": 10,
                    "max_returned_findings": 10,
                }
            )

        self.assertEqual(payload["service"], ["cloudwatch", "ec2"])
        self.assertEqual(
            payload["summary"]["services_requested"],
            ["cloudwatch", "ec2"],
        )
        self.assertEqual(
            payload["summary"]["services_scanned"],
            ["cloudwatch", "ec2"],
        )
        self.assertEqual(
            {opportunity["service"] for opportunity in payload["opportunities"]},
            {"cloudwatch", "ec2"},
        )

    def test_find_opportunities_preserves_partial_service_failures(self) -> None:
        with patch(
            "bluearch_aws_steward.mcp_server._client",
            return_value=CloudWatchDeniedProvider(),
        ):
            payload = _tool_find_opportunities(
                {
                    "objective": "cost_optimization",
                    "service": "all",
                    "max_returned_resources": 10,
                    "max_returned_findings": 10,
                }
            )

        self.assertTrue(payload["summary"]["incomplete"])
        self.assertEqual(payload["service_errors"][0]["service"], "cloudwatch")
        self.assertNotIn("cloudwatch", payload["summary"]["services_scanned"])

    def test_mcp_policy_overrides_reach_detectors(self) -> None:
        with patch(
            "bluearch_aws_steward.mcp_server._client",
            return_value=MultiServiceFakeProvider(),
        ):
            payload = _tool_find_opportunities(
                {
                    "objective": "cost_optimization",
                    "service": "all",
                    "ebs_min_unattached_days": 3650,
                    "cloudwatch_retention_days": 14,
                    "cloudwatch_min_stored_bytes": 0,
                }
            )

        self.assertEqual(payload["summary"]["opportunities"], 1)
        opportunity = payload["opportunities"][0]
        self.assertEqual(opportunity["service"], "cloudwatch")
        self.assertEqual(opportunity["evidence"]["recommended_retention_days"], 14)
        self.assertEqual(opportunity["cost_estimate"]["status"], "estimated")
        self.assertEqual(
            payload["policy_overrides"],
            {
                "cloudwatch_min_stored_bytes": 0,
                "cloudwatch_retention_days": 14,
                "ebs_min_unattached_days": 3650,
            },
        )

    def test_diverse_top_n_and_complete_grouping(self) -> None:
        cloudwatch_finding = (
            scan_cloudwatch(
                MultiServiceFakeProvider(),
                profile=None,
                endpoint_url=None,
                region="us-east-1",
            )
            .findings[0]
            .to_dict()
        )
        ebs_finding = (
            scan_ec2(
                MultiServiceFakeProvider(),
                profile=None,
                endpoint_url=None,
                region="us-east-1",
            )
            .findings[0]
            .to_dict()
        )
        findings = []
        for index in range(5):
            cloudwatch_copy = {
                **cloudwatch_finding,
                "finding_id": f"cw-{index}",
                "resource": f"cw://{index}",
            }
            ebs_copy = {
                **ebs_finding,
                "finding_id": f"ebs-{index}",
                "resource": f"ebs://vol-{index}",
            }
            findings.extend([ebs_copy, cloudwatch_copy])

        payload = _tool_find_opportunities(
            {
                "objective": "cost_optimization",
                "scan_result": {"service": "all", "findings": findings},
                "max_returned_findings": 4,
            }
        )
        returned_services = [opportunity["service"] for opportunity in payload["opportunities"]]
        self.assertEqual(returned_services, ["ec2", "cloudwatch", "ec2", "cloudwatch"])
        self.assertEqual(len(payload["opportunity_groups"]), 2)
        self.assertEqual(payload["opportunity_groups"][0]["rule"], "ec2-unattached-ebs-volume")

        one_card = _tool_find_opportunities(
            {
                "objective": "cost_optimization",
                "scan_result": {"service": "all", "findings": findings},
                "max_returned_findings": 1,
            }
        )
        self.assertEqual(len(one_card["opportunities"]), 1)
        self.assertEqual(len(one_card["opportunity_groups"]), 2)

    def test_advisory_s3_lifecycle_is_excluded_from_cost_opportunities(self) -> None:
        s3_finding = (
            scan_s3(
                MissingLifecycleProvider(),
                profile=None,
                endpoint_url=None,
                region="us-east-1",
                rule_filter="s3-no-lifecycle",
            )
            .findings[0]
            .to_dict()
        )
        cloudwatch_finding = (
            scan_cloudwatch(
                MultiServiceFakeProvider(),
                profile=None,
                endpoint_url=None,
                region="us-east-1",
            )
            .findings[0]
            .to_dict()
        )
        payload = _tool_find_opportunities(
            {
                "objective": "cost_optimization",
                "scan_result": {"service": "all", "findings": [s3_finding, cloudwatch_finding]},
            }
        )

        self.assertEqual(payload["summary"]["opportunities"], 1)
        self.assertEqual(payload["rules"], ["cloudwatch-log-retention-missing"])

    def test_scan_policy_validation(self) -> None:
        policy = build_scan_policy(
            ebs_min_unattached_days=30,
            cloudwatch_retention_days=90,
            cloudwatch_min_stored_bytes=1024,
            exclude_tags={"owner": "platform"},
        )
        self.assertEqual(policy.to_dict()["ebs_min_unattached_days"], 30)
        self.assertEqual(policy.exclude_tags, {"owner": "platform"})
        with self.assertRaisesRegex(ValueError, "KEY=VALUE"):
            build_scan_policy(exclude_tags=["invalid"])

    def test_cloudwatch_remediation_requires_server_held_plan(self) -> None:
        result = scan_cloudwatch(
            MultiServiceFakeProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
        )
        plan = _tool_plan_remediation({"finding": result.findings[0].to_dict()})

        self.assertTrue(plan["apply_supported"])
        self.assertEqual(plan["mcp_apply_tool"]["name"], "bluearch_apply_remediation")
        self.assertIn("plan_id", plan["mcp_apply_tool"]["required_arguments"])
        self.assertNotIn("cli_equivalent", plan)


if __name__ == "__main__":
    unittest.main()
