from __future__ import annotations

import unittest
from datetime import datetime, timezone

from bluearch_aws_steward.mcp_server import StewardMcpServer
from bluearch_aws_steward.signal_sources import collect_live_signal_results


class FakeSignalProvider:
    def __init__(self) -> None:
        self.operations = []

    def capabilities(self) -> set[str]:
        return {
            "securityhub.get_findings",
            "compute-optimizer.get_ec2_instance_recommendations",
            "compute-optimizer.get_ebs_volume_recommendations",
            "compute-optimizer.get_lambda_function_recommendations",
            "cost-optimization-hub.list_recommendations",
        }

    def caller_identity(self) -> dict:
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:sts::123456789012:assumed-role/Test/session",
        }

    def read(self, operation: str, **parameters: object) -> dict:
        self.operations.append((operation, parameters))
        if operation == "securityhub.get_findings":
            return {
                "Findings": [
                    {
                        "Id": "sh-1",
                        "AwsAccountId": "123456789012",
                        "Compliance": {"Status": "FAILED", "SecurityControlId": "S3.4"},
                        "Resources": [
                            {
                                "Id": "arn:aws:s3:::demo",
                                "Type": "AwsS3Bucket",
                                "Region": "us-east-1",
                            }
                        ],
                    }
                ]
            }
        if operation == "compute-optimizer.get_ec2_instance_recommendations":
            return {
                "instanceRecommendations": [
                    {
                        "instanceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
                        "finding": "Overprovisioned",
                        "lastRefreshTimestamp": datetime(2026, 7, 16, tzinfo=timezone.utc),
                    }
                ]
            }
        if operation == "cost-optimization-hub.list_recommendations":
            return {
                "items": [
                    {
                        "recommendationId": "coh-1",
                        "accountId": "123456789012",
                        "region": "us-east-1",
                        "resourceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-123",
                        "currentResourceType": "Ec2Instance",
                        "actionType": "Rightsize",
                    }
                ]
            }
        return {}


class LiveSignalSourceTests(unittest.TestCase):
    def test_mcp_assessment_deduplicates_live_cost_sources(self) -> None:
        provider = FakeSignalProvider()
        server = StewardMcpServer(
            aws_context_loader=lambda: {
                "profiles": [{"name": "test", "region": "us-east-1"}],
                "profile_count": 1,
                "active_profile": "test",
                "environment_region": "us-east-1",
                "credential_sources": [],
                "non_profile_credentials_configured": False,
                "discovery_errors": [],
                "secrets_included": False,
            },
            aws_provider_factory=lambda _: provider,  # type: ignore[arg-type]
        )
        started = server._call_tool(
            "bluearch_assess",
            {
                "prompt": "Combine Compute Optimizer and Cost Optimization Hub recommendations.",
                "profile": "test",
                "region": "us-east-1",
                "services": ["all"],
                "objectives": ["all"],
                "signal_sources": ["compute-optimizer", "cost-optimization-hub"],
            },
        )

        completed = server._assessments.wait(started["assessment_id"], timeout=2)

        self.assertEqual(completed["status"], "completed")
        result = completed["result"]
        self.assertTrue(result["summary"]["unified_recommendation_queue"])
        self.assertEqual(result["summary"]["signals_received"], 2)
        self.assertEqual(result["summary"]["deduplicated_signals"], 1)
        self.assertEqual(len(result["opportunities"]), 1)
        self.assertEqual(
            result["opportunities"][0]["sources"],
            ["compute-optimizer", "cost-optimization-hub"],
        )
        self.assertEqual(result["opportunities"][0]["validation"]["status"], "source_current")

    def test_live_sources_use_allowlisted_reads_and_mark_freshness(self) -> None:
        provider = FakeSignalProvider()

        snapshots, errors = collect_live_signal_results(
            provider,
            ["security-hub", "compute-optimizer", "cost-optimization-hub"],
            region="us-east-1",
            account_id="123456789012",
        )

        self.assertEqual(errors, [])
        self.assertEqual(len(snapshots), 5)
        findings = [finding for snapshot in snapshots for finding in snapshot["findings"]]
        self.assertEqual(len(findings), 3)
        self.assertTrue(
            all(
                finding["evidence"]["live_validation"]["status"] == "source_current"
                for finding in findings
            )
        )
        self.assertTrue(
            all(
                finding["evidence"]["external_content_trust"] == "trusted_aws_api_signal"
                for finding in findings
            )
        )
        self.assertEqual(len(provider.operations), 5)

    def test_missing_capability_is_non_fatal_and_explicit(self) -> None:
        provider = FakeSignalProvider()
        provider.capabilities = lambda: {"securityhub.get_findings"}  # type: ignore[method-assign]

        snapshots, errors = collect_live_signal_results(
            provider,
            ["compute-optimizer"],
            region="us-east-1",
        )

        self.assertEqual(snapshots, [])
        self.assertEqual(len(errors), 3)
        self.assertTrue(all(error["reason"] == "provider_capability_missing" for error in errors))


if __name__ == "__main__":
    unittest.main()
