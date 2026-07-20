from __future__ import annotations

import unittest
from typing import Any, Dict, List, Optional, Set

from bluearch_aws_steward.detectors.ecs import scan_ecs
from bluearch_aws_steward.detectors.s3 import scan_s3
from bluearch_aws_steward.providers.operations import READ_OPERATIONS


class FilteredS3Provider:
    def __init__(self) -> None:
        self.policy_reads = 0

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def list_buckets(self) -> List[str]:
        return ["cloudtrail-destination"]

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        self.policy_reads += 1
        return {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "cloudtrail.amazonaws.com"},
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/*",
                }
            ]
        }

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "s3.get_bucket_logging":
            return {}
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class FilteredEcsProvider:
    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "ecs.list_clusters":
            return {"clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/demo"]}
        if operation == "ecs.list_services":
            return {"serviceArns": ["arn:aws:ecs:us-east-1:123456789012:service/demo/api"]}
        if operation == "ecs.describe_services":
            return {
                "services": [
                    {
                        "serviceArn": "arn:aws:ecs:us-east-1:123456789012:service/demo/api",
                        "serviceName": "api",
                        "desiredCount": 2,
                        "runningCount": 1,
                        "pendingCount": 1,
                        "deployments": [],
                        "tags": [],
                    }
                ]
            }
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class V060RuleFilterTests(unittest.TestCase):
    def test_cloudtrail_bucket_logging_rule_loads_policy_when_filtered_alone(self) -> None:
        provider = FilteredS3Provider()

        result = scan_s3(
            provider,
            None,
            None,
            "us-east-1",
            rule_filter="s3-cloudtrail-access-logging-disabled",
        )

        self.assertEqual(provider.policy_reads, 1)
        self.assertEqual(
            [finding.rule_short_id for finding in result.findings],
            ["s3-cloudtrail-access-logging-disabled"],
        )

    def test_ecs_health_rule_returns_finding_when_filtered_alone(self) -> None:
        result = scan_ecs(
            FilteredEcsProvider(),
            None,
            None,
            "us-east-1",
            rule_filter="ecs-service-health-degraded",
        )

        self.assertEqual(
            [finding.rule_short_id for finding in result.findings],
            ["ecs-service-health-degraded"],
        )


if __name__ == "__main__":
    unittest.main()
