from __future__ import annotations

import unittest
from typing import Any, Dict, List, Optional, Set

from bluearch_aws_steward.detectors.s3 import scan_s3
from bluearch_aws_steward.providers.operations import READ_OPERATIONS


class PublicReadPolicyProvider:
    """Bucket whose policy grants anonymous read while public access block is complete."""

    def __init__(self, action: Any = "s3:GetObject", principal: Any = "*") -> None:
        self.action = action
        self.principal = principal

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def list_buckets(self) -> List[str]:
        return ["exposed-bucket"]

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
                    "Sid": "AnonymousRead",
                    "Effect": "Allow",
                    "Principal": self.principal,
                    "Action": self.action,
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ],
        }


class PublicReadPolicyRuleTests(unittest.TestCase):
    def test_detects_public_read_policy_even_with_complete_public_access_block(self) -> None:
        result = scan_s3(
            PublicReadPolicyProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="s3-policy-public-read",
        )

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.rule_short_id, "s3-policy-public-read")
        self.assertEqual(finding.resource, "s3://exposed-bucket")
        self.assertEqual(
            finding.evidence["public_read_actions"][0]["actions"],
            ["s3:GetObject"],
        )
        self.assertTrue(finding.evidence["public_access_block_complete"])

    def test_wildcard_only_statement_is_left_to_the_all_actions_rule(self) -> None:
        result = scan_s3(
            PublicReadPolicyProvider(action="s3:*"),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="s3-policy-public-read",
        )

        self.assertEqual(result.findings, [])

    def test_non_public_principal_is_not_flagged(self) -> None:
        result = scan_s3(
            PublicReadPolicyProvider(principal={"AWS": "arn:aws:iam::123456789012:root"}),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="s3-policy-public-read",
        )

        self.assertEqual(result.findings, [])
