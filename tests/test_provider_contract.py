from __future__ import annotations

import unittest
from typing import Any, Dict, List, Optional

from bluearch_aws_steward.detectors.s3 import scan_s3


class FakeProvider:
    def __init__(self) -> None:
        self.actions: List[str] = []

    def caller_identity(self) -> Dict[str, Any]:
        return {"Account": "123456789012"}

    def list_buckets(self) -> List[str]:
        return ["demo-bucket", "ignored-bucket"]

    def list_log_groups(self) -> List[Dict[str, Any]]:
        return []

    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        return []

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {}

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket}/*",
                }
            ]
        }

    def get_bucket_encryption_rules(self, bucket: str) -> List[Dict[str, Any]]:
        return []

    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        return []

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        return None

    def put_public_access_block(self, bucket: str) -> None:
        self.actions.append(f"public-access-block:{bucket}")

    def put_default_encryption(self, bucket: str) -> None:
        self.actions.append(f"default-encryption:{bucket}")

    def put_lifecycle(
        self,
        bucket: str,
        *,
        transition_days: int = 30,
        storage_class: str = "STANDARD_IA",
    ) -> None:
        self.actions.append(f"lifecycle:{bucket}")

    def put_versioning(self, bucket: str) -> None:
        self.actions.append(f"versioning:{bucket}")


class ProviderContractTests(unittest.TestCase):
    def test_s3_scan_uses_provider_protocol(self) -> None:
        result = scan_s3(
            FakeProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            bucket_prefix="demo",
            rule_filter="s3-no-lifecycle,s3-versioning-disabled",
        )

        finding_rules = {finding.rule_short_id for finding in result.findings}
        self.assertEqual(finding_rules, {"s3-no-lifecycle", "s3-versioning-disabled"})
        self.assertEqual(result.provider, "aws-cli")
        self.assertEqual(result.summary["resources_scanned"], 1)
        self.assertEqual(result.summary["rules_evaluated"], 2)


if __name__ == "__main__":
    unittest.main()
