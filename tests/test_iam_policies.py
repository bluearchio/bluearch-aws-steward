from __future__ import annotations

import unittest

from bluearch_aws_steward.iam_policies import (
    generated_policies,
    policies_match,
    read_actions,
    remediation_actions,
)
from bluearch_aws_steward.providers.operations import READ_OPERATIONS, iam_action_for_operation


class IamPolicyTests(unittest.TestCase):
    def test_generated_policies_match_capabilities_and_remediation_manifest(self) -> None:
        self.assertTrue(policies_match())
        self.assertIn("cloudwatch:GetMetricData", read_actions())
        self.assertIn("elasticloadbalancing:DescribeLoadBalancers", read_actions())
        self.assertIn("elasticfilesystem:DescribeMountTargets", read_actions())
        self.assertIn("s3:GetBucketObjectLockConfiguration", read_actions())
        self.assertIn("s3:GetReplicationConfiguration", read_actions())
        self.assertNotIn("efs:DescribeMountTargets", read_actions())
        self.assertNotIn("s3:GetBucketReplication", read_actions())
        self.assertNotIn("s3:GetObjectLockConfiguration", read_actions())
        self.assertEqual(
            read_actions(),
            sorted(iam_action_for_operation(operation) for operation in READ_OPERATIONS),
        )
        self.assertIn("s3:PutBucketLogging", remediation_actions())
        self.assertIn(
            "elasticloadbalancing:ModifyLoadBalancerAttributes",
            remediation_actions(),
        )
        self.assertEqual(len(generated_policies()), 2)


if __name__ == "__main__":
    unittest.main()
