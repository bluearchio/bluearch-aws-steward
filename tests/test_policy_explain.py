"""Pure policy-evaluation core for bluearch_explain_denial.

Each test is one benchmark defect class from cloudarch-eval
sweep-2026-08-12 (docs/explain-denial-design.md). Pure fixtures only --
no AWS, no providers.
"""

from __future__ import annotations

import unittest

from bluearch_aws_steward.policy_explain import AccessRequest, evaluate_access

ACCOUNT = "123456789012"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/workload"
BUCKET_ARN = "arn:aws:s3:::app-data"
OBJECT_ARN = "arn:aws:s3:::app-data/reports/q1.csv"
KEY_ARN = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/11111111-2222-3333-4444-555555555555"
QUEUE_ARN = f"arn:aws:sqs:us-east-1:{ACCOUNT}:orders"
TOPIC_ARN = f"arn:aws:sns:us-east-1:{ACCOUNT}:order-events"


def _request(action: str, resource: str, principal: str = ROLE, **context: str) -> AccessRequest:
    return AccessRequest(
        action=action,
        resource=resource,
        principal=principal,
        account_id=ACCOUNT,
        condition_context=dict(context),
    )


class ExplicitDenyTests(unittest.TestCase):
    def test_explicit_deny_masks_an_identity_allow(self) -> None:
        # Defect class: iam-explicit-deny-masks-allow
        evaluation = evaluate_access(
            _request("s3:GetObject", OBJECT_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowReads",
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::app-data/*",
                        },
                        {
                            "Sid": "CanaryDenyReports",
                            "Effect": "Deny",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::app-data/reports/*",
                        },
                    ]
                }
            ],
        )

        self.assertEqual(evaluation.verdict["effect"], "explicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "identity_policy")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "denying_statement")
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "CanaryDenyReports")

    def test_missing_identity_permission_is_an_implicit_deny(self) -> None:
        # Defect class: iam-s3-workload-permission
        evaluation = evaluate_access(
            _request("s3:PutObject", OBJECT_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowReads",
                            "Effect": "Allow",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::app-data/*",
                        }
                    ]
                }
            ],
        )

        self.assertEqual(evaluation.verdict["effect"], "implicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "identity_policy")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "missing_permission")
        self.assertIn("s3:PutObject", decisive["explanation"])

    def test_same_account_identity_allow_is_an_allow(self) -> None:
        evaluation = evaluate_access(
            _request("s3:GetObject", OBJECT_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowReads",
                            "Effect": "Allow",
                            "Action": "s3:Get*",
                            "Resource": "arn:aws:s3:::app-data/*",
                        }
                    ]
                }
            ],
        )

        self.assertEqual(evaluation.verdict["effect"], "allow")
        self.assertEqual(evaluation.verdict["blocking_layer"], "none")
        self.assertEqual(evaluation.claims[0]["kind"], "satisfied_layer")


class KmsKeyPolicyTests(unittest.TestCase):
    def test_key_policy_excluding_the_principal_blocks_despite_identity_allow(self) -> None:
        # Defect classes: kms-key-policy-excludes-workload, s3-upload-kms-denied
        evaluation = evaluate_access(
            _request("kms:GenerateDataKey", KEY_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowKms",
                            "Effect": "Allow",
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ]
                }
            ],
            kms_key_policy={
                "Statement": [
                    {
                        "Sid": "CanaryAdminOnly",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/other-admin"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ]
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "implicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "kms_key_policy")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "missing_permission")
        self.assertEqual(decisive["layer"], "kms_key_policy")

    def test_key_policy_root_delegation_defers_to_the_identity_policy(self) -> None:
        # Real IAM semantics: a key policy granting the account root
        # delegates the decision to identity policies.
        evaluation = evaluate_access(
            _request("kms:GenerateDataKey", KEY_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowKms",
                            "Effect": "Allow",
                            "Action": "kms:GenerateDataKey",
                            "Resource": "*",
                        }
                    ]
                }
            ],
            kms_key_policy={
                "Statement": [
                    {
                        "Sid": "EnableRootDelegation",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    }
                ]
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "allow")

    def test_key_policy_granting_the_principal_allows(self) -> None:
        evaluation = evaluate_access(
            _request("kms:GenerateDataKey", KEY_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowKms",
                            "Effect": "Allow",
                            "Action": "kms:GenerateDataKey",
                            "Resource": "*",
                        }
                    ]
                }
            ],
            kms_key_policy={
                "Statement": [
                    {
                        "Sid": "AllowWorkload",
                        "Effect": "Allow",
                        "Principal": {"AWS": ROLE},
                        "Action": "kms:GenerateDataKey",
                        "Resource": "*",
                    }
                ]
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "allow")


class ServiceDeliveryConditionTests(unittest.TestCase):
    def _queue_policy(self, source_arn: str) -> dict:
        return {
            "Statement": [
                {
                    "Sid": "CanaryAllowSns",
                    "Effect": "Allow",
                    "Principal": {"Service": "sns.amazonaws.com"},
                    "Action": "sqs:SendMessage",
                    "Resource": QUEUE_ARN,
                    "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
                }
            ]
        }

    def test_source_arn_condition_mismatch_blocks_delivery(self) -> None:
        # Defect classes: sns-sqs-delivery-rejected,
        # eventbridge-sqs-policy-rejects-delivery, sqs-dlq-redrive-misconfigured
        evaluation = evaluate_access(
            _request(
                "sqs:SendMessage",
                QUEUE_ARN,
                principal="sns.amazonaws.com",
                **{"aws:SourceArn": TOPIC_ARN},
            ),
            resource_policy=self._queue_policy("arn:aws:sns:us-east-1:123456789012:other-topic"),
        )

        self.assertEqual(evaluation.verdict["effect"], "implicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "condition_mismatch")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "condition_mismatch")
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "CanaryAllowSns")
        self.assertIn(TOPIC_ARN, decisive["explanation"])

    def test_matching_source_arn_allows_delivery(self) -> None:
        evaluation = evaluate_access(
            _request(
                "sqs:SendMessage",
                QUEUE_ARN,
                principal="sns.amazonaws.com",
                **{"aws:SourceArn": TOPIC_ARN},
            ),
            resource_policy=self._queue_policy(TOPIC_ARN),
        )

        self.assertEqual(evaluation.verdict["effect"], "allow")

    def test_unsupplied_condition_key_is_conditional_not_a_guess(self) -> None:
        evaluation = evaluate_access(
            _request("sqs:SendMessage", QUEUE_ARN, principal="sns.amazonaws.com"),
            resource_policy=self._queue_policy(TOPIC_ARN),
        )

        self.assertEqual(evaluation.verdict["effect"], "conditional")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "condition_mismatch")
        self.assertIn("aws:SourceArn", decisive["explanation"])


class PublicAccessBlockTests(unittest.TestCase):
    def test_complete_public_access_block_blocks_an_anonymous_read(self) -> None:
        evaluation = evaluate_access(
            _request("s3:GetObject", OBJECT_ARN, principal="*"),
            resource_policy={
                "Statement": [
                    {
                        "Sid": "AnonymousRead",
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::app-data/*",
                    }
                ]
            },
            public_access_block={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "explicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "public_access_block")
        self.assertEqual(evaluation.claims[0]["kind"], "blocking_control")


if __name__ == "__main__":
    unittest.main()
