"""Pure policy-evaluation core for bluearch_explain_denial.

Each test is one benchmark defect class from cloudarch-eval
sweep-2026-08-12 (docs/explain-denial-design.md). Pure fixtures only --
no AWS, no providers.
"""

from __future__ import annotations

import unittest

from bluearch_aws_steward.policy_explain import AccessRequest, _evaluate_conditions, evaluate_access

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


class ConditionOperatorTests(unittest.TestCase):
    """Documented AWS condition semantics, computed exactly."""

    def _status(self, condition, context):
        status, _detail = _evaluate_conditions({"Condition": condition}, context)
        return status

    def test_string_not_equals_mismatching_value_is_satisfied(self) -> None:
        self.assertEqual(
            self._status(
                {"StringNotEquals": {"aws:SourceAccount": "111111111111"}},
                {"aws:SourceAccount": "222222222222"},
            ),
            "satisfied",
        )

    def test_string_not_equals_matching_value_is_a_mismatch(self) -> None:
        self.assertEqual(
            self._status(
                {"StringNotEquals": {"aws:SourceAccount": "111111111111"}},
                {"aws:SourceAccount": "111111111111"},
            ),
            "mismatch",
        )

    def test_negated_operator_with_absent_key_is_satisfied(self) -> None:
        # AWS: negated condition operators evaluate true when the key is
        # absent from the request context.
        self.assertEqual(
            self._status({"StringNotEquals": {"aws:SourceAccount": "111111111111"}}, {}),
            "satisfied",
        )

    def test_arn_not_like_blocks_matching_pattern(self) -> None:
        self.assertEqual(
            self._status(
                {"ArnNotLike": {"aws:SourceArn": "arn:aws:sns:*:111111111111:*"}},
                {"aws:SourceArn": "arn:aws:sns:us-east-1:111111111111:topic"},
            ),
            "mismatch",
        )

    def test_null_true_requires_the_key_absent(self) -> None:
        self.assertEqual(
            self._status({"Null": {"aws:TokenIssueTime": "true"}}, {}),
            "satisfied",
        )
        self.assertEqual(
            self._status(
                {"Null": {"aws:TokenIssueTime": "true"}}, {"aws:TokenIssueTime": "2026-01-01"}
            ),
            "mismatch",
        )

    def test_if_exists_with_absent_key_is_satisfied(self) -> None:
        self.assertEqual(
            self._status({"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1"}}, {}),
            "satisfied",
        )
        self.assertEqual(
            self._status(
                {"StringEqualsIfExists": {"aws:SourceVpce": "vpce-1"}}, {"aws:SourceVpce": "vpce-2"}
            ),
            "mismatch",
        )

    def test_ip_address_cidr_containment(self) -> None:
        self.assertEqual(
            self._status(
                {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "10.1.2.3"}
            ),
            "satisfied",
        )
        self.assertEqual(
            self._status(
                {"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}, {"aws:SourceIp": "10.1.2.3"}
            ),
            "mismatch",
        )

    def test_unknown_operator_stays_unsupported(self) -> None:
        self.assertEqual(
            self._status(
                {"DateGreaterThan": {"aws:CurrentTime": "2026-01-01T00:00:00Z"}},
                {"aws:CurrentTime": "2026-02-01T00:00:00Z"},
            ),
            "unsupported",
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


class ResourceNearMissTests(unittest.TestCase):
    def test_action_matching_statements_surface_as_near_misses(self) -> None:
        # Asking about the bucket ARN when the statements scope objects:
        # the decisive claim is the honest missing_permission, but the
        # expert also names the statements that match the ACTION with a
        # different resource scope -- including the planted deny.
        evaluation = evaluate_access(
            _request("s3:GetObject", BUCKET_ARN),
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
                            "Sid": "FaultTargetReadDeny",
                            "Effect": "Deny",
                            "Action": "s3:GetObject",
                            "Resource": "arn:aws:s3:::app-data/config*",
                        },
                    ]
                }
            ],
        )

        self.assertEqual(evaluation.verdict["effect"], "implicit_deny")
        self.assertEqual(evaluation.claims[0]["kind"], "missing_permission")
        near_sids = [
            (claim.get("policy_ref") or {}).get("statement_sid") for claim in evaluation.claims[1:]
        ]
        self.assertIn("FaultTargetReadDeny", near_sids)
        self.assertIn("AllowReads", near_sids)
        deny_claim = next(
            claim
            for claim in evaluation.claims[1:]
            if (claim.get("policy_ref") or {}).get("statement_sid") == "FaultTargetReadDeny"
        )
        self.assertEqual(deny_claim["kind"], "denying_statement")
        self.assertIn("does not match", deny_claim["explanation"])


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

    def test_delegation_with_no_identity_evidence_blames_the_key_policy(self) -> None:
        # Sweep-diagnosis-2026-08-19 defect: root delegation exists (the
        # standard EnableIAMUserPermissions statement) and identity
        # policies are empty/unreadable -- the decisive layer must be the
        # key policy that grants this principal nothing, never a
        # confident identity_policy verdict built on evidence we do not
        # have.
        evaluation = evaluate_access(
            _request("kms:Encrypt", KEY_ARN),
            identity_policies=[],
            kms_key_policy={
                "Statement": [
                    {
                        "Sid": "EnableIAMUserPermissions",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "WorkloadKeyUse",
                        "Effect": "Allow",
                        "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:role/other-workload"},
                        "Action": ["kms:Encrypt", "kms:Decrypt"],
                        "Resource": "*",
                    },
                ]
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "implicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "kms_key_policy")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "missing_permission")
        self.assertEqual(decisive["layer"], "kms_key_policy")
        self.assertEqual(decisive["policy_ref"]["resource"], KEY_ARN)

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


class PermissionBoundaryTests(unittest.TestCase):
    BOUNDARY_ARN = f"arn:aws:iam::{ACCOUNT}:policy/team-boundary"

    def test_boundary_without_the_action_blocks_despite_identity_allow(self) -> None:
        evaluation = evaluate_access(
            _request("s3:PutObject", OBJECT_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowWrites",
                            "Effect": "Allow",
                            "Action": "s3:PutObject",
                            "Resource": "arn:aws:s3:::app-data/*",
                        }
                    ]
                }
            ],
            permission_boundary={
                "arn": self.BOUNDARY_ARN,
                "document": {
                    "Statement": [
                        {
                            "Sid": "BoundaryReadOnly",
                            "Effect": "Allow",
                            "Action": ["s3:GetObject", "s3:ListBucket"],
                            "Resource": "*",
                        }
                    ]
                },
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "implicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "permission_boundary")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "missing_permission")
        self.assertEqual(decisive["policy_ref"]["resource"], self.BOUNDARY_ARN)

    def test_boundary_deny_wins_with_its_statement_named(self) -> None:
        evaluation = evaluate_access(
            _request("s3:PutObject", OBJECT_ARN),
            identity_policies=[
                {
                    "Statement": [
                        {
                            "Sid": "AllowWrites",
                            "Effect": "Allow",
                            "Action": "s3:*",
                            "Resource": "*",
                        }
                    ]
                }
            ],
            permission_boundary={
                "arn": self.BOUNDARY_ARN,
                "document": {
                    "Statement": [
                        {
                            "Sid": "BoundaryNoWrites",
                            "Effect": "Deny",
                            "Action": "s3:PutObject",
                            "Resource": "*",
                        },
                        {
                            "Sid": "BoundaryWide",
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        },
                    ]
                },
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "explicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "permission_boundary")
        decisive = evaluation.claims[0]
        self.assertEqual(decisive["kind"], "denying_statement")
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "BoundaryNoWrites")

    def test_boundary_and_identity_both_allowing_is_an_allow(self) -> None:
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
                        }
                    ]
                }
            ],
            permission_boundary={
                "arn": self.BOUNDARY_ARN,
                "document": {
                    "Statement": [
                        {
                            "Sid": "BoundaryReads",
                            "Effect": "Allow",
                            "Action": "s3:Get*",
                            "Resource": "*",
                        }
                    ]
                },
            },
        )

        self.assertEqual(evaluation.verdict["effect"], "allow")


class RedriveAllowPolicyTests(unittest.TestCase):
    DLQ_ARN = f"arn:aws:sqs:us-east-1:{ACCOUNT}:orders-dlq"
    SOURCE_ARN = f"arn:aws:sqs:us-east-1:{ACCOUNT}:orders"

    def _evaluate(self, redrive_allow, **context):
        return evaluate_access(
            AccessRequest(
                action="sqs:SendMessage",
                resource=self.DLQ_ARN,
                principal="sqs.amazonaws.com",
                account_id=ACCOUNT,
                condition_context=dict(context),
            ),
            redrive_allow_policy=redrive_allow,
        )

    def test_deny_all_blocks_the_redrive_flow(self) -> None:
        evaluation = self._evaluate({"redrivePermission": "denyAll"})
        self.assertEqual(evaluation.verdict["effect"], "explicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "redrive_allow_policy")
        self.assertEqual(evaluation.claims[0]["kind"], "blocking_control")

    def test_by_queue_mismatch_names_the_expected_sources(self) -> None:
        evaluation = self._evaluate(
            {"redrivePermission": "byQueue", "sourceQueueArns": [self.SOURCE_ARN + "-unrelated"]},
            **{"aws:SourceArn": self.SOURCE_ARN},
        )
        self.assertEqual(evaluation.verdict["effect"], "explicit_deny")
        self.assertEqual(evaluation.verdict["blocking_layer"], "redrive_allow_policy")
        self.assertIn(self.SOURCE_ARN, evaluation.claims[0]["explanation"])

    def test_by_queue_without_context_is_conditional(self) -> None:
        evaluation = self._evaluate(
            {"redrivePermission": "byQueue", "sourceQueueArns": [self.SOURCE_ARN]}
        )
        self.assertEqual(evaluation.verdict["effect"], "conditional")

    def test_allow_all_or_matching_source_is_not_denied(self) -> None:
        self.assertEqual(
            self._evaluate({"redrivePermission": "allowAll"}).verdict["effect"], "allow"
        )
        self.assertEqual(
            self._evaluate(
                {"redrivePermission": "byQueue", "sourceQueueArns": [self.SOURCE_ARN]},
                **{"aws:SourceArn": self.SOURCE_ARN},
            ).verdict["effect"],
            "allow",
        )


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
