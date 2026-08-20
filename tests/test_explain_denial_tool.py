"""bluearch_explain_denial end-to-end through the MCP server.

Fake providers only -- no AWS. Contract: docs/explain-denial-design.md.
"""

from __future__ import annotations

import json
import unittest
from typing import Any, Dict, Optional, Set

from bluearch_aws_steward.mcp_server import StewardMcpServer
from bluearch_aws_steward.policy_explain import AccessRequest, assemble_response, evaluate_access
from bluearch_aws_steward.providers.aws_sdk import AwsProviderError
from bluearch_aws_steward.providers.operations import READ_OPERATIONS

ACCOUNT = "123456789012"
QUEUE_ARN = f"arn:aws:sqs:us-east-1:{ACCOUNT}:orders"
TOPIC_ARN = f"arn:aws:sns:us-east-1:{ACCOUNT}:order-events"

_QUEUE_POLICY = {
    "Statement": [
        {
            "Sid": "CanaryAllowSns",
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": QUEUE_ARN,
            "Condition": {
                "ArnEquals": {"aws:SourceArn": f"arn:aws:sns:us-east-1:{ACCOUNT}:other-topic"}
            },
        }
    ]
}


class QueuePolicyProvider:
    def __init__(self, *, deny_policy_read: bool = False) -> None:
        self.deny_policy_read = deny_policy_read
        self.reads: list[str] = []

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/workload/session",
        }

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        self.reads.append(operation)
        if operation == "sqs.get_queue_url":
            return {"QueueUrl": f"http://127.0.0.1/{ACCOUNT}/orders"}
        if operation == "sqs.get_queue_attributes":
            if self.deny_policy_read:
                raise AwsProviderError(
                    "AWS SDK operation failed: sqs.get_queue_attributes AccessDenied"
                )
            return {"Attributes": {"Policy": json.dumps(_QUEUE_POLICY)}}
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


def _server(provider: Any) -> StewardMcpServer:
    return StewardMcpServer(
        aws_context_loader=lambda: {"profiles": ["test-sso"], "default_profile": "test-sso"},
        aws_provider_factory=lambda _: provider,
    )


def _call(server: StewardMcpServer, arguments: Dict[str, Any]) -> Dict[str, Any]:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "bluearch_explain_denial", "arguments": arguments},
        }
    )
    assert response is not None
    if response["result"]["isError"]:
        raise AssertionError(response["result"]["content"][0]["text"])
    return json.loads(response["result"]["content"][0]["text"])


class ExplainDenialToolTests(unittest.TestCase):
    def test_names_the_condition_mismatch_statement_end_to_end(self) -> None:
        provider = QueuePolicyProvider()
        result = _call(
            _server(provider),
            {
                "action": "sqs:SendMessage",
                "resource": QUEUE_ARN,
                "principal": "sns.amazonaws.com",
                "condition_context": {"aws:SourceArn": TOPIC_ARN},
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["schema_version"], "1")
        self.assertEqual(result["status"], "explained")
        self.assertEqual(result["verdict"]["blocking_layer"], "condition_mismatch")
        decisive = result["claims"][0]
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "CanaryAllowSns")
        self.assertIn(TOPIC_ARN, decisive["explanation"])
        layers = {entry["layer"]: entry["result"] for entry in result["evaluation_ledger"]}
        self.assertEqual(layers.get("resource_policy"), "evaluated")
        # v1 never evaluates SCPs; the contract requires that limit declared,
        # never silently passed (docs/explain-denial-design.md).
        self.assertEqual(layers.get("scp"), "not_evaluated")
        scp_unknowns = [
            entry
            for entry in result["unknowns"]
            if entry["layer"] == "scp" and entry["reason"] == "not_evaluated_v1"
        ]
        self.assertEqual(len(scp_unknowns), 1)
        self.assertIn("verification", result["next"])
        self.assertIn("sqs.get_queue_attributes", provider.reads)

    def test_denied_policy_read_degrades_to_insufficient_access(self) -> None:
        provider = QueuePolicyProvider(deny_policy_read=True)
        result = _call(
            _server(provider),
            {
                "action": "sqs:SendMessage",
                "resource": QUEUE_ARN,
                "principal": "sns.amazonaws.com",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "insufficient_access")
        self.assertEqual(result["verdict"]["blocking_layer"], "unknown")
        unknown_layers = {entry["layer"] for entry in result["unknowns"]}
        self.assertIn("resource_policy", unknown_layers)
        reasons = {entry["reason"] for entry in result["unknowns"]}
        self.assertIn("read_denied", reasons)

    def test_unsupported_service_is_honest_and_reads_nothing(self) -> None:
        provider = QueuePolicyProvider()
        result = _call(
            _server(provider),
            {
                "action": "elasticache:DescribeCacheClusters",
                "resource": f"arn:aws:elasticache:us-east-1:{ACCOUNT}:cluster:demo",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "not_supported")
        self.assertEqual(provider.reads, [])
        self.assertIn("proceed", result["message"].lower())


class IdentityCollectionProvider:
    """S3 request decided by the caller role's attached managed policy."""

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/workload/session",
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return None

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {"BlockPublicAcls": False}

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "iam.get_role":
            return {"Role": {"RoleName": parameters["RoleName"]}}
        if operation == "iam.list_attached_role_policies":
            assert parameters["RoleName"] == "workload"
            return {"AttachedPolicies": [{"PolicyArn": f"arn:aws:iam::{ACCOUNT}:policy/app-reads"}]}
        if operation == "iam.get_policy":
            return {"Policy": {"DefaultVersionId": "v2"}}
        if operation == "iam.get_policy_version":
            assert parameters["VersionId"] == "v2"
            return {
                "PolicyVersion": {
                    "Document": {
                        "Statement": [
                            {
                                "Sid": "AllowReads",
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::app-data/*",
                            }
                        ]
                    }
                }
            }
        if operation == "iam.list_role_policies":
            return {"PolicyNames": []}
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class IdentityCollectionTests(unittest.TestCase):
    def test_defaults_the_principal_to_the_caller_role_and_reads_its_policies(
        self,
    ) -> None:
        result = _call(
            _server(IdentityCollectionProvider()),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/reports/q1.csv",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "not_denied")
        self.assertEqual(result["verdict"]["effect"], "allow")
        decisive = result["claims"][0]
        self.assertEqual(decisive["kind"], "satisfied_layer")
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "AllowReads")
        layers = {entry["layer"] for entry in result["evaluation_ledger"]}
        self.assertIn("identity_policy", layers)


class LeastPrivilegeIdentityProvider:
    """Real-world least-privilege shape (and the diagnosis-iam sandbox):
    attached-policy listing denied, inline policies readable -- the
    planted deny lives in an inline policy."""

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator",
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        raise AwsProviderError("AWS SDK operation failed: s3.get_bucket_policy AccessDenied")

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        raise AwsProviderError("AWS SDK operation failed: s3.get_public_access_block AccessDenied")

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "iam.get_role":
            return {"Role": {"RoleName": parameters["RoleName"]}}
        if operation == "iam.list_attached_role_policies":
            raise AwsProviderError(
                "AWS SDK operation failed: iam.list_attached_role_policies AccessDenied"
            )
        if operation == "iam.list_role_policies":
            assert parameters["RoleName"] == "workload"
            return {"PolicyNames": ["fault-target"]}
        if operation == "iam.get_role_policy":
            return {
                "PolicyDocument": {
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
            }
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class InlineFallbackTests(unittest.TestCase):
    def test_denied_attached_listing_still_evaluates_inline_policies(self) -> None:
        result = _call(
            _server(LeastPrivilegeIdentityProvider()),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/config.json",
                "principal": f"arn:aws:iam::{ACCOUNT}:role/workload",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "explained")
        self.assertEqual(result["verdict"]["effect"], "explicit_deny")
        self.assertEqual(result["verdict"]["blocking_layer"], "identity_policy")
        decisive = result["claims"][0]
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "FaultTargetReadDeny")
        # The denied attached listing degrades to a declared unknown, and
        # the inline half still counts as an evaluated identity layer.
        identity_rows = {
            entry["read"]: entry["result"]
            for entry in result["evaluation_ledger"]
            if entry["layer"] == "identity_policy"
        }
        self.assertEqual(identity_rows.get("iam.list_attached_role_policies"), "access_denied")
        self.assertEqual(identity_rows.get("iam.list_role_policies"), "evaluated")
        unknown_layers = {entry["layer"] for entry in result["unknowns"]}
        self.assertIn("identity_policy", unknown_layers)


class GuessedRoleNameProvider:
    """The caller passed a role name that does not exist (agents guess
    names on real accounts every day); role listing is granted."""

    def __init__(self) -> None:
        self.policy_reads: list[str] = []

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator",
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return None

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {"BlockPublicAcls": False}

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "iam.get_role":
            raise AwsProviderError(
                "AWS SDK operation failed: iam.get_role NoSuchEntity: The role "
                f"with name {parameters['RoleName']} cannot be found."
            )
        if operation == "iam.list_roles":
            return {
                "Roles": [
                    {"RoleName": "cloudarch-workload-cc8643"},
                    {"RoleName": "deploy-pipeline"},
                ]
            }
        if operation in ("iam.list_attached_role_policies", "iam.list_role_policies"):
            self.policy_reads.append(operation)
            raise AssertionError("policy reads must be skipped for a missing role")
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class PrincipalDiscoveryTests(unittest.TestCase):
    def test_missing_role_gets_discovery_help_instead_of_wasted_reads(self) -> None:
        provider = GuessedRoleNameProvider()
        result = _call(
            _server(provider),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/config.json",
                "principal": f"arn:aws:iam::{ACCOUNT}:role/workload-role",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "insufficient_access")
        self.assertEqual(result["verdict"]["blocking_layer"], "unknown")
        identity_unknowns = [
            entry for entry in result["unknowns"] if entry["layer"] == "identity_policy"
        ]
        (unknown,) = identity_unknowns
        self.assertIn("was not found", unknown["detail"])
        self.assertIn("cloudarch-workload-cc8643", unknown["detail"])
        self.assertIn("exact role ARN", unknown["detail"])
        self.assertEqual(provider.policy_reads, [])
        reads = {entry["read"] for entry in result["evaluation_ledger"]}
        self.assertIn("iam.get_role", reads)


class ServicePrincipalGuardTests(unittest.TestCase):
    def test_service_principals_never_trigger_role_existence_checks(self) -> None:
        """A service principal is not a role: no iam.* read may fire.
        Pinned at the harness owner's request -- the certification probe
        runs with principal sns.amazonaws.com against a LocalEmu without
        the iam service, and this is also correct on real AWS."""
        provider = QueuePolicyProvider()
        result = _call(
            _server(provider),
            {
                "action": "sqs:SendMessage",
                "resource": QUEUE_ARN,
                "principal": "sns.amazonaws.com",
                "condition_context": {"aws:SourceArn": TOPIC_ARN},
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "explained")
        self.assertFalse([read for read in provider.reads if read.startswith("iam.")])


class ScopedDenialRoleProvider:
    """Real-AWS shape: permissions scoped to the real role ARN, so reads
    on a guessed name return AccessDenied (never an existence oracle);
    listing roles is granted."""

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator",
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return None

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {"BlockPublicAcls": False}

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "iam.list_roles":
            return {"Roles": [{"RoleName": "cloudarch-workload-cc8643"}]}
        if operation in (
            "iam.get_role",
            "iam.list_attached_role_policies",
            "iam.list_role_policies",
        ):
            raise AwsProviderError(f"AWS SDK operation failed: {operation} AccessDenied")
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class RoleDiscoveryHintTests(unittest.TestCase):
    def test_denied_role_evaluation_still_offers_the_visible_roles(self) -> None:
        result = _call(
            _server(ScopedDenialRoleProvider()),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/config.json",
                "principal": f"arn:aws:iam::{ACCOUNT}:role/guessed-name",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "insufficient_access")
        details = " ".join(str(entry.get("detail")) for entry in result["unknowns"])
        self.assertIn("cloudarch-workload-cc8643", details)
        self.assertIn("exact role ARN", details)

    def test_out_of_scope_caller_without_principal_gets_role_candidates(self) -> None:
        result = _call(
            _server(ScopedDenialRoleProvider()),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/config.json",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "insufficient_access")
        details = " ".join(str(entry.get("detail")) for entry in result["unknowns"])
        self.assertIn("cloudarch-workload-cc8643", details)
        self.assertIn("principal", details)


class MultiSubjectProvider:
    """No principal given; two roles visible; exactly one is blocked for
    the requested action -- the expert evaluates the candidates in one
    pass and answers for the blocked subject, explicitly labeled."""

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator",
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return None

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {"BlockPublicAcls": False}

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "iam.list_roles":
            return {"Roles": [{"RoleName": "reader"}, {"RoleName": "workload"}]}
        if operation == "iam.get_role":
            return {"Role": {"RoleName": parameters["RoleName"]}}
        if operation == "iam.list_attached_role_policies":
            return {"AttachedPolicies": []}
        if operation == "iam.list_role_policies":
            return {"PolicyNames": ["main"]}
        if operation == "iam.get_role_policy":
            if parameters["RoleName"] == "reader":
                statements = [
                    {
                        "Sid": "ReaderAllow",
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::app-data/*",
                    }
                ]
            else:
                statements = [
                    {
                        "Sid": "WorkloadAllow",
                        "Effect": "Allow",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::app-data/*",
                    },
                    {
                        "Sid": "CanaryConfigDeny",
                        "Effect": "Deny",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::app-data/config*",
                    },
                ]
            return {"PolicyDocument": {"Statement": statements}}
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")


class MultiSubjectDiagnosisTests(unittest.TestCase):
    def test_single_blocked_candidate_is_answered_as_that_subject(self) -> None:
        result = _call(
            _server(MultiSubjectProvider()),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/config.json",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "explained")
        self.assertEqual(result["verdict"]["effect"], "explicit_deny")
        self.assertEqual(result["verdict"]["blocking_layer"], "identity_policy")
        decisive = result["claims"][0]
        self.assertEqual(decisive["policy_ref"]["statement_sid"], "CanaryConfigDeny")
        # The answered subject must be unmistakable: named in an unknowns
        # note and carried in the verification recipe.
        details = " ".join(str(entry.get("detail")) for entry in result["unknowns"])
        self.assertIn("workload", details)
        self.assertIn("reader", details)
        verification = result["next"]["verification"]
        self.assertEqual(
            verification["arguments"]["principal"],
            f"arn:aws:iam::{ACCOUNT}:role/workload",
        )


class OperatorUserCallerProvider:
    """Caller is an IAM user (outside v1 identity collection)."""

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation == "iam.list_roles":
            return {"Roles": []}
        raise AssertionError(f"Unexpected operation: {operation} {parameters}")

    def caller_identity(self) -> Dict[str, Any]:
        return {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:user/operator",
        }

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        return None

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        return {"BlockPublicAcls": False}


class UnevaluatedDecidingLayerTests(unittest.TestCase):
    def test_never_asserts_a_verdict_over_an_unevaluated_deciding_layer(
        self,
    ) -> None:
        # Sweep-diagnosis-2026-08-19 defect: with an out-of-scope caller
        # (IAM user) and no explicit principal, identity policies are
        # not_evaluated -- the old code still returned a confident
        # implicit_deny/identity_policy built on nothing.
        result = _call(
            _server(OperatorUserCallerProvider()),
            {
                "action": "s3:GetObject",
                "resource": "arn:aws:s3:::app-data/reports/q1.csv",
                "profile": "test-sso",
                "region": "us-east-1",
            },
        )

        self.assertEqual(result["status"], "insufficient_access")
        self.assertEqual(result["verdict"]["blocking_layer"], "unknown")
        reasons = {entry["reason"] for entry in result["unknowns"]}
        self.assertIn("not_evaluated_v1", reasons)


class ServerNeverDiesTests(unittest.TestCase):
    def test_unexpected_tool_exception_returns_error_instead_of_killing_the_server(
        self,
    ) -> None:
        """The diagnosis sandbox has no aws binary; a provider factory
        crash there escaped the tools/call boundary and killed the stdio
        server (mcp_protocol_failure). Any unexpected exception must come
        back as an isError response."""

        def _exploding_factory(_arguments):
            raise RuntimeError("aws binary not present in this sandbox")

        server = StewardMcpServer(
            aws_context_loader=lambda: {"profiles": ["test-sso"], "default_profile": "test-sso"},
            aws_provider_factory=_exploding_factory,
        )
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_explain_denial",
                    "arguments": {
                        "action": "s3:GetObject",
                        "resource": "arn:aws:s3:::app-data/x",
                        "principal": f"arn:aws:iam::{ACCOUNT}:role/workload",
                        "profile": "test-sso",
                        "region": "us-east-1",
                    },
                },
            }
        )

        assert response is not None
        self.assertTrue(response["result"]["isError"])
        self.assertIn("internal error", response["result"]["content"][0]["text"].lower())


class ResponseBudgetTests(unittest.TestCase):
    def test_oversized_statement_evidence_is_trimmed_with_a_digest(self) -> None:
        big_statement = {
            "Sid": "Big",
            "Effect": "Deny",
            "Action": "s3:GetObject",
            "Resource": ["arn:aws:s3:::x/y"]
            + ["arn:aws:s3:::x/" + ("y" * 200) + str(i) for i in range(40)],
        }
        evaluation = evaluate_access(
            AccessRequest(
                action="s3:GetObject",
                resource="arn:aws:s3:::x/y",
                principal=f"arn:aws:iam::{ACCOUNT}:role/workload",
                account_id=ACCOUNT,
            ),
            identity_policies=[{"Statement": [big_statement]}],
        )
        self.assertEqual(evaluation.verdict["effect"], "explicit_deny")

        response = assemble_response(
            request=AccessRequest(
                action="s3:GetObject",
                resource="arn:aws:s3:::x/y",
                principal=f"arn:aws:iam::{ACCOUNT}:role/workload",
                account_id=ACCOUNT,
            ),
            evaluation=evaluation,
            ledger=[
                {"layer": "identity_policy", "read": "iam.get_role_policy", "result": "evaluated"}
            ],
            unknowns=[],
        )

        decisive = response["claims"][0]
        evidence = decisive["evidence"]
        self.assertTrue(evidence["evidence_truncated"])
        self.assertTrue(evidence["statement_sha256"])
        self.assertLessEqual(len(json.dumps(evidence["statement"])), 2048)
        self.assertLessEqual(len(json.dumps(response)), 8192)


if __name__ == "__main__":
    unittest.main()
