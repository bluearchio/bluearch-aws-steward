from __future__ import annotations

import json
import unittest
from typing import Any, Dict, Set

from bluearch_aws_steward.detectors.api_gateway import scan_api_gateway
from bluearch_aws_steward.detectors.kms import scan_kms
from bluearch_aws_steward.detectors.secrets_manager import scan_secrets_manager
from bluearch_aws_steward.detectors.sns import scan_sns
from bluearch_aws_steward.detectors.sqs import scan_sqs
from bluearch_aws_steward.providers.base import AwsProviderError
from bluearch_aws_steward.providers.operations import READ_OPERATIONS

NEW_RULES = {
    "api-gateway-access-logging-disabled",
    "api-gateway-execution-logging-disabled",
    "api-gateway-method-authorization-missing",
    "api-gateway-xray-tracing-disabled",
    "kms-key-rotation-disabled",
    "secrets-manager-rotation-disabled",
    "sns-topic-encryption-disabled",
    "sns-topic-public-access",
    "sqs-queue-encryption-disabled",
    "sqs-queue-public-access",
}


class V050Provider:
    def __init__(self, *, healthy: bool = False) -> None:
        self.healthy = healthy
        self.calls: list[str] = []

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        self.calls.append(operation)
        handler = getattr(self, "_" + operation.replace(".", "_"), None)
        if handler is None:
            raise AssertionError(f"Unexpected operation: {operation} {parameters}")
        return handler(parameters)

    def _kms_list_keys(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Keys": [{"KeyId": "key-fixture", "KeyArn": self._kms_arn()}]}

    def _kms_describe_key(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "KeyMetadata": {
                "KeyId": "key-fixture",
                "Arn": self._kms_arn(),
                "Description": "fixture key",
                "KeyManager": "CUSTOMER",
                "KeyState": "Enabled",
                "KeySpec": "SYMMETRIC_DEFAULT",
                "KeyUsage": "ENCRYPT_DECRYPT",
                "Origin": "AWS_KMS",
            }
        }

    def _kms_list_resource_tags(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Tags": [{"TagKey": "fixture", "TagValue": "true"}]}

    def _kms_get_key_rotation_status(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"KeyRotationEnabled": self.healthy}

    def _secretsmanager_list_secrets(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "SecretList": [
                {
                    "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture",
                    "Name": "fixture",
                }
            ]
        }

    def _secretsmanager_describe_secret(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "ARN": "arn:aws:secretsmanager:us-east-1:123456789012:secret:fixture",
            "Name": "fixture",
            "RotationEnabled": self.healthy,
            "Tags": [{"Key": "fixture", "Value": "true"}],
        }

    def _sns_list_topics(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Topics": [{"TopicArn": self._sns_arn()}]}

    def _sns_list_tags_for_resource(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Tags": [{"Key": "fixture", "Value": "true"}]}

    def _sns_get_topic_attributes(self, _: Dict[str, Any]) -> Dict[str, Any]:
        policy = (
            self._restricted_policy("sns:Publish")
            if self.healthy
            else self._public_policy("sns:Publish")
        )
        attributes = {"Policy": json.dumps(policy)}
        if self.healthy:
            attributes["KmsMasterKeyId"] = "alias/aws/sns"
        return {"Attributes": attributes}

    def _sqs_list_queues(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"QueueUrls": ["http://localhost:4566/000000000000/fixture-queue"]}

    def _sqs_list_queue_tags(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Tags": {"fixture": "true"}}

    def _sqs_get_queue_attributes(self, _: Dict[str, Any]) -> Dict[str, Any]:
        policy = (
            self._restricted_policy("sqs:SendMessage")
            if self.healthy
            else self._public_policy("sqs:SendMessage")
        )
        attributes = {
            "QueueArn": "arn:aws:sqs:us-east-1:123456789012:fixture-queue",
            "Policy": json.dumps(policy),
        }
        if self.healthy:
            attributes["SqsManagedSseEnabled"] = "true"
        return {"Attributes": attributes}

    def _apigateway_get_rest_apis(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"items": [{"id": "api123", "name": "fixture-api"}]}

    def _apigateway_get_tags(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"tags": {"fixture": "true"}}

    def _apigateway_get_stages(self, _: Dict[str, Any]) -> Dict[str, Any]:
        stage: Dict[str, Any] = {
            "stageName": "demo",
            "deploymentId": "deployment-1",
            "tracingEnabled": self.healthy,
            "methodSettings": {"*/*": {"loggingLevel": "ERROR"}} if self.healthy else {},
        }
        if self.healthy:
            stage["accessLogSettings"] = {
                "destinationArn": "arn:aws:logs:us-east-1:123456789012:log-group:fixture",
                "format": '{"requestId":"$context.requestId"}',
            }
        return {"item": [stage]}

    def _apigateway_get_resources(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "items": [
                {
                    "id": "root",
                    "path": "/",
                    "resourceMethods": {"GET": {}},
                }
            ]
        }

    def _apigateway_get_method(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"authorizationType": "AWS_IAM" if self.healthy else "NONE"}

    @staticmethod
    def _kms_arn() -> str:
        return "arn:aws:kms:us-east-1:123456789012:key/key-fixture"

    @staticmethod
    def _sns_arn() -> str:
        return "arn:aws:sns:us-east-1:123456789012:fixture-topic"

    @staticmethod
    def _public_policy(action: str) -> Dict[str, Any]:
        return {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "PublicFixture",
                "Effect": "Allow",
                "Principal": "*",
                "Action": action,
                "Resource": "*",
            },
        }

    @staticmethod
    def _restricted_policy(action: str) -> Dict[str, Any]:
        return {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "OwnerRestricted",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": action,
                "Resource": "*",
                "Condition": {"StringEquals": {"AWS:SourceOwner": "123456789012"}},
            },
        }


class DeniedKmsProvider(V050Provider):
    def _kms_get_key_rotation_status(self, _: Dict[str, Any]) -> Dict[str, Any]:
        raise AwsProviderError("denied", detail="AccessDenied")


class V050RuleTests(unittest.TestCase):
    def test_new_service_detectors_report_all_ten_positive_rules(self) -> None:
        provider = V050Provider()
        results = [
            scan_kms(provider, None, None, "us-east-1"),
            scan_secrets_manager(provider, None, None, "us-east-1"),
            scan_sns(provider, None, None, "us-east-1"),
            scan_sqs(provider, None, None, "us-east-1"),
            scan_api_gateway(provider, None, None, "us-east-1"),
        ]

        findings = [finding for result in results for finding in result.findings]
        self.assertEqual({finding.rule_short_id for finding in findings}, NEW_RULES)
        self.assertEqual(sum(result.summary["rules_evaluated"] for result in results), 10)
        serialized = json.dumps([finding.to_dict() for finding in findings], default=str)
        self.assertNotIn("SecretString", serialized)
        self.assertNotIn("Integration", serialized)
        self.assertNotIn('"Statement"', serialized)
        self.assertTrue(
            all(
                finding.evidence.get("policy_document_redacted") is True
                for finding in findings
                if "public-access" in finding.rule_short_id
            )
        )

    def test_healthy_controls_and_conditioned_public_principals_do_not_find(self) -> None:
        provider = V050Provider(healthy=True)
        results = [
            scan_kms(provider, None, None, "us-east-1"),
            scan_secrets_manager(provider, None, None, "us-east-1"),
            scan_sns(provider, None, None, "us-east-1"),
            scan_sqs(provider, None, None, "us-east-1"),
            scan_api_gateway(provider, None, None, "us-east-1"),
        ]

        self.assertEqual([finding for result in results for finding in result.findings], [])
        self.assertEqual(sum(result.summary["rules_evaluated"] for result in results), 10)

    def test_rule_filter_avoids_unrelated_api_gateway_calls(self) -> None:
        provider = V050Provider()
        result = scan_api_gateway(
            provider,
            None,
            None,
            "us-east-1",
            rule_filter="api-gateway-xray-tracing-disabled",
        )

        self.assertEqual(result.summary["rules_evaluated"], 1)
        self.assertEqual(
            provider.calls,
            ["apigateway.get_rest_apis", "apigateway.get_tags", "apigateway.get_stages"],
        )

    def test_permission_failure_marks_rule_skipped_instead_of_passing(self) -> None:
        result = scan_kms(DeniedKmsProvider(), None, None, "us-east-1")

        self.assertEqual(result.findings, [])
        self.assertEqual(result.summary["rules_evaluated"], 0)
        self.assertEqual(result.summary["rules_skipped"][0]["reason"], "aws_read_failed")
        self.assertEqual(
            result.summary["capability_errors"][0]["operation"], "kms.get_key_rotation_status"
        )


if __name__ == "__main__":
    unittest.main()
