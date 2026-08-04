from __future__ import annotations

import unittest

from bluearch_aws_steward.models import ResourceRef
from bluearch_aws_steward.relationships import (
    collect_live_relationships,
    relationship_collector_services,
)
from bluearch_aws_steward.scanner import AWS_SCAN_SERVICES


class _Provider:
    def __init__(self, responses: dict[str, dict]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, dict]] = []

    def read(self, operation: str, **parameters: object) -> dict:
        self.calls.append((operation, dict(parameters)))
        return self.responses.get(operation, {})


class RelationshipCollectorTests(unittest.TestCase):
    def test_every_runtime_scope_has_a_direct_collector(self) -> None:
        self.assertEqual(set(relationship_collector_services()), set(AWS_SCAN_SERVICES))

    def test_s3_relationships_are_exact_typed_and_redacted(self) -> None:
        provider = _Provider(
            {
                "s3.get_bucket_encryption": {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [
                            {
                                "ApplyServerSideEncryptionByDefault": {
                                    "SSEAlgorithm": "aws:kms",
                                    "KMSMasterKeyID": "arn:aws:kms:us-east-1:123456789012:key/key-1",
                                }
                            }
                        ]
                    }
                },
                "s3.get_bucket_logging": {"LoggingEnabled": {"TargetBucket": "audit-logs"}},
                "s3.get_bucket_replication": {
                    "ReplicationConfiguration": {
                        "Role": "arn:aws:iam::123456789012:role/replication",
                        "Rules": [{"Destination": {"Bucket": "arn:aws:s3:::replica-bucket"}}],
                    }
                },
            }
        )

        result = collect_live_relationships(
            provider,
            ResourceRef(
                provider="aws",
                service="s3",
                resource_type="aws.s3.bucket",
                resource_id="application-data",
                region="us-east-1",
                account_id="123456789012",
            ),
        )

        self.assertEqual(
            {item["relationship_type"] for item in result["relationships"]},
            {"encrypted_by", "logs_to", "assumes_role", "replicates_to"},
        )
        self.assertEqual(result["errors"], [])
        self.assertEqual(
            [parameters for _operation, parameters in provider.calls],
            [
                {"Bucket": "application-data"},
                {"Bucket": "application-data"},
                {"Bucket": "application-data"},
            ],
        )
        self.assertTrue(
            all(
                item["evidence_provenance"]["sensitive_values_included"] is False
                for item in result["relationships"]
            )
        )

    def test_lambda_relationships_do_not_include_environment_values(self) -> None:
        provider = _Provider(
            {
                "lambda.get_function_configuration": {
                    "Role": "arn:aws:iam::123456789012:role/function-role",
                    "VpcConfig": {
                        "SubnetIds": ["subnet-123"],
                        "SecurityGroupIds": ["sg-123"],
                    },
                    "Environment": {
                        "Variables": {"PASSWORD": "must-not-appear"}  # pragma: allowlist secret
                    },
                },
                "lambda.list_event_source_mappings": {
                    "EventSourceMappings": [
                        {"EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:events"}
                    ]
                },
            }
        )

        result = collect_live_relationships(
            provider,
            ResourceRef(
                provider="aws",
                service="lambda",
                resource_type="aws.lambda.function",
                resource_id="processor",
                region="us-east-1",
                account_id="123456789012",
            ),
        )

        rendered = str(result)
        self.assertNotIn("must-not-appear", rendered)
        self.assertEqual(
            {item["relationship_type"] for item in result["relationships"]},
            {"assumes_role", "protected_by", "deployed_in", "invoked_by"},
        )


if __name__ == "__main__":
    unittest.main()
