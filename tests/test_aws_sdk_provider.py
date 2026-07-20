from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from typing import Any, Dict, List
from unittest.mock import patch

from bluearch_aws_steward.cli import _build_parser
from bluearch_aws_steward.mcp_server import StewardMcpServer, _provider_name, list_mcp_tools
from bluearch_aws_steward.providers.aws_sdk import AwsSdkError, AwsSdkProvider, AwsSdkProviderConfig
from bluearch_aws_steward.providers.factory import create_aws_provider, provider_dependency_status
from bluearch_aws_steward.providers.operations import READ_OPERATIONS


class FakeClientError(Exception):
    def __init__(self, code: str, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.response = {
            "Error": {"Code": code, "Message": message},
            "ResponseMetadata": {"HTTPStatusCode": status},
        }


class FakeStsClient:
    def get_caller_identity(self) -> Dict[str, Any]:
        return {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test"}


class FakePaginator:
    def __init__(self, pages: List[Dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self) -> List[Dict[str, Any]]:
        return self.pages


class ContractPaginator:
    def __init__(self, result_keys: tuple[str, ...]) -> None:
        self.result_keys = result_keys
        self.parameters: Dict[str, Any] = {}

    def paginate(self, **parameters: Any) -> List[Dict[str, Any]]:
        self.parameters = parameters
        return [{key: [{"page": page, "key": key}] for key in self.result_keys} for page in (1, 2)]


class ContractPaginatedClient:
    def __init__(self, service: str) -> None:
        self.service = service
        self.paginators: Dict[str, ContractPaginator] = {}

    def can_paginate(self, operation: str) -> bool:
        return True

    def get_paginator(self, operation: str) -> ContractPaginator:
        spec = next(
            candidate
            for candidate in READ_OPERATIONS.values()
            if candidate.service == self.service and candidate.sdk_operation == operation
        )
        paginator = ContractPaginator(spec.result_keys)
        self.paginators[operation] = paginator
        return paginator


class ContractPaginatedSession:
    def __init__(self) -> None:
        self.clients: Dict[str, ContractPaginatedClient] = {}

    def client(self, service: str, **_: Any) -> ContractPaginatedClient:
        return self.clients.setdefault(service, ContractPaginatedClient(service))


class FakeLogsClient:
    def __init__(self) -> None:
        self.writes: List[Dict[str, Any]] = []

    def can_paginate(self, operation: str) -> bool:
        return operation == "describe_log_groups"

    def get_paginator(self, operation: str) -> FakePaginator:
        return FakePaginator(
            [
                {
                    "logGroups": [
                        {
                            "logGroupName": "/aws/lambda/no-retention",
                            "arn": "arn:log-group:no-retention:*",
                            "storedBytes": 2048,
                            "creationTime": 1234,
                        }
                    ]
                },
                {
                    "logGroups": [
                        {
                            "logGroupName": "/aws/lambda/retained",
                            "retentionInDays": 30,
                            "storedBytes": 0,
                        }
                    ]
                },
            ]
        )

    def put_retention_policy(self, **kwargs: Any) -> Dict[str, Any]:
        self.writes.append(kwargs)
        return {}


class FakeEc2Client:
    def can_paginate(self, operation: str) -> bool:
        return operation == "describe_volumes"

    def get_paginator(self, operation: str) -> FakePaginator:
        return FakePaginator(
            [
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-002",
                            "State": "available",
                            "Size": 100,
                            "VolumeType": "gp3",
                            "AvailabilityZone": "us-east-1a",
                            "Encrypted": True,
                            "CreateTime": datetime(2026, 1, 2, tzinfo=timezone.utc),
                            "Attachments": [],
                            "Tags": [{"Key": "owner", "Value": "platform"}],
                        }
                    ]
                },
                {
                    "Volumes": [
                        {
                            "VolumeId": "vol-001",
                            "State": "in-use",
                            "Size": 20,
                            "VolumeType": "gp3",
                            "AvailabilityZone": "us-east-1b",
                            "Encrypted": True,
                            "Attachments": [{"InstanceId": "i-123", "State": "attached"}],
                        }
                    ]
                },
            ]
        )

    def describe_addresses(self) -> Dict[str, Any]:
        return {
            "Addresses": [
                {
                    "AllocationId": "eipalloc-002",
                    "PublicIp": "192.0.2.2",
                    "Domain": "vpc",
                },
                {
                    "AllocationId": "eipalloc-001",
                    "AssociationId": "eipassoc-001",
                    "PublicIp": "192.0.2.1",
                    "InstanceId": "i-123",
                    "NetworkInterfaceId": "eni-123",
                    "Domain": "vpc",
                    "Tags": [{"Key": "owner", "Value": "platform"}],
                },
            ]
        }


class FakeIamClient:
    def get_account_summary(self) -> Dict[str, Any]:
        return {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}


class FakeCloudTrailClient:
    def __init__(self) -> None:
        self.writes: List[Dict[str, Any]] = []

    def describe_trails(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "trailList": [
                {
                    "Name": "audit",
                    "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/audit",
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "kms-key",
                    "CloudWatchLogsLogGroupArn": "log-group",
                }
            ]
        }

    def get_trail_status(self, **kwargs: Any) -> Dict[str, Any]:
        return {"IsLogging": True, "LatestDeliveryTime": datetime(2026, 7, 1, tzinfo=timezone.utc)}

    def update_trail(self, **kwargs: Any) -> Dict[str, Any]:
        self.writes.append(kwargs)
        return {}


class FakeRdsClient:
    def can_paginate(self, operation: str) -> bool:
        return operation == "describe_db_instances"

    def get_paginator(self, operation: str) -> FakePaginator:
        return FakePaginator(
            [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "demo-db",
                            "Engine": "postgres",
                            "DBInstanceStatus": "available",
                            "PubliclyAccessible": False,
                            "StorageEncrypted": True,
                            "MultiAZ": True,
                            "StorageType": "gp3",
                            "TagList": [{"Key": "owner", "Value": "platform"}],
                        }
                    ]
                }
            ]
        )


class FakeLambdaClient:
    def can_paginate(self, operation: str) -> bool:
        return operation == "list_functions"

    def get_paginator(self, operation: str) -> FakePaginator:
        return FakePaginator(
            [
                {
                    "Functions": [
                        {
                            "FunctionName": "demo-function",
                            "Runtime": "python3.13",
                            "TracingConfig": {"Mode": "Active"},
                        }
                    ]
                }
            ]
        )


class FakeS3Client:
    def __init__(self) -> None:
        self.writes: List[tuple[str, Dict[str, Any]]] = []
        self.versioning_error: FakeClientError | None = None

    def list_buckets(self) -> Dict[str, Any]:
        return {"Buckets": [{"Name": "zeta"}, {"Name": "alpha"}]}

    def get_public_access_block(self, **kwargs: Any) -> Dict[str, Any]:
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}

    def get_bucket_policy(self, **kwargs: Any) -> Dict[str, Any]:
        return {"Policy": json.dumps({"Statement": [{"Effect": "Allow"}]})}

    def get_bucket_encryption(self, **kwargs: Any) -> Dict[str, Any]:
        return {"ServerSideEncryptionConfiguration": {"Rules": [{"enabled": True}]}}

    def get_bucket_lifecycle_configuration(self, **kwargs: Any) -> Dict[str, Any]:
        return {"Rules": [{"Status": "Enabled"}]}

    def get_bucket_versioning(self, **kwargs: Any) -> Dict[str, Any]:
        if self.versioning_error:
            raise self.versioning_error
        return {"Status": "Enabled"}

    def put_public_access_block(self, **kwargs: Any) -> Dict[str, Any]:
        self.writes.append(("put_public_access_block", kwargs))
        return {}

    def put_bucket_encryption(self, **kwargs: Any) -> Dict[str, Any]:
        self.writes.append(("put_bucket_encryption", kwargs))
        return {}

    def put_bucket_lifecycle_configuration(self, **kwargs: Any) -> Dict[str, Any]:
        self.writes.append(("put_bucket_lifecycle_configuration", kwargs))
        return {}

    def put_bucket_versioning(self, **kwargs: Any) -> Dict[str, Any]:
        self.writes.append(("put_bucket_versioning", kwargs))
        return {}


class MissingConfigS3Client(FakeS3Client):
    def get_public_access_block(self, **kwargs: Any) -> Dict[str, Any]:
        raise FakeClientError("NoSuchPublicAccessBlockConfiguration", "missing")

    def get_bucket_policy(self, **kwargs: Any) -> Dict[str, Any]:
        raise FakeClientError("NoSuchBucketPolicy", "missing")

    def get_bucket_encryption(self, **kwargs: Any) -> Dict[str, Any]:
        raise FakeClientError("ServerSideEncryptionConfigurationNotFoundError", "missing")

    def get_bucket_lifecycle_configuration(self, **kwargs: Any) -> Dict[str, Any]:
        raise FakeClientError("NoSuchLifecycleConfiguration", "missing")


class FakeSession:
    def __init__(self, s3: FakeS3Client) -> None:
        self.s3 = s3
        self.logs = FakeLogsClient()
        self.ec2 = FakeEc2Client()
        self.iam = FakeIamClient()
        self.cloudtrail = FakeCloudTrailClient()
        self.rds = FakeRdsClient()
        self.lambda_client = FakeLambdaClient()
        self.client_requests: List[tuple[str, Dict[str, Any]]] = []

    def client(self, service: str, **kwargs: Any) -> Any:
        self.client_requests.append((service, kwargs))
        return {
            "sts": FakeStsClient(),
            "s3": self.s3,
            "logs": self.logs,
            "ec2": self.ec2,
            "iam": self.iam,
            "cloudtrail": self.cloudtrail,
            "rds": self.rds,
            "lambda": self.lambda_client,
        }[service]


class AwsSdkProviderTests(unittest.TestCase):
    def _provider(self, s3: FakeS3Client) -> tuple[AwsSdkProvider, FakeSession]:
        session = FakeSession(s3)
        provider = AwsSdkProvider(
            AwsSdkProviderConfig(
                profile="test-profile",
                endpoint_url="http://localhost:4566",
                region="us-east-1",
            ),
            session=session,
        )
        return provider, session

    def test_normalizes_sdk_reads(self) -> None:
        provider, session = self._provider(FakeS3Client())

        self.assertEqual(provider.caller_identity()["Account"], "123456789012")
        self.assertEqual(provider.list_buckets(), ["alpha", "zeta"])
        self.assertEqual(provider.get_public_access_block("demo"), {"BlockPublicAcls": True})
        self.assertEqual(provider.get_bucket_policy("demo"), {"Statement": [{"Effect": "Allow"}]})
        self.assertEqual(provider.get_bucket_encryption_rules("demo"), [{"enabled": True}])
        self.assertEqual(provider.get_bucket_lifecycle_rules("demo"), [{"Status": "Enabled"}])
        self.assertEqual(provider.get_bucket_versioning_status("demo"), "Enabled")
        self.assertEqual(
            [group["name"] for group in provider.list_log_groups()],
            ["/aws/lambda/no-retention", "/aws/lambda/retained"],
        )
        volumes = provider.list_ebs_volumes()
        self.assertEqual([volume["volume_id"] for volume in volumes], ["vol-001", "vol-002"])
        self.assertEqual(volumes[1]["created_at"], "2026-01-02T00:00:00+00:00")
        self.assertEqual(volumes[1]["tags"], {"owner": "platform"})
        addresses = provider.list_elastic_ips()
        self.assertEqual(
            [address["allocation_id"] for address in addresses],
            ["eipalloc-001", "eipalloc-002"],
        )
        self.assertEqual(addresses[0]["association_id"], "eipassoc-001")
        self.assertEqual(addresses[0]["tags"], {"owner": "platform"})
        self.assertEqual(provider.get_iam_account_summary()["AccountMFAEnabled"], 1)
        trails = provider.list_cloudtrail_trails()
        self.assertEqual(trails[0]["name"], "audit")
        self.assertTrue(trails[0]["is_logging"])
        self.assertEqual(trails[0]["latest_delivery_time"], "2026-07-01T00:00:00+00:00")
        instances = provider.list_rds_instances()
        self.assertEqual(instances[0]["identifier"], "demo-db")
        self.assertEqual(instances[0]["tags"], {"owner": "platform"})
        functions = provider.list_lambda_functions()
        self.assertEqual(functions[0]["name"], "demo-function")
        self.assertEqual(functions[0]["tracing_mode"], "Active")
        self.assertEqual(
            session.client_requests,
            [
                ("sts", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
                ("s3", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
                ("logs", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
                ("ec2", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
                ("iam", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
                (
                    "cloudtrail",
                    {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"},
                ),
                ("rds", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
                ("lambda", {"region_name": "us-east-1", "endpoint_url": "http://localhost:4566"}),
            ],
        )

    def test_every_allowlisted_paginated_read_merges_all_pages(self) -> None:
        session = ContractPaginatedSession()
        provider = AwsSdkProvider(
            AwsSdkProviderConfig(region="us-east-1"),
            session=session,
        )

        paginated = [operation for operation in READ_OPERATIONS.values() if operation.paginated]
        self.assertTrue(paginated)
        for operation in paginated:
            with self.subTest(operation=operation.key):
                result = provider.read(operation.key, ContractMarker=operation.key)
                for result_key in operation.result_keys:
                    self.assertEqual(
                        result[result_key],
                        [
                            {"page": 1, "key": result_key},
                            {"page": 2, "key": result_key},
                        ],
                    )
                paginator = session.clients[operation.service].paginators[operation.sdk_operation]
                self.assertEqual(paginator.parameters, {"ContractMarker": operation.key})

    def test_expected_missing_configuration_errors_become_empty_state(self) -> None:
        provider, _ = self._provider(MissingConfigS3Client())

        self.assertEqual(provider.get_public_access_block("demo"), {})
        self.assertIsNone(provider.get_bucket_policy("demo"))
        self.assertEqual(provider.get_bucket_encryption_rules("demo"), [])
        self.assertEqual(provider.get_bucket_lifecycle_rules("demo"), [])

    def test_unexpected_sdk_error_is_normalized(self) -> None:
        s3 = FakeS3Client()
        s3.versioning_error = FakeClientError("AccessDenied", "not allowed", status=403)
        provider, _ = self._provider(s3)

        with self.assertRaises(AwsSdkError) as context:
            provider.get_bucket_versioning_status("demo")

        self.assertEqual(context.exception.code, "AccessDenied")
        self.assertEqual(context.exception.returncode, 403)
        self.assertEqual(context.exception.detail, "AccessDenied: not allowed")

    def test_missing_boto3_has_actionable_error(self) -> None:
        with patch(
            "bluearch_aws_steward.providers.aws_sdk.import_module",
            side_effect=ModuleNotFoundError("No module named 'boto3'"),
        ):
            with self.assertRaises(AwsSdkError) as context:
                AwsSdkProvider(AwsSdkProviderConfig())

        self.assertEqual(context.exception.code, "MissingDependency")
        self.assertIn("Reinstall BlueArch AWS Steward", context.exception.detail)

    def test_sdk_remediation_calls_use_structured_parameters(self) -> None:
        s3 = FakeS3Client()
        provider, _ = self._provider(s3)

        provider.put_public_access_block("demo")
        provider.put_default_encryption("demo")
        provider.put_lifecycle("demo", transition_days=90, storage_class="GLACIER_IR")
        provider.put_versioning("demo")
        provider.put_log_retention("/aws/lambda/demo", 30)
        provider.update_cloudtrail_log_file_validation("audit", enabled=True)

        self.assertEqual(
            [operation for operation, _ in s3.writes],
            [
                "put_public_access_block",
                "put_bucket_encryption",
                "put_bucket_lifecycle_configuration",
                "put_bucket_versioning",
            ],
        )
        self.assertTrue(s3.writes[0][1]["PublicAccessBlockConfiguration"]["RestrictPublicBuckets"])
        self.assertEqual(
            s3.writes[1][1]["ServerSideEncryptionConfiguration"]["Rules"][0][
                "ApplyServerSideEncryptionByDefault"
            ]["SSEAlgorithm"],
            "AES256",
        )
        lifecycle = s3.writes[2][1]["LifecycleConfiguration"]["Rules"][0]["Transitions"][0]
        self.assertEqual(lifecycle, {"Days": 90, "StorageClass": "GLACIER_IR"})
        self.assertEqual(
            provider._clients["logs"].writes,
            [{"logGroupName": "/aws/lambda/demo", "retentionInDays": 30}],
        )
        self.assertEqual(
            provider._clients["cloudtrail"].writes,
            [{"Name": "audit", "EnableLogFileValidation": True}],
        )


class ProviderSelectionTests(unittest.TestCase):
    def test_cli_and_mcp_expose_provider_selection(self) -> None:
        args = _build_parser().parse_args(
            [
                "scan",
                "aws",
                "--provider",
                "aws-sdk",
                "--service",
                "all",
                "--ebs-min-unattached-days",
                "30",
                "--exclude-tag",
                "owner=platform",
            ]
        )
        self.assertEqual(args.provider, "aws-sdk")
        self.assertEqual(args.service, "all")
        self.assertEqual(args.ebs_min_unattached_days, 30)
        self.assertEqual(args.exclude_tag, ["owner=platform"])

        tools = {tool["name"]: tool for tool in list_mcp_tools()}
        scan_provider = tools["bluearch_scan_aws"]["inputSchema"]["properties"]["provider"]
        doctor_provider = tools["bluearch_doctor"]["inputSchema"]["properties"]["provider"]
        self.assertEqual(scan_provider["enum"], ["aws-sdk", "aws-cli"])
        self.assertEqual(doctor_provider["default"], "aws-sdk")

    def test_factory_rejects_unknown_provider(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unsupported AWS provider"):
            create_aws_provider(provider="unknown")

        response = StewardMcpServer().handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "bluearch_doctor", "arguments": {"provider": "unknown"}},
            }
        )
        self.assertTrue(response["result"]["isError"])
        self.assertIn("Unsupported AWS provider", response["result"]["content"][0]["text"])

    def test_provider_selection_inherits_scan_metadata(self) -> None:
        self.assertEqual(_provider_name({"scan_result": {"provider": "aws-sdk"}}), "aws-sdk")
        self.assertEqual(
            _provider_name({"provider": "aws-cli", "scan_result": {"provider": "aws-sdk"}}),
            "aws-cli",
        )

    def test_sdk_dependency_check_is_safe_without_importing_boto3(self) -> None:
        status = provider_dependency_status("aws-sdk")
        self.assertEqual(status["name"], "boto3")
        self.assertIn("ok", status)


if __name__ == "__main__":
    unittest.main()
