from __future__ import annotations

import unittest
from typing import Any, Dict, List

from bluearch_aws_steward.aws_cli import AwsCli, AwsCliConfig


class StubAwsCli(AwsCli):
    def __init__(self) -> None:
        super().__init__(AwsCliConfig(region="us-east-1"))
        self.commands: List[List[str]] = []

    def run_json(self, args: List[str], allow_error: bool = False) -> Dict[str, Any]:
        self.commands.append(args)
        if args == ["logs", "describe-log-groups"]:
            return {
                "logGroups": [
                    {
                        "logGroupName": "/aws/lambda/demo",
                        "retentionInDays": 30,
                        "storedBytes": 2048,
                        "creationTime": 1234,
                    }
                ]
            }
        if args == ["ec2", "describe-volumes"]:
            return {
                "Volumes": [
                    {
                        "VolumeId": "vol-123",
                        "State": "available",
                        "Size": 50,
                        "VolumeType": "gp3",
                        "AvailabilityZone": "us-east-1a",
                        "Encrypted": True,
                        "CreateTime": "2026-01-02T00:00:00+00:00",
                        "Attachments": [],
                        "Tags": [{"Key": "owner", "Value": "platform"}],
                    }
                ]
            }
        if args == ["ec2", "describe-addresses"]:
            return {
                "Addresses": [
                    {
                        "AllocationId": "eipalloc-123",
                        "PublicIp": "192.0.2.10",
                        "Domain": "vpc",
                        "Tags": [{"Key": "owner", "Value": "platform"}],
                    }
                ]
            }
        if args == ["iam", "get-account-summary"]:
            return {"SummaryMap": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0}}
        if args == ["cloudtrail", "describe-trails", "--no-include-shadow-trails"]:
            return {
                "trailList": [
                    {
                        "Name": "audit",
                        "TrailARN": "trail-arn",
                        "HomeRegion": "us-east-1",
                        "IsMultiRegionTrail": True,
                        "LogFileValidationEnabled": True,
                    }
                ]
            }
        if args == ["cloudtrail", "get-trail-status", "--name", "trail-arn"]:
            return {"IsLogging": True}
        if args == ["rds", "describe-db-instances"]:
            return {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "demo-db",
                        "PubliclyAccessible": False,
                        "StorageEncrypted": True,
                        "MultiAZ": True,
                        "StorageType": "gp3",
                    }
                ]
            }
        if args == ["lambda", "list-functions"]:
            return {
                "Functions": [
                    {
                        "FunctionName": "demo-function",
                        "TracingConfig": {"Mode": "Active"},
                    }
                ]
            }
        raise AssertionError(f"Unexpected AWS CLI command: {args}")

    def run_no_output(self, args: List[str]) -> None:
        self.commands.append(args)


class AwsCliMultiServiceProviderTests(unittest.TestCase):
    def test_normalizes_supported_service_inventory(self) -> None:
        provider = StubAwsCli()

        groups = provider.list_log_groups()
        volumes = provider.list_ebs_volumes()
        addresses = provider.list_elastic_ips()
        account_summary = provider.get_iam_account_summary()
        trails = provider.list_cloudtrail_trails()
        instances = provider.list_rds_instances()
        functions = provider.list_lambda_functions()

        self.assertEqual(groups[0]["name"], "/aws/lambda/demo")
        self.assertEqual(groups[0]["retention_days"], 30)
        self.assertEqual(volumes[0]["volume_id"], "vol-123")
        self.assertEqual(volumes[0]["attachments"], [])
        self.assertEqual(volumes[0]["tags"], {"owner": "platform"})
        self.assertEqual(addresses[0]["allocation_id"], "eipalloc-123")
        self.assertEqual(addresses[0]["tags"], {"owner": "platform"})
        self.assertEqual(account_summary["AccountMFAEnabled"], 1)
        self.assertTrue(trails[0]["is_logging"])
        self.assertEqual(instances[0]["identifier"], "demo-db")
        self.assertEqual(functions[0]["name"], "demo-function")
        self.assertEqual(
            provider.commands,
            [
                ["logs", "describe-log-groups"],
                ["ec2", "describe-volumes"],
                ["ec2", "describe-addresses"],
                ["iam", "get-account-summary"],
                ["cloudtrail", "describe-trails", "--no-include-shadow-trails"],
                ["cloudtrail", "get-trail-status", "--name", "trail-arn"],
                ["rds", "describe-db-instances"],
                ["lambda", "list-functions"],
            ],
        )

    def test_guarded_write_methods_build_explicit_cli_arguments(self) -> None:
        provider = StubAwsCli()

        provider.put_lifecycle("demo", transition_days=90, storage_class="GLACIER_IR")
        provider.put_log_retention("/aws/lambda/demo", 30)
        provider.update_cloudtrail_log_file_validation("audit", enabled=True)

        lifecycle = provider.commands[0]
        self.assertEqual(
            lifecycle[:4], ["s3api", "put-bucket-lifecycle-configuration", "--bucket", "demo"]
        )
        configuration = lifecycle[lifecycle.index("--lifecycle-configuration") + 1]
        self.assertIn('"Days":90', configuration)
        self.assertIn('"StorageClass":"GLACIER_IR"', configuration)
        self.assertEqual(
            provider.commands[1],
            [
                "logs",
                "put-retention-policy",
                "--log-group-name",
                "/aws/lambda/demo",
                "--retention-in-days",
                "30",
            ],
        )
        self.assertEqual(
            provider.commands[2],
            ["cloudtrail", "update-trail", "--name", "audit", "--enable-log-file-validation"],
        )


if __name__ == "__main__":
    unittest.main()
