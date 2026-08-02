#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bluearch_aws_steward.aws_endpoints import is_loopback_aws_endpoint  # noqa: E402

ACCOUNT_ID = "000000000000"
REGION = "us-east-1"
FIXTURE_TAG = "bluearch-steward-fixture"
BUSYBOX_IMAGE = (
    "public.ecr.aws/docker/library/busybox@sha256:"
    "b7f3d86d6e84fc17718c48bcde1450807faa2d56704205c697b4bd5df7b9e29f"  # pragma: allowlist secret
)


class FixtureError(RuntimeError):
    pass


class ExtendedFixtures:
    def __init__(self, endpoint_url: str, region: str, prefix: str) -> None:
        if not is_loopback_aws_endpoint(endpoint_url):
            raise FixtureError("AWS emulator fixtures require an explicit loopback endpoint")
        self.endpoint_url = endpoint_url
        self.region = region
        self.prefix = prefix
        self.artifact_dir = Path(__file__).resolve().parents[1] / ".artifacts"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.session = boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",  # pragma: allowlist secret
            aws_session_token="test",
            region_name=region,
        )
        self._clients: Dict[str, Any] = {}

    def client(self, service: str) -> Any:
        if service not in self._clients:
            self._clients[service] = self.session.client(
                service,
                endpoint_url=self.endpoint_url,
                region_name=self.region,
            )
        return self._clients[service]

    @property
    def safe_lambda_role(self) -> str:
        return f"{self.prefix}-lambda-role"

    @property
    def admin_lambda_role(self) -> str:
        return f"{self.prefix}-lambda-admin-role"

    @property
    def iam_user(self) -> str:
        return f"{self.prefix}-iam-console-admin"

    @property
    def cloudtrail_name(self) -> str:
        return f"{self.prefix}-trail"

    @property
    def rds_identifier(self) -> str:
        return f"{self.prefix}-rds"

    @property
    def high_cpu_rds_identifier(self) -> str:
        return f"{self.prefix}-rds-high-cpu"

    @property
    def ecs_cluster(self) -> str:
        return f"{self.prefix}-cluster"

    @property
    def ecs_family(self) -> str:
        return f"{self.prefix}-unsafe"

    @property
    def ecs_service(self) -> str:
        return f"{self.prefix}-outdated"

    @property
    def ecs_healthy_family(self) -> str:
        return f"{self.prefix}-healthy"

    @property
    def ecs_healthy_service(self) -> str:
        return f"{self.prefix}-healthy"

    @property
    def admin_lambda(self) -> str:
        return f"{self.prefix}-admin-role"

    @property
    def unused_lambda(self) -> str:
        return f"{self.prefix}-unused"

    @property
    def high_error_lambda(self) -> str:
        return f"{self.prefix}-high-error"

    @property
    def wildcard_role(self) -> str:
        return f"{self.prefix}-wildcard-trust"

    @property
    def dynamodb_inactive_table(self) -> str:
        return f"{self.prefix}-ddb-inactive"

    @property
    def dynamodb_provisioned_table(self) -> str:
        return f"{self.prefix}-ddb-provisioned-low"

    @property
    def dynamodb_infrequent_table(self) -> str:
        return f"{self.prefix}-ddb-infrequent"

    @property
    def http_alb(self) -> str:
        return f"{self.prefix}-http"

    @property
    def tls_alb(self) -> str:
        return f"{self.prefix}-tls"

    @property
    def http_target_group(self) -> str:
        return f"{self.prefix}-http-tg"

    @property
    def tls_target_group(self) -> str:
        return f"{self.prefix}-tls-tg"

    @property
    def secret_name(self) -> str:
        return f"{self.prefix}-secret-no-rotation"

    @property
    def sns_topic(self) -> str:
        return f"{self.prefix}-topic-public-unencrypted"

    @property
    def sqs_queue(self) -> str:
        return f"{self.prefix}-queue-public-unencrypted"

    @property
    def api_name(self) -> str:
        return f"{self.prefix}-api-no-controls"

    @property
    def api_stage(self) -> str:
        return "fixture"

    def seed(self) -> None:
        self._seed_s3_controls()
        self._seed_iam()
        self._seed_cloudtrail()
        self._seed_rds()
        self._seed_dynamodb()
        self._seed_efs()
        network = self._seed_ec2()
        self._seed_lambda()
        self._seed_ecs(network)
        self._seed_alb(network)
        self._seed_kms()
        self._seed_secrets_manager()
        self._seed_sns()
        self._seed_sqs()
        self._seed_api_gateway()

    def reset(self) -> None:
        self._reset_api_gateway()
        self._reset_sqs()
        self._reset_sns()
        self._reset_secrets_manager()
        self._reset_kms()
        self._reset_alb()
        self._reset_ecs()
        self._reset_lambda()
        self._reset_ec2()
        self._reset_efs()
        self._reset_rds()
        self._reset_dynamodb()
        self._reset_cloudtrail()
        self._reset_iam()
        self._reset_s3_controls()

    def assert_state(self) -> None:
        self._assert_s3()
        self._assert_iam()
        self._assert_cloudtrail()
        self._assert_rds()
        self._assert_dynamodb()
        self._assert_efs()
        self._assert_ec2()
        self._assert_lambda()
        self._assert_ecs()
        self._assert_alb()
        self._assert_kms()
        self._assert_secrets_manager()
        self._assert_sns()
        self._assert_sqs()
        self._assert_api_gateway()

    def _seed_s3_controls(self) -> None:
        s3 = self.client("s3")
        logging_disabled = f"{self.prefix}-server-logging-disabled"
        secure_bucket = f"{self.prefix}-secure"
        existing = {item["Name"] for item in s3.list_buckets().get("Buckets", [])}
        if logging_disabled not in existing:
            parameters: Dict[str, Any] = {"Bucket": logging_disabled}
            if self.region != "us-east-1":
                parameters["CreateBucketConfiguration"] = {"LocationConstraint": self.region}
            s3.create_bucket(**parameters)
        s3.put_public_access_block(
            Bucket=logging_disabled,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_bucket_encryption(
            Bucket=logging_disabled,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )
        s3.put_bucket_lifecycle_configuration(
            Bucket=logging_disabled,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "transition-old-objects",
                        "Status": "Enabled",
                        "Filter": {"Prefix": ""},
                        "Transitions": [{"Days": 30, "StorageClass": "STANDARD_IA"}],
                    }
                ]
            },
        )
        s3.put_bucket_versioning(
            Bucket=logging_disabled,
            VersioningConfiguration={"Status": "Enabled"},
        )
        s3.put_bucket_policy(
            Bucket=logging_disabled,
            Policy=json.dumps(_cloudtrail_tls_policy(logging_disabled)),
        )
        s3.put_bucket_logging(Bucket=logging_disabled, BucketLoggingStatus={})
        s3.put_bucket_tagging(
            Bucket=logging_disabled,
            Tagging={
                "TagSet": [
                    {"Key": FIXTURE_TAG, "Value": "s3-expanded-controls"},
                    {"Key": "bluearch:object-lock-required", "Value": "true"},
                    {"Key": "bluearch:replication-required", "Value": "true"},
                    {"Key": "bluearch:kms-required", "Value": "true"},
                ]
            },
        )

        fixture_buckets = sorted(
            bucket
            for bucket in {item["Name"] for item in s3.list_buckets().get("Buckets", [])}
            if bucket.startswith(self.prefix + "-") and bucket != logging_disabled
        )
        for bucket in fixture_buckets:
            s3.put_bucket_logging(
                Bucket=bucket,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": secure_bucket,
                        "TargetPrefix": f"access-logs/{bucket}/",
                    }
                },
            )

    def _seed_iam(self) -> None:
        iam = self.client("iam")
        iam.create_user(
            UserName=self.iam_user,
            Tags=[{"Key": FIXTURE_TAG, "Value": "iam-console-admin-old-key"}],
        )
        iam.create_login_profile(
            UserName=self.iam_user,
            Password=secrets.token_urlsafe(24) + "Aa1!",
            PasswordResetRequired=True,
        )
        iam.put_user_policy(
            UserName=self.iam_user,
            PolicyName=f"{self.prefix}-full-admin",
            PolicyDocument=json.dumps(_full_admin_policy()),
        )
        iam.create_access_key(UserName=self.iam_user)
        iam.create_role(
            RoleName=self.wildcard_role,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "*"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            Tags=[{"Key": FIXTURE_TAG, "Value": "iam-wildcard-trust"}],
        )

    def _seed_cloudtrail(self) -> None:
        cloudtrail = self.client("cloudtrail")
        cloudtrail.create_trail(
            Name=self.cloudtrail_name,
            S3BucketName=f"{self.prefix}-secure",
            IncludeGlobalServiceEvents=True,
            IsMultiRegionTrail=False,
            EnableLogFileValidation=False,
        )
        cloudtrail.start_logging(Name=self.cloudtrail_name)

    def _seed_rds(self) -> None:
        rds = self.client("rds")
        rds.create_db_instance(
            DBInstanceIdentifier=self.rds_identifier,
            DBInstanceClass="db.m3.medium",
            Engine="mysql",
            MasterUsername="fixture",
            MasterUserPassword=secrets.token_urlsafe(24) + "Aa1!",
            AllocatedStorage=20,
            StorageType="gp2",
            PubliclyAccessible=True,
            StorageEncrypted=False,
            MultiAZ=False,
            Tags=[{"Key": FIXTURE_TAG, "Value": "rds-risky-idle"}],
        )
        self._put_daily_metrics(
            "AWS/RDS",
            [
                {
                    "MetricName": "DatabaseConnections",
                    "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": self.rds_identifier}],
                    "Value": 0.0,
                    "Unit": "Count",
                },
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": self.rds_identifier}],
                    "Value": 2.0,
                    "Unit": "Percent",
                },
                {
                    "MetricName": "ReadIOPS",
                    "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": self.rds_identifier}],
                    "Value": 200.0,
                    "Unit": "Count/Second",
                },
                {
                    "MetricName": "WriteIOPS",
                    "Dimensions": [{"Name": "DBInstanceIdentifier", "Value": self.rds_identifier}],
                    "Value": 10.0,
                    "Unit": "Count/Second",
                },
            ],
            days=7,
        )
        rds.create_db_instance(
            DBInstanceIdentifier=self.high_cpu_rds_identifier,
            DBInstanceClass="db.t3.micro",
            Engine="mysql",
            MasterUsername="fixture",
            MasterUserPassword=secrets.token_urlsafe(24) + "Aa1!",
            AllocatedStorage=20,
            StorageType="gp3",
            PubliclyAccessible=False,
            StorageEncrypted=False,
            MultiAZ=False,
            Tags=[{"Key": FIXTURE_TAG, "Value": "rds-high-cpu"}],
        )
        self._put_daily_metrics(
            "AWS/RDS",
            [
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [
                        {"Name": "DBInstanceIdentifier", "Value": self.high_cpu_rds_identifier}
                    ],
                    "Value": 98.0,
                    "Unit": "Percent",
                },
                {
                    "MetricName": "ReadIOPS",
                    "Dimensions": [
                        {"Name": "DBInstanceIdentifier", "Value": self.high_cpu_rds_identifier}
                    ],
                    "Value": 20.0,
                    "Unit": "Count/Second",
                },
                {
                    "MetricName": "WriteIOPS",
                    "Dimensions": [
                        {"Name": "DBInstanceIdentifier", "Value": self.high_cpu_rds_identifier}
                    ],
                    "Value": 20.0,
                    "Unit": "Count/Second",
                },
            ],
            days=7,
        )

    def _seed_dynamodb(self) -> None:
        dynamodb = self.client("dynamodb")
        for table_name, billing_mode in (
            (self.dynamodb_inactive_table, "PAY_PER_REQUEST"),
            (self.dynamodb_infrequent_table, "PAY_PER_REQUEST"),
            (self.dynamodb_provisioned_table, "PROVISIONED"),
        ):
            parameters: Dict[str, Any] = {
                "TableName": table_name,
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "BillingMode": billing_mode,
                "Tags": [{"Key": FIXTURE_TAG, "Value": table_name}],
            }
            if billing_mode == "PROVISIONED":
                parameters["ProvisionedThroughput"] = {
                    "ReadCapacityUnits": 10,
                    "WriteCapacityUnits": 10,
                }
            dynamodb.create_table(**parameters)
        dynamodb.tag_resource(
            ResourceArn=dynamodb.describe_table(TableName=self.dynamodb_infrequent_table)["Table"][
                "TableArn"
            ],
            Tags=[{"Key": "bluearch:infrequent-access", "Value": "true"}],
        )
        self._put_daily_metrics(
            "AWS/DynamoDB",
            [
                {
                    "MetricName": metric,
                    "Dimensions": [{"Name": "TableName", "Value": table}],
                    "Value": value,
                    "Unit": "Count",
                }
                for table, value in (
                    (self.dynamodb_inactive_table, 0.0),
                    (self.dynamodb_infrequent_table, 25.0),
                    (self.dynamodb_provisioned_table, 1000.0),
                )
                for metric in ("ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits")
            ],
            days=30,
        )

    def _seed_efs(self) -> None:
        efs = self.client("efs")
        file_system = efs.create_file_system(
            CreationToken=f"{self.prefix}-efs",
            Encrypted=False,
            Tags=[
                {"Key": "Name", "Value": f"{self.prefix}-efs"},
                {"Key": FIXTURE_TAG, "Value": "efs-unencrypted-no-lifecycle"},
                {"Key": "bluearch:customer-kms-required", "Value": "true"},
            ],
        )
        provisioned = efs.create_file_system(
            CreationToken=f"{self.prefix}-efs-provisioned",
            Encrypted=False,
            ThroughputMode="provisioned",
            ProvisionedThroughputInMibps=1.0,
            Tags=[
                {"Key": "Name", "Value": f"{self.prefix}-efs-provisioned"},
                {"Key": FIXTURE_TAG, "Value": "efs-throughput-overprovisioned"},
            ],
        )
        self._put_daily_metrics(
            "AWS/EFS",
            [
                {
                    "MetricName": "ClientConnections",
                    "Dimensions": [{"Name": "FileSystemId", "Value": file_system["FileSystemId"]}],
                    "Value": 0.0,
                    "Unit": "Count",
                },
                {
                    "MetricName": "PercentIOLimit",
                    "Dimensions": [{"Name": "FileSystemId", "Value": provisioned["FileSystemId"]}],
                    "Value": 5.0,
                    "Unit": "Percent",
                },
            ],
            days=30,
        )

    def _network(self) -> Dict[str, Any]:
        ec2 = self.client("ec2")
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "is-default", "Values": ["true"]}]).get(
            "Vpcs", []
        )
        if not vpcs:
            raise FixtureError("LocalEmu did not provide a default VPC")
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get(
            "Subnets", []
        )
        if len(subnets) < 2:
            raise FixtureError("LocalEmu did not provide two default subnets")
        default_groups = ec2.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ]
        ).get("SecurityGroups", [])
        if not default_groups:
            raise FixtureError("LocalEmu did not provide a default security group")
        return {
            "vpc_id": vpc_id,
            "subnet_ids": [item["SubnetId"] for item in subnets[:2]],
            "default_security_group_id": default_groups[0]["GroupId"],
        }

    def _seed_ec2(self) -> Dict[str, Any]:
        ec2 = self.client("ec2")
        network = self._network()
        group = ec2.create_security_group(
            GroupName=f"{self.prefix}-open-admin",
            Description="BlueArch Steward fixture only",
            VpcId=network["vpc_id"],
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [{"Key": FIXTURE_TAG, "Value": "ec2-open-admin-high-count"}],
                }
            ],
        )
        group_id = group["GroupId"]
        unused_group = ec2.create_security_group(
            GroupName=f"{self.prefix}-unused",
            Description="BlueArch Steward unused security-group fixture",
            VpcId=network["vpc_id"],
            TagSpecifications=[
                {
                    "ResourceType": "security-group",
                    "Tags": [{"Key": FIXTURE_TAG, "Value": "ec2-unused-security-group"}],
                }
            ],
        )
        ec2.authorize_security_group_ingress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 10000,
                    "ToPort": 10000,
                    "IpRanges": [{"CidrIp": f"192.0.2.{index}/32"} for index in range(1, 52)],
                },
            ],
        )
        instances = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="t3.micro",
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": network["subnet_ids"][0],
                    "Groups": [group_id],
                    "DeleteOnTermination": True,
                }
            ],
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "VolumeSize": 8,
                        "VolumeType": "gp3",
                        "Encrypted": True,
                        "DeleteOnTermination": False,
                    },
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"{self.prefix}-idle"},
                        {"Key": FIXTURE_TAG, "Value": "ec2-idle-delete-disabled"},
                    ],
                },
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": FIXTURE_TAG, "Value": "ec2-instance-root-delete-disabled"}],
                },
            ],
        )["Instances"]
        instance_id = instances[0]["InstanceId"]
        high_cpu_instance = ec2.run_instances(
            ImageId="ami-12345678",
            InstanceType="m3.medium",
            MinCount=1,
            MaxCount=1,
            NetworkInterfaces=[
                {
                    "DeviceIndex": 0,
                    "SubnetId": network["subnet_ids"][0],
                    "Groups": [group_id],
                    "DeleteOnTermination": True,
                }
            ],
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "Name", "Value": f"{self.prefix}-high-cpu-old-dev"},
                        {"Key": "environment", "Value": "dev"},
                        {"Key": FIXTURE_TAG, "Value": "ec2-high-cpu-old-dev"},
                    ],
                }
            ],
        )["Instances"][0]
        high_cpu_instance_id = high_cpu_instance["InstanceId"]
        self._put_daily_metrics(
            "AWS/EC2",
            [
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    "Value": 0.0,
                    "Unit": "Percent",
                },
                {
                    "MetricName": "NetworkIn",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    "Value": 0.0,
                    "Unit": "Bytes",
                },
                {
                    "MetricName": "NetworkOut",
                    "Dimensions": [{"Name": "InstanceId", "Value": instance_id}],
                    "Value": 0.0,
                    "Unit": "Bytes",
                },
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": [{"Name": "InstanceId", "Value": high_cpu_instance_id}],
                    "Value": 98.0,
                    "Unit": "Percent",
                },
            ],
            days=14,
        )

        magnetic = ec2.create_volume(
            AvailabilityZone=f"{self.region}a",
            Size=1,
            VolumeType="standard",
            Encrypted=False,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": FIXTURE_TAG, "Value": "ebs-magnetic-overutilized"}],
                }
            ],
        )
        self._wait_for(
            lambda: (
                ec2.describe_volumes(VolumeIds=[magnetic["VolumeId"]])["Volumes"][0]["State"]
                == "available"
            ),
            "magnetic volume",
        )
        gp2_volumes = ec2.describe_volumes(
            Filters=[
                {
                    "Name": f"tag:{FIXTURE_TAG}",
                    "Values": ["ec2-unencrypted-unattached"],
                }
            ]
        ).get("Volumes", [])
        if not gp2_volumes:
            raise FixtureError("Base gp2 fixture volume was not found")
        volume_metrics: List[Dict[str, Any]] = []
        for volume_id, iops in (
            (magnetic["VolumeId"], 120.0),
            (gp2_volumes[0]["VolumeId"], 100.0),
        ):
            volume_metrics.extend(
                [
                    {
                        "MetricName": "VolumeReadOps",
                        "Dimensions": [{"Name": "VolumeId", "Value": volume_id}],
                        "Value": iops * 86400.0,
                        "Unit": "Count",
                    },
                    {
                        "MetricName": "VolumeWriteOps",
                        "Dimensions": [{"Name": "VolumeId", "Value": volume_id}],
                        "Value": 0.0,
                        "Unit": "Count",
                    },
                ]
            )
        self._put_daily_metrics("AWS/EBS", volume_metrics, days=7)

        volume = ec2.create_volume(
            AvailabilityZone=f"{self.region}a",
            Size=1,
            VolumeType="gp3",
            Encrypted=True,
            TagSpecifications=[
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": FIXTURE_TAG, "Value": "ebs-orphan-source"}],
                }
            ],
        )
        volume_id = volume["VolumeId"]
        self._wait_for(
            lambda: (
                ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"] == "available"
            ),
            "orphan-source volume",
        )
        snapshot = ec2.create_snapshot(
            VolumeId=volume_id,
            Description=f"{self.prefix}-fixture-orphaned-snapshot",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": FIXTURE_TAG, "Value": "ebs-orphaned-snapshot"}],
                }
            ],
        )
        snapshot_id = snapshot["SnapshotId"]
        self._wait_for(
            lambda: (
                ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"]
                == "completed"
            ),
            "orphan snapshot",
        )
        ec2.delete_volume(VolumeId=volume_id)
        network.update(
            {
                "fixture_security_group_id": group_id,
                "fixture_instance_id": instance_id,
                "fixture_high_cpu_instance_id": high_cpu_instance_id,
                "fixture_snapshot_id": snapshot_id,
                "fixture_unused_security_group_id": unused_group["GroupId"],
                "fixture_magnetic_volume_id": magnetic["VolumeId"],
            }
        )
        return network

    def _seed_lambda(self) -> None:
        iam = self.client("iam")
        lambda_client = self.client("lambda")
        assume_role = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        admin_role = iam.create_role(
            RoleName=self.admin_lambda_role,
            AssumeRolePolicyDocument=json.dumps(assume_role),
            Tags=[{"Key": FIXTURE_TAG, "Value": "lambda-admin-role"}],
        )["Role"]
        iam.put_role_policy(
            RoleName=self.admin_lambda_role,
            PolicyName=f"{self.prefix}-lambda-full-admin",
            PolicyDocument=json.dumps(_full_admin_policy()),
        )
        safe_role = iam.get_role(RoleName=self.safe_lambda_role)["Role"]
        archive = (self.artifact_dir / "lambda-fixture.zip").read_bytes()
        published_versions: Dict[str, str] = {}
        for name, role_arn in (
            (self.admin_lambda, admin_role["Arn"]),
            (self.unused_lambda, safe_role["Arn"]),
            (self.high_error_lambda, safe_role["Arn"]),
        ):
            created = lambda_client.create_function(
                FunctionName=name,
                Runtime="python3.11",
                Role=role_arn,
                Handler="lambda_function.handler",
                Code={"ZipFile": archive},
                TracingConfig={"Mode": "Active"},
                Timeout=3,
                MemorySize=128,
                Publish=name == self.unused_lambda,
                Tags={FIXTURE_TAG: name},
            )
            if name == self.unused_lambda:
                published_versions[name] = str(created.get("Version") or "1")
        self._wait_for(
            lambda: self._published_lambda_is_active(
                self.unused_lambda,
                published_versions[self.unused_lambda],
            ),
            "published Lambda fixture version",
        )
        lambda_client.put_provisioned_concurrency_config(
            FunctionName=self.unused_lambda,
            Qualifier=published_versions[self.unused_lambda],
            ProvisionedConcurrentExecutions=1,
        )
        self._put_daily_metrics(
            "AWS/Lambda",
            [
                {
                    "MetricName": "Invocations",
                    "Dimensions": [{"Name": "FunctionName", "Value": self.unused_lambda}],
                    "Value": 0.0,
                    "Unit": "Count",
                },
                {
                    "MetricName": "Invocations",
                    "Dimensions": [{"Name": "FunctionName", "Value": self.high_error_lambda}],
                    "Value": 10.0,
                    "Unit": "Count",
                },
                {
                    "MetricName": "Errors",
                    "Dimensions": [{"Name": "FunctionName", "Value": self.high_error_lambda}],
                    "Value": 2.0,
                    "Unit": "Count",
                },
                {
                    "MetricName": "Duration",
                    "Dimensions": [{"Name": "FunctionName", "Value": self.high_error_lambda}],
                    "Value": 2900.0,
                    "Unit": "Milliseconds",
                },
                {
                    "MetricName": "Throttles",
                    "Dimensions": [{"Name": "FunctionName", "Value": self.high_error_lambda}],
                    "Value": 1.0,
                    "Unit": "Count",
                },
            ],
            days=30,
        )
        self._put_daily_metrics(
            "LambdaInsights",
            [
                {
                    "MetricName": "memory_utilization",
                    "Dimensions": [{"Name": "function_name", "Value": self.unused_lambda}],
                    "Value": 10.0,
                    "Unit": "Percent",
                },
                {
                    "MetricName": "memory_utilization",
                    "Dimensions": [{"Name": "function_name", "Value": self.high_error_lambda}],
                    "Value": 95.0,
                    "Unit": "Percent",
                },
            ],
            days=7,
        )

    def _seed_ecs(self, network: Dict[str, Any]) -> None:
        ecs = self.client("ecs")
        task = ecs.register_task_definition(
            family=self.ecs_family,
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "fixture",
                    "image": BUSYBOX_IMAGE,
                    "essential": True,
                    "privileged": True,
                    "environment": [{"name": "API_TOKEN", "value": "fixture-only-value"}],
                }
            ],
            tags=[{"key": FIXTURE_TAG, "value": "ecs-unsafe"}],
        )["taskDefinition"]
        ecs.create_cluster(
            clusterName=self.ecs_cluster,
            tags=[{"key": FIXTURE_TAG, "value": "ecs-outdated"}],
        )
        ecs.create_service(
            cluster=self.ecs_cluster,
            serviceName=self.ecs_service,
            taskDefinition=task["taskDefinitionArn"],
            desiredCount=1,
            launchType="FARGATE",
            platformVersion="1.3.0",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [network["subnet_ids"][0]],
                    "securityGroups": [network["default_security_group_id"]],
                    "assignPublicIp": "DISABLED",
                }
            },
            tags=[{"key": FIXTURE_TAG, "value": "ecs-outdated"}],
        )
        healthy_task = ecs.register_task_definition(
            family=self.ecs_healthy_family,
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "healthy-fixture",
                    "image": BUSYBOX_IMAGE,
                    "command": ["sh", "-c", "sleep 3600"],
                    "essential": True,
                    "privileged": False,
                }
            ],
            tags=[{"key": FIXTURE_TAG, "value": "ecs-healthy"}],
        )["taskDefinition"]
        ecs.create_service(
            cluster=self.ecs_cluster,
            serviceName=self.ecs_healthy_service,
            taskDefinition=healthy_task["taskDefinitionArn"],
            desiredCount=1,
            launchType="FARGATE",
            platformVersion="LATEST",
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [network["subnet_ids"][0]],
                    "securityGroups": [network["default_security_group_id"]],
                    "assignPublicIp": "DISABLED",
                }
            },
            tags=[{"key": FIXTURE_TAG, "value": "ecs-healthy"}],
        )
        self._wait_for(
            lambda: self._ecs_task_is_running(self.ecs_healthy_family),
            "healthy ECS service task",
            timeout=45,
        )
        inactive = ecs.register_task_definition(
            family=f"{self.ecs_family}-inactive",
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            cpu="256",
            memory="512",
            containerDefinitions=[
                {
                    "name": "inactive-fixture",
                    "image": BUSYBOX_IMAGE,
                    "essential": True,
                }
            ],
            tags=[{"key": FIXTURE_TAG, "value": "ecs-inactive"}],
        )["taskDefinition"]
        ecs.deregister_task_definition(taskDefinition=inactive["taskDefinitionArn"])

    def _seed_alb(self, network: Dict[str, Any]) -> None:
        elbv2 = self.client("elbv2")
        acm = self.client("acm")
        load_balancers: Dict[str, Dict[str, Any]] = {}
        for name in (self.http_alb, self.tls_alb):
            load_balancers[name] = elbv2.create_load_balancer(
                Name=name,
                Subnets=network["subnet_ids"],
                SecurityGroups=[network["fixture_security_group_id"]],
                Scheme="internet-facing",
                Type="application",
                Tags=[{"Key": FIXTURE_TAG, "Value": name}],
            )["LoadBalancers"][0]

        target_groups: Dict[str, Dict[str, Any]] = {}
        for name, port in (
            (self.http_target_group, 6553),
            (self.tls_target_group, 6554),
        ):
            target_groups[name] = elbv2.create_target_group(
                Name=name,
                Protocol="HTTP",
                Port=port,
                VpcId=network["vpc_id"],
                TargetType="ip",
                HealthCheckProtocol="TCP",
                HealthCheckPort="traffic-port",
                Tags=[{"Key": FIXTURE_TAG, "Value": name}],
            )["TargetGroups"][0]
            elbv2.register_targets(
                TargetGroupArn=target_groups[name]["TargetGroupArn"],
                Targets=[{"Id": "127.0.0.1", "Port": port}],
            )

        elbv2.create_listener(
            LoadBalancerArn=load_balancers[self.http_alb]["LoadBalancerArn"],
            Protocol="HTTP",
            Port=8081,
            DefaultActions=[
                {
                    "Type": "forward",
                    "TargetGroupArn": target_groups[self.http_target_group]["TargetGroupArn"],
                }
            ],
        )

        certificate_path = self.artifact_dir / "fixture-cert.pem"
        private_key_path = self.artifact_dir / "fixture-cert-key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-sha256",
                "-nodes",
                "-days",
                "5",
                "-subj",
                "/CN=bluearch-steward.local",
                "-keyout",
                str(private_key_path),
                "-out",
                str(certificate_path),
            ],
            check=True,
            capture_output=True,
        )
        certificate_arn = acm.import_certificate(
            Certificate=certificate_path.read_bytes(),
            PrivateKey=private_key_path.read_bytes(),
            Tags=[{"Key": FIXTURE_TAG, "Value": "alb-expiring-certificate"}],
        )["CertificateArn"]
        elbv2.create_listener(
            LoadBalancerArn=load_balancers[self.tls_alb]["LoadBalancerArn"],
            Protocol="HTTPS",
            Port=8443,
            Certificates=[{"CertificateArn": certificate_arn}],
            SslPolicy="ELBSecurityPolicy-2016-08",
            DefaultActions=[
                {
                    "Type": "forward",
                    "TargetGroupArn": target_groups[self.tls_target_group]["TargetGroupArn"],
                }
            ],
        )

        metrics: List[Dict[str, Any]] = []
        for load_balancer in load_balancers.values():
            dimension = load_balancer["LoadBalancerArn"].split("loadbalancer/", 1)[1]
            metrics.append(
                {
                    "MetricName": "RequestCount",
                    "Dimensions": [{"Name": "LoadBalancer", "Value": dimension}],
                    "Value": 0.0,
                    "Unit": "Count",
                }
            )
        self._put_daily_metrics("AWS/ApplicationELB", metrics, days=7)

    def _put_daily_metrics(
        self,
        namespace: str,
        templates: Iterable[Dict[str, Any]],
        *,
        days: int,
    ) -> None:
        now = datetime.now(timezone.utc) - timedelta(minutes=5)
        metric_data = [
            {**template, "Timestamp": now - timedelta(days=day)}
            for day in range(days)
            for template in templates
        ]
        cloudwatch = self.client("cloudwatch")
        for offset in range(0, len(metric_data), 1000):
            cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=metric_data[offset : offset + 1000],
            )

    def _seed_kms(self) -> None:
        kms = self.client("kms")
        for key in kms.list_keys().get("Keys", []):
            metadata = kms.describe_key(KeyId=key["KeyId"]).get("KeyMetadata", {})
            if (
                metadata.get("Description") == f"{self.prefix}-rotation-disabled"
                and metadata.get("KeyState") == "Enabled"
            ):
                return
        kms.create_key(
            Description=f"{self.prefix}-rotation-disabled",
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Origin="AWS_KMS",
            Tags=[{"TagKey": FIXTURE_TAG, "TagValue": "kms-rotation-disabled"}],
        )

    def _seed_secrets_manager(self) -> None:
        self.client("secretsmanager").create_secret(
            Name=self.secret_name,
            Description="BlueArch Steward emulator fixture with no automatic rotation",
            SecretString="fixture-only-not-a-credential",  # pragma: allowlist secret
            Tags=[{"Key": FIXTURE_TAG, "Value": "secrets-manager-rotation-disabled"}],
        )

    def _seed_sns(self) -> None:
        sns = self.client("sns")
        arn = sns.create_topic(
            Name=self.sns_topic,
            Tags=[{"Key": FIXTURE_TAG, "Value": "sns-public-unencrypted"}],
        )["TopicArn"]
        sns.set_topic_attributes(
            TopicArn=arn,
            AttributeName="Policy",
            AttributeValue=json.dumps(_public_policy(arn, "sns:Publish")),
        )

    def _seed_sqs(self) -> None:
        sqs = self.client("sqs")
        queue_url = sqs.create_queue(
            QueueName=self.sqs_queue,
            Attributes={"SqsManagedSseEnabled": "false"},
            tags={FIXTURE_TAG: "sqs-public-unencrypted"},
        )["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["QueueArn"],
        )["Attributes"]["QueueArn"]
        sqs.set_queue_attributes(
            QueueUrl=queue_url,
            Attributes={"Policy": json.dumps(_public_policy(queue_arn, "sqs:SendMessage"))},
        )

    def _seed_api_gateway(self) -> None:
        api_gateway = self.client("apigateway")
        api_id = api_gateway.create_rest_api(
            name=self.api_name,
            description="BlueArch Steward emulator fixture",
            tags={FIXTURE_TAG: "api-gateway-no-controls"},
        )["id"]
        resources = api_gateway.get_resources(restApiId=api_id).get("items", [])
        root_id = next(item["id"] for item in resources if item.get("path") == "/")
        api_gateway.put_method(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            authorizationType="NONE",
        )
        api_gateway.put_integration(
            restApiId=api_id,
            resourceId=root_id,
            httpMethod="GET",
            type="MOCK",
            requestTemplates={"application/json": '{"statusCode": 200}'},
        )
        api_gateway.create_deployment(restApiId=api_id, stageName=self.api_stage)

    def _reset_api_gateway(self) -> None:
        api_gateway = self.client("apigateway")
        for api in api_gateway.get_rest_apis().get("items", []):
            if api.get("name") == self.api_name:
                api_gateway.delete_rest_api(restApiId=api["id"])

    def _reset_sqs(self) -> None:
        sqs = self.client("sqs")
        for queue_url in sqs.list_queues(QueueNamePrefix=self.sqs_queue).get("QueueUrls", []):
            if queue_url.rstrip("/").endswith("/" + self.sqs_queue):
                sqs.delete_queue(QueueUrl=queue_url)

    def _reset_sns(self) -> None:
        sns = self.client("sns")
        for topic in sns.list_topics().get("Topics", []):
            if str(topic.get("TopicArn") or "").endswith(":" + self.sns_topic):
                sns.delete_topic(TopicArn=topic["TopicArn"])

    def _reset_secrets_manager(self) -> None:
        try:
            self.client("secretsmanager").delete_secret(
                SecretId=self.secret_name,
                ForceDeleteWithoutRecovery=True,
            )
        except ClientError as exc:
            self._ignore(exc, "ResourceNotFoundException")

    def _reset_kms(self) -> None:
        kms = self.client("kms")
        for key in kms.list_keys().get("Keys", []):
            metadata = kms.describe_key(KeyId=key["KeyId"]).get("KeyMetadata", {})
            if metadata.get("Description") != f"{self.prefix}-rotation-disabled":
                continue
            if metadata.get("KeyState") == "Enabled":
                kms.disable_key(KeyId=key["KeyId"])
            if metadata.get("KeyState") != "PendingDeletion":
                kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7)

    def _reset_s3_controls(self) -> None:
        s3 = self.client("s3")
        bucket = f"{self.prefix}-server-logging-disabled"
        try:
            s3.delete_bucket_policy(Bucket=bucket)
        except ClientError as exc:
            self._ignore(exc, "NoSuchBucket", "NoSuchBucketPolicy")
        try:
            objects = s3.list_object_versions(Bucket=bucket)
            identifiers = [
                {"Key": item["Key"], "VersionId": item["VersionId"]}
                for key in ("Versions", "DeleteMarkers")
                for item in objects.get(key, [])
            ]
            if identifiers:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": identifiers})
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            self._ignore(exc, "NoSuchBucket")

    def _reset_iam(self) -> None:
        iam = self.client("iam")
        try:
            for policy_name in iam.list_role_policies(RoleName=self.wildcard_role).get(
                "PolicyNames", []
            ):
                iam.delete_role_policy(RoleName=self.wildcard_role, PolicyName=policy_name)
            iam.delete_role(RoleName=self.wildcard_role)
        except ClientError as exc:
            self._ignore(exc, "NoSuchEntity")
        try:
            for key in iam.list_access_keys(UserName=self.iam_user).get("AccessKeyMetadata", []):
                iam.delete_access_key(UserName=self.iam_user, AccessKeyId=key["AccessKeyId"])
            try:
                iam.delete_login_profile(UserName=self.iam_user)
            except ClientError as exc:
                self._ignore(exc, "NoSuchEntity")
            for name in iam.list_user_policies(UserName=self.iam_user).get("PolicyNames", []):
                iam.delete_user_policy(UserName=self.iam_user, PolicyName=name)
            for policy in iam.list_attached_user_policies(UserName=self.iam_user).get(
                "AttachedPolicies", []
            ):
                iam.detach_user_policy(UserName=self.iam_user, PolicyArn=policy["PolicyArn"])
            iam.delete_user(UserName=self.iam_user)
        except ClientError as exc:
            self._ignore(exc, "NoSuchEntity")

    def _reset_cloudtrail(self) -> None:
        cloudtrail = self.client("cloudtrail")
        trails = cloudtrail.describe_trails(
            trailNameList=[self.cloudtrail_name], includeShadowTrails=False
        ).get("trailList", [])
        if not trails:
            return
        try:
            cloudtrail.stop_logging(Name=self.cloudtrail_name)
            cloudtrail.delete_trail(Name=self.cloudtrail_name)
        except ClientError as exc:
            self._ignore(exc, "TrailNotFoundException")

    def _reset_rds(self) -> None:
        for identifier in (self.rds_identifier, self.high_cpu_rds_identifier):
            try:
                self.client("rds").delete_db_instance(
                    DBInstanceIdentifier=identifier,
                    SkipFinalSnapshot=True,
                    DeleteAutomatedBackups=True,
                )
            except ClientError as exc:
                self._ignore(exc, "DBInstanceNotFound")

    def _reset_dynamodb(self) -> None:
        dynamodb = self.client("dynamodb")
        for table_name in (
            self.dynamodb_inactive_table,
            self.dynamodb_provisioned_table,
            self.dynamodb_infrequent_table,
        ):
            try:
                dynamodb.delete_table(TableName=table_name)
            except ClientError as exc:
                self._ignore(exc, "ResourceNotFoundException")

    def _reset_efs(self) -> None:
        efs = self.client("efs")
        for file_system in efs.describe_file_systems().get("FileSystems", []):
            if file_system.get("CreationToken") not in {
                f"{self.prefix}-efs",
                f"{self.prefix}-efs-provisioned",
            }:
                continue
            try:
                efs.delete_file_system(FileSystemId=file_system["FileSystemId"])
            except ClientError as exc:
                self._ignore(exc, "FileSystemNotFound")

    def _reset_ec2(self) -> None:
        ec2 = self.client("ec2")
        reservations = ec2.describe_instances(
            Filters=[
                {
                    "Name": f"tag:{FIXTURE_TAG}",
                    "Values": ["ec2-idle-delete-disabled", "ec2-high-cpu-old-dev"],
                }
            ]
        ).get("Reservations", [])
        instances = [
            instance
            for reservation in reservations
            for instance in reservation.get("Instances", [])
        ]
        instance_ids = [
            instance["InstanceId"]
            for instance in instances
            if (instance.get("State") or {}).get("Name")
            in {"pending", "running", "stopping", "stopped"}
        ]
        instance_volume_ids = {
            str((mapping.get("Ebs") or {}).get("VolumeId") or "")
            for instance in instances
            for mapping in instance.get("BlockDeviceMappings") or []
            if (mapping.get("Ebs") or {}).get("VolumeId")
        }
        if instance_ids:
            ec2.terminate_instances(InstanceIds=instance_ids)
            self._wait_for(
                lambda: all(
                    instance["State"]["Name"] == "terminated"
                    for reservation in ec2.describe_instances(InstanceIds=instance_ids).get(
                        "Reservations", []
                    )
                    for instance in reservation.get("Instances", [])
                ),
                "fixture instances to terminate",
            )
        snapshots = ec2.describe_snapshots(
            OwnerIds=["self"],
            Filters=[{"Name": f"tag:{FIXTURE_TAG}", "Values": ["ebs-orphaned-snapshot"]}],
        ).get("Snapshots", [])
        for snapshot in snapshots:
            ec2.delete_snapshot(SnapshotId=snapshot["SnapshotId"])
        fixture_volume_tags = {
            "ebs-orphan-source",
            "ebs-magnetic-overutilized",
            "ec2-instance-root-delete-disabled",
        }
        volumes = [
            volume
            for volume in ec2.describe_volumes().get("Volumes", [])
            if volume.get("VolumeId") in instance_volume_ids
            or any(
                tag.get("Key") == FIXTURE_TAG and tag.get("Value") in fixture_volume_tags
                for tag in volume.get("Tags") or []
            )
        ]
        for volume in volumes:
            try:
                self._wait_for(
                    lambda volume_id=volume["VolumeId"]: (
                        ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
                        == "available"
                    ),
                    f"volume {volume['VolumeId']} dependencies",
                )
                ec2.delete_volume(VolumeId=volume["VolumeId"])
            except ClientError as exc:
                self._ignore(exc, "InvalidVolume.NotFound")
        groups = ec2.describe_security_groups(
            Filters=[
                {
                    "Name": f"tag:{FIXTURE_TAG}",
                    "Values": ["ec2-open-admin-high-count", "ec2-unused-security-group"],
                }
            ]
        ).get("SecurityGroups", [])
        for group in groups:
            self._wait_for(
                lambda group_id=group["GroupId"]: not self._network_interface_uses_group(group_id),
                f"security group {group['GroupId']} dependencies",
            )
            ec2.delete_security_group(GroupId=group["GroupId"])

    def _reset_lambda(self) -> None:
        lambda_client = self.client("lambda")
        for name in (self.admin_lambda, self.unused_lambda, self.high_error_lambda):
            try:
                lambda_client.delete_function(FunctionName=name)
            except ClientError as exc:
                self._ignore(exc, "ResourceNotFoundException")
        iam = self.client("iam")
        try:
            for policy_name in iam.list_role_policies(RoleName=self.admin_lambda_role).get(
                "PolicyNames", []
            ):
                iam.delete_role_policy(RoleName=self.admin_lambda_role, PolicyName=policy_name)
            iam.delete_role(RoleName=self.admin_lambda_role)
        except ClientError as exc:
            self._ignore(exc, "NoSuchEntity")

    def _reset_ecs(self) -> None:
        ecs = self.client("ecs")
        for service_name in (self.ecs_service, self.ecs_healthy_service):
            try:
                ecs.delete_service(cluster=self.ecs_cluster, service=service_name, force=True)
            except ClientError as exc:
                self._ignore(exc, "ClusterNotFoundException", "ServiceNotFoundException")
        try:
            ecs.delete_cluster(cluster=self.ecs_cluster)
        except ClientError as exc:
            self._ignore(exc, "ClusterNotFoundException")
        for arn in ecs.list_task_definitions(familyPrefix=self.ecs_family, status="ACTIVE").get(
            "taskDefinitionArns", []
        ):
            ecs.deregister_task_definition(taskDefinition=arn)
        for arn in ecs.list_task_definitions(
            familyPrefix=self.ecs_healthy_family,
            status="ACTIVE",
        ).get("taskDefinitionArns", []):
            ecs.deregister_task_definition(taskDefinition=arn)
        inactive = ecs.list_task_definitions(
            familyPrefix=self.ecs_family,
            status="INACTIVE",
        ).get("taskDefinitionArns", [])
        if inactive:
            try:
                ecs.delete_task_definitions(taskDefinitions=inactive)
            except ClientError as exc:
                self._ignore(exc, "ClientException")

    def _reset_alb(self) -> None:
        elbv2 = self.client("elbv2")
        load_balancers = elbv2.describe_load_balancers().get("LoadBalancers", [])
        for load_balancer in load_balancers:
            if load_balancer.get("LoadBalancerName") not in {
                self.http_alb,
                self.tls_alb,
            }:
                continue
            arn = load_balancer["LoadBalancerArn"]
            for listener in elbv2.describe_listeners(LoadBalancerArn=arn).get("Listeners", []):
                elbv2.delete_listener(ListenerArn=listener["ListenerArn"])
            elbv2.delete_load_balancer(LoadBalancerArn=arn)
        target_groups = elbv2.describe_target_groups().get("TargetGroups", [])
        for target_group in target_groups:
            if target_group.get("TargetGroupName") in {
                self.http_target_group,
                self.tls_target_group,
            }:
                try:
                    elbv2.delete_target_group(TargetGroupArn=target_group["TargetGroupArn"])
                except ClientError as exc:
                    self._ignore(exc, "ResourceInUse")
        acm = self.client("acm")
        for summary in acm.list_certificates().get("CertificateSummaryList", []):
            arn = summary["CertificateArn"]
            detail = acm.describe_certificate(CertificateArn=arn).get("Certificate", {})
            if detail.get("DomainName") == "bluearch-steward.local":
                try:
                    acm.delete_certificate(CertificateArn=arn)
                except ClientError as exc:
                    self._ignore(exc, "ResourceInUseException")

    def _assert_s3(self) -> None:
        s3 = self.client("s3")
        bucket = f"{self.prefix}-server-logging-disabled"
        response = s3.get_bucket_logging(Bucket=bucket)
        self._expect("LoggingEnabled" not in response, "S3 logging-disabled bucket")
        tags = {
            item["Key"]: item["Value"]
            for item in s3.get_bucket_tagging(Bucket=bucket).get("TagSet", [])
        }
        self._expect(
            tags.get("bluearch:object-lock-required") == "true", "S3 Object Lock requirement"
        )
        self._expect(
            tags.get("bluearch:replication-required") == "true", "S3 replication requirement"
        )
        self._expect(tags.get("bluearch:kms-required") == "true", "S3 KMS requirement")
        policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
        self._expect(
            any(
                statement.get("Principal") == {"Service": "cloudtrail.amazonaws.com"}
                for statement in policy.get("Statement", [])
            ),
            "S3 CloudTrail delivery policy",
        )

    def _assert_kms(self) -> None:
        kms = self.client("kms")
        matching = []
        for key in kms.list_keys().get("Keys", []):
            metadata = kms.describe_key(KeyId=key["KeyId"]).get("KeyMetadata", {})
            if (
                metadata.get("Description") == f"{self.prefix}-rotation-disabled"
                and metadata.get("KeyState") == "Enabled"
            ):
                matching.append(metadata)
        self._expect(len(matching) == 1, "KMS rotation-disabled key fixture")
        rotation = kms.get_key_rotation_status(KeyId=matching[0]["KeyId"])
        self._expect(rotation.get("KeyRotationEnabled") is False, "KMS rotation state")

    def _assert_secrets_manager(self) -> None:
        secret = self.client("secretsmanager").describe_secret(SecretId=self.secret_name)
        self._expect(secret.get("RotationEnabled") is not True, "Secrets Manager rotation state")

    def _assert_sns(self) -> None:
        sns = self.client("sns")
        arn = next(
            item["TopicArn"]
            for item in sns.list_topics().get("Topics", [])
            if str(item.get("TopicArn") or "").endswith(":" + self.sns_topic)
        )
        attributes = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
        self._expect(not attributes.get("KmsMasterKeyId"), "SNS encryption state")
        policy = json.loads(attributes.get("Policy") or "{}")
        self._expect(_has_public_allow(policy, "sns:Publish"), "SNS public policy")

    def _assert_sqs(self) -> None:
        sqs = self.client("sqs")
        queue_url = next(
            item
            for item in sqs.list_queues(QueueNamePrefix=self.sqs_queue).get("QueueUrls", [])
            if item.rstrip("/").endswith("/" + self.sqs_queue)
        )
        attributes = sqs.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=["All"],
        ).get("Attributes", {})
        self._expect(
            not attributes.get("KmsMasterKeyId")
            and attributes.get("SqsManagedSseEnabled") != "true",
            "SQS encryption state",
        )
        policy = json.loads(attributes.get("Policy") or "{}")
        self._expect(_has_public_allow(policy, "sqs:SendMessage"), "SQS public policy")

    def _assert_api_gateway(self) -> None:
        api_gateway = self.client("apigateway")
        api = next(
            item
            for item in api_gateway.get_rest_apis().get("items", [])
            if item.get("name") == self.api_name
        )
        stage = api_gateway.get_stage(restApiId=api["id"], stageName=self.api_stage)
        self._expect(not stage.get("accessLogSettings"), "API Gateway access logging state")
        self._expect(not stage.get("methodSettings"), "API Gateway execution logging state")
        self._expect(stage.get("tracingEnabled") is not True, "API Gateway X-Ray state")
        root = next(
            item
            for item in api_gateway.get_resources(restApiId=api["id"]).get("items", [])
            if item.get("path") == "/"
        )
        method = api_gateway.get_method(
            restApiId=api["id"], resourceId=root["id"], httpMethod="GET"
        )
        self._expect(method.get("authorizationType") == "NONE", "API Gateway method auth state")

    def _assert_iam(self) -> None:
        iam = self.client("iam")
        iam.get_login_profile(UserName=self.iam_user)
        self._expect(
            not iam.list_mfa_devices(UserName=self.iam_user).get("MFADevices"),
            "IAM fixture user must not have MFA",
        )
        self._expect(
            bool(iam.list_user_policies(UserName=self.iam_user).get("PolicyNames")),
            "IAM fixture user must have a direct policy",
        )
        self._expect(
            bool(iam.list_access_keys(UserName=self.iam_user).get("AccessKeyMetadata")),
            "IAM fixture user must have an access key",
        )
        role = iam.get_role(RoleName=self.wildcard_role)["Role"]
        trust = role.get("AssumeRolePolicyDocument") or {}
        self._expect(
            any(
                statement.get("Principal") == {"AWS": "*"}
                for statement in trust.get("Statement", [])
            ),
            "IAM wildcard trust fixture",
        )

    def _assert_cloudtrail(self) -> None:
        cloudtrail = self.client("cloudtrail")
        trails = cloudtrail.describe_trails(
            trailNameList=[self.cloudtrail_name], includeShadowTrails=False
        ).get("trailList", [])
        self._expect(len(trails) == 1, "CloudTrail fixture")
        trail = trails[0]
        self._expect(not trail.get("IsMultiRegionTrail"), "CloudTrail multi-region state")
        self._expect(not trail.get("LogFileValidationEnabled"), "CloudTrail validation state")
        self._expect(not trail.get("KmsKeyId"), "CloudTrail KMS state")
        self._expect(not trail.get("CloudWatchLogsLogGroupArn"), "CloudTrail CloudWatch state")
        self._expect(
            bool(cloudtrail.get_trail_status(Name=self.cloudtrail_name).get("IsLogging")),
            "CloudTrail logging state",
        )

    def _assert_rds(self) -> None:
        instances = self.client("rds").describe_db_instances(
            DBInstanceIdentifier=self.rds_identifier
        )["DBInstances"]
        self._expect(len(instances) == 1, "RDS fixture")
        instance = instances[0]
        self._expect(instance.get("PubliclyAccessible") is True, "RDS public state")
        self._expect(instance.get("StorageEncrypted") is False, "RDS encryption state")
        self._expect(instance.get("MultiAZ") is False, "RDS Multi-AZ state")
        self._expect(instance.get("StorageType") == "gp2", "RDS storage type")
        self._expect(
            instance.get("DBInstanceClass") == "db.m3.medium", "RDS previous generation class"
        )
        self._expect(not instance.get("MaxAllocatedStorage"), "RDS storage autoscaling state")
        high_cpu = self.client("rds").describe_db_instances(
            DBInstanceIdentifier=self.high_cpu_rds_identifier
        )["DBInstances"]
        self._expect(len(high_cpu) == 1, "RDS high CPU fixture")

    def _assert_dynamodb(self) -> None:
        dynamodb = self.client("dynamodb")
        tables = set(dynamodb.list_tables().get("TableNames", []))
        expected = {
            self.dynamodb_inactive_table,
            self.dynamodb_provisioned_table,
            self.dynamodb_infrequent_table,
        }
        self._expect(expected.issubset(tables), "DynamoDB table fixtures")
        provisioned = dynamodb.describe_table(TableName=self.dynamodb_provisioned_table)["Table"]
        self._expect(
            provisioned.get("BillingModeSummary", {}).get("BillingMode") != "PAY_PER_REQUEST",
            "DynamoDB provisioned billing fixture",
        )

    def _assert_efs(self) -> None:
        systems = [
            item
            for item in self.client("efs").describe_file_systems().get("FileSystems", [])
            if item.get("CreationToken") == f"{self.prefix}-efs"
        ]
        self._expect(len(systems) == 1, "EFS fixture")
        self._expect(systems[0].get("Encrypted") is False, "EFS encryption state")
        lifecycle = self.client("efs").describe_lifecycle_configuration(
            FileSystemId=systems[0]["FileSystemId"]
        )
        self._expect(not lifecycle.get("LifecyclePolicies"), "EFS lifecycle configuration")
        provisioned = [
            item
            for item in self.client("efs").describe_file_systems().get("FileSystems", [])
            if item.get("CreationToken") == f"{self.prefix}-efs-provisioned"
        ]
        self._expect(len(provisioned) == 1, "EFS provisioned throughput fixture")
        self._expect(
            provisioned[0].get("ThroughputMode") == "provisioned",
            "EFS provisioned throughput mode",
        )

    def _assert_ec2(self) -> None:
        ec2 = self.client("ec2")
        groups = ec2.describe_security_groups(
            Filters=[
                {
                    "Name": f"tag:{FIXTURE_TAG}",
                    "Values": ["ec2-open-admin-high-count"],
                }
            ]
        ).get("SecurityGroups", [])
        self._expect(len(groups) == 1, "EC2 security-group fixture")
        permissions = groups[0].get("IpPermissions", [])
        expanded = sum(
            max(
                1,
                sum(
                    len(permission.get(key, []))
                    for key in (
                        "IpRanges",
                        "Ipv6Ranges",
                        "PrefixListIds",
                        "UserIdGroupPairs",
                    )
                ),
            )
            for permission in permissions
        )
        self._expect(expanded > 50, "EC2 high rule count")
        self._expect(
            any(
                item.get("CidrIp") == "0.0.0.0/0"
                for permission in permissions
                if permission.get("FromPort", 22) <= 22 <= permission.get("ToPort", 22)
                for item in permission.get("IpRanges", [])
            ),
            "EC2 public SSH fixture",
        )
        self._expect(
            any(
                item.get("CidrIpv6") == "::/0"
                for permission in permissions
                if permission.get("FromPort", 3389) <= 3389 <= permission.get("ToPort", 3389)
                for item in permission.get("Ipv6Ranges", [])
            ),
            "EC2 public RDP fixture",
        )
        reservations = ec2.describe_instances(
            Filters=[
                {"Name": f"tag:{FIXTURE_TAG}", "Values": ["ec2-idle-delete-disabled"]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        ).get("Reservations", [])
        instances = [
            instance
            for reservation in reservations
            for instance in reservation.get("Instances", [])
        ]
        self._expect(len(instances) == 1, "EC2 instance fixture")
        root = instances[0].get("RootDeviceName")
        mapping = next(
            item
            for item in instances[0].get("BlockDeviceMappings", [])
            if item.get("DeviceName") == root
        )
        self._expect(
            mapping.get("Ebs", {}).get("DeleteOnTermination") is False,
            "EC2 delete-on-termination state",
        )
        snapshots = ec2.describe_snapshots(
            OwnerIds=["self"],
            Filters=[{"Name": f"tag:{FIXTURE_TAG}", "Values": ["ebs-orphaned-snapshot"]}],
        ).get("Snapshots", [])
        self._expect(len(snapshots) == 1, "orphaned EBS snapshot fixture")
        high_cpu = ec2.describe_instances(
            Filters=[
                {"Name": f"tag:{FIXTURE_TAG}", "Values": ["ec2-high-cpu-old-dev"]},
                {
                    "Name": "instance-state-name",
                    "Values": ["pending", "running", "stopping", "stopped"],
                },
            ]
        ).get("Reservations", [])
        high_cpu_instances = [
            instance for reservation in high_cpu for instance in reservation.get("Instances", [])
        ]
        self._expect(len(high_cpu_instances) == 1, "EC2 high CPU fixture")
        self._expect(
            high_cpu_instances[0].get("InstanceType") == "m3.medium",
            "EC2 previous generation fixture",
        )
        unused = ec2.describe_security_groups(
            Filters=[{"Name": f"tag:{FIXTURE_TAG}", "Values": ["ec2-unused-security-group"]}]
        ).get("SecurityGroups", [])
        self._expect(len(unused) == 1, "EC2 unused security group fixture")
        magnetic = ec2.describe_volumes(
            Filters=[{"Name": f"tag:{FIXTURE_TAG}", "Values": ["ebs-magnetic-overutilized"]}]
        ).get("Volumes", [])
        self._expect(
            len(magnetic) == 1 and magnetic[0].get("VolumeType") == "standard",
            "EBS magnetic fixture",
        )

    def _assert_lambda(self) -> None:
        functions = {
            item["FunctionName"]: item
            for item in self.client("lambda").list_functions().get("Functions", [])
        }
        self._expect(self.admin_lambda in functions, "Lambda admin-role fixture")
        self._expect(self.unused_lambda in functions, "Lambda unused fixture")
        self._expect(self.high_error_lambda in functions, "Lambda high-error fixture")
        self._expect(
            functions[self.admin_lambda]["Role"].endswith("/" + self.admin_lambda_role),
            "Lambda admin role binding",
        )
        self._expect(
            functions[self.admin_lambda].get("TracingConfig", {}).get("Mode") == "Active",
            "Lambda admin fixture tracing control",
        )
        self._expect(
            functions[self.high_error_lambda].get("Timeout") == 3, "Lambda timeout fixture"
        )
        configs = (
            self.client("lambda")
            .list_provisioned_concurrency_configs(FunctionName=self.unused_lambda)
            .get("ProvisionedConcurrencyConfigs", [])
        )
        self._expect(bool(configs), "Lambda provisioned concurrency fixture")

    def _assert_ecs(self) -> None:
        ecs = self.client("ecs")
        definitions = ecs.list_task_definitions(familyPrefix=self.ecs_family, status="ACTIVE").get(
            "taskDefinitionArns", []
        )
        self._expect(len(definitions) == 1, "ECS task definition fixture")
        definition = ecs.describe_task_definition(taskDefinition=definitions[0]).get(
            "taskDefinition", {}
        )
        containers = definition.get("containerDefinitions", [])
        self._expect(
            any(container.get("privileged") is True for container in containers),
            "ECS privileged container fixture",
        )
        services = ecs.describe_services(cluster=self.ecs_cluster, services=[self.ecs_service]).get(
            "services", []
        )
        self._expect(len(services) == 1, "ECS service fixture")
        self._expect(
            services[0].get("platformVersion") == "1.3.0",
            "ECS platform version fixture",
        )
        self._expect(
            int(services[0].get("desiredCount") or 0) > int(services[0].get("runningCount") or 0),
            "ECS degraded service fixture",
        )
        healthy_services = ecs.describe_services(
            cluster=self.ecs_cluster,
            services=[self.ecs_healthy_service],
        ).get("services", [])
        self._expect(len(healthy_services) == 1, "healthy ECS service fixture")
        self._expect(
            int(healthy_services[0].get("desiredCount") or 0) == 1
            and healthy_services[0].get("platformVersion") == "LATEST",
            "healthy ECS service desired count and platform version",
        )
        self._expect(
            self._ecs_task_is_running(self.ecs_healthy_family),
            "healthy ECS task and container status",
        )
        inactive = ecs.list_task_definitions(
            familyPrefix=f"{self.ecs_family}-inactive",
            status="INACTIVE",
        ).get("taskDefinitionArns", [])
        self._expect(bool(inactive), "ECS inactive task definition fixture")

    def _assert_alb(self) -> None:
        elbv2 = self.client("elbv2")
        load_balancers = {
            item["LoadBalancerName"]: item
            for item in elbv2.describe_load_balancers().get("LoadBalancers", [])
            if item.get("LoadBalancerName") in {self.http_alb, self.tls_alb}
        }
        self._expect(len(load_balancers) == 2, "ALB fixtures")
        http_listeners = elbv2.describe_listeners(
            LoadBalancerArn=load_balancers[self.http_alb]["LoadBalancerArn"]
        ).get("Listeners", [])
        self._expect(
            {item.get("Protocol") for item in http_listeners} == {"HTTP"},
            "HTTP-only ALB fixture",
        )
        tls_listeners = elbv2.describe_listeners(
            LoadBalancerArn=load_balancers[self.tls_alb]["LoadBalancerArn"]
        ).get("Listeners", [])
        self._expect(
            len(tls_listeners) == 1
            and tls_listeners[0].get("SslPolicy") == "ELBSecurityPolicy-2016-08",
            "weak TLS ALB fixture",
        )
        groups = {
            item["TargetGroupName"]: item
            for item in elbv2.describe_target_groups().get("TargetGroups", [])
            if item.get("TargetGroupName") in {self.http_target_group, self.tls_target_group}
        }
        self._expect(len(groups) == 2, "ALB target groups")
        for target_group in groups.values():
            health = elbv2.describe_target_health(
                TargetGroupArn=target_group["TargetGroupArn"]
            ).get("TargetHealthDescriptions", [])
            self._expect(
                health and health[0].get("TargetHealth", {}).get("State") == "unhealthy",
                "ALB unhealthy target fixture",
            )

    def _network_interface_uses_group(self, group_id: str) -> bool:
        interfaces = (
            self.client("ec2")
            .describe_network_interfaces(Filters=[{"Name": "group-id", "Values": [group_id]}])
            .get("NetworkInterfaces", [])
        )
        return bool(interfaces)

    def _ecs_task_is_running(self, family: str) -> bool:
        ecs = self.client("ecs")
        task_arns = ecs.list_tasks(cluster=self.ecs_cluster).get("taskArns", [])
        if not task_arns:
            return False
        tasks = ecs.describe_tasks(cluster=self.ecs_cluster, tasks=task_arns).get("tasks", [])
        return any(
            f"task-definition/{family}:" in str(task.get("taskDefinitionArn") or "")
            and task.get("lastStatus") == "RUNNING"
            and bool(task.get("containers"))
            and all(
                container.get("lastStatus") == "RUNNING"
                for container in task.get("containers") or []
            )
            for task in tasks
        )

    def _published_lambda_is_active(self, function_name: str, qualifier: str) -> bool:
        configuration = self.client("lambda").get_function(
            FunctionName=function_name,
            Qualifier=qualifier,
        )["Configuration"]
        return configuration.get("State") in {None, "Active"}

    @staticmethod
    def _wait_for(
        predicate: Callable[[], bool],
        label: str,
        *,
        timeout: float = 20.0,
    ) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except ClientError:
                pass
            time.sleep(0.2)
        raise FixtureError(f"Timed out waiting for {label}")

    @staticmethod
    def _ignore(exc: ClientError, *codes: str) -> None:
        code = str(exc.response.get("Error", {}).get("Code") or "")
        if code not in codes:
            raise exc

    @staticmethod
    def _expect(condition: bool, label: str) -> None:
        if not condition:
            raise FixtureError(f"Fixture assertion failed: {label}")


def _full_admin_policy() -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }


def _tls_policy(bucket: str) -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureTransport",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                "Condition": {"Bool": {"aws:SecureTransport": "false"}},
            }
        ],
    }


def _cloudtrail_tls_policy(bucket: str) -> Dict[str, Any]:
    policy = _tls_policy(bucket)
    policy["Statement"].append(
        {
            "Sid": "AllowCloudTrailDelivery",
            "Effect": "Allow",
            "Principal": {"Service": "cloudtrail.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/*",
        }
    )
    return policy


def _public_policy(resource_arn: str, action: str) -> Dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "BlueArchStewardPublicFixture",
                "Effect": "Allow",
                "Principal": "*",
                "Action": action,
                "Resource": resource_arn,
            }
        ],
    }


def _has_public_allow(policy: Dict[str, Any], action: str) -> bool:
    return any(
        statement.get("Effect") == "Allow"
        and statement.get("Principal") == "*"
        and statement.get("Action") == action
        and not statement.get("Condition")
        for statement in policy.get("Statement") or []
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("seed", "reset", "assert"))
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--region", default=REGION)
    parser.add_argument("--prefix", default="bluearch-steward")
    args = parser.parse_args()
    fixtures = ExtendedFixtures(args.endpoint_url, args.region, args.prefix)
    if args.action == "seed":
        fixtures.seed()
        print("Seeded extended AWS emulator fixtures for all active Steward services.")
    elif args.action == "reset":
        fixtures.reset()
        print("Reset extended AWS emulator fixtures.")
    else:
        fixtures.assert_state()
        print("Extended AWS emulator fixture assertions passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
