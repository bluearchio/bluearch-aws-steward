from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Set

from bluearch_aws_steward.catalog import load_rules
from bluearch_aws_steward.detectors.efs import scan_efs
from bluearch_aws_steward.mcp_server import _tool_find_opportunities
from bluearch_aws_steward.policy import build_scan_policy
from bluearch_aws_steward.providers.base import AwsProviderError
from bluearch_aws_steward.providers.operations import READ_OPERATIONS
from bluearch_aws_steward.scanner import run_aws_scan

NEW_RULES: Set[str] = {
    "iam-password-policy-missing",
    "iam-console-user-mfa-disabled",
    "iam-access-key-older-than-90-days",
    "iam-policy-full-admin",
    "iam-policy-attached-directly-to-user",
    "ec2-security-group-ssh-open",
    "ec2-security-group-rdp-open",
    "ec2-default-security-group-not-restricted",
    "vpc-flow-logs-disabled",
    "ebs-orphaned-snapshot-or-ami",
    "ec2-ebs-delete-on-termination-disabled",
    "s3-server-access-logging-disabled",
    "s3-mfa-delete-disabled",
    "efs-encryption-disabled",
    "efs-lifecycle-policy-missing",
    "lambda-admin-execution-role",
    "lambda-unused-function",
    "lambda-high-error-rate",
    "ecs-unsafe-task-definition",
    "ecs-platform-version-outdated",
    "ec2-security-group-rule-count-high",
    "ec2-idle-instance",
    "rds-idle-instance",
    "alb-access-logging-disabled",
    "alb-https-listener-missing",
    "alb-weak-tls-policy",
    "alb-certificate-expiring",
    "alb-unhealthy-targets",
    "alb-idle-load-balancer",
}


class V040FixtureProvider:
    def __init__(self, *, healthy: bool = False) -> None:
        self.healthy = healthy
        self.now = datetime.now(timezone.utc)

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def list_buckets(self) -> List[str]:
        return ["fixture-source"]

    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        return []

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        handler = getattr(self, "_" + operation.replace(".", "_"), None)
        if handler is None:
            raise AssertionError(f"Unexpected operation: {operation} {parameters}")
        return handler(parameters)

    def _iam_get_account_authorization_details(self, _: Dict[str, Any]) -> Dict[str, Any]:
        attached = (
            []
            if self.healthy
            else [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }
            ]
        )
        return {
            "UserDetailList": [
                {
                    "UserName": "fixture-user",
                    "Arn": "arn:aws:iam::123456789012:user/fixture-user",
                    "UserPolicyList": [],
                    "AttachedManagedPolicies": attached,
                }
            ],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [
                {
                    "Arn": "arn:aws:iam::aws:policy/AdministratorAccess",
                    "PolicyVersionList": [
                        {
                            "IsDefaultVersion": True,
                            "Document": {
                                "Version": "2012-10-17",
                                "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"},
                            },
                        }
                    ],
                }
            ],
        }

    def _iam_get_login_profile(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"LoginProfile": {"UserName": "fixture-user"}}

    def _iam_get_account_password_policy(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"PasswordPolicy": {"MinimumPasswordLength": 14}} if self.healthy else {}

    def _iam_list_mfa_devices(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return (
            {"MFADevices": [{"SerialNumber": "redacted"}]} if self.healthy else {"MFADevices": []}
        )

    def _iam_list_access_keys(self, _: Dict[str, Any]) -> Dict[str, Any]:
        age = 10 if self.healthy else 120
        return {
            "AccessKeyMetadata": [
                {
                    "AccessKeyId": "AKIAEXAMPLESHOULDNOTLEAK",  # pragma: allowlist secret
                    "Status": "Active",
                    "CreateDate": self.now - timedelta(days=age),
                }
            ]
        }

    def _ec2_describe_security_groups(self, _: Dict[str, Any]) -> Dict[str, Any]:
        if self.healthy:
            return {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-safe",
                        "GroupName": "default",
                        "VpcId": "vpc-1",
                        "IpPermissions": [],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ranges = [{"CidrIp": "0.0.0.0/0"}] + [
            {"CidrIp": f"10.0.{index}.0/24"} for index in range(50)
        ]
        return {
            "SecurityGroups": [
                {
                    "GroupId": "sg-risky",
                    "GroupName": "default",
                    "VpcId": "vpc-1",
                    "OwnerId": "123456789012",
                    "IpPermissions": [
                        {
                            "IpProtocol": "-1",
                            "IpRanges": ranges,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                    "IpPermissionsEgress": [],
                }
            ]
        }

    def _ec2_describe_vpcs(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Vpcs": [{"VpcId": "vpc-1", "IsDefault": True}]}

    def _ec2_describe_flow_logs(self, _: Dict[str, Any]) -> Dict[str, Any]:
        if self.healthy:
            return {
                "FlowLogs": [
                    {"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE", "LogStatus": "SUCCESS"}
                ]
            }
        return {"FlowLogs": []}

    def _ec2_describe_instances(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-fixture",
                            "ImageId": "ami-used",
                            "InstanceType": "t3.micro",
                            "State": {"Name": "running"},
                            "RootDeviceName": "/dev/xvda",
                            "BlockDeviceMappings": [
                                {
                                    "DeviceName": "/dev/xvda",
                                    "Ebs": {
                                        "VolumeId": "vol-root",
                                        "DeleteOnTermination": self.healthy,
                                    },
                                }
                            ],
                        }
                    ]
                }
            ]
        }

    def _ec2_describe_snapshots(self, _: Dict[str, Any]) -> Dict[str, Any]:
        age = 10 if self.healthy else 120
        return {
            "Snapshots": [
                {
                    "SnapshotId": "snap-fixture",
                    "VolumeId": "vol-deleted",
                    "StartTime": self.now - timedelta(days=age),
                }
            ]
        }

    def _ec2_describe_images(self, _: Dict[str, Any]) -> Dict[str, Any]:
        age = 10 if self.healthy else 120
        return {
            "Images": [
                {
                    "ImageId": "ami-orphan",
                    "Name": "fixture-ami",
                    "CreationDate": (self.now - timedelta(days=age)).isoformat(),
                    "BlockDeviceMappings": [],
                }
            ]
        }

    def _ec2_describe_launch_templates(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"LaunchTemplates": []}

    def _s3_get_bucket_logging(self, _: Dict[str, Any]) -> Dict[str, Any]:
        if self.healthy:
            return {"LoggingEnabled": {"TargetBucket": "logs", "TargetPrefix": "fixture/"}}
        return {}

    def _s3_get_bucket_versioning(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Status": "Enabled", "MFADelete": "Enabled" if self.healthy else "Disabled"}

    def _efs_describe_file_systems(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "FileSystems": [
                {
                    "FileSystemId": "fs-fixture",
                    "OwnerId": "123456789012",
                    "Encrypted": self.healthy,
                    "PerformanceMode": "generalPurpose",
                    "ThroughputMode": "bursting",
                }
            ]
        }

    def _efs_describe_lifecycle_configuration(self, _: Dict[str, Any]) -> Dict[str, Any]:
        policies = [{"TransitionToIA": "AFTER_30_DAYS"}] if self.healthy else []
        return {"LifecyclePolicies": policies}

    def _lambda_list_functions(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "Functions": [
                {
                    "FunctionName": "unused-function",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:unused-function",
                    "Role": "arn:aws:iam::123456789012:role/fixture-role",
                    "Runtime": "python3.13",
                    "LastModified": (self.now - timedelta(days=40)).isoformat(),
                    "TracingConfig": {"Mode": "Active"},
                },
                {
                    "FunctionName": "high-error-function",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:high-error-function",
                    "Role": "arn:aws:iam::123456789012:role/fixture-role",
                    "Runtime": "python3.13",
                    "LastModified": self.now.isoformat(),
                    "TracingConfig": {"Mode": "Active"},
                },
            ]
        }

    def _iam_list_attached_role_policies(self, _: Dict[str, Any]) -> Dict[str, Any]:
        policies = (
            []
            if self.healthy
            else [
                {
                    "PolicyName": "AdministratorAccess",
                    "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                }
            ]
        )
        return {"AttachedPolicies": policies}

    def _iam_get_policy(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Policy": {"DefaultVersionId": "v1"}}

    def _iam_get_policy_version(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "PolicyVersion": {
                "Document": {"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
            }
        }

    def _iam_list_role_policies(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"PolicyNames": []}

    def _ecs_list_task_definitions(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "taskDefinitionArns": ["arn:aws:ecs:us-east-1:123456789012:task-definition/fixture:1"]
        }

    def _ecs_describe_task_definition(self, _: Dict[str, Any]) -> Dict[str, Any]:
        environment = [] if self.healthy else [{"name": "DB_PASSWORD", "value": "super-secret"}]
        return {
            "taskDefinition": {
                "taskDefinitionArn": "arn:aws:ecs:us-east-1:123456789012:task-definition/fixture:1",
                "containerDefinitions": [
                    {"name": "app", "privileged": not self.healthy, "environment": environment}
                ],
            },
            "tags": [],
        }

    def _ecs_list_clusters(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"clusterArns": ["arn:aws:ecs:us-east-1:123456789012:cluster/fixture"]}

    def _ecs_list_services(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"serviceArns": ["arn:aws:ecs:us-east-1:123456789012:service/fixture/app"]}

    def _ecs_describe_services(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "services": [
                {
                    "serviceArn": "arn:aws:ecs:us-east-1:123456789012:service/fixture/app",
                    "serviceName": "app",
                    "launchType": "FARGATE",
                    "platformVersion": "LATEST" if self.healthy else "1.3.0",
                    "desiredCount": 1,
                    "runningCount": 1,
                }
            ]
        }

    def _rds_describe_db_instances(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "idle-db",
                    "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:idle-db",
                    "DBInstanceStatus": "available",
                    "Engine": "postgres",
                    "StorageEncrypted": True,
                    "MultiAZ": True,
                }
            ]
        }

    def _elbv2_describe_load_balancers(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "LoadBalancers": [
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/http/1",
                    "LoadBalancerName": "http",
                    "Type": "application",
                    "Scheme": "internet-facing",
                },
                {
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/https/2",
                    "LoadBalancerName": "https",
                    "Type": "application",
                    "Scheme": "internet-facing",
                },
            ]
        }

    def _elbv2_describe_load_balancer_attributes(self, _: Dict[str, Any]) -> Dict[str, Any]:
        enabled = "true" if self.healthy else "false"
        return {"Attributes": [{"Key": "access_logs.s3.enabled", "Value": enabled}]}

    def _elbv2_describe_listeners(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        arn = parameters["LoadBalancerArn"]
        if "/http/" in arn:
            listeners = [{"ListenerArn": arn + "/listener/http", "Protocol": "HTTP", "Port": 80}]
            if self.healthy:
                listeners.append(
                    {
                        "ListenerArn": arn + "/listener/https",
                        "Protocol": "HTTPS",
                        "Port": 443,
                        "SslPolicy": "modern",
                        "Certificates": [],
                    }
                )
            return {"Listeners": listeners}
        return {
            "Listeners": [
                {
                    "ListenerArn": arn + "/listener/https",
                    "Protocol": "HTTPS",
                    "Port": 443,
                    "SslPolicy": "modern" if self.healthy else "weak",
                    "Certificates": [
                        {"CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/fixture"}
                    ],
                }
            ]
        }

    def _elbv2_describe_ssl_policies(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "SslPolicies": [
                {
                    "Name": "modern" if self.healthy else "weak",
                    "SslProtocols": ["TLSv1.2"] if self.healthy else ["TLSv1", "TLSv1.2"],
                }
            ]
        }

    def _elbv2_describe_listener_certificates(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "Certificates": [
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/fixture",
                    "IsDefault": True,
                },
                {
                    "CertificateArn": "arn:aws:acm:us-east-1:123456789012:certificate/sni",
                    "IsDefault": False,
                },
            ]
        }

    def _acm_describe_certificate(self, _: Dict[str, Any]) -> Dict[str, Any]:
        days = 90 if self.healthy else 5
        return {
            "Certificate": {
                "NotAfter": self.now + timedelta(days=days),
                "RenewalEligibility": "ELIGIBLE",
            }
        }

    def _elbv2_describe_target_groups(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        if "/https/" not in parameters["LoadBalancerArn"]:
            return {"TargetGroups": []}
        return {
            "TargetGroups": [
                {
                    "TargetGroupArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/fixture/1",
                    "TargetGroupName": "fixture",
                }
            ]
        }

    def _elbv2_describe_target_health(self, _: Dict[str, Any]) -> Dict[str, Any]:
        state = "healthy" if self.healthy else "unhealthy"
        return {
            "TargetHealthDescriptions": [
                {
                    "Target": {"Id": "i-target", "Port": 8080},
                    "TargetHealth": {"State": state, "Reason": "Target.ResponseCodeMismatch"},
                }
            ]
        }

    def _cloudwatch_get_metric_data(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        results = []
        for query in parameters["MetricDataQueries"]:
            metric = query["MetricStat"]["Metric"]
            namespace = metric["Namespace"]
            lookback = {
                "AWS/EC2": 14,
                "AWS/Lambda": 30,
                "AWS/RDS": 7,
                "AWS/ApplicationELB": 7,
            }[namespace]
            if namespace == "AWS/Lambda":
                function_name = next(
                    (
                        item["Value"]
                        for item in metric.get("Dimensions", [])
                        if item.get("Name") == "FunctionName"
                    ),
                    "",
                )
                if metric["MetricName"] == "Invocations":
                    value = 20.0 if self.healthy or function_name == "high-error-function" else 0.0
                elif metric["MetricName"] == "Errors":
                    value = 0.0 if self.healthy else 3.0
                else:
                    value = 0.0
            elif self.healthy:
                value = 20.0 if namespace != "AWS/ApplicationELB" else 200.0
            elif namespace == "AWS/EC2" and metric["MetricName"] == "CPUUtilization":
                value = 1.0
            elif namespace == "AWS/EC2":
                value = 100.0
            elif namespace == "AWS/ApplicationELB":
                value = 10.0
            else:
                value = 0.0
            results.append(
                {
                    "Id": query["Id"],
                    "StatusCode": "Complete",
                    "Values": [value] * lookback,
                    "Timestamps": [self.now - timedelta(days=index) for index in range(lookback)],
                }
            )
        return {"MetricDataResults": results}


class EfsPermissionDeniedProvider(V040FixtureProvider):
    def _efs_describe_lifecycle_configuration(self, _: Dict[str, Any]) -> Dict[str, Any]:
        raise AwsProviderError(
            "denied", detail="AccessDenied: elasticfilesystem:DescribeLifecycleConfiguration"
        )


class DeniedOperationsProvider(V040FixtureProvider):
    def __init__(self, denied_operations: Set[str]) -> None:
        super().__init__()
        self.denied_operations = denied_operations

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        if operation in self.denied_operations:
            raise AwsProviderError("denied", detail=f"AccessDenied: {operation}")
        return super().read(operation, **parameters)


class MissingMetricsProvider(V040FixtureProvider):
    def _cloudwatch_get_metric_data(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "MetricDataResults": [
                {
                    "Id": query["Id"],
                    "StatusCode": "Complete",
                    "Values": [],
                    "Timestamps": [],
                }
                for query in parameters["MetricDataQueries"]
            ]
        }


class IncompleteMetricsProvider(V040FixtureProvider):
    def _cloudwatch_get_metric_data(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "MetricDataResults": [
                {
                    "Id": query["Id"],
                    "StatusCode": "Complete",
                    "Values": [0.0],
                    "Timestamps": [self.now],
                }
                for query in parameters["MetricDataQueries"]
            ]
        }


class MultiListenerCertificateProvider(V040FixtureProvider):
    def _elbv2_describe_listeners(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._elbv2_describe_listeners(parameters)
        if "/http/" in parameters["LoadBalancerArn"]:
            payload["Listeners"].append(
                {
                    "ListenerArn": parameters["LoadBalancerArn"] + "/listener/https",
                    "Protocol": "HTTPS",
                    "Port": 443,
                    "SslPolicy": "modern",
                    "Certificates": [],
                }
            )
        return payload


class HttpListenerWithDefaultSslPolicyProvider(V040FixtureProvider):
    def _elbv2_describe_listeners(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "Listeners": [
                {
                    "ListenerArn": parameters["LoadBalancerArn"] + "/listener/http",
                    "Protocol": "HTTP",
                    "Port": 80,
                    "SslPolicy": "legacy",
                }
            ]
        }


class TaggedV040FixtureProvider(V040FixtureProvider):
    tag = {"Key": "steward", "Value": "skip"}

    def _iam_get_account_authorization_details(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._iam_get_account_authorization_details(parameters)
        payload["UserDetailList"][0]["Tags"] = [self.tag]
        return payload

    def _ec2_describe_security_groups(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ec2_describe_security_groups(parameters)
        for item in payload["SecurityGroups"]:
            item["Tags"] = [self.tag]
        return payload

    def _ec2_describe_vpcs(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ec2_describe_vpcs(parameters)
        payload["Vpcs"][0]["Tags"] = [self.tag]
        return payload

    def _ec2_describe_instances(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ec2_describe_instances(parameters)
        payload["Reservations"][0]["Instances"][0]["Tags"] = [self.tag]
        return payload

    def _ec2_describe_snapshots(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ec2_describe_snapshots(parameters)
        payload["Snapshots"][0]["Tags"] = [self.tag]
        return payload

    def _ec2_describe_images(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ec2_describe_images(parameters)
        payload["Images"][0]["Tags"] = [self.tag]
        return payload

    def _s3_get_bucket_tagging(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"TagSet": [self.tag]}

    def _efs_describe_file_systems(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._efs_describe_file_systems(parameters)
        payload["FileSystems"][0]["Tags"] = [self.tag]
        return payload

    def _lambda_list_tags(self, _: Dict[str, Any]) -> Dict[str, Any]:
        return {"Tags": {"steward": "skip"}}

    def _ecs_describe_task_definition(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ecs_describe_task_definition(parameters)
        payload["tags"] = [{"key": "steward", "value": "skip"}]
        return payload

    def _ecs_describe_services(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._ecs_describe_services(parameters)
        payload["services"][0]["tags"] = [{"key": "steward", "value": "skip"}]
        return payload

    def _rds_describe_db_instances(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        payload = super()._rds_describe_db_instances(parameters)
        payload["DBInstances"][0]["TagList"] = [self.tag]
        return payload

    def _elbv2_describe_tags(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "TagDescriptions": [
                {"ResourceArn": arn, "Tags": [self.tag]} for arn in parameters["ResourceArns"]
            ]
        }


class V040RuleTests(unittest.TestCase):
    def test_all_29_new_rules_detect_expected_resources_and_redact_sensitive_values(self) -> None:
        result = run_aws_scan(
            V040FixtureProvider(),
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter=",".join(sorted(NEW_RULES)),
        )

        found = {finding.rule_short_id for finding in result.findings}
        self.assertEqual(found, NEW_RULES)
        self.assertEqual(result.schema_version, "0.2")
        self.assertEqual(result.summary["rules_evaluated"], 29)
        self.assertTrue(result.summary["detection_coverage"]["complete_catalog_evaluation"])
        encoded = json.dumps(result.to_dict(), default=str)
        self.assertNotIn("super-secret", encoded)
        self.assertNotIn("AKIAEXAMPLESHOULDNOTLEAK", encoded)  # pragma: allowlist secret
        for finding in result.findings:
            self.assertIn("observation", finding.evidence)
            self.assertIsNotNone(finding.resource_ref)
            self.assertTrue(finding.remediation.summary)
            self.assertTrue(finding.remediation.actions)
            self.assertTrue(finding.remediation.verification)

    def test_native_evidence_kinds_match_configuration_and_signal_design(self) -> None:
        rules = load_rules()

        self.assertEqual(
            sum(rule.evaluation_kind == "configuration" for rule in rules),
            93,
        )
        self.assertEqual(sum(rule.evaluation_kind == "signal" for rule in rules), 27)

    def test_all_29_new_rules_accept_healthy_resources(self) -> None:
        result = run_aws_scan(
            V040FixtureProvider(healthy=True),
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter=",".join(sorted(NEW_RULES)),
        )

        self.assertEqual(result.findings, [])
        self.assertEqual(result.summary["rules_evaluated"], 29)
        self.assertTrue(result.summary["detection_coverage"]["complete_catalog_evaluation"])

    def test_alb_certificate_rule_covers_default_and_sni_certificates_without_duplicates(
        self,
    ) -> None:
        result = run_aws_scan(
            MultiListenerCertificateProvider(),
            service="alb",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter="alb-certificate-expiring",
        )

        self.assertEqual(
            {finding.resource for finding in result.findings},
            {"acm://certificate/fixture", "acm://certificate/sni"},
        )
        self.assertEqual(len(result.findings), 2)
        self.assertEqual(len({finding.finding_id for finding in result.findings}), 2)
        for finding in result.findings:
            self.assertEqual(finding.resource_ref.service, "acm")
            self.assertEqual(finding.evidence["listener_binding_count"], 2)

    def test_weak_tls_rule_ignores_non_https_listeners(self) -> None:
        result = run_aws_scan(
            HttpListenerWithDefaultSslPolicyProvider(),
            service="alb",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter="alb-weak-tls-policy",
        )

        self.assertEqual(result.findings, [])
        self.assertEqual(result.summary["rules_evaluated"], 1)

    def test_permission_failure_skips_only_affected_rule(self) -> None:
        result = scan_efs(
            EfsPermissionDeniedProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter="efs-encryption-disabled,efs-lifecycle-policy-missing",
        )

        self.assertEqual(
            {finding.rule_short_id for finding in result.findings},
            {"efs-encryption-disabled"},
        )
        self.assertEqual(result.summary["rules_evaluated"], 1)
        self.assertEqual(result.summary["rules_skipped"][0]["rule"], "efs-lifecycle-policy-missing")
        self.assertEqual(
            result.summary["capability_errors"][0]["operation"],
            "efs.describe_lifecycle_configuration",
        )

    def test_every_new_rule_reports_permission_failure_as_skipped(self) -> None:
        rules = {rule.short_id: rule for rule in load_rules() if rule.short_id in NEW_RULES}
        self.assertEqual(set(rules), NEW_RULES)

        for short_id, rule in sorted(rules.items()):
            with self.subTest(rule=short_id):
                result = run_aws_scan(
                    DeniedOperationsProvider(set(rule.capabilities)),
                    service=rule.service,
                    profile=None,
                    endpoint_url=None,
                    region="us-east-1",
                    provider="aws-sdk",
                    rule_filter=short_id,
                )

                self.assertEqual(result.findings, [])
                self.assertEqual(result.summary["rules_evaluated"], 0)
                self.assertIn(
                    short_id,
                    {item["rule"] for item in result.summary["rules_skipped"]},
                )
                self.assertTrue(result.summary["capability_errors"])

    def test_missing_or_incomplete_metric_datapoints_are_not_interpreted_as_zero(self) -> None:
        metric_rules = {
            "ec2-idle-instance",
            "rds-idle-instance",
            "lambda-unused-function",
            "lambda-high-error-rate",
            "alb-idle-load-balancer",
        }
        for provider in (MissingMetricsProvider(), IncompleteMetricsProvider()):
            with self.subTest(provider=provider.__class__.__name__):
                result = run_aws_scan(
                    provider,
                    service="all",
                    profile=None,
                    endpoint_url=None,
                    region="us-east-1",
                    provider="aws-sdk",
                    rule_filter=",".join(sorted(metric_rules)),
                )

                self.assertEqual(result.findings, [])
                self.assertEqual(result.summary["rules_evaluated"], 5)
                self.assertEqual(result.summary["scan_errors"], 0)

    def test_metric_rules_are_returned_as_cost_opportunities_without_invented_savings(self) -> None:
        scan = run_aws_scan(
            V040FixtureProvider(),
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter=",".join(sorted(NEW_RULES)),
        ).to_dict()

        response = _tool_find_opportunities(
            {
                "objective": "cost_optimization",
                "scan_result": scan,
                "max_returned_findings": 50,
            }
        )
        metric_rules = {
            "ec2-idle-instance",
            "rds-idle-instance",
            "lambda-unused-function",
            "lambda-high-error-rate",
            "alb-idle-load-balancer",
        }
        returned = {
            item["rule"]: item for item in response["opportunities"] if item["rule"] in metric_rules
        }

        self.assertEqual(set(returned), metric_rules)
        for opportunity in returned.values():
            self.assertEqual(opportunity["cost_estimate"]["status"], "usage_evidence")
            self.assertIsNone(opportunity["cost_estimate"]["estimated_monthly_savings_usd"])

    def test_explicit_exception_tags_suppress_tagged_resources_across_new_collectors(self) -> None:
        result = run_aws_scan(
            TaggedV040FixtureProvider(),
            service="all",
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            provider="aws-sdk",
            rule_filter=",".join(sorted(NEW_RULES)),
            policy=build_scan_policy(exclude_tags={"steward": "skip"}),
        )

        self.assertEqual(result.findings, [])
        self.assertEqual(result.summary["rules_evaluated"], 29)
        self.assertEqual(result.summary["policy_overrides"]["exclude_tags"], {"steward": "skip"})


if __name__ == "__main__":
    unittest.main()
