from __future__ import annotations

import unittest
from datetime import datetime, timezone
from typing import Any, Dict

from bluearch_aws_steward.investigation import investigate_deletion_readiness, investigate_finding
from bluearch_aws_steward.providers.base import AwsProviderError


class StubProvider:
    def __init__(self, responses: Dict[str, Dict[str, Any] | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, Dict[str, Any]]] = []

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        self.calls.append((operation, parameters))
        response = self.responses.get(operation, {})
        if isinstance(response, Exception):
            raise response
        return response


def _context() -> Dict[str, Any]:
    return {
        "account_id": "123456789012",
        "principal_arn": "arn:aws:sts::123456789012:assumed-role/Reviewer/session",
        "profile": "reviewer-sso",
        "provider": "aws-sdk",
        "region": "us-east-1",
    }


def _ebs_finding() -> Dict[str, Any]:
    return {
        "finding_id": "finding-ebs",
        "rule_short_id": "ec2-unattached-ebs-volume",
        "service": "ec2",
        "resource": "ebs://vol-123",
        "resource_ref": {
            "provider": "aws",
            "service": "ec2",
            "resource_type": "aws.ec2.volume",
            "resource_id": "vol-123",
            "region": "us-east-1",
        },
        "evidence": {"state": "available", "attachments": []},
    }


class DeletionInvestigationTests(unittest.TestCase):
    def test_unattached_volume_requires_context_even_with_recovery_snapshot(self) -> None:
        provider = StubProvider(
            {
                "ec2.describe_volumes": {
                    "Volumes": [
                        {
                            "VolumeId": "vol-123",
                            "State": "available",
                            "Size": 100,
                            "VolumeType": "gp3",
                            "AvailabilityZone": "us-east-1a",
                            "Encrypted": True,
                            "CreateTime": datetime(2026, 1, 1, tzinfo=timezone.utc),
                            "Attachments": [],
                            "Tags": [
                                {"Key": "owner", "Value": "platform"},
                                {"Key": "environment", "Value": "development"},
                                {"Key": "secret", "Value": "must-not-be-returned"},
                            ],
                        }
                    ]
                },
                "ec2.describe_snapshots": {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-123",
                            "State": "completed",
                            "StartTime": datetime(2026, 7, 20, tzinfo=timezone.utc),
                        }
                    ]
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )

        dossier = investigate_deletion_readiness(provider, _ebs_finding(), aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "needs_context")
        self.assertFalse(dossier["deletion_readiness"]["safe_to_delete"])
        self.assertEqual(dossier["recovery"]["status"], "partially_prepared")
        self.assertEqual(dossier["business_context"]["ownership"], {"owner": "platform"})
        self.assertNotIn("secret", dossier["business_context"]["selected_tags"])
        self.assertEqual(dossier["dependency_summary"]["cross_service_graph"], "unavailable")
        self.assertEqual(dossier["business_impact"]["category"], "persistent_data")
        self.assertEqual(dossier["confidence"]["score"], 66.7)
        self.assertEqual(
            dossier["change_plan_preview"]["target_operation"]["aws_api"],
            "ec2:DeleteVolume",
        )
        self.assertFalse(dossier["change_plan_preview"]["executable_by_steward"])
        self.assertGreater(len(dossier["post_change_verification"]), 1)
        self.assertTrue(dossier["read_only"])
        self.assertFalse(dossier["write_actions_applied"])

    def test_explicit_confirmations_create_candidate_but_never_safe_to_delete(self) -> None:
        provider = StubProvider(
            {
                "ec2.describe_volumes": {
                    "Volumes": [
                        {
                            "VolumeId": "vol-123",
                            "State": "available",
                            "Attachments": [],
                            "Tags": [{"Key": "owner", "Value": "platform"}],
                        }
                    ]
                },
                "ec2.describe_snapshots": {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-123",
                            "State": "completed",
                            "StartTime": "2026-07-20T00:00:00Z",
                        }
                    ]
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )

        dossier = investigate_deletion_readiness(
            provider,
            _ebs_finding(),
            aws_context=_context(),
            confirmations={"owner_approved": True, "iac_references_reviewed": True},
        )

        self.assertEqual(dossier["deletion_readiness"]["status"], "candidate_for_approval")
        self.assertFalse(dossier["deletion_readiness"]["safe_to_delete"])
        self.assertFalse(dossier["deletion_readiness"]["automatic_deletion_supported"])

    def test_live_attachment_blocks_volume_deletion(self) -> None:
        provider = StubProvider(
            {
                "ec2.describe_volumes": {
                    "Volumes": [
                        {
                            "VolumeId": "vol-123",
                            "State": "in-use",
                            "Attachments": [
                                {
                                    "InstanceId": "i-123",
                                    "Device": "/dev/xvdf",
                                    "State": "attached",
                                }
                            ],
                        }
                    ]
                },
                "ec2.describe_snapshots": {"Snapshots": []},
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )

        dossier = investigate_deletion_readiness(
            provider,
            _ebs_finding(),
            aws_context=_context(),
            confirmations={"owner_approved": True, "iac_references_reviewed": True},
        )

        self.assertEqual(dossier["deletion_readiness"]["status"], "blocked")
        self.assertEqual(dossier["relationships"][0]["resource_id"], "i-123")
        self.assertEqual(dossier["blast_radius"]["level"], "high")

    def test_aws_config_relationship_blocks_deletion_even_without_attachment(self) -> None:
        provider = StubProvider(
            {
                "ec2.describe_volumes": {
                    "Volumes": [
                        {
                            "VolumeId": "vol-123",
                            "State": "available",
                            "Attachments": [],
                            "Tags": [{"Key": "owner", "Value": "platform"}],
                        }
                    ]
                },
                "ec2.describe_snapshots": {
                    "Snapshots": [
                        {
                            "SnapshotId": "snap-123",
                            "State": "completed",
                            "StartTime": "2026-07-20T00:00:00Z",
                        }
                    ]
                },
                "config.describe_configuration_recorders": {
                    "ConfigurationRecorders": [{"name": "default"}]
                },
                "config.describe_configuration_recorder_status": {
                    "ConfigurationRecordersStatus": [{"name": "default", "recording": True}]
                },
                "config.get_resource_config_history": {
                    "configurationItems": [
                        {
                            "configurationItemCaptureTime": "2026-07-21T00:00:00Z",
                            "relationships": [
                                {
                                    "relationshipName": "is attached to Instance",
                                    "resourceType": "AWS::EC2::Instance",
                                    "resourceId": "i-123",
                                }
                            ],
                        }
                    ]
                },
            }
        )

        dossier = investigate_deletion_readiness(provider, _ebs_finding(), aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "blocked")
        self.assertEqual(dossier["dependency_summary"]["cross_service_graph"], "available")
        self.assertEqual(dossier["relationships"][0]["resource_id"], "i-123")

    def test_route53_reference_blocks_elastic_ip_release(self) -> None:
        provider = StubProvider(
            {
                "ec2.describe_addresses": {
                    "Addresses": [
                        {
                            "AllocationId": "eipalloc-123",
                            "PublicIp": "192.0.2.10",
                            "Domain": "vpc",
                            "Tags": [{"Key": "team", "Value": "network"}],
                        }
                    ]
                },
                "route53.list_hosted_zones": {
                    "HostedZones": [{"Id": "/hostedzone/Z123", "Name": "example.com."}]
                },
                "route53.list_resource_record_sets": {
                    "ResourceRecordSets": [
                        {
                            "Name": "api.example.com.",
                            "Type": "A",
                            "ResourceRecords": [{"Value": "192.0.2.10"}],
                        }
                    ]
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-eip",
            "rule_short_id": "ec2-unassociated-elastic-ip",
            "service": "ec2",
            "resource": "eip://eipalloc-123",
            "resource_ref": {
                "resource_type": "aws.ec2.elastic-ip",
                "resource_id": "eipalloc-123",
            },
            "evidence": {},
        }

        dossier = investigate_deletion_readiness(provider, finding, aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "blocked")
        self.assertEqual(dossier["relationships"][0]["record_name"], "api.example.com.")
        self.assertFalse(dossier["recovery"]["status"] == "prepared")

    def test_permission_failure_reduces_coverage_without_implying_no_dependency(self) -> None:
        denied = AwsProviderError("denied", detail="AccessDenied")
        provider = StubProvider(
            {
                "ec2.describe_addresses": {
                    "Addresses": [
                        {
                            "AllocationId": "eipalloc-123",
                            "PublicIp": "192.0.2.10",
                            "Domain": "vpc",
                        }
                    ]
                },
                "route53.list_hosted_zones": denied,
                "config.describe_configuration_recorders": denied,
            }
        )
        finding = {
            "finding_id": "finding-eip",
            "rule_short_id": "ec2-unassociated-elastic-ip",
            "service": "ec2",
            "resource": "eip://eipalloc-123",
            "resource_ref": {
                "resource_type": "aws.ec2.elastic-ip",
                "resource_id": "eipalloc-123",
            },
            "evidence": {},
        }

        dossier = investigate_deletion_readiness(provider, finding, aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "needs_context")
        self.assertEqual(dossier["evidence_coverage"]["label"], "low")
        self.assertEqual(len(dossier["capability_errors"]), 2)
        self.assertFalse(
            dossier["dependency_summary"]["absence_of_observed_relationships_proves_no_dependency"]
        )

    def test_inactive_ecs_task_definition_checks_live_service_references(self) -> None:
        task_arn = "arn:aws:ecs:us-east-1:123456789012:task-definition/demo:3"
        provider = StubProvider(
            {
                "ecs.describe_task_definition": {
                    "taskDefinition": {
                        "taskDefinitionArn": task_arn,
                        "family": "demo",
                        "revision": 3,
                        "status": "INACTIVE",
                        "containerDefinitions": [
                            {
                                "name": "api",
                                "environment": [
                                    {"name": "PASSWORD", "value": "must-not-be-returned"}
                                ],
                            }
                        ],
                    },
                    "tags": [{"key": "owner", "value": "platform"}],
                },
                "ecs.list_clusters": {"clusterArns": ["cluster/demo"]},
                "ecs.list_services": {"serviceArns": ["service/api"]},
                "ecs.describe_services": {
                    "services": [
                        {
                            "serviceName": "api",
                            "serviceArn": "service/api",
                            "taskDefinition": task_arn,
                        }
                    ]
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-ecs",
            "rule_short_id": "ecs-inactive-task-definition",
            "service": "ecs",
            "resource": "ecs://task-definition/demo:3",
            "resource_ref": {
                "resource_type": "aws.ecs.task-definition",
                "resource_id": "demo:3",
            },
            "evidence": {"task_definition_arn": task_arn},
        }

        dossier = investigate_deletion_readiness(provider, finding, aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "blocked")
        self.assertEqual(dossier["relationships"][0]["resource_id"], "api")
        self.assertEqual(
            dossier["change_plan_preview"]["target_operation"]["aws_api"],
            "ecs:DeleteTaskDefinitions",
        )
        self.assertNotIn("must-not-be-returned", str(dossier))

    def test_inactive_efs_requires_backup_and_owner_context(self) -> None:
        provider = StubProvider(
            {
                "efs.describe_file_systems": {
                    "FileSystems": [
                        {
                            "FileSystemId": "fs-123",
                            "FileSystemArn": "arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-123",
                            "LifeCycleState": "available",
                            "Encrypted": True,
                            "SizeInBytes": {"Value": 1024},
                            "Tags": [{"Key": "team", "Value": "storage"}],
                        }
                    ]
                },
                "efs.describe_mount_targets": {"MountTargets": []},
                "efs.describe_access_points": {"AccessPoints": []},
                "backup.list_recovery_points_by_resource": {"RecoveryPoints": []},
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-efs",
            "rule_short_id": "efs-inactive-unmounted",
            "service": "efs",
            "resource": "efs://file-system/fs-123",
            "resource_ref": {
                "resource_type": "aws.efs.file-system",
                "resource_id": "fs-123",
            },
            "evidence": {"client_connections": 0.0},
        }

        dossier = investigate_deletion_readiness(provider, finding, aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "needs_context")
        self.assertEqual(dossier["business_impact"]["category"], "shared_persistent_data")
        self.assertEqual(dossier["recovery"]["status"], "not_observed")
        self.assertIn(
            "backup_restore_reviewed",
            dossier["change_plan_preview"]["required_confirmation_keys"],
        )

    def test_unused_lambda_redacts_environment_and_blocks_on_invocation_path(self) -> None:
        provider = StubProvider(
            {
                "lambda.get_function_configuration": {
                    "FunctionName": "unused",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:unused",
                    "Runtime": "python3.12",
                    "State": "Active",
                    "Environment": {"Variables": {"CONFIG_VALUE": "redaction-fixture"}},
                },
                "lambda.list_event_source_mappings": {
                    "EventSourceMappings": [
                        {
                            "UUID": "mapping-1",
                            "EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:queue",
                            "State": "Enabled",
                        }
                    ]
                },
                "lambda.list_function_url_configs": {"FunctionUrlConfigs": []},
                "lambda.list_aliases": {"Aliases": []},
                "lambda.list_versions_by_function": {"Versions": [{"Version": "$LATEST"}]},
                "events.list_rule_names_by_target": {"RuleNames": []},
                "lambda.get_policy": {},
                "lambda.list_tags": {"Tags": {"owner": "platform"}},
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-lambda",
            "rule_short_id": "lambda-unused-function",
            "service": "lambda",
            "resource": "lambda://function/unused",
            "resource_ref": {
                "resource_type": "aws.lambda.function",
                "resource_id": "unused",
            },
            "evidence": {"invocation_sum": 0.0},
        }

        dossier = investigate_deletion_readiness(provider, finding, aws_context=_context())

        self.assertEqual(dossier["deletion_readiness"]["status"], "blocked")
        self.assertEqual(dossier["business_impact"]["category"], "event_driven_workload")
        self.assertEqual(dossier["current_state"]["environment_variable_count"], 1)
        self.assertNotIn("redaction-fixture", str(dossier))
        self.assertEqual(
            dossier["change_plan_preview"]["target_operation"]["aws_api"],
            "lambda:DeleteFunction",
        )

    def test_idle_rds_is_blocked_by_deletion_protection_and_preserves_recovery(self) -> None:
        provider = StubProvider(
            {
                "rds.describe_db_instances": {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "orders",
                            "DBInstanceStatus": "available",
                            "DBInstanceClass": "db.t4g.medium",
                            "Engine": "postgres",
                            "EngineVersion": "16.3",
                            "DeletionProtection": True,
                            "Endpoint": {"Address": "orders.example.internal"},
                            "TagList": [
                                {"Key": "owner", "Value": "payments"},
                                {"Key": "environment", "Value": "production"},
                            ],
                        }
                    ]
                },
                "rds.describe_db_snapshots": {
                    "DBSnapshots": [
                        {
                            "DBSnapshotIdentifier": "orders-recovery",
                            "Status": "available",
                            "SnapshotCreateTime": "2026-07-20T00:00:00Z",
                        }
                    ]
                },
                "route53.list_hosted_zones": {"HostedZones": []},
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-rds-idle",
            "rule_short_id": "rds-idle-instance",
            "service": "rds",
            "resource": "rds://db/orders",
            "resource_ref": {
                "resource_type": "aws.rds.db-instance",
                "resource_id": "orders",
            },
            "evidence": {"maximum_database_connections": 0.0, "lookback_days": 7},
        }

        dossier = investigate_finding(provider, finding, aws_context=_context())

        self.assertEqual(dossier["investigation"], "deletion_readiness")
        self.assertEqual(dossier["deletion_readiness"]["status"], "blocked")
        self.assertFalse(dossier["deletion_readiness"]["safe_to_delete"])
        self.assertEqual(dossier["business_impact"]["category"], "stateful_database")
        self.assertEqual(dossier["recovery"]["status"], "snapshot_observed")
        self.assertEqual(
            dossier["change_plan_preview"]["target_operation"]["aws_api"],
            "rds:DeleteDBInstance",
        )
        self.assertNotIn("orders.example.internal", str(dossier))

    def test_rds_high_cpu_returns_hypotheses_without_claiming_root_cause(self) -> None:
        provider = StubProvider(
            {
                "rds.describe_db_instances": {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "orders",
                            "DBInstanceStatus": "available",
                            "DBInstanceClass": "db.t4g.medium",
                            "Engine": "postgres",
                            "AllocatedStorage": 100,
                            "StorageType": "gp3",
                            "TagList": [{"Key": "owner", "Value": "payments"}],
                        }
                    ]
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-rds-cpu",
            "rule_short_id": "rds-high-cpu",
            "service": "rds",
            "resource": "rds://db/orders",
            "resource_ref": {
                "resource_type": "aws.rds.db-instance",
                "resource_id": "orders",
            },
            "evidence": {
                "cpu_breach_days": 5,
                "threshold_percent": 90.0,
                "lookback_days": 7,
            },
        }

        dossier = investigate_finding(provider, finding, aws_context=_context())

        self.assertEqual(dossier["investigation"], "operational_diagnosis")
        self.assertFalse(dossier["operational_diagnosis"]["root_cause_confirmed"])
        self.assertEqual(
            dossier["operational_diagnosis"]["hypotheses"][0]["id"],
            "query_or_connection_pressure",
        )
        self.assertTrue(dossier["change_plan_preview"]["root_cause_required_before_change"])
        self.assertIsNone(dossier["change_plan_preview"]["target_operation"])
        self.assertFalse(dossier["write_actions_applied"])

    def test_degraded_ecs_diagnosis_redacts_failure_details(self) -> None:
        task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/api:7"
        provider = StubProvider(
            {
                "ecs.describe_services": {
                    "services": [
                        {
                            "serviceName": "api",
                            "serviceArn": "arn:aws:ecs:us-east-1:123456789012:service/demo/api",
                            "status": "ACTIVE",
                            "desiredCount": 2,
                            "runningCount": 1,
                            "pendingCount": 0,
                            "platformVersion": "1.4.0",
                            "taskDefinition": task_definition,
                            "deployments": [
                                {
                                    "status": "PRIMARY",
                                    "rolloutState": "FAILED",
                                    "taskDefinition": task_definition,
                                    "desiredCount": 2,
                                    "runningCount": 1,
                                }
                            ],
                            "tags": [{"key": "owner", "value": "platform"}],
                        }
                    ]
                },
                "ecs.list_tasks": {
                    "taskArns": ["arn:aws:ecs:us-east-1:123456789012:task/demo/task-1"]
                },
                "ecs.describe_tasks": {
                    "tasks": [
                        {
                            "taskArn": "arn:aws:ecs:us-east-1:123456789012:task/demo/task-1",
                            "taskDefinitionArn": task_definition,
                            "group": "service:api",
                            "desiredStatus": "STOPPED",
                            "lastStatus": "STOPPED",
                            "stopCode": "TaskFailedToStart",
                            "stoppedReason": "CannotPullContainerError: token=must-not-be-returned",
                            "containers": [
                                {
                                    "name": "api",
                                    "lastStatus": "STOPPED",
                                    "reason": "CannotPullContainerError: password=must-not-be-returned",
                                }
                            ],
                        }
                    ]
                },
                "ecs.describe_task_definition": {
                    "taskDefinition": {
                        "taskDefinitionArn": task_definition,
                        "family": "api",
                        "revision": 7,
                        "containerDefinitions": [
                            {
                                "name": "api",
                                "environment": [
                                    {"name": "PASSWORD", "value": "must-not-be-returned"}
                                ],
                            }
                        ],
                    }
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-ecs-health",
            "rule_short_id": "ecs-service-health-degraded",
            "service": "ecs",
            "resource": "ecs://service/api",
            "resource_ref": {
                "resource_type": "aws.ecs.service",
                "resource_id": "api",
            },
            "evidence": {"cluster_arn": "arn:aws:ecs:us-east-1:123456789012:cluster/demo"},
        }

        dossier = investigate_finding(provider, finding, aws_context=_context())

        self.assertEqual(dossier["investigation"], "operational_diagnosis")
        self.assertFalse(dossier["operational_diagnosis"]["root_cause_confirmed"])
        self.assertIn(
            "deployment_rollout_failed",
            {item["id"] for item in dossier["operational_diagnosis"]["hypotheses"]},
        )
        self.assertNotIn("must-not-be-returned", str(dossier))
        self.assertTrue(dossier["current_state"]["service_events_redacted"])
        self.assertFalse(dossier["write_actions_applied"])

    def test_unsafe_ecs_task_definition_never_returns_environment_values(self) -> None:
        task_definition = "arn:aws:ecs:us-east-1:123456789012:task-definition/api:7"
        provider = StubProvider(
            {
                "ecs.describe_task_definition": {
                    "taskDefinition": {
                        "taskDefinitionArn": task_definition,
                        "family": "api",
                        "revision": 7,
                        "status": "ACTIVE",
                        "containerDefinitions": [
                            {
                                "name": "api",
                                "privileged": True,
                                "environment": [
                                    {"name": "API_TOKEN", "value": "must-not-be-returned"}
                                ],
                            }
                        ],
                    },
                    "tags": [{"key": "owner", "value": "platform"}],
                },
                "config.describe_configuration_recorders": {"ConfigurationRecorders": []},
            }
        )
        finding = {
            "finding_id": "finding-ecs-unsafe",
            "rule_short_id": "ecs-unsafe-task-definition",
            "service": "ecs",
            "resource": "ecs://task-definition/api:7",
            "resource_ref": {
                "resource_type": "aws.ecs.task-definition",
                "resource_id": "api:7",
            },
            "evidence": {"task_definition_arn": task_definition},
        }

        dossier = investigate_finding(provider, finding, aws_context=_context())

        self.assertEqual(dossier["investigation"], "operational_diagnosis")
        self.assertEqual(
            {item["id"] for item in dossier["operational_diagnosis"]["hypotheses"]},
            {"privileged_container_escape_risk", "literal_secret_material_in_task_definition"},
        )
        self.assertNotIn("must-not-be-returned", str(dossier))
        self.assertFalse(dossier["change_plan_preview"]["executable_by_steward"])


if __name__ == "__main__":
    unittest.main()
