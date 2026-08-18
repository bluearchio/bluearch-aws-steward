from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List

from bluearch_aws_steward.models import Rule

CATALOG_SCHEMA_VERSION = "0.2"
FULL_CATALOG_SCHEMA_VERSION = "0.1"
CATALOG_SOURCE = "bluearchio/aws-misconfig-db"

EVALUATION_MODE_NATIVE = "native"
EVALUATION_MODE_ALIAS = "native_alias"
EVALUATION_MODE_MANUAL = "manual_review"
EVALUATION_MODE_METADATA = "metadata_required"
EVALUATION_MODE_SIGNAL = "signal_required"
EVALUATION_MODE_SPECIFICATION = "specification_required"
EVALUATION_MODES = (
    EVALUATION_MODE_NATIVE,
    EVALUATION_MODE_ALIAS,
    EVALUATION_MODE_MANUAL,
    EVALUATION_MODE_METADATA,
    EVALUATION_MODE_SIGNAL,
    EVALUATION_MODE_SPECIFICATION,
)


@dataclass(frozen=True)
class ExecutableRuleSpec:
    source_id: str
    short_id: str
    detector: str
    scenario: str
    remediation_summary: str
    safety_level: str = "low_risk"
    requires_approval: bool = True
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_detail: str = ""
    runtime_service: str | None = None
    aliases: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    evaluation_kind: str = "configuration"
    objectives: tuple[str, ...] = ()
    access_tier: str = "free"


# Compatibility for downstream imports while the public name moves to RuleSpec.
ExecutableRuleMapping = ExecutableRuleSpec


EXECUTABLE_S3_RULES: Dict[str, ExecutableRuleMapping] = {
    "356570fe-de33-4782-bc81-152cb144fb05": ExecutableRuleMapping(
        source_id="356570fe-de33-4782-bc81-152cb144fb05",
        short_id="s3-public-bucket",
        detector="s3_public_bucket",
        scenario="Public S3 bucket or contents",
        remediation_summary="Enable S3 bucket public access block.",
    ),
    "03736e4a-6ce5-4375-84ce-278711247314": ExecutableRuleMapping(
        source_id="03736e4a-6ce5-4375-84ce-278711247314",
        short_id="s3-no-default-encryption",
        detector="s3_missing_default_encryption",
        scenario="S3 object or bucket data is not encrypted",
        remediation_summary="Enable default SSE-S3 bucket encryption.",
    ),
    "e9b21a0d-2fe8-4f5b-8875-52995b4cf2e7": ExecutableRuleMapping(
        source_id="e9b21a0d-2fe8-4f5b-8875-52995b4cf2e7",
        short_id="s3-no-lifecycle",
        detector="s3_missing_lifecycle",
        scenario="S3 lifecycle manager is turned off",
        remediation_summary="Add a lifecycle rule for older objects.",
        parameters={
            "cost_evidence_required": True,
            "advisory_without_cost_evidence": True,
        },
    ),
    "ffc337be-4cb6-4899-b02c-d447af23221e": ExecutableRuleSpec(
        source_id="ffc337be-4cb6-4899-b02c-d447af23221e",
        short_id="s3-intelligent-tiering-missing",
        detector="s3_storage_tiering_missing",
        scenario="S3 bucket lifecycle rules do not transition or expire aging data",
        remediation_summary="Add a reviewed lifecycle transition, expiration, or Intelligent-Tiering policy.",
        safety_level="review_required",
        capabilities=("s3.list_buckets", "s3.get_bucket_lifecycle_configuration"),
        evaluation_kind="configuration",
        objectives=("cost_optimization", "sustainability", "operations"),
        parameters={
            "requires_existing_lifecycle_configuration": True,
            "accepted_transition_storage_classes": (
                "STANDARD_IA",
                "ONEZONE_IA",
                "INTELLIGENT_TIERING",
                "GLACIER",
                "DEEP_ARCHIVE",
                "GLACIER_IR",
            ),
        },
        risk_detail="cost, operations, sustainability",
    ),
    "60c00aeb-ec1d-4b10-91fa-7025fd7a70be": ExecutableRuleMapping(
        source_id="60c00aeb-ec1d-4b10-91fa-7025fd7a70be",
        short_id="s3-versioning-disabled",
        detector="s3_versioning_disabled",
        scenario="S3 versioning should support object recovery",
        remediation_summary="Enable bucket versioning.",
    ),
    "06aabba0-436b-4295-91b1-165ee4741dc8": ExecutableRuleMapping(
        source_id="06aabba0-436b-4295-91b1-165ee4741dc8",
        short_id="s3-policy-all-actions-public",
        detector="s3_policy_all_actions_public",
        scenario="S3 bucket policy allows all actions to a public principal",
        remediation_summary="Remove or narrowly scope public wildcard actions in the bucket policy.",
        safety_level="review_required",
        risk_detail="security, operations",
    ),
    "743e9f6e-7cda-4e47-bbbb-10e47c728456": ExecutableRuleMapping(
        source_id="743e9f6e-7cda-4e47-bbbb-10e47c728456",
        short_id="s3-policy-public-delete",
        detector="s3_policy_public_delete",
        scenario="S3 bucket policy allows delete actions to a public principal",
        remediation_summary="Remove public delete permissions from the bucket policy.",
        safety_level="review_required",
        risk_detail="security, operations",
    ),
    "c7db823b-24c5-4033-a01e-fa2345106f9e": ExecutableRuleMapping(
        source_id="c7db823b-24c5-4033-a01e-fa2345106f9e",
        short_id="s3-policy-public-read",
        detector="s3_policy_public_read",
        scenario="S3 bucket policy allows read actions to a public principal",
        remediation_summary="Remove or narrowly scope public read statements in the bucket policy.",
        safety_level="review_required",
        risk_detail="security, operations",
    ),
    "ce620d59-96ae-4465-b6cf-6262e9e5f403": ExecutableRuleMapping(
        source_id="ce620d59-96ae-4465-b6cf-6262e9e5f403",
        short_id="s3-tls-enforcement-missing",
        detector="s3_tls_enforcement_missing",
        scenario="S3 bucket policy does not deny requests that do not use TLS",
        remediation_summary="Add a reviewed bucket policy statement that denies non-TLS requests.",
        safety_level="review_required",
        risk_detail="security, operations",
    ),
    "fa44e6cf-5243-4819-8256-2379e5347eff": ExecutableRuleSpec(
        source_id="fa44e6cf-5243-4819-8256-2379e5347eff",
        short_id="s3-server-access-logging-disabled",
        detector="s3_server_access_logging_disabled",
        scenario="S3 bucket does not deliver server access logs",
        remediation_summary="Enable logging to an existing reviewed destination bucket and prefix.",
        safety_level="low_risk",
        capabilities=(
            "s3.list_buckets",
            "s3.get_bucket_logging",
            "s3.get_bucket_tagging",
        ),
        objectives=("security", "operations"),
    ),
    "a97bfdeb-87c8-4550-a146-e926be7e6ecf": ExecutableRuleSpec(
        source_id="a97bfdeb-87c8-4550-a146-e926be7e6ecf",
        short_id="s3-mfa-delete-disabled",
        detector="s3_mfa_delete_disabled",
        scenario="Versioned S3 bucket does not have MFA Delete enabled",
        remediation_summary="Review root-account operational requirements before enabling MFA Delete.",
        safety_level="high_risk",
        capabilities=(
            "s3.list_buckets",
            "s3.get_bucket_versioning",
            "s3.get_bucket_tagging",
        ),
        objectives=("security", "reliability"),
    ),
}

EXECUTABLE_CLOUDWATCH_RULES: Dict[str, ExecutableRuleMapping] = {
    "e7b5c9a1-3f2d-4e8b-9c6a-1d5e8f2b4a3c": ExecutableRuleMapping(
        source_id="e7b5c9a1-3f2d-4e8b-9c6a-1d5e8f2b4a3c",
        short_id="cloudwatch-log-retention-missing",
        detector="cloudwatch_log_retention_missing",
        scenario="CloudWatch Logs groups without retention policies accumulating costs indefinitely",
        remediation_summary="Set a reviewed retention period for the CloudWatch Logs group.",
        safety_level="review_required",
        parameters={
            "recommended_retention_days": 30,
            "minimum_stored_bytes_for_cost_opportunity": 10485760,
            "storage_cost_usd_per_gb_month": 0.03,
        },
    ),
}

EXECUTABLE_EC2_RULES: Dict[str, ExecutableRuleMapping] = {
    "033ae438-4620-4f65-80cd-776fd0102bb0": ExecutableRuleMapping(
        source_id="033ae438-4620-4f65-80cd-776fd0102bb0",
        short_id="ec2-unattached-ebs-volume",
        detector="ec2_unattached_ebs_volume",
        scenario="Unattached EBS volume continues to incur storage charges",
        remediation_summary="Review, snapshot if required, and delete the unused EBS volume.",
        safety_level="high_risk",
        parameters={
            "minimum_unattached_days": 7,
            "pricing_region": "us-east-1",
            "default_storage_cost_usd_per_gib_month": 0.10,
            "storage_cost_usd_per_gib_month": {
                "gp3": 0.08,
                "gp2": 0.10,
                "io1": 0.125,
                "io2": 0.125,
                "st1": 0.045,
                "sc1": 0.015,
                "standard": 0.05,
            },
            "exempt_tags": {"bluearch:steward-exempt": "true"},
        },
    ),
    "249dd667-4b1e-4200-bec5-19c6c718f958": ExecutableRuleMapping(
        source_id="249dd667-4b1e-4200-bec5-19c6c718f958",
        short_id="ec2-ebs-volume-unencrypted",
        detector="ec2_ebs_volume_unencrypted",
        scenario="EBS volume is not encrypted at rest",
        remediation_summary="Replace the volume through a reviewed encrypted snapshot workflow.",
        safety_level="high_risk",
    ),
    "40d46878-ac12-44c8-902f-196a18dc9f6c": ExecutableRuleMapping(
        source_id="40d46878-ac12-44c8-902f-196a18dc9f6c",
        short_id="ec2-unassociated-elastic-ip",
        detector="ec2_unassociated_elastic_ip",
        scenario="Elastic IP address is not associated with a running EC2 instance",
        remediation_summary="Associate the address with an active resource or release it after dependency review.",
        safety_level="high_risk",
    ),
    "63b4f412-c3ab-4ec8-af7f-ddfecbc25269": ExecutableRuleSpec(
        source_id="63b4f412-c3ab-4ec8-af7f-ddfecbc25269",
        short_id="ec2-security-group-rule-count-high",
        detector="ec2_security_group_rule_count_high",
        scenario="EC2 VPC security group has more than 50 ingress and egress rules",
        remediation_summary="Review and consolidate redundant security-group rules.",
        safety_level="review_required",
        capabilities=("ec2.describe_security_groups",),
        parameters={"maximum_security_group_rules": 50},
        objectives=("security", "performance", "operations"),
    ),
    "74492e33-2626-4630-bf53-2bd5ef074061": ExecutableRuleSpec(
        source_id="74492e33-2626-4630-bf53-2bd5ef074061",
        short_id="ec2-idle-instance",
        detector="ec2_idle_instance",
        scenario="Running EC2 instance has sustained low CPU and network activity",
        remediation_summary="Validate dependencies before rightsizing, scheduling, stopping, or terminating the instance.",
        safety_level="high_risk",
        capabilities=("ec2.describe_instances", "cloudwatch.get_metric_data"),
        evaluation_kind="signal",
        parameters={
            "lookback_days": 14,
            "minimum_idle_days": 4,
            "maximum_daily_cpu_percent": 5.0,
            "maximum_daily_network_bytes": 5242880,
        },
        objectives=("cost_optimization",),
        risk_detail="cost",
    ),
}


EXECUTABLE_NETWORKING_RULES: Dict[str, ExecutableRuleMapping] = {
    "bfea29bc-2ef9-4c6e-9ce3-d0c5823e3447": ExecutableRuleSpec(
        source_id="bfea29bc-2ef9-4c6e-9ce3-d0c5823e3447",
        short_id="ec2-security-group-ssh-open",
        detector="ec2_security_group_ssh_open",
        scenario="Security group exposes SSH to the public internet",
        remediation_summary="Restrict SSH ingress to reviewed trusted networks or Session Manager.",
        safety_level="high_risk",
        runtime_service="ec2",
        capabilities=("ec2.describe_security_groups",),
        parameters={"port": 22},
        objectives=("security",),
        risk_detail="security",
    ),
    "64036652-ec42-41db-a7d6-32819a169fe5": ExecutableRuleSpec(
        source_id="64036652-ec42-41db-a7d6-32819a169fe5",
        short_id="ec2-security-group-rdp-open",
        detector="ec2_security_group_rdp_open",
        scenario="Security group exposes RDP to the public internet",
        remediation_summary="Restrict RDP ingress to reviewed trusted networks or managed access.",
        safety_level="high_risk",
        runtime_service="ec2",
        capabilities=("ec2.describe_security_groups",),
        parameters={"port": 3389},
        objectives=("security",),
        risk_detail="security",
    ),
    "7e35eb21-1180-43d0-8d7d-5bb01fff7874": ExecutableRuleSpec(
        source_id="7e35eb21-1180-43d0-8d7d-5bb01fff7874",
        short_id="ec2-default-security-group-not-restricted",
        detector="ec2_default_security_group_not_restricted",
        scenario="Default VPC security group contains ingress or egress rules",
        remediation_summary="Remove default-group rules after confirming no workload dependency.",
        safety_level="high_risk",
        runtime_service="ec2",
        capabilities=("ec2.describe_security_groups",),
        objectives=("security",),
        risk_detail="security",
    ),
    "15ed0da6-a382-4fe0-969b-e0c4f66425bd": ExecutableRuleSpec(
        source_id="15ed0da6-a382-4fe0-969b-e0c4f66425bd",
        short_id="vpc-flow-logs-disabled",
        detector="vpc_flow_logs_disabled",
        scenario="VPC has no active flow log",
        remediation_summary="Create a reviewed VPC flow log destination and retention policy.",
        safety_level="review_required",
        runtime_service="ec2",
        aliases=("955b348e-b934-4d1a-bc1b-966994f99322",),
        capabilities=("ec2.describe_vpcs", "ec2.describe_flow_logs"),
        objectives=("security", "operations"),
    ),
}


EXECUTABLE_EBS_RULES: Dict[str, ExecutableRuleMapping] = {
    "8312c521-673e-48df-aca3-ae6a284f7079": ExecutableRuleSpec(
        source_id="8312c521-673e-48df-aca3-ae6a284f7079",
        short_id="ebs-orphaned-snapshot-or-ami",
        detector="ebs_orphaned_snapshot_or_ami",
        scenario="Owned EBS snapshot or AMI is old and no longer referenced",
        remediation_summary="Confirm retention requirements before deregistering the AMI or deleting its snapshots.",
        safety_level="high_risk",
        runtime_service="ec2",
        capabilities=(
            "ec2.describe_snapshots",
            "ec2.describe_images",
            "ec2.describe_instances",
            "ec2.describe_launch_templates",
            "ec2.describe_launch_template_versions",
        ),
        parameters={"minimum_orphan_age_days": 90},
        objectives=("cost_optimization", "operations"),
        risk_detail="cost",
    ),
    "9b4bd9b6-9139-4e8d-a157-055bbb6bacc3": ExecutableRuleSpec(
        source_id="9b4bd9b6-9139-4e8d-a157-055bbb6bacc3",
        short_id="ec2-ebs-delete-on-termination-disabled",
        detector="ec2_ebs_delete_on_termination_disabled",
        scenario="EC2 root EBS volume is retained after instance termination",
        remediation_summary="Review retention requirements before enabling delete-on-termination.",
        safety_level="high_risk",
        runtime_service="ec2",
        capabilities=("ec2.describe_instances",),
        objectives=("cost_optimization", "operations"),
        risk_detail="cost, operations",
    ),
}

EXECUTABLE_IAM_RULES: Dict[str, ExecutableRuleMapping] = {
    "314f0d94-7381-454d-915d-45b962d801e3": ExecutableRuleMapping(
        source_id="314f0d94-7381-454d-915d-45b962d801e3",
        short_id="iam-root-mfa-disabled",
        detector="iam_root_mfa_disabled",
        scenario="AWS account root user does not have MFA enabled",
        remediation_summary="Register and protect an MFA device for the root user.",
        safety_level="review_required",
    ),
    "e53ff93a-a43d-4580-bf17-a915dfeba8ce": ExecutableRuleMapping(
        source_id="e53ff93a-a43d-4580-bf17-a915dfeba8ce",
        short_id="iam-root-access-key-present",
        detector="iam_root_access_key_present",
        scenario="AWS account root user has an active access key",
        remediation_summary="Replace root access-key usage and remove the root access key.",
        safety_level="high_risk",
    ),
    "aead0be5-3b3f-4e96-b561-6bafc7162801": ExecutableRuleSpec(
        source_id="aead0be5-3b3f-4e96-b561-6bafc7162801",
        short_id="iam-password-policy-missing",
        detector="iam_password_policy_missing",
        scenario="IAM password policy is missing for an account with console users",
        remediation_summary="Define a reviewed IAM account password policy.",
        safety_level="review_required",
        capabilities=(
            "iam.get_account_password_policy",
            "iam.get_account_authorization_details",
            "iam.get_login_profile",
        ),
        objectives=("security", "operations"),
    ),
    "e3e22326-af1e-4fc5-89e6-757cf12a2f4a": ExecutableRuleSpec(
        source_id="e3e22326-af1e-4fc5-89e6-757cf12a2f4a",
        short_id="iam-console-user-mfa-disabled",
        detector="iam_console_user_mfa_disabled",
        scenario="IAM user with console access has no MFA device",
        remediation_summary="Register MFA for each IAM user that retains console access.",
        safety_level="review_required",
        capabilities=(
            "iam.get_account_authorization_details",
            "iam.get_login_profile",
            "iam.list_mfa_devices",
        ),
        objectives=("security",),
    ),
    "8c0a3d78-a5e3-4ac1-a1ca-f25306b46143": ExecutableRuleSpec(
        source_id="8c0a3d78-a5e3-4ac1-a1ca-f25306b46143",
        short_id="iam-access-key-older-than-90-days",
        detector="iam_access_key_older_than_90_days",
        scenario="Active IAM access key is older than the approved rotation window",
        remediation_summary="Replace dependent usage before deactivating and removing the old key.",
        safety_level="high_risk",
        aliases=(
            "85d589af-ca9b-4cb6-8311-6c9e50da0687",
            "13bddd8f-7a89-4fa4-8f4e-bce30b3da26c",
            "299fc2d0-a2f2-4b79-a3d2-2b479b25d07f",
        ),
        capabilities=("iam.get_account_authorization_details", "iam.list_access_keys"),
        parameters={"maximum_access_key_age_days": 90},
        objectives=("security", "operations"),
    ),
    "20da6654-9c4a-4b02-aaaf-5327efab6599": ExecutableRuleSpec(
        source_id="20da6654-9c4a-4b02-aaaf-5327efab6599",
        short_id="iam-policy-full-admin",
        detector="iam_policy_full_admin",
        scenario="IAM policy grants unrestricted Allow * on Resource *",
        remediation_summary="Replace unrestricted administration with reviewed least-privilege permissions.",
        safety_level="high_risk",
        capabilities=(
            "iam.get_account_authorization_details",
            "iam.get_policy",
            "iam.get_policy_version",
        ),
        objectives=("security",),
    ),
    "6a285348-b16e-4905-b347-09df596d02d5": ExecutableRuleSpec(
        source_id="6a285348-b16e-4905-b347-09df596d02d5",
        short_id="iam-policy-attached-directly-to-user",
        detector="iam_policy_attached_directly_to_user",
        scenario="IAM managed or inline policy is attached directly to a user",
        remediation_summary="Move permissions to a reviewed group or role before detaching user policies.",
        safety_level="high_risk",
        capabilities=("iam.get_account_authorization_details",),
        objectives=("security", "operations"),
    ),
}

EXECUTABLE_CLOUDTRAIL_RULES: Dict[str, ExecutableRuleMapping] = {
    "1a48e014-dc5b-4b3d-9e8a-4fa00ebd4223": ExecutableRuleMapping(
        source_id="1a48e014-dc5b-4b3d-9e8a-4fa00ebd4223",
        short_id="cloudtrail-multi-region-logging-disabled",
        detector="cloudtrail_multi_region_logging_disabled",
        scenario="No active multi-region CloudTrail trail records account activity",
        remediation_summary="Create or enable an actively logging multi-region trail.",
        safety_level="review_required",
    ),
    "450eb05d-23fe-47dc-83f0-4e13c1149c00": ExecutableRuleMapping(
        source_id="450eb05d-23fe-47dc-83f0-4e13c1149c00",
        short_id="cloudtrail-log-validation-disabled",
        detector="cloudtrail_log_validation_disabled",
        scenario="CloudTrail log file integrity validation is disabled",
        remediation_summary="Enable log file validation for the trail.",
        safety_level="review_required",
    ),
    "bbeaea1f-8aeb-4a4b-978c-7f05c0ed0722": ExecutableRuleMapping(
        source_id="bbeaea1f-8aeb-4a4b-978c-7f05c0ed0722",
        short_id="cloudtrail-kms-encryption-disabled",
        detector="cloudtrail_kms_encryption_disabled",
        scenario="CloudTrail logs are not encrypted with a customer-managed KMS key",
        remediation_summary="Configure a reviewed KMS key for CloudTrail log encryption.",
        safety_level="review_required",
    ),
    "3eae64a8-7a42-4ffc-b552-6e7a8555d3c3": ExecutableRuleMapping(
        source_id="3eae64a8-7a42-4ffc-b552-6e7a8555d3c3",
        short_id="cloudtrail-cloudwatch-integration-missing",
        detector="cloudtrail_cloudwatch_integration_missing",
        scenario="CloudTrail is not integrated with CloudWatch Logs",
        remediation_summary="Send CloudTrail events to a reviewed CloudWatch Logs group.",
        safety_level="review_required",
    ),
}

EXECUTABLE_RDS_RULES: Dict[str, ExecutableRuleMapping] = {
    "c0764b9f-5241-46c5-af3f-3bcf30721fec": ExecutableRuleMapping(
        source_id="c0764b9f-5241-46c5-af3f-3bcf30721fec",
        short_id="rds-publicly-accessible",
        detector="rds_publicly_accessible",
        scenario="RDS instance has a public network interface",
        remediation_summary="Move the database to private connectivity after validating application access.",
        safety_level="high_risk",
    ),
    "4a77b3fb-647d-4f79-8605-28d7ab946ad2": ExecutableRuleMapping(
        source_id="4a77b3fb-647d-4f79-8605-28d7ab946ad2",
        short_id="rds-storage-unencrypted",
        detector="rds_storage_unencrypted",
        scenario="RDS storage encryption is disabled",
        remediation_summary="Migrate the database to encrypted storage using a reviewed snapshot workflow.",
        safety_level="high_risk",
    ),
    "67c7713f-5866-4e0e-bd65-2fd445775878": ExecutableRuleMapping(
        source_id="67c7713f-5866-4e0e-bd65-2fd445775878",
        short_id="rds-multi-az-disabled",
        detector="rds_multi_az_disabled",
        scenario="RDS instance does not use Multi-AZ deployment for failover",
        remediation_summary="Evaluate and enable Multi-AZ for workloads requiring database failover.",
        safety_level="review_required",
    ),
    "b3c7e2d1-8a4f-4b6e-9c5d-7e1a8f3b2c4d": ExecutableRuleMapping(
        source_id="b3c7e2d1-8a4f-4b6e-9c5d-7e1a8f3b2c4d",
        short_id="rds-gp2-storage",
        detector="rds_gp2_storage",
        scenario="RDS instance uses GP2 storage instead of GP3",
        remediation_summary="Evaluate a GP3 storage migration using workload IOPS and throughput requirements.",
        safety_level="review_required",
        parameters={"cost_evidence_required": True},
    ),
    "3afeb36c-4c09-400f-8f70-13314ff8d578": ExecutableRuleSpec(
        source_id="3afeb36c-4c09-400f-8f70-13314ff8d578",
        short_id="rds-idle-instance",
        detector="rds_idle_instance",
        scenario="Available RDS instance has no database connections for seven days",
        remediation_summary="Validate application and retention dependencies before stopping or deleting the database.",
        safety_level="high_risk",
        capabilities=("rds.describe_db_instances", "cloudwatch.get_metric_data"),
        evaluation_kind="signal",
        parameters={"lookback_days": 7, "maximum_connections": 0.0},
        objectives=("cost_optimization",),
        risk_detail="cost",
    ),
}

EXECUTABLE_LAMBDA_RULES: Dict[str, ExecutableRuleMapping] = {
    "2cd8897d-8db5-4bde-8476-1edbe7f97894": ExecutableRuleMapping(
        source_id="2cd8897d-8db5-4bde-8476-1edbe7f97894",
        short_id="lambda-xray-tracing-disabled",
        detector="lambda_xray_tracing_disabled",
        scenario="Lambda function does not have active AWS X-Ray tracing",
        remediation_summary="Enable active tracing after reviewing trace volume, permissions, and cost.",
        safety_level="review_required",
    ),
    "5539e36a-7ff0-4feb-9edf-02a6a51ebd51": ExecutableRuleSpec(
        source_id="5539e36a-7ff0-4feb-9edf-02a6a51ebd51",
        short_id="lambda-admin-execution-role",
        detector="lambda_admin_execution_role",
        scenario="Lambda execution role has an unrestricted administrator policy",
        remediation_summary="Replace administrator permissions with the function's reviewed minimum actions.",
        safety_level="high_risk",
        capabilities=(
            "lambda.list_functions",
            "lambda.list_tags",
            "iam.list_attached_role_policies",
            "iam.list_role_policies",
            "iam.get_role_policy",
            "iam.get_policy",
            "iam.get_policy_version",
        ),
        objectives=("security",),
    ),
    "d814745d-a655-4612-9d03-07f7236cab77": ExecutableRuleSpec(
        source_id="d814745d-a655-4612-9d03-07f7236cab77",
        short_id="lambda-unused-function",
        detector="lambda_unused_function",
        scenario="Lambda function is older than 30 days and has no invocations in that period",
        remediation_summary="Confirm triggers and ownership before deleting or archiving the function.",
        safety_level="high_risk",
        capabilities=(
            "lambda.list_functions",
            "lambda.list_tags",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 30, "minimum_function_age_days": 30},
        objectives=("cost_optimization", "operations"),
        risk_detail="cost, operations",
    ),
    "59b90e10-df31-4a2e-9cd7-1a598eecb2a1": ExecutableRuleSpec(
        source_id="59b90e10-df31-4a2e-9cd7-1a598eecb2a1",
        short_id="lambda-high-error-rate",
        detector="lambda_high_error_rate",
        scenario="Lambda function has a daily error rate above 10 percent in the last seven days",
        remediation_summary="Inspect logs, traces, recent deployments, and upstream dependencies before changing code or retry behavior.",
        safety_level="review_required",
        capabilities=(
            "lambda.list_functions",
            "lambda.list_tags",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 7, "maximum_error_rate_percent": 10.0},
        objectives=("reliability", "operations", "cost_optimization"),
        risk_detail="reliability, operations, cost",
    ),
}


EXECUTABLE_EFS_RULES: Dict[str, ExecutableRuleMapping] = {
    "74b0f0d7-fcb8-46ed-beb4-3d3ec6ecbe64": ExecutableRuleSpec(
        source_id="74b0f0d7-fcb8-46ed-beb4-3d3ec6ecbe64",
        short_id="efs-encryption-disabled",
        detector="efs_encryption_disabled",
        scenario="EFS file system is not encrypted at rest",
        remediation_summary="Migrate data to a reviewed encrypted EFS file system.",
        safety_level="high_risk",
        capabilities=("efs.describe_file_systems",),
        objectives=("security",),
    ),
    "d5001002-ef02-4002-b002-002000000002": ExecutableRuleSpec(
        source_id="d5001002-ef02-4002-b002-002000000002",
        short_id="efs-lifecycle-policy-missing",
        detector="efs_lifecycle_policy_missing",
        scenario="EFS file system has no transition to an infrequent-access storage class",
        remediation_summary="Review access patterns before enabling an EFS lifecycle transition.",
        safety_level="review_required",
        capabilities=("efs.describe_file_systems", "efs.describe_lifecycle_configuration"),
        objectives=("cost_optimization",),
        risk_detail="cost",
    ),
}


EXECUTABLE_ECS_RULES: Dict[str, ExecutableRuleMapping] = {
    "b792ba90-f7d5-4324-938d-3213142d9d01": ExecutableRuleSpec(
        source_id="b792ba90-f7d5-4324-938d-3213142d9d01",
        short_id="ecs-unsafe-task-definition",
        detector="ecs_unsafe_task_definition",
        scenario="ECS task definition uses privileged containers or literal secret-like environment variables",
        remediation_summary="Create a reviewed task-definition revision using non-privileged containers and secret references.",
        safety_level="high_risk",
        capabilities=("ecs.list_task_definitions", "ecs.describe_task_definition"),
        objectives=("security",),
    ),
    "326eaec8-4b35-417d-b883-33c31948a9cd": ExecutableRuleSpec(
        source_id="326eaec8-4b35-417d-b883-33c31948a9cd",
        short_id="ecs-platform-version-outdated",
        detector="ecs_platform_version_outdated",
        scenario="ECS Fargate service is pinned to a platform version instead of LATEST",
        remediation_summary="Deploy a reviewed service update using the current Fargate platform.",
        safety_level="review_required",
        capabilities=("ecs.list_clusters", "ecs.list_services", "ecs.describe_services"),
        objectives=("security", "operations"),
    ),
}


EXECUTABLE_ALB_RULES: Dict[str, ExecutableRuleMapping] = {
    "8ac617e8-5a7a-4da8-8084-7ef5e5cbc74c": ExecutableRuleSpec(
        source_id="8ac617e8-5a7a-4da8-8084-7ef5e5cbc74c",
        short_id="alb-access-logging-disabled",
        detector="alb_access_logging_disabled",
        scenario="Application Load Balancer access logging is disabled",
        remediation_summary="Enable ALB access logging to an existing reviewed S3 destination.",
        safety_level="low_risk",
        runtime_service="alb",
        capabilities=(
            "elbv2.describe_load_balancers",
            "elbv2.describe_load_balancer_attributes",
            "elbv2.describe_tags",
        ),
        objectives=("security", "operations"),
    ),
    "b5337466-a827-460e-873e-613c28a101e4": ExecutableRuleSpec(
        source_id="b5337466-a827-460e-873e-613c28a101e4",
        short_id="alb-https-listener-missing",
        detector="alb_https_listener_missing",
        scenario="Internet-facing Application Load Balancer exposes HTTP without an HTTPS listener",
        remediation_summary="Add a reviewed HTTPS listener and redirect HTTP after validating clients.",
        safety_level="high_risk",
        runtime_service="alb",
        capabilities=(
            "elbv2.describe_load_balancers",
            "elbv2.describe_listeners",
            "elbv2.describe_tags",
        ),
        objectives=("security",),
    ),
    "00b372b2-8825-4bdf-834f-b10742dc715b": ExecutableRuleSpec(
        source_id="00b372b2-8825-4bdf-834f-b10742dc715b",
        short_id="alb-weak-tls-policy",
        detector="alb_weak_tls_policy",
        scenario="ALB listener security policy permits a TLS protocol older than TLS 1.2",
        remediation_summary="Test clients before changing the listener to a modern TLS policy.",
        safety_level="high_risk",
        runtime_service="alb",
        capabilities=(
            "elbv2.describe_load_balancers",
            "elbv2.describe_listeners",
            "elbv2.describe_ssl_policies",
            "elbv2.describe_tags",
        ),
        objectives=("security",),
    ),
    "38ef673f-016f-4b10-ba8c-e0ab9d15494a": ExecutableRuleSpec(
        source_id="38ef673f-016f-4b10-ba8c-e0ab9d15494a",
        short_id="alb-certificate-expiring",
        detector="alb_certificate_expiring",
        scenario="ALB listener certificate expires within 30 days",
        remediation_summary="Renew or replace the certificate before expiration, then verify every listener binding.",
        safety_level="review_required",
        runtime_service="alb",
        aliases=("255365fe-3007-414f-85b6-713846173847",),
        capabilities=(
            "elbv2.describe_load_balancers",
            "elbv2.describe_listeners",
            "elbv2.describe_listener_certificates",
            "elbv2.describe_tags",
            "acm.describe_certificate",
        ),
        parameters={"warning_days": 30, "critical_days": 7},
        objectives=("security", "reliability"),
    ),
    "01e58c92-8f90-4ef0-a438-e35bf01ecfd8": ExecutableRuleSpec(
        source_id="01e58c92-8f90-4ef0-a438-e35bf01ecfd8",
        short_id="alb-unhealthy-targets",
        detector="alb_unhealthy_targets",
        scenario="Application Load Balancer target group contains unhealthy registered targets",
        remediation_summary="Investigate health checks and workload state before changing registration or routing.",
        safety_level="review_required",
        runtime_service="alb",
        capabilities=(
            "elbv2.describe_load_balancers",
            "elbv2.describe_target_groups",
            "elbv2.describe_target_health",
            "elbv2.describe_tags",
        ),
        objectives=("reliability", "operations"),
    ),
    "475b24d9-4b5b-4ce4-8161-af25f89bee49": ExecutableRuleSpec(
        source_id="475b24d9-4b5b-4ce4-8161-af25f89bee49",
        short_id="alb-idle-load-balancer",
        detector="alb_idle_load_balancer",
        scenario="Application Load Balancer receives fewer than 100 requests per day for seven days",
        remediation_summary="Validate DNS, listeners, targets, and ownership before deleting the load balancer.",
        safety_level="high_risk",
        runtime_service="alb",
        aliases=(
            "f8873ffb-d1ce-44d2-adf9-50148350fc92",
            "75ba739e-a10d-4233-9d93-233587bf1de5",
        ),
        capabilities=(
            "elbv2.describe_load_balancers",
            "elbv2.describe_tags",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 7, "maximum_daily_requests": 100},
        objectives=("cost_optimization",),
        risk_detail="cost",
    ),
}


EXECUTABLE_KMS_RULES: Dict[str, ExecutableRuleMapping] = {
    "e2a5568c-90b0-4153-877d-246efb62ffad": ExecutableRuleSpec(
        source_id="e2a5568c-90b0-4153-877d-246efb62ffad",
        short_id="kms-key-rotation-disabled",
        detector="kms_key_rotation_disabled",
        scenario="Customer-managed symmetric KMS key has automatic key rotation disabled",
        remediation_summary=(
            "Review key consumers and the rotation period before enabling automatic rotation."
        ),
        safety_level="review_required",
        capabilities=(
            "kms.list_keys",
            "kms.describe_key",
            "kms.get_key_rotation_status",
            "kms.list_resource_tags",
        ),
        objectives=("security", "operations"),
    ),
}


EXECUTABLE_SECRETS_MANAGER_RULES: Dict[str, ExecutableRuleMapping] = {
    "4961a508-8ee9-4568-8236-b63c6acb4207": ExecutableRuleSpec(
        source_id="4961a508-8ee9-4568-8236-b63c6acb4207",
        short_id="secrets-manager-rotation-disabled",
        detector="secrets_manager_rotation_disabled",
        scenario="Active Secrets Manager secret does not have automatic rotation enabled",
        remediation_summary=(
            "Define and test a service-specific rotation strategy before enabling rotation."
        ),
        safety_level="high_risk",
        capabilities=(
            "secretsmanager.list_secrets",
            "secretsmanager.describe_secret",
        ),
        objectives=("security", "operations"),
    ),
}


EXECUTABLE_SNS_RULES: Dict[str, ExecutableRuleMapping] = {
    "e3b3d09c-82b1-48b3-ad01-6205fd754e00": ExecutableRuleSpec(
        source_id="e3b3d09c-82b1-48b3-ad01-6205fd754e00",
        short_id="sns-topic-encryption-disabled",
        detector="sns_topic_encryption_disabled",
        scenario="SNS topic does not use server-side encryption",
        remediation_summary=(
            "Enable SNS encryption with an AWS-managed or reviewed customer-managed KMS key."
        ),
        safety_level="review_required",
        capabilities=(
            "sns.list_topics",
            "sns.get_topic_attributes",
            "sns.list_tags_for_resource",
        ),
        objectives=("security",),
    ),
    "f90db437-325b-489b-9f05-6e813cb3524c": ExecutableRuleSpec(
        source_id="f90db437-325b-489b-9f05-6e813cb3524c",
        short_id="sns-topic-public-access",
        detector="sns_topic_public_access",
        scenario="SNS topic policy grants public access without a restricting condition",
        remediation_summary=(
            "Replace public topic permissions with reviewed principals and source conditions."
        ),
        safety_level="high_risk",
        capabilities=(
            "sns.list_topics",
            "sns.get_topic_attributes",
            "sns.list_tags_for_resource",
        ),
        objectives=("security",),
    ),
}


EXECUTABLE_SQS_RULES: Dict[str, ExecutableRuleMapping] = {
    "6c5fa948-aff9-4c05-ac0b-a1e3f532bcc4": ExecutableRuleSpec(
        source_id="6c5fa948-aff9-4c05-ac0b-a1e3f532bcc4",
        short_id="sqs-queue-encryption-disabled",
        detector="sqs_queue_encryption_disabled",
        scenario="SQS queue does not use server-side encryption",
        remediation_summary="Enable SSE-SQS or a reviewed KMS key and verify queue integrations.",
        safety_level="review_required",
        capabilities=(
            "sqs.list_queues",
            "sqs.get_queue_attributes",
            "sqs.list_queue_tags",
        ),
        objectives=("security",),
    ),
    "4f58c3ff-168e-4b6f-a628-ba279a021fe9": ExecutableRuleSpec(
        source_id="4f58c3ff-168e-4b6f-a628-ba279a021fe9",
        short_id="sqs-queue-public-access",
        detector="sqs_queue_public_access",
        scenario="SQS queue policy grants public access without a restricting condition",
        remediation_summary=(
            "Replace public queue permissions with reviewed principals and source conditions."
        ),
        safety_level="high_risk",
        capabilities=(
            "sqs.list_queues",
            "sqs.get_queue_attributes",
            "sqs.list_queue_tags",
        ),
        objectives=("security",),
    ),
}


EXECUTABLE_API_GATEWAY_RULES: Dict[str, ExecutableRuleMapping] = {
    "dca2e61d-15af-4931-a043-ff3b984a8e08": ExecutableRuleSpec(
        source_id="dca2e61d-15af-4931-a043-ff3b984a8e08",
        short_id="api-gateway-access-logging-disabled",
        detector="api_gateway_access_logging_disabled",
        scenario="Deployed API Gateway REST API stage does not publish access logs",
        remediation_summary=(
            "Configure structured access logs to an existing reviewed CloudWatch Logs group."
        ),
        safety_level="review_required",
        capabilities=(
            "apigateway.get_rest_apis",
            "apigateway.get_stages",
            "apigateway.get_tags",
        ),
        objectives=("security", "operations"),
    ),
    "bcf46b63-7bdb-4bcc-897a-70dde0abc60b": ExecutableRuleSpec(
        source_id="bcf46b63-7bdb-4bcc-897a-70dde0abc60b",
        short_id="api-gateway-execution-logging-disabled",
        detector="api_gateway_execution_logging_disabled",
        scenario="Deployed API Gateway REST API stage has execution logging disabled",
        remediation_summary=(
            "Enable ERROR or INFO execution logging without enabling production data tracing."
        ),
        safety_level="review_required",
        capabilities=(
            "apigateway.get_rest_apis",
            "apigateway.get_stages",
            "apigateway.get_resources",
            "apigateway.get_tags",
        ),
        objectives=("security", "operations"),
    ),
    "6ee0ddf4-c23a-443d-8e42-c1fa8dfde10a": ExecutableRuleSpec(
        source_id="6ee0ddf4-c23a-443d-8e42-c1fa8dfde10a",
        short_id="api-gateway-xray-tracing-disabled",
        detector="api_gateway_xray_tracing_disabled",
        scenario="Deployed API Gateway REST API stage has AWS X-Ray tracing disabled",
        remediation_summary=(
            "Review sampling, data handling, and cost before enabling active X-Ray tracing."
        ),
        safety_level="review_required",
        capabilities=(
            "apigateway.get_rest_apis",
            "apigateway.get_stages",
            "apigateway.get_tags",
        ),
        objectives=("operations",),
    ),
    "90de045c-f234-4b34-ab13-6e660ba2ab5a": ExecutableRuleSpec(
        source_id="90de045c-f234-4b34-ab13-6e660ba2ab5a",
        short_id="api-gateway-method-authorization-missing",
        detector="api_gateway_method_authorization_missing",
        scenario="API Gateway REST method allows unauthenticated access",
        remediation_summary=(
            "Confirm whether the method is intentionally public before configuring authorization."
        ),
        safety_level="high_risk",
        capabilities=(
            "apigateway.get_rest_apis",
            "apigateway.get_stages",
            "apigateway.get_resources",
            "apigateway.get_method",
            "apigateway.get_tags",
        ),
        objectives=("security",),
    ),
}


# v0.6 expands the deterministic free tier to 100 canonical rules. These
# mappings intentionally reuse reviewed catalog rows whose criteria match the
# implemented detector; aliases never increase the native-rule count.
EXECUTABLE_S3_RULES.update(
    {
        "73c98951-d7a6-4858-b14a-e209b16bb222": ExecutableRuleSpec(
            source_id="73c98951-d7a6-4858-b14a-e209b16bb222",
            short_id="s3-object-lock-required",
            detector="s3_object_lock_required",
            scenario="S3 bucket explicitly classified for WORM retention does not have Object Lock enabled",
            remediation_summary="Create a reviewed Object Lock configuration and retention policy before storing regulated data.",
            safety_level="high_risk",
            capabilities=(
                "s3.list_buckets",
                "s3.get_bucket_tagging",
                "s3.get_object_lock_configuration",
            ),
            objectives=("security", "reliability", "operations"),
            parameters={"requirement_tags": {"bluearch:object-lock-required": "true"}},
            risk_detail="security, reliability, operations",
        ),
        "5449c935-aa36-4885-86e0-fee05a533361": ExecutableRuleSpec(
            source_id="5449c935-aa36-4885-86e0-fee05a533361",
            short_id="s3-cloudtrail-access-logging-disabled",
            detector="s3_cloudtrail_access_logging_disabled",
            scenario="S3 bucket receiving CloudTrail logs does not have server access logging enabled",
            remediation_summary="Enable access logging to a separate reviewed destination bucket.",
            safety_level="review_required",
            capabilities=("s3.list_buckets", "s3.get_bucket_policy", "s3.get_bucket_logging"),
            objectives=("security", "operations"),
            risk_detail="security, operations",
        ),
        "b874846b-c586-47bf-a2fd-167ef2877f9f": ExecutableRuleSpec(
            source_id="b874846b-c586-47bf-a2fd-167ef2877f9f",
            short_id="s3-replication-required",
            detector="s3_replication_required",
            scenario="S3 bucket explicitly classified for cross-Region availability has no replication configuration",
            remediation_summary="Configure reviewed versioning, destination ownership, encryption, and replication rules.",
            safety_level="high_risk",
            capabilities=("s3.list_buckets", "s3.get_bucket_tagging", "s3.get_bucket_replication"),
            objectives=("reliability", "performance"),
            parameters={"requirement_tags": {"bluearch:replication-required": "true"}},
            risk_detail="reliability, performance",
        ),
        "83c3686a-7b31-478e-b388-453384ad53ba": ExecutableRuleSpec(
            source_id="83c3686a-7b31-478e-b388-453384ad53ba",
            short_id="s3-kms-encryption-required",
            detector="s3_kms_encryption_required",
            scenario="S3 bucket explicitly requiring KMS encryption uses no aws:kms default encryption rule",
            remediation_summary="Configure a reviewed KMS key and bucket default encryption after validating key-policy access.",
            safety_level="high_risk",
            capabilities=("s3.list_buckets", "s3.get_bucket_tagging", "s3.get_bucket_encryption"),
            objectives=("security", "operations"),
            parameters={"requirement_tags": {"bluearch:kms-required": "true"}},
            risk_detail="security, operations",
        ),
    }
)

EXECUTABLE_IAM_RULES.update(
    {
        "f2ee54dd-37e7-4118-80f9-f164d89f3a8f": ExecutableRuleSpec(
            source_id="f2ee54dd-37e7-4118-80f9-f164d89f3a8f",
            short_id="iam-password-policy-number-missing",
            detector="iam_password_policy_number_missing",
            scenario="IAM account password policy does not require at least one number",
            remediation_summary="Update the reviewed account password policy to require numbers.",
            safety_level="review_required",
            capabilities=("iam.get_account_password_policy",),
            objectives=("security",),
            risk_detail="security",
        ),
        "07f63c10-f164-4f31-95fb-57c07eb87261": ExecutableRuleSpec(
            source_id="07f63c10-f164-4f31-95fb-57c07eb87261",
            short_id="iam-support-role-missing",
            detector="iam_support_role_missing",
            scenario="AWS account has no role with the AWSSupportAccess managed policy",
            remediation_summary="Create a reviewed incident-support role with controlled trust and AWSSupportAccess.",
            safety_level="review_required",
            capabilities=("iam.get_account_authorization_details",),
            objectives=("security", "operations"),
            risk_detail="security, operations",
        ),
        "718ac930-9ba0-42a1-a31b-fad73f2a66da": ExecutableRuleSpec(
            source_id="718ac930-9ba0-42a1-a31b-fad73f2a66da",
            short_id="iam-role-wildcard-trust",
            detector="iam_role_wildcard_trust",
            scenario="IAM role trust policy allows an unconditional wildcard AWS principal",
            remediation_summary="Replace wildcard trust with reviewed principals and organization or external-ID conditions.",
            safety_level="high_risk",
            capabilities=("iam.get_account_authorization_details",),
            objectives=("security",),
            risk_detail="security",
        ),
        "a843c50e-63a8-4e20-8ef8-c7f6ec4a4500": ExecutableRuleSpec(
            source_id="a843c50e-63a8-4e20-8ef8-c7f6ec4a4500",
            short_id="iam-root-hardware-mfa-missing",
            detector="iam_root_hardware_mfa_missing",
            scenario="AWS root user does not have MFA enabled and therefore has no hardware MFA protection",
            remediation_summary="Register a phishing-resistant hardware MFA device for the root user.",
            safety_level="review_required",
            capabilities=("iam.get_account_summary",),
            objectives=("security",),
            risk_detail="security",
        ),
    }
)

EXECUTABLE_EC2_RULES.update(
    {
        "a2e6377a-b62c-47a6-b957-452e9b79883b": ExecutableRuleSpec(
            source_id="a2e6377a-b62c-47a6-b957-452e9b79883b",
            short_id="ec2-unused-security-group",
            detector="ec2_unused_security_group",
            scenario="Non-default EC2 security group is not attached to any network interface",
            remediation_summary="Confirm ownership and IaC references before deleting the unused security group.",
            safety_level="high_risk",
            runtime_service="ec2",
            capabilities=("ec2.describe_security_groups", "ec2.describe_network_interfaces"),
            objectives=("security", "operations"),
            risk_detail="security, operations",
        ),
        "0f5cfb3e-623b-4140-a5ed-db4b5be406f8": ExecutableRuleSpec(
            source_id="0f5cfb3e-623b-4140-a5ed-db4b5be406f8",
            short_id="ec2-gp2-volume-candidate",
            detector="ec2_gp2_volume_candidate",
            scenario="EBS gp2 volume is a candidate for a reviewed gp3 migration",
            remediation_summary="Compare workload IOPS and throughput before planning a gp3 migration.",
            safety_level="review_required",
            capabilities=("ec2.describe_volumes",),
            objectives=("cost_optimization", "performance"),
            risk_detail="cost, performance",
        ),
        "030f361e-eb21-4382-8d26-fcd86f47c8d5": ExecutableRuleSpec(
            source_id="030f361e-eb21-4382-8d26-fcd86f47c8d5",
            short_id="ec2-previous-generation-instance",
            detector="ec2_previous_generation_instance",
            scenario="Running EC2 instance uses a previous-generation instance family",
            remediation_summary="Benchmark a current-generation replacement and update IaC through a reviewed rollout.",
            safety_level="high_risk",
            capabilities=("ec2.describe_instances",),
            parameters={
                "previous_generation_families": (
                    "c1",
                    "c3",
                    "cc2",
                    "cg1",
                    "cr1",
                    "g2",
                    "hi1",
                    "hs1",
                    "i2",
                    "m1",
                    "m2",
                    "m3",
                    "r3",
                    "t1",
                )
            },
            objectives=("cost_optimization", "performance", "operations"),
            risk_detail="cost, performance, operations",
        ),
        "a0ffe81c-483b-448e-a899-884e5258a106": ExecutableRuleSpec(
            source_id="a0ffe81c-483b-448e-a899-884e5258a106",
            short_id="ec2-dev-schedule-missing",
            detector="ec2_dev_schedule_missing",
            scenario="Running development or test EC2 instance has no reviewed schedule tag",
            remediation_summary="Define an owner-approved start and stop schedule in IaC or automation.",
            safety_level="high_risk",
            capabilities=("ec2.describe_instances",),
            parameters={
                "environment_values": ("dev", "development", "test", "staging"),
                "schedule_tag_keys": ("schedule", "bluearch:schedule", "instance-schedule"),
            },
            objectives=("cost_optimization", "sustainability", "operations"),
            risk_detail="cost, sustainability, operations",
        ),
        "fb608bb0-abfd-4543-876d-b7d44bc64329": ExecutableRuleSpec(
            source_id="fb608bb0-abfd-4543-876d-b7d44bc64329",
            short_id="ec2-low-cpu-rightsizing",
            detector="ec2_low_cpu_rightsizing",
            scenario="Running EC2 instance has average CPU below 10 percent for 14 complete days",
            remediation_summary="Review workload peaks and dependencies before rightsizing the instance.",
            safety_level="high_risk",
            capabilities=("ec2.describe_instances", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 14, "maximum_average_cpu_percent": 10.0},
            objectives=("cost_optimization", "sustainability"),
            risk_detail="cost, sustainability",
        ),
        "f15adfc7-d970-4925-b0fb-99dbe1796d3b": ExecutableRuleSpec(
            source_id="f15adfc7-d970-4925-b0fb-99dbe1796d3b",
            short_id="ec2-high-cpu",
            detector="ec2_high_cpu",
            scenario="Running EC2 instance has maximum CPU above 90 percent for four or more days",
            remediation_summary="Investigate workload, scaling, and code bottlenecks before changing capacity.",
            safety_level="review_required",
            capabilities=("ec2.describe_instances", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={
                "lookback_days": 14,
                "minimum_breach_days": 4,
                "minimum_daily_cpu_percent": 90.0,
            },
            objectives=("performance", "reliability", "operations"),
            risk_detail="performance, reliability, operations",
        ),
        "03060d2d-96d3-43aa-ba18-2968fc8a7189": ExecutableRuleSpec(
            source_id="03060d2d-96d3-43aa-ba18-2968fc8a7189",
            short_id="ebs-magnetic-volume-overutilized",
            detector="ebs_magnetic_volume_overutilized",
            scenario="EBS magnetic volume sustains more than 100 read and write operations per second",
            remediation_summary="Benchmark an SSD replacement and migrate only through a reviewed storage plan.",
            safety_level="high_risk",
            runtime_service="ec2",
            capabilities=("ec2.describe_volumes", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "maximum_average_iops": 100.0},
            objectives=("performance", "reliability"),
            risk_detail="performance, reliability",
        ),
        "33fc1c4b-3302-4eb4-8f10-a43041c80105": ExecutableRuleSpec(
            source_id="33fc1c4b-3302-4eb4-8f10-a43041c80105",
            short_id="ebs-iops-saturation",
            detector="ebs_iops_saturation",
            scenario="EBS volume workload reaches at least 95 percent of provisioned IOPS",
            remediation_summary="Validate workload and queue-depth evidence before changing IOPS or volume type.",
            safety_level="high_risk",
            runtime_service="ec2",
            capabilities=("ec2.describe_volumes", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "minimum_utilization_percent": 95.0},
            objectives=("performance", "reliability"),
            risk_detail="performance, reliability",
        ),
    }
)

EXECUTABLE_RDS_RULES.update(
    {
        "a1f5645b-0bce-475a-b036-d34b9abd5dbb": ExecutableRuleSpec(
            source_id="a1f5645b-0bce-475a-b036-d34b9abd5dbb",
            short_id="rds-previous-generation-instance",
            detector="rds_previous_generation_instance",
            scenario="RDS instance uses a previous-generation DB instance class",
            remediation_summary="Benchmark a current-generation class and migrate through a reviewed maintenance plan.",
            safety_level="high_risk",
            capabilities=("rds.describe_db_instances",),
            parameters={
                "previous_generation_families": ("db.m1", "db.m2", "db.m3", "db.r3", "db.t1")
            },
            objectives=("cost_optimization", "performance", "operations"),
            risk_detail="cost, performance, operations",
        ),
        "a4d8f3e1-9c2b-4f7e-8a5d-6b1c9e3f2a4d": ExecutableRuleSpec(
            source_id="a4d8f3e1-9c2b-4f7e-8a5d-6b1c9e3f2a4d",
            short_id="rds-storage-autoscaling-disabled",
            detector="rds_storage_autoscaling_disabled",
            scenario="RDS instance does not configure a maximum storage autoscaling threshold",
            remediation_summary="Set a reviewed maximum storage threshold after validating engine and growth limits.",
            safety_level="review_required",
            capabilities=("rds.describe_db_instances",),
            objectives=("reliability", "cost_optimization"),
            risk_detail="reliability, cost",
        ),
        "d5daba29-69b4-4a46-8223-73ece5a7b5ef": ExecutableRuleSpec(
            source_id="d5daba29-69b4-4a46-8223-73ece5a7b5ef",
            short_id="rds-low-cpu-rightsizing",
            detector="rds_low_cpu_rightsizing",
            scenario="RDS instance has average CPU below 10 percent for seven complete days",
            remediation_summary="Review connections, memory, storage, and peaks before rightsizing the DB instance.",
            safety_level="high_risk",
            capabilities=("rds.describe_db_instances", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "maximum_average_cpu_percent": 10.0},
            objectives=("cost_optimization", "sustainability"),
            risk_detail="cost, sustainability",
        ),
        "b0c84bfb-87ed-4bc0-8cd5-76289fc81aa1": ExecutableRuleSpec(
            source_id="b0c84bfb-87ed-4bc0-8cd5-76289fc81aa1",
            short_id="rds-high-cpu",
            detector="rds_high_cpu",
            scenario="RDS instance has maximum CPU above 90 percent for three or more days",
            remediation_summary="Inspect query load, locks, memory, storage, and scaling options before changing capacity.",
            safety_level="review_required",
            capabilities=("rds.describe_db_instances", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={
                "lookback_days": 7,
                "minimum_breach_days": 3,
                "minimum_daily_cpu_percent": 90.0,
            },
            objectives=("performance", "reliability"),
            risk_detail="performance, reliability",
        ),
        "daff4201-ab90-42a9-a503-17ec9374a89e": ExecutableRuleSpec(
            source_id="daff4201-ab90-42a9-a503-17ec9374a89e",
            short_id="rds-read-heavy-no-replica",
            detector="rds_read_heavy_no_replica",
            scenario="Read-heavy RDS source instance has no read replica",
            remediation_summary="Validate consistency and failover requirements before adding a read replica or cache.",
            safety_level="high_risk",
            capabilities=("rds.describe_db_instances", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={
                "lookback_days": 7,
                "minimum_daily_read_iops": 100.0,
                "maximum_daily_write_iops": 20.0,
            },
            objectives=("performance", "reliability"),
            risk_detail="performance, reliability",
        ),
    }
)

EXECUTABLE_LAMBDA_RULES.update(
    {
        "51e22636-4dae-4f77-ab58-c4f4961013a2": ExecutableRuleSpec(
            source_id="51e22636-4dae-4f77-ab58-c4f4961013a2",
            short_id="lambda-timeout-rate-high",
            detector="lambda_timeout_rate_high",
            scenario="Lambda duration reaches at least 95 percent of configured timeout on more than 10 percent of observed days",
            remediation_summary="Investigate code and dependencies before increasing timeout or retry behavior.",
            safety_level="review_required",
            capabilities=("lambda.list_functions", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={
                "lookback_days": 7,
                "minimum_timeout_utilization_percent": 95.0,
                "minimum_breach_percentage": 10.0,
            },
            objectives=("reliability", "performance", "cost_optimization"),
            risk_detail="reliability, performance, cost",
        ),
        "44183041-c87c-4bf2-ab10-3a593057135a": ExecutableRuleSpec(
            source_id="44183041-c87c-4bf2-ab10-3a593057135a",
            short_id="lambda-memory-underutilized",
            detector="lambda_memory_underutilized",
            scenario="Lambda Insights reports memory utilization below 30 percent for seven complete days",
            remediation_summary="Benchmark lower memory settings before changing the function deployment configuration.",
            safety_level="review_required",
            capabilities=("lambda.list_functions", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "maximum_memory_utilization_percent": 30.0},
            objectives=("cost_optimization", "sustainability"),
            risk_detail="cost, sustainability",
        ),
        "f11f43fb-072f-4a2a-9a4a-2851f8bae0aa": ExecutableRuleSpec(
            source_id="f11f43fb-072f-4a2a-9a4a-2851f8bae0aa",
            short_id="lambda-memory-pressure",
            detector="lambda_memory_pressure",
            scenario="Lambda Insights reports memory utilization above 90 percent for seven complete days",
            remediation_summary="Inspect allocation and code memory behavior before increasing function memory.",
            safety_level="review_required",
            capabilities=("lambda.list_functions", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "minimum_memory_utilization_percent": 90.0},
            objectives=("performance", "reliability"),
            risk_detail="performance, reliability",
        ),
        "c8fd0f3c-90c1-45ec-9467-963920497527": ExecutableRuleSpec(
            source_id="c8fd0f3c-90c1-45ec-9467-963920497527",
            short_id="lambda-throttling-detected",
            detector="lambda_throttling_detected",
            scenario="Lambda function has one or more throttled invocations in the last seven days",
            remediation_summary="Inspect concurrency consumers and retry behavior before changing limits.",
            safety_level="review_required",
            capabilities=("lambda.list_functions", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "minimum_throttles": 1.0},
            objectives=("performance", "reliability", "operations"),
            risk_detail="performance, reliability, operations",
        ),
        "24a0eea7-9e43-4549-9c5d-17d1ddcaa4ef": ExecutableRuleSpec(
            source_id="24a0eea7-9e43-4549-9c5d-17d1ddcaa4ef",
            short_id="lambda-shared-execution-role",
            detector="lambda_shared_execution_role",
            scenario="Multiple Lambda functions share the same IAM execution role",
            remediation_summary="Create least-privilege function-specific roles through the owning IaC project.",
            safety_level="high_risk",
            capabilities=("lambda.list_functions",),
            objectives=("security", "operations"),
            risk_detail="security, operations",
        ),
        "b2c8d3e9-4f1a-5b6c-9d7e-1a8f4b5c6d7e": ExecutableRuleSpec(
            source_id="b2c8d3e9-4f1a-5b6c-9d7e-1a8f4b5c6d7e",
            short_id="lambda-provisioned-concurrency-underused",
            detector="lambda_provisioned_concurrency_underused",
            scenario="Lambda function has provisioned concurrency but fewer than ten invocations per day",
            remediation_summary="Validate latency requirements before reducing or scheduling provisioned concurrency.",
            safety_level="high_risk",
            capabilities=(
                "lambda.list_functions",
                "lambda.list_provisioned_concurrency_configs",
                "cloudwatch.get_metric_data",
            ),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "maximum_daily_invocations": 10.0},
            objectives=("cost_optimization",),
            risk_detail="cost",
        ),
        "1f780989-b697-4817-b38c-dee807324c6b": ExecutableRuleSpec(
            source_id="1f780989-b697-4817-b38c-dee807324c6b",
            short_id="lambda-duration-near-timeout",
            detector="lambda_duration_near_timeout",
            scenario="Lambda maximum duration exceeds 80 percent of configured timeout for three or more days",
            remediation_summary="Profile code and downstream calls before changing memory, timeout, or architecture.",
            safety_level="review_required",
            capabilities=("lambda.list_functions", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={
                "lookback_days": 7,
                "minimum_breach_days": 3,
                "minimum_timeout_utilization_percent": 80.0,
            },
            objectives=("performance", "reliability"),
            risk_detail="performance, reliability",
        ),
    }
)

EXECUTABLE_EFS_RULES.update(
    {
        "d5001001-ef01-4001-b001-001000000001": ExecutableRuleSpec(
            source_id="d5001001-ef01-4001-b001-001000000001",
            short_id="efs-inactive-unmounted",
            detector="efs_inactive_unmounted",
            scenario="EFS file system has no mount targets and no client activity for 30 complete days",
            remediation_summary="Confirm ownership and backups before deleting or archiving the file system.",
            safety_level="high_risk",
            capabilities=(
                "efs.describe_file_systems",
                "efs.describe_mount_targets",
                "cloudwatch.get_metric_data",
            ),
            evaluation_kind="signal",
            parameters={"lookback_days": 30},
            objectives=("cost_optimization", "operations"),
            risk_detail="cost, operations",
        ),
        "d5001004-ef04-4004-b004-004000000004": ExecutableRuleSpec(
            source_id="d5001004-ef04-4004-b004-004000000004",
            short_id="efs-throughput-overprovisioned",
            detector="efs_throughput_overprovisioned",
            scenario="Provisioned EFS throughput averages below 20 percent utilization for seven complete days",
            remediation_summary="Review peak throughput and workload guarantees before changing throughput mode.",
            safety_level="high_risk",
            capabilities=("efs.describe_file_systems", "cloudwatch.get_metric_data"),
            evaluation_kind="signal",
            parameters={"lookback_days": 7, "maximum_utilization_percent": 20.0},
            objectives=("cost_optimization", "sustainability"),
            risk_detail="cost, sustainability",
        ),
        "4e33a295-b0c0-4cb5-a8ac-942a08de57b3": ExecutableRuleSpec(
            source_id="4e33a295-b0c0-4cb5-a8ac-942a08de57b3",
            short_id="efs-customer-kms-key-missing",
            detector="efs_customer_kms_key_missing",
            scenario="EFS file system explicitly requiring a customer-managed KMS key does not use one",
            remediation_summary="Migrate to an encrypted EFS file system using a reviewed customer-managed KMS key.",
            safety_level="high_risk",
            capabilities=("efs.describe_file_systems",),
            parameters={"requirement_tags": {"bluearch:customer-kms-required": "true"}},
            objectives=("security", "operations"),
            risk_detail="security, operations",
        ),
    }
)

EXECUTABLE_ECS_RULES.update(
    {
        "4305d944-eb3c-473c-b9ce-99fe6911713b": ExecutableRuleSpec(
            source_id="4305d944-eb3c-473c-b9ce-99fe6911713b",
            short_id="ecs-inactive-task-definition",
            detector="ecs_inactive_task_definition",
            scenario="Inactive ECS task definition remains registered",
            remediation_summary="Confirm no service, rollback, or deployment references the revision before deregistration.",
            safety_level="high_risk",
            capabilities=("ecs.list_task_definitions", "ecs.describe_task_definition"),
            objectives=("operations",),
            risk_detail="operations",
        ),
        "57fdeba4-4823-4bd7-957f-5cb8b0d9f84e": ExecutableRuleSpec(
            source_id="57fdeba4-4823-4bd7-957f-5cb8b0d9f84e",
            short_id="ecs-service-health-degraded",
            detector="ecs_service_health_degraded",
            scenario="ECS service has fewer running tasks than its desired count",
            remediation_summary="Inspect deployments, events, task exits, capacity, and health checks before changing desired count.",
            safety_level="review_required",
            capabilities=("ecs.list_clusters", "ecs.list_services", "ecs.describe_services"),
            objectives=("reliability", "operations"),
            risk_detail="reliability, operations",
        ),
    }
)

EXECUTABLE_DYNAMODB_RULES: Dict[str, ExecutableRuleMapping] = {
    "b4839001-ddb1-4001-c001-001000000001": ExecutableRuleSpec(
        source_id="b4839001-ddb1-4001-c001-001000000001",
        short_id="dynamodb-inactive-table",
        detector="dynamodb_inactive_table",
        scenario="DynamoDB table has no reads or writes for 30 complete days",
        remediation_summary="Confirm consumers, backups, and retention before deleting or exporting the table.",
        safety_level="high_risk",
        capabilities=(
            "dynamodb.list_tables",
            "dynamodb.describe_table",
            "dynamodb.list_tags_of_resource",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 30},
        objectives=("cost_optimization", "operations"),
        risk_detail="cost, operations",
    ),
    "b4839002-ddb2-4002-c002-002000000002": ExecutableRuleSpec(
        source_id="b4839002-ddb2-4002-c002-002000000002",
        short_id="dynamodb-on-demand-low-utilization",
        detector="dynamodb_on_demand_low_utilization",
        scenario="On-demand DynamoDB table averages fewer than 100 read and write requests per day",
        remediation_summary="Compare actual traffic variability and reserved capacity economics before changing billing mode.",
        safety_level="high_risk",
        capabilities=(
            "dynamodb.list_tables",
            "dynamodb.describe_table",
            "dynamodb.list_tags_of_resource",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 14, "maximum_daily_requests": 100.0},
        objectives=("cost_optimization",),
        risk_detail="cost",
    ),
    "b4839003-ddb3-4003-c003-003000000003": ExecutableRuleSpec(
        source_id="b4839003-ddb3-4003-c003-003000000003",
        short_id="dynamodb-standard-ia-candidate",
        detector="dynamodb_standard_ia_candidate",
        scenario="Large DynamoDB Standard table is explicitly classified as infrequently accessed",
        remediation_summary="Validate storage and request cost before changing the table class.",
        safety_level="review_required",
        capabilities=(
            "dynamodb.list_tables",
            "dynamodb.describe_table",
            "dynamodb.list_tags_of_resource",
        ),
        parameters={
            "minimum_size_bytes": 1073741824,
            "requirement_tags": {"bluearch:infrequent-access": "true"},
        },
        objectives=("cost_optimization", "sustainability"),
        risk_detail="cost, sustainability",
    ),
    "b4839004-ddb4-4004-c004-004000000004": ExecutableRuleSpec(
        source_id="b4839004-ddb4-4004-c004-004000000004",
        short_id="dynamodb-read-capacity-underutilized",
        detector="dynamodb_read_capacity_underutilized",
        scenario="Provisioned DynamoDB read capacity averages below 20 percent utilization",
        remediation_summary="Review traffic peaks and auto scaling before lowering provisioned read capacity.",
        safety_level="high_risk",
        capabilities=(
            "dynamodb.list_tables",
            "dynamodb.describe_table",
            "dynamodb.list_tags_of_resource",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 14, "maximum_utilization_percent": 20.0},
        objectives=("cost_optimization", "sustainability"),
        risk_detail="cost, sustainability",
    ),
    "b4839005-ddb5-4005-c005-005000000005": ExecutableRuleSpec(
        source_id="b4839005-ddb5-4005-c005-005000000005",
        short_id="dynamodb-write-capacity-underutilized",
        detector="dynamodb_write_capacity_underutilized",
        scenario="Provisioned DynamoDB write capacity averages below 20 percent utilization",
        remediation_summary="Review traffic peaks and auto scaling before lowering provisioned write capacity.",
        safety_level="high_risk",
        capabilities=(
            "dynamodb.list_tables",
            "dynamodb.describe_table",
            "dynamodb.list_tags_of_resource",
            "cloudwatch.get_metric_data",
        ),
        evaluation_kind="signal",
        parameters={"lookback_days": 14, "maximum_utilization_percent": 20.0},
        objectives=("cost_optimization", "sustainability"),
        risk_detail="cost, sustainability",
    ),
}

EXECUTABLE_EKS_RULES: Dict[str, ExecutableRuleMapping] = {
    "66fe80cd-33a4-4176-8718-13f64147a423": ExecutableRuleSpec(
        source_id="66fe80cd-33a4-4176-8718-13f64147a423",
        short_id="eks-public-endpoint-open",
        detector="eks_public_endpoint_open",
        scenario="EKS cluster API endpoint is publicly reachable from unrestricted CIDRs",
        remediation_summary="Restrict public endpoint CIDRs or use a reviewed private access path.",
        safety_level="high_risk",
        capabilities=("eks.list_clusters", "eks.describe_cluster"),
        objectives=("security", "operations"),
        risk_detail="security, operations",
    ),
    "f5227b51-735c-4d67-897f-a905c3cab5dd": ExecutableRuleSpec(
        source_id="f5227b51-735c-4d67-897f-a905c3cab5dd",
        short_id="eks-private-endpoint-disabled",
        detector="eks_private_endpoint_disabled",
        scenario="EKS cluster private API endpoint is disabled while public access is enabled",
        remediation_summary="Validate a reachable private administration path before changing endpoints.",
        safety_level="high_risk",
        capabilities=("eks.list_clusters", "eks.describe_cluster"),
        objectives=("security", "operations"),
        risk_detail="security, operations",
    ),
    "61cedb38-f6a3-492b-b9a9-cdff2408305f": ExecutableRuleSpec(
        source_id="61cedb38-f6a3-492b-b9a9-cdff2408305f",
        short_id="eks-control-plane-logging-incomplete",
        detector="eks_control_plane_logging_incomplete",
        scenario="EKS control-plane logging omits one or more supported log types",
        remediation_summary="Enable missing log types with reviewed retention and cost settings.",
        safety_level="review_required",
        capabilities=("eks.list_clusters", "eks.describe_cluster"),
        parameters={
            "required_log_types": (
                "api",
                "audit",
                "authenticator",
                "controllerManager",
                "scheduler",
            )
        },
        objectives=("security", "operations"),
        risk_detail="security, operations",
    ),
    "414ff551-cee0-4aa9-9fe5-68dec58a90a1": ExecutableRuleSpec(
        source_id="414ff551-cee0-4aa9-9fe5-68dec58a90a1",
        short_id="eks-version-support-risk",
        detector="eks_version_support_risk",
        scenario="EKS Kubernetes version is in extended support or approaching end of support",
        remediation_summary="Validate workloads, add-ons, nodes, and rollback capacity before upgrading.",
        safety_level="high_risk",
        capabilities=(
            "eks.list_clusters",
            "eks.describe_cluster",
            "eks.describe_cluster_versions",
        ),
        parameters={"support_warning_days": 90, "critical_warning_days": 30},
        objectives=("security", "operations", "reliability"),
        risk_detail="security, operations, reliability",
    ),
    "38c186b1-36f2-4133-a6ef-9c1628f5c6f6": ExecutableRuleSpec(
        source_id="38c186b1-36f2-4133-a6ef-9c1628f5c6f6",
        short_id="eks-guardduty-runtime-monitoring-disabled",
        detector="eks_guardduty_runtime_monitoring_disabled",
        scenario="GuardDuty EKS Runtime Monitoring is not enabled",
        remediation_summary="Enable GuardDuty EKS Runtime Monitoring through a reviewed regional plan.",
        safety_level="review_required",
        capabilities=("guardduty.list_detectors", "guardduty.get_detector"),
        objectives=("security",),
        risk_detail="security",
    ),
    "17002d8c-9748-4ae1-8d70-0d747a78b64e": ExecutableRuleSpec(
        source_id="17002d8c-9748-4ae1-8d70-0d747a78b64e",
        short_id="eks-nodegroup-version-skew",
        detector="eks_nodegroup_version_skew",
        scenario="EKS managed node group Kubernetes version is behind its cluster version",
        remediation_summary="Review disruption budgets and spare capacity before upgrading the node group.",
        safety_level="high_risk",
        capabilities=(
            "eks.list_clusters",
            "eks.describe_cluster",
            "eks.list_nodegroups",
            "eks.describe_nodegroup",
        ),
        objectives=("operations", "reliability"),
        risk_detail="operations, reliability",
    ),
    "c6dea539-c4af-4428-9e81-2e34f7265acb": ExecutableRuleSpec(
        source_id="c6dea539-c4af-4428-9e81-2e34f7265acb",
        short_id="eks-nodegroup-ami-outdated",
        detector="eks_nodegroup_ami_outdated",
        scenario="EKS managed node group uses an outdated EKS-optimized AMI release",
        remediation_summary="Review launch templates, PDBs, and capacity before updating the AMI.",
        safety_level="high_risk",
        capabilities=(
            "eks.list_clusters",
            "eks.describe_cluster",
            "eks.list_nodegroups",
            "eks.describe_nodegroup",
            "ssm.get_parameter",
        ),
        objectives=("security", "operations", "reliability"),
        risk_detail="security, operations, reliability",
    ),
    "48ed2c60-b006-4f24-9e09-e7e3b6aa03b1": ExecutableRuleSpec(
        source_id="48ed2c60-b006-4f24-9e09-e7e3b6aa03b1",
        short_id="eks-nodegroup-health-degraded",
        detector="eks_nodegroup_health_degraded",
        scenario="EKS managed node group reports health issues",
        remediation_summary="Correlate AWS health issues with nodes, pods, events, and capacity.",
        safety_level="high_risk",
        capabilities=(
            "eks.list_clusters",
            "eks.describe_cluster",
            "eks.list_nodegroups",
            "eks.describe_nodegroup",
        ),
        objectives=("operations", "reliability"),
        risk_detail="operations, reliability",
    ),
    "1a7530de-a49e-4c19-b5ce-285e5ddc24c2": ExecutableRuleSpec(
        source_id="1a7530de-a49e-4c19-b5ce-285e5ddc24c2",
        short_id="eks-managed-addon-unhealthy",
        detector="eks_managed_addon_unhealthy",
        scenario="EKS managed add-on reports a degraded or failed status",
        remediation_summary="Correlate add-on health with kube-system pods and events before changing it.",
        safety_level="high_risk",
        capabilities=(
            "eks.list_clusters",
            "eks.describe_cluster",
            "eks.list_addons",
            "eks.describe_addon",
        ),
        objectives=("operations", "reliability"),
        risk_detail="operations, reliability",
    ),
    "43b72440-6061-4b3d-a245-587b5cf38f6e": ExecutableRuleSpec(
        source_id="43b72440-6061-4b3d-a245-587b5cf38f6e",
        short_id="eks-managed-addon-update-available",
        detector="eks_managed_addon_update_available",
        scenario="A compatible default version update is available for an EKS managed add-on",
        remediation_summary="Review compatibility, conflicts, workload health, and rollback before updating.",
        safety_level="review_required",
        capabilities=(
            "eks.list_clusters",
            "eks.describe_cluster",
            "eks.list_addons",
            "eks.describe_addon",
            "eks.describe_addon_versions",
        ),
        objectives=("security", "operations", "reliability"),
        risk_detail="security, operations, reliability",
    ),
    "5fc3d4a9-96ef-4bba-82e9-bccabe531b34": ExecutableRuleSpec(
        source_id="5fc3d4a9-96ef-4bba-82e9-bccabe531b34",
        short_id="eks-workload-overprovisioned",
        detector="eks_workload_overprovisioned",
        scenario="Kubernetes workload requests materially exceed observed P95 usage",
        remediation_summary="Generate a reviewed request change only after validating seasonality and autoscaling.",
        safety_level="high_risk",
        capabilities=("cloudwatch.get_metric_data",),
        evaluation_kind="signal",
        parameters={
            "lookback_days": 14,
            "minimum_completeness_percent": 70.0,
            "safety_margin": 1.4,
        },
        objectives=("cost_optimization", "performance_efficiency", "sustainability"),
        risk_detail="cost, performance",
    ),
}

EXECUTABLE_KUBERNETES_RULES: Dict[str, ExecutableRuleMapping] = {
    "1d2e851b-4f16-40bc-8a1b-89dd07c09a1e": ExecutableRuleSpec(
        source_id="1d2e851b-4f16-40bc-8a1b-89dd07c09a1e",
        short_id="k8s-workload-missing-resource-requests",
        detector="k8s_workload_missing_resource_requests",
        scenario="Kubernetes workload containers omit CPU or memory requests",
        remediation_summary="Measure representative usage before adding reviewed requests.",
        safety_level="review_required",
        runtime_service="eks",
        objectives=("performance_efficiency", "reliability", "cost_optimization"),
        risk_detail="performance, reliability, cost",
    ),
    "82ee867e-d1d8-4f7d-90b6-f24dcd20acef": ExecutableRuleSpec(
        source_id="82ee867e-d1d8-4f7d-90b6-f24dcd20acef",
        short_id="k8s-workload-missing-memory-limit",
        detector="k8s_workload_missing_memory_limit",
        scenario="Kubernetes workload containers omit memory limits",
        remediation_summary="Measure peak memory and add reviewed limits.",
        safety_level="review_required",
        runtime_service="eks",
        objectives=("performance_efficiency", "reliability"),
        risk_detail="performance, reliability",
    ),
    "5452b6e0-43df-44e0-a34d-362e9c2ac1d9": ExecutableRuleSpec(
        source_id="5452b6e0-43df-44e0-a34d-362e9c2ac1d9",
        short_id="k8s-workload-missing-probes",
        detector="k8s_workload_missing_probes",
        scenario="Kubernetes workload containers omit readiness or liveness probes",
        remediation_summary="Define application-specific probes and validate them in a staged rollout.",
        safety_level="high_risk",
        runtime_service="eks",
        objectives=("operations", "reliability"),
        risk_detail="operations, reliability",
    ),
    "a9d36d97-5c67-49bd-918f-994419830cab": ExecutableRuleSpec(
        source_id="a9d36d97-5c67-49bd-918f-994419830cab",
        short_id="k8s-workload-disruption-unprotected",
        detector="k8s_workload_disruption_unprotected",
        scenario="Replicated service-exposed Kubernetes workload has no PodDisruptionBudget",
        remediation_summary="Add a reviewed PDB that preserves availability without blocking maintenance.",
        safety_level="review_required",
        runtime_service="eks",
        objectives=("reliability", "operations"),
        risk_detail="reliability, operations",
    ),
    "45189c42-86bf-4a4f-a7fe-947e4c1ef8d0": ExecutableRuleSpec(
        source_id="45189c42-86bf-4a4f-a7fe-947e4c1ef8d0",
        short_id="k8s-workload-dangerous-privileges",
        detector="k8s_workload_dangerous_privileges",
        scenario="Kubernetes workload requests dangerous host or container privileges",
        remediation_summary="Remove unnecessary privileges in source manifests and validate the rollout.",
        safety_level="high_risk",
        runtime_service="eks",
        objectives=("security",),
        risk_detail="security",
    ),
    "f576861a-fe3d-4ce9-a1ba-2bc088d86d64": ExecutableRuleSpec(
        source_id="f576861a-fe3d-4ce9-a1ba-2bc088d86d64",
        short_id="k8s-pod-restart-loop",
        detector="k8s_pod_restart_loop",
        scenario="Kubernetes pod is repeatedly restarting or waiting in CrashLoopBackOff",
        remediation_summary="Correlate termination state, probes, resources, rollout, and events.",
        safety_level="high_risk",
        runtime_service="eks",
        parameters={"minimum_recent_restarts": 5},
        objectives=("reliability", "operations"),
        risk_detail="reliability, operations",
    ),
    "8e69205c-40e6-4f9f-80ba-3981a20913c4": ExecutableRuleSpec(
        source_id="8e69205c-40e6-4f9f-80ba-3981a20913c4",
        short_id="k8s-pod-unschedulable",
        detector="k8s_pod_unschedulable",
        scenario="Kubernetes pod remains unschedulable",
        remediation_summary="Explain the exact scheduler constraint before proposing a change.",
        safety_level="high_risk",
        runtime_service="eks",
        parameters={"minimum_unschedulable_minutes": 5},
        objectives=("reliability", "operations"),
        risk_detail="reliability, operations",
    ),
    "ee15e84f-3bfd-43fe-8751-1c4065b3c7dd": ExecutableRuleSpec(
        source_id="ee15e84f-3bfd-43fe-8751-1c4065b3c7dd",
        short_id="k8s-pod-cpu-limit-pressure",
        detector="k8s_pod_cpu_limit_pressure",
        scenario="Kubernetes pod CPU use remains close to its configured limit",
        remediation_summary="Review HPA, code behavior, and throttling-specific evidence before changing CPU.",
        safety_level="high_risk",
        runtime_service="eks",
        evaluation_kind="signal",
        parameters={"threshold_percent": 80.0, "minimum_breach_periods": 5, "periods": 6},
        objectives=("performance_efficiency", "reliability"),
        risk_detail="performance, reliability",
    ),
    "19711ad3-7aae-46e2-8d1d-936474ad1ba2": ExecutableRuleSpec(
        source_id="19711ad3-7aae-46e2-8d1d-936474ad1ba2",
        short_id="k8s-pod-memory-pressure",
        detector="k8s_pod_memory_pressure",
        scenario="Kubernetes pod has OOM termination or sustained memory pressure",
        remediation_summary="Correlate limits, working set, OOM termination, restarts, and node pressure.",
        safety_level="high_risk",
        runtime_service="eks",
        evaluation_kind="signal",
        parameters={"threshold_percent": 90.0, "minimum_breach_periods": 5, "periods": 6},
        objectives=("performance_efficiency", "reliability"),
        risk_detail="performance, reliability",
    ),
}

# Catalog ownership and runtime ownership are intentionally separate. Keep
# source IDs under their catalog file while routing execution to EC2.
EXECUTABLE_IAM_RULES["a2e6377a-b62c-47a6-b957-452e9b79883b"] = EXECUTABLE_EC2_RULES.pop(
    "a2e6377a-b62c-47a6-b957-452e9b79883b"
)
for _ebs_source_id in (
    "03060d2d-96d3-43aa-ba18-2968fc8a7189",
    "33fc1c4b-3302-4eb4-8f10-a43041c80105",
):
    EXECUTABLE_EBS_RULES[_ebs_source_id] = EXECUTABLE_EC2_RULES.pop(_ebs_source_id)

EXECUTABLE_RULES_BY_SERVICE = {
    "alb-elb": EXECUTABLE_ALB_RULES,
    "api-gateway": EXECUTABLE_API_GATEWAY_RULES,
    "cloudtrail": EXECUTABLE_CLOUDTRAIL_RULES,
    "cloudwatch": EXECUTABLE_CLOUDWATCH_RULES,
    "dynamodb": EXECUTABLE_DYNAMODB_RULES,
    "ebs": EXECUTABLE_EBS_RULES,
    "ec2": EXECUTABLE_EC2_RULES,
    "ecs": EXECUTABLE_ECS_RULES,
    "efs": EXECUTABLE_EFS_RULES,
    "eks": EXECUTABLE_EKS_RULES,
    "iam": EXECUTABLE_IAM_RULES,
    "kms": EXECUTABLE_KMS_RULES,
    "kubernetes": EXECUTABLE_KUBERNETES_RULES,
    "lambda": EXECUTABLE_LAMBDA_RULES,
    "networking": EXECUTABLE_NETWORKING_RULES,
    "rds": EXECUTABLE_RDS_RULES,
    "s3": EXECUTABLE_S3_RULES,
    "secrets-manager": EXECUTABLE_SECRETS_MANAGER_RULES,
    "sns": EXECUTABLE_SNS_RULES,
    "sqs": EXECUTABLE_SQS_RULES,
}

DEFAULT_EXECUTABLE_SERVICES = tuple(sorted(EXECUTABLE_RULES_BY_SERVICE))


def default_catalog_output_path() -> Path:
    return Path(__file__).resolve().parent / "catalog" / "rules.json"


def default_full_catalog_output_path() -> Path:
    return Path(__file__).resolve().parent / "catalog" / "full_rules.json"


def build_catalog_from_misconfig_db(
    source_root: Path,
    services: Iterable[str] = DEFAULT_EXECUTABLE_SERVICES,
) -> Dict[str, Any]:
    rules: List[Rule] = []
    skipped: Dict[str, int] = {}
    for service in services:
        service_rules, skipped_count = _load_service_rules(source_root, service)
        rules.extend(service_rules)
        skipped[service] = skipped_count

    return {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "source": CATALOG_SOURCE,
        "rules": [
            _rule_to_json(rule)
            for rule in sorted(rules, key=lambda item: (item.service, item.short_id))
        ],
        "sync": {
            "services": sorted(set(services)),
            "imported_rules": len(rules),
            "skipped_unsupported_rules": skipped,
        },
    }


def write_catalog_from_misconfig_db(
    source_root: Path, output_path: Path | None = None
) -> Dict[str, Any]:
    target = output_path or default_catalog_output_path()
    payload = build_catalog_from_misconfig_db(source_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return payload


def catalog_matches(source_root: Path, output_path: Path | None = None) -> bool:
    target = output_path or default_catalog_output_path()
    expected = (
        json.dumps(build_catalog_from_misconfig_db(source_root), indent=2, sort_keys=False) + "\n"
    )
    try:
        actual = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    return actual == expected


def build_full_catalog_from_misconfig_db(source_root: Path) -> Dict[str, Any]:
    """Compile every source row while keeping detector support product-owned."""

    rules: List[Dict[str, Any]] = []
    seen_ids = set()
    for source_file in sorted((source_root / "data" / "by-service").glob("*.json")):
        with source_file.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        service_key = source_file.stem
        for entry in payload.get("misconfigurations", []):
            rule_id = str(entry.get("id") or "").strip()
            if not rule_id:
                raise ValueError(f"Catalog row without an id in {source_file}")
            if rule_id in seen_ids:
                raise ValueError(f"Duplicate catalog rule id: {rule_id}")
            seen_ids.add(rule_id)
            rules.append(_full_rule_from_entry(entry, service_key, source_file.name))

    rules.sort(key=lambda item: (item["service"], item["scenario"].lower(), item["id"]))
    mode_counts = Counter(rule["evaluation"]["mode"] for rule in rules)
    service_counts = Counter(rule["service"] for rule in rules)
    return {
        "schema_version": FULL_CATALOG_SCHEMA_VERSION,
        "source": CATALOG_SOURCE,
        "rules": rules,
        "sync": {
            "catalog_rules": len(rules),
            "catalog_services": len(service_counts),
            "rules_by_evaluation_mode": {
                mode: mode_counts.get(mode, 0) for mode in EVALUATION_MODES
            },
            "rules_by_service": dict(sorted(service_counts.items())),
        },
    }


def write_full_catalog_from_misconfig_db(
    source_root: Path,
    output_path: Path | None = None,
) -> Dict[str, Any]:
    target = output_path or default_full_catalog_output_path()
    payload = build_full_catalog_from_misconfig_db(source_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    return payload


def full_catalog_matches(source_root: Path, output_path: Path | None = None) -> bool:
    target = output_path or default_full_catalog_output_path()
    expected = (
        json.dumps(build_full_catalog_from_misconfig_db(source_root), indent=2, sort_keys=False)
        + "\n"
    )
    try:
        actual = target.read_text(encoding="utf-8")
    except FileNotFoundError:
        return False
    return actual == expected


def _load_service_rules(source_root: Path, service: str) -> tuple[List[Rule], int]:
    mappings = EXECUTABLE_RULES_BY_SERVICE.get(service, {})
    source_file = source_root / "data" / "by-service" / f"{service}.json"
    if not source_file.exists():
        return [], 0
    with source_file.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    imported: List[Rule] = []
    total = 0
    for entry in payload.get("misconfigurations", []):
        total += 1
        mapping = mappings.get(str(entry.get("id") or ""))
        if not mapping:
            continue
        imported.append(_rule_from_entry(entry, mapping))
    return imported, max(0, total - len(imported))


def _rule_from_entry(entry: Dict[str, Any], mapping: ExecutableRuleMapping) -> Rule:
    return Rule(
        id=str(entry["id"]),
        short_id=mapping.short_id,
        service=mapping.runtime_service or str(entry.get("service_name") or "unknown"),
        scenario=mapping.scenario,
        risk_detail=mapping.risk_detail or str(entry.get("risk_detail") or ""),
        severity=_severity_from_risk_value(entry.get("risk_value")),
        detector=mapping.detector,
        remediation={
            "summary": mapping.remediation_summary,
            "safety_level": mapping.safety_level,
            "requires_approval": mapping.requires_approval,
        },
        parameters=mapping.parameters,
        catalog_service=str(entry.get("service_name") or "unknown"),
        capabilities=list(mapping.capabilities),
        evaluation_kind=mapping.evaluation_kind,
        objectives=list(mapping.objectives),
        access_tier=mapping.access_tier,
    )


def _full_rule_from_entry(
    entry: Dict[str, Any],
    service_key: str,
    source_file: str,
) -> Dict[str, Any]:
    raw_metadata = entry.get("metadata")
    metadata: Dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    evaluation = _evaluation_from_entry(entry)
    mapping = _executable_mapping_by_source_id().get(str(entry.get("id") or ""))
    source_metadata_keys = (
        "source",
        "updated_at",
        "detection_status",
        "detector_status",
        "support_reason",
        "roadmap_phase",
        "well_architected_pillar",
        "well_architected_best_practice",
    )
    return {
        "id": str(entry["id"]),
        "short_id": evaluation["short_id"],
        "service": service_key,
        "service_name": str(entry.get("service_name") or service_key),
        "runtime_service": mapping.runtime_service or service_key if mapping else None,
        "scenario": str(entry.get("scenario") or ""),
        "alert_criteria": str(entry.get("alert_criteria") or ""),
        "recommendation_action": str(entry.get("recommendation_action") or ""),
        "risk_detail": (
            mapping.risk_detail
            if mapping and mapping.risk_detail
            else str(entry.get("risk_detail") or "")
        ),
        "severity": _severity_from_risk_value(entry.get("risk_value")),
        "detector": evaluation["detector"],
        "automated": evaluation["automated"],
        "build_priority": entry.get("build_priority"),
        "action_value": entry.get("action_value"),
        "effort_level": entry.get("effort_level"),
        "risk_value": entry.get("risk_value"),
        "description": str(entry.get("recommendation_description_detailed") or ""),
        "category": entry.get("category"),
        "output_notes": entry.get("output_notes"),
        "notes": entry.get("notes"),
        "pillars": list(entry.get("pillars") or []),
        "external_refs": dict(entry.get("external_refs") or {}),
        "compliance_mappings": list(entry.get("compliance_mappings") or []),
        "detection_methods": list(entry.get("detection_methods") or []),
        "references": list(entry.get("references") or []),
        "aws_doc_url": entry.get("aws_doc_url"),
        "tags": list(entry.get("tags") or []),
        "source": {
            "repository": CATALOG_SOURCE,
            "file": source_file,
            **{key: metadata[key] for key in source_metadata_keys if metadata.get(key) is not None},
        },
        "evaluation": evaluation,
    }


def _evaluation_from_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    rule_id = str(entry.get("id") or "")
    mapping = _executable_mapping_by_source_id().get(rule_id)
    if mapping:
        return {
            "mode": EVALUATION_MODE_NATIVE,
            "automated": True,
            "short_id": mapping.short_id,
            "detector": mapping.detector,
            "support_reason": "Implemented by a deterministic BlueArch AWS Steward detector.",
            "runtime_service": mapping.runtime_service,
            "capabilities": list(mapping.capabilities),
            "evaluation_kind": mapping.evaluation_kind,
            "access_tier": mapping.access_tier,
        }

    alias = _executable_aliases_by_source_id().get(rule_id)
    if alias:
        return {
            "mode": EVALUATION_MODE_ALIAS,
            "automated": False,
            "short_id": alias.short_id,
            "detector": alias.detector,
            "canonical_source_id": alias.source_id,
            "support_reason": "Catalog alias evaluated by the canonical native detector; not counted as another rule.",
            "runtime_service": alias.runtime_service,
            "capabilities": list(alias.capabilities),
            "evaluation_kind": alias.evaluation_kind,
        }

    raw_metadata = entry.get("metadata")
    metadata: Dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
    raw_methods = entry.get("detection_methods")
    methods: List[Any] = raw_methods if isinstance(raw_methods, list) else []
    method_names = {
        str(method.get("method") or "").strip().lower()
        for method in methods
        if isinstance(method, dict)
    }
    detector_status = str(metadata.get("detector_status") or "").strip().lower()
    if detector_status == "manual_review" or any("manual" in method for method in method_names):
        mode = EVALUATION_MODE_MANUAL
        default_reason = "This catalog rule requires human or organizational evidence."
    elif "resource metadata roadmap" in method_names:
        mode = EVALUATION_MODE_METADATA
        default_reason = (
            "A typed resource metadata collector and predicate are not implemented yet."
        )
    elif method_names:
        mode = EVALUATION_MODE_SIGNAL
        default_reason = (
            "This rule requires an external AWS metric, log, flow, or performance signal adapter."
        )
    elif detector_status == "planned":
        mode = EVALUATION_MODE_METADATA
        default_reason = (
            "A typed resource metadata collector and predicate are not implemented yet."
        )
    else:
        mode = EVALUATION_MODE_SPECIFICATION
        default_reason = (
            "The catalog row needs a reviewed detector specification before automation."
        )
    return {
        "mode": mode,
        "automated": False,
        "short_id": None,
        "detector": None,
        "support_reason": str(metadata.get("support_reason") or default_reason),
    }


def _executable_mapping_by_source_id() -> Dict[str, ExecutableRuleMapping]:
    return {
        source_id: mapping
        for mappings in EXECUTABLE_RULES_BY_SERVICE.values()
        for source_id, mapping in mappings.items()
    }


def _executable_aliases_by_source_id() -> Dict[str, ExecutableRuleMapping]:
    return {
        alias: mapping
        for mappings in EXECUTABLE_RULES_BY_SERVICE.values()
        for mapping in mappings.values()
        for alias in mapping.aliases
    }


def _severity_from_risk_value(value: Any) -> str:
    try:
        numeric_value = int(value)
    except (TypeError, ValueError):
        return "medium"
    if numeric_value >= 3:
        return "high"
    if numeric_value <= 1:
        return "low"
    return "medium"


def _rule_to_json(rule: Rule) -> Dict[str, Any]:
    return {
        "id": rule.id,
        "short_id": rule.short_id,
        "service": rule.service,
        "scenario": rule.scenario,
        "risk_detail": rule.risk_detail,
        "severity": rule.severity,
        "detector": rule.detector,
        "remediation": rule.remediation,
        "parameters": rule.parameters,
        "catalog_service": rule.catalog_service,
        "capabilities": rule.capabilities,
        "evaluation_kind": rule.evaluation_kind,
        "objectives": rule.objectives,
        "access_tier": rule.access_tier,
    }
