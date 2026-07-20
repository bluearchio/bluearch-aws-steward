from __future__ import annotations

import hashlib
import hmac
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from threading import Lock
from typing import Any, Dict, Optional
from urllib.parse import unquote
from uuid import uuid4

from bluearch_aws_steward.detectors.aws_common import policy_document
from bluearch_aws_steward.providers.base import AwsProvider

JSON = Dict[str, Any]
PLAN_SCHEMA_VERSION = "1.0"
DEFAULT_PLAN_TTL_SECONDS = 600
CLOUDWATCH_RETENTION_DAYS = (
    1,
    3,
    5,
    7,
    14,
    30,
    60,
    90,
    120,
    150,
    180,
    365,
    400,
    545,
    731,
    1096,
    1827,
    2192,
    2557,
    2922,
    3288,
    3653,
)
S3_LIFECYCLE_STORAGE_CLASSES = (
    "STANDARD_IA",
    "INTELLIGENT_TIERING",
    "GLACIER_IR",
    "GLACIER",
    "DEEP_ARCHIVE",
)


REMEDIATION_MANIFEST: Dict[str, JSON] = {
    "s3-public-bucket": {
        "read_actions": [
            "s3:ListAllMyBuckets",
            "s3:GetBucketPublicAccessBlock",
            "s3:GetBucketPolicy",
        ],
        "iam_actions": ["s3:PutBucketPublicAccessBlock"],
        "operation": "s3.PutPublicAccessBlock",
        "blast_radius": "single_bucket",
        "downtime": "none_expected",
        "warnings": [
            "Applications that intentionally rely on public bucket access may stop working.",
            "Bucket policy statements are not removed by this operation and still require review.",
        ],
        "rollback": "Restore the previously captured public access block only after reviewing the bucket policy.",
    },
    "s3-no-default-encryption": {
        "read_actions": ["s3:ListAllMyBuckets", "s3:GetEncryptionConfiguration"],
        "iam_actions": ["s3:PutEncryptionConfiguration"],
        "operation": "s3.PutBucketEncryption",
        "blast_radius": "single_bucket",
        "downtime": "none_expected",
        "warnings": [
            "The setting applies to newly written objects; it does not re-encrypt existing objects."
        ],
        "rollback": "Removing default encryption is possible but is not automated by Steward.",
    },
    "s3-no-lifecycle": {
        "read_actions": ["s3:ListAllMyBuckets", "s3:GetLifecycleConfiguration"],
        "iam_actions": ["s3:PutLifecycleConfiguration"],
        "operation": "s3.PutBucketLifecycleConfiguration",
        "blast_radius": "single_bucket",
        "downtime": "none_expected",
        "warnings": [
            "Lifecycle transitions can create retrieval charges and minimum-storage-duration charges.",
            "Confirm retention, legal hold, replication, and application access requirements first.",
        ],
        "rollback": "Remove the Steward lifecycle rule after reviewing objects already transitioned.",
    },
    "s3-versioning-disabled": {
        "read_actions": ["s3:ListAllMyBuckets", "s3:GetBucketVersioning"],
        "iam_actions": ["s3:PutBucketVersioning"],
        "operation": "s3.PutBucketVersioning",
        "blast_radius": "single_bucket",
        "downtime": "none_expected",
        "warnings": [
            "Versioning can increase storage cost.",
            "A never-versioned bucket cannot be restored exactly after versioning is enabled; it can only be suspended.",
        ],
        "rollback": "Suspend versioning after review; the original never-versioned state cannot be restored exactly.",
    },
    "cloudwatch-log-retention-missing": {
        "read_actions": ["logs:DescribeLogGroups"],
        "iam_actions": ["logs:PutRetentionPolicy"],
        "operation": "logs.PutRetentionPolicy",
        "blast_radius": "single_log_group",
        "downtime": "none_expected",
        "warnings": [
            "CloudWatch Logs permanently deletes events older than the selected retention period.",
            "Export logs required for audit, incident response, or recovery before applying the policy.",
        ],
        "rollback": "Delete the retention policy to retain new events indefinitely; deleted historical events cannot be recovered.",
    },
    "cloudtrail-log-validation-disabled": {
        "read_actions": ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"],
        "iam_actions": ["cloudtrail:UpdateTrail"],
        "operation": "cloudtrail.UpdateTrail",
        "blast_radius": "single_trail",
        "downtime": "none_expected",
        "warnings": [
            "Digest files are produced for newly delivered logs; existing logs are not retroactively covered."
        ],
        "rollback": "Disable log file validation on the same trail after explicit review.",
    },
    "s3-server-access-logging-disabled": {
        "read_actions": [
            "s3:ListAllMyBuckets",
            "s3:GetBucketLogging",
            "s3:GetBucketLocation",
            "s3:GetBucketPolicy",
            "s3:GetEncryptionConfiguration",
        ],
        "iam_actions": ["s3:PutBucketLogging"],
        "operation": "s3.PutBucketLogging",
        "blast_radius": "single_bucket",
        "downtime": "none_expected",
        "warnings": [
            "The destination bucket must already exist and allow S3 log delivery.",
            "Steward does not create or modify the destination bucket, its policy, encryption, or retention.",
            "Log delivery is best effort and increases storage and request cost.",
        ],
        "rollback": "Disable source-bucket logging manually after preserving required delivered logs.",
    },
    "alb-access-logging-disabled": {
        "read_actions": [
            "elasticloadbalancing:DescribeLoadBalancers",
            "elasticloadbalancing:DescribeLoadBalancerAttributes",
            "s3:ListAllMyBuckets",
            "s3:GetBucketLocation",
            "s3:GetBucketPolicy",
            "s3:GetEncryptionConfiguration",
        ],
        "iam_actions": ["elasticloadbalancing:ModifyLoadBalancerAttributes"],
        "operation": "elasticloadbalancing.ModifyLoadBalancerAttributes",
        "blast_radius": "single_load_balancer",
        "downtime": "none_expected",
        "warnings": [
            "The destination bucket must already exist in the load balancer Region and allow ALB log delivery.",
            "Steward does not create or modify bucket policies, encryption, retention, or destination infrastructure.",
            "Access logs increase S3 storage and request cost.",
        ],
        "rollback": "Disable ALB access logging manually after preserving required delivered logs.",
    },
}


class RemediationPlanError(ValueError):
    pass


class RemediationPlanStore:
    def __init__(
        self, *, ttl_seconds: int = DEFAULT_PLAN_TTL_SECONDS, max_plans: int = 100
    ) -> None:
        self._ttl = timedelta(seconds=max(1, ttl_seconds))
        self._max_plans = max(1, max_plans)
        self._plans: Dict[str, JSON] = {}
        self._lock = Lock()

    def create(self, document: JSON, finding: JSON) -> JSON:
        now = datetime.now(timezone.utc)
        plan = deepcopy(document)
        plan["schema_version"] = PLAN_SCHEMA_VERSION
        plan["plan_id"] = f"plan_{uuid4().hex}"
        plan["created_at"] = _iso(now)
        plan["expires_at"] = _iso(now + self._ttl)
        plan["status"] = "awaiting_approval"
        plan["plan_digest"] = _plan_digest(plan)

        with self._lock:
            self._cleanup_locked(now)
            self._make_room_locked()
            self._plans[plan["plan_id"]] = {
                "plan": deepcopy(plan),
                "finding": deepcopy(finding),
                "status": "awaiting_approval",
            }
        return plan

    def get(self, plan_id: str, plan_digest: str) -> JSON:
        if not plan_id or not plan_digest:
            raise RemediationPlanError("plan_id and plan_digest are required.")
        now = datetime.now(timezone.utc)
        with self._lock:
            self._cleanup_locked(now)
            stored = self._plans.get(plan_id)
            if stored is None:
                raise RemediationPlanError(
                    "Remediation plan was not found or has expired. Create a new plan."
                )
            expected_digest = str(stored["plan"].get("plan_digest") or "")
            if not hmac.compare_digest(expected_digest, str(plan_digest)):
                raise RemediationPlanError(
                    "Remediation plan digest does not match the server-held plan."
                )
            if stored["status"] != "awaiting_approval":
                raise RemediationPlanError(
                    f"Remediation plan is already {stored['status']} and cannot be replayed."
                )
            return deepcopy(stored)

    def claim(self, plan_id: str, plan_digest: str) -> JSON:
        if not plan_id or not plan_digest:
            raise RemediationPlanError("plan_id and plan_digest are required.")
        now = datetime.now(timezone.utc)
        with self._lock:
            self._cleanup_locked(now)
            stored = self._plans.get(plan_id)
            if stored is None:
                raise RemediationPlanError(
                    "Remediation plan was not found or has expired. Create a new plan."
                )
            expected_digest = str(stored["plan"].get("plan_digest") or "")
            if not hmac.compare_digest(expected_digest, str(plan_digest)):
                raise RemediationPlanError(
                    "Remediation plan digest does not match the server-held plan."
                )
            if stored["status"] != "awaiting_approval":
                raise RemediationPlanError(
                    f"Remediation plan is already {stored['status']} and cannot be replayed."
                )
            stored["status"] = "applying"
            stored["plan"]["status"] = "applying"
            return deepcopy(stored)

    def mark_completed(self, plan_id: str, status: str) -> None:
        if status not in {
            "applied",
            "applied_unverified",
            "apply_failed",
            "no_change_required",
            "stale",
        }:
            raise ValueError(f"Unsupported terminal remediation plan status: {status}")
        with self._lock:
            stored = self._plans.get(plan_id)
            if stored is not None:
                stored["status"] = status
                stored["plan"]["status"] = status

    def _cleanup_locked(self, now: datetime) -> None:
        expired = [
            plan_id
            for plan_id, stored in self._plans.items()
            if _parse_iso(str(stored["plan"].get("expires_at") or "")) <= now
        ]
        for plan_id in expired:
            del self._plans[plan_id]

    def _make_room_locked(self) -> None:
        if len(self._plans) < self._max_plans:
            return
        oldest = min(
            self._plans,
            key=lambda plan_id: str(self._plans[plan_id]["plan"].get("created_at") or ""),
        )
        del self._plans[oldest]


def is_apply_supported(value: Any) -> bool:
    if isinstance(value, dict):
        rule = value.get("rule_short_id") or value.get("rule")
    else:
        rule = value
    return str(rule or "") in REMEDIATION_MANIFEST


def evidence_digest(finding: JSON) -> str:
    payload = {
        "rule": finding.get("rule_short_id") or finding.get("rule_id"),
        "resource": finding.get("resource"),
        "remediation_state": _remediation_state(finding),
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def validate_logging_destination(
    client: AwsProvider,
    finding: JSON,
    options: JSON,
    *,
    region: str,
    account_id: str,
) -> JSON:
    rule = str(finding.get("rule_short_id") or "")
    if rule not in {"s3-server-access-logging-disabled", "alb-access-logging-disabled"}:
        return {}
    target_bucket, target_prefix = _logging_destination(options)
    normalized_account_id = str(account_id or "").strip()
    if not normalized_account_id:
        raise RemediationPlanError(
            "Steward could not validate the AWS account for the logging destination. Create a new plan after AWS identity validation."
        )
    buckets = set(client.list_buckets())
    if target_bucket not in buckets:
        raise RemediationPlanError(
            "The logging destination bucket does not exist or is not visible to the selected AWS principal."
        )
    if rule == "s3-server-access-logging-disabled" and target_bucket == _s3_bucket(
        str(finding.get("resource") or "")
    ):
        raise RemediationPlanError(
            "The S3 logging destination must differ from the source bucket to prevent recursive log delivery."
        )
    location = client.read("s3.get_bucket_location", Bucket=target_bucket)
    bucket_region = _bucket_region(location.get("LocationConstraint"))
    if bucket_region != region:
        raise RemediationPlanError(
            f"The logging destination bucket is in {bucket_region}, but the selected AWS Region is {region}."
        )

    encryption = client.read("s3.get_bucket_encryption", Bucket=target_bucket)
    encryption_rules = (encryption.get("ServerSideEncryptionConfiguration") or {}).get(
        "Rules"
    ) or []
    algorithms = sorted(
        {
            str((rule.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm") or "")
            for rule in encryption_rules
            if isinstance(rule, dict)
        }
        - {""}
    )
    unsupported_algorithms = [algorithm for algorithm in algorithms if algorithm != "AES256"]
    if unsupported_algorithms:
        raise RemediationPlanError(
            "The logging destination must use SSE-S3 (AES256); unsupported default encryption was found: "
            + ", ".join(unsupported_algorithms)
            + "."
        )

    source_resource = str(finding.get("resource") or "")
    if rule == "s3-server-access-logging-disabled":
        destination_logging = client.read("s3.get_bucket_logging", Bucket=target_bucket)
        if destination_logging.get("LoggingEnabled"):
            raise RemediationPlanError(
                "The S3 logging destination already has server access logging enabled. Choose a dedicated destination without access logging to avoid recursive log delivery."
            )
        source_arn = f"arn:aws:s3:::{_s3_bucket(source_resource)}"
        service_principal = "logging.s3.amazonaws.com"
        object_probe_arn = (
            f"arn:aws:s3:::{target_bucket}/{target_prefix}BlueArchStewardPermissionProbe"
        )
        api_prefix = target_prefix
    else:
        api_prefix = target_prefix.rstrip("/")
        if "awslogs" in api_prefix.casefold():
            raise RemediationPlanError("The ALB logging prefix must not contain AWSLogs.")
        source_arn = str((finding.get("evidence") or {}).get("load_balancer_arn") or "")
        if not source_arn:
            raise RemediationPlanError("ALB finding evidence does not include a load balancer ARN.")
        service_principal = "logdelivery.elasticloadbalancing.amazonaws.com"
        object_probe_arn = (
            f"arn:aws:s3:::{target_bucket}/{api_prefix}/AWSLogs/"
            f"{normalized_account_id}/ELBAccessLogTestFile"
        )

    policy_payload = client.read("s3.get_bucket_policy", Bucket=target_bucket)
    policy = policy_document(policy_payload.get("Policy"))
    if not _policy_allows_log_delivery(
        policy,
        service_principal=service_principal,
        object_arn=object_probe_arn,
        source_arn=source_arn,
        account_id=normalized_account_id,
    ):
        raise RemediationPlanError(
            "The destination bucket policy does not contain a compatible s3:PutObject allow for "
            f"{service_principal} and the requested prefix. Steward will not create or modify that policy."
        )
    return {
        "target_bucket": target_bucket,
        "target_prefix": api_prefix,
        "target_bucket_exists": True,
        "target_bucket_region": bucket_region,
        "target_bucket_encryption": algorithms or ["AES256 (Amazon S3 default)"],
        "delivery_service_principal": service_principal,
        "delivery_policy_validated": True,
        "delivery_policy_managed_by_steward": False,
    }


def build_remediation_document(
    finding: JSON,
    *,
    aws_context: JSON,
    options: Optional[JSON] = None,
    source_finding_id: Optional[str] = None,
) -> JSON:
    rule = str(finding.get("rule_short_id") or "")
    manifest = REMEDIATION_MANIFEST.get(rule)
    if manifest is None:
        raise RemediationPlanError(f"Steward does not implement an AWS write action for {rule}.")

    selected_options = dict(options or {})
    before = deepcopy(finding.get("evidence") or {})
    desired, changes, parameters = _desired_change(rule, finding, selected_options)
    remediation = finding.get("remediation") or {}
    return {
        "finding": {
            "finding_id": finding.get("finding_id"),
            "source_finding_id": source_finding_id,
            "rule": rule,
            "service": finding.get("service"),
            "resource": finding.get("resource"),
            "severity": finding.get("severity"),
        },
        "aws_context": {
            "account_id": aws_context.get("account_id"),
            "principal_arn": aws_context.get("principal_arn"),
            "profile": aws_context.get("profile"),
            "provider": aws_context.get("provider"),
            "region": aws_context.get("region"),
            "endpoint_url": aws_context.get("endpoint_url"),
        },
        "observation": {
            "observed_at": aws_context.get("observed_at"),
            "before_state": before,
            "evidence_digest": evidence_digest(finding),
            "point_in_time": True,
        },
        "desired_state": desired,
        "change_preview": changes,
        "aws_operations": [
            {
                "operation": manifest["operation"],
                "parameters": parameters,
            }
        ],
        "required_iam_actions": sorted(
            {"sts:GetCallerIdentity", *manifest["read_actions"], *manifest["iam_actions"]}
        ),
        "required_iam_permissions": {
            "identity": ["sts:GetCallerIdentity"],
            "read": list(manifest["read_actions"]),
            "write": list(manifest["iam_actions"]),
        },
        "impact": {
            "blast_radius": manifest["blast_radius"],
            "downtime": manifest["downtime"],
            "warnings": list(manifest["warnings"]),
        },
        "rollback": {
            "automatic": False,
            "guidance": manifest["rollback"],
        },
        "verification": {
            "method": "fresh_rule_scan",
            "expected": remediation.get("verification"),
            "finding_must_be_absent": True,
        },
        "approval": {
            "required": True,
            "scope": "one finding on one resource",
            "apply_tool": "bluearch_apply_remediation",
            "required_arguments": ["plan_id", "plan_digest", "allow_write=true"],
        },
        "preconditions": {
            "account_must_match": True,
            "region_must_match": True,
            "finding_must_still_match": True,
            "evidence_must_be_unchanged": True,
            "destination_bucket_must_exist": rule
            in {"s3-server-access-logging-disabled", "alb-access-logging-disabled"},
            "destination_delivery_permissions_must_be_preconfigured": rule
            in {"s3-server-access-logging-disabled", "alb-access-logging-disabled"},
        },
        "summary": remediation.get("summary"),
        "safety_level": remediation.get("safety_level"),
    }


def execute_remediation_plan(client: AwsProvider, plan: JSON) -> list[str]:
    finding = plan.get("finding") or {}
    rule = str(finding.get("rule") or "")
    resource = str(finding.get("resource") or "")
    operation = (plan.get("aws_operations") or [{}])[0]
    parameters = operation.get("parameters") or {}

    if rule == "s3-public-bucket":
        client.put_public_access_block(_s3_bucket(resource))
        return ["enabled S3 public access block"]
    if rule == "s3-no-default-encryption":
        client.put_default_encryption(_s3_bucket(resource))
        return ["enabled default SSE-S3 encryption"]
    if rule == "s3-no-lifecycle":
        transition = (
            (parameters.get("LifecycleConfiguration") or {})
            .get("Rules", [{}])[0]
            .get("Transitions", [{}])[0]
        )
        client.put_lifecycle(
            _s3_bucket(resource),
            transition_days=int(transition["Days"]),
            storage_class=str(transition["StorageClass"]),
        )
        return ["added reviewed S3 lifecycle transition rule"]
    if rule == "s3-versioning-disabled":
        client.put_versioning(_s3_bucket(resource))
        return ["enabled S3 bucket versioning"]
    if rule == "cloudwatch-log-retention-missing":
        client.put_log_retention(
            _log_group_name(resource),
            int(parameters["retentionInDays"]),
        )
        return [f"set CloudWatch Logs retention to {parameters['retentionInDays']} days"]
    if rule == "cloudtrail-log-validation-disabled":
        client.update_cloudtrail_log_file_validation(_trail_name(resource), enabled=True)
        return ["enabled CloudTrail log file validation"]
    if rule == "s3-server-access-logging-disabled":
        target_bucket = str(parameters["TargetBucket"])
        target_prefix = str(parameters["TargetPrefix"])
        validate_logging_destination(
            client,
            {"rule_short_id": rule, "resource": resource},
            {
                "logging_destination_bucket": target_bucket,
                "logging_destination_prefix": target_prefix,
            },
            region=str((plan.get("aws_context") or {}).get("region") or "us-east-1"),
            account_id=str((plan.get("aws_context") or {}).get("account_id") or ""),
        )
        client.put_bucket_logging(
            _s3_bucket(resource),
            target_bucket=target_bucket,
            target_prefix=target_prefix,
        )
        return ["enabled S3 server access logging to the reviewed existing destination"]
    if rule == "alb-access-logging-disabled":
        target_bucket = str(parameters["TargetBucket"])
        target_prefix = str(parameters["TargetPrefix"])
        validate_logging_destination(
            client,
            {
                "rule_short_id": rule,
                "resource": resource,
                "evidence": {"load_balancer_arn": parameters["LoadBalancerArn"]},
            },
            {
                "logging_destination_bucket": target_bucket,
                "logging_destination_prefix": target_prefix,
            },
            region=str((plan.get("aws_context") or {}).get("region") or "us-east-1"),
            account_id=str((plan.get("aws_context") or {}).get("account_id") or ""),
        )
        client.enable_alb_access_logging(
            str(parameters["LoadBalancerArn"]),
            target_bucket=target_bucket,
            target_prefix=target_prefix,
        )
        return ["enabled ALB access logging to the reviewed existing destination"]
    raise RemediationPlanError(f"Unsupported remediation rule: {rule}")


def _desired_change(rule: str, finding: JSON, options: JSON) -> tuple[JSON, list[JSON], JSON]:
    evidence = finding.get("evidence") or {}
    desired: JSON
    if rule == "s3-public-bucket":
        desired = {
            "public_access_block": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        return (
            desired,
            [
                _change(
                    "public_access_block",
                    evidence.get("public_access_block"),
                    desired["public_access_block"],
                )
            ],
            {
                "Bucket": _s3_bucket(str(finding.get("resource") or "")),
                "PublicAccessBlockConfiguration": desired["public_access_block"],
            },
        )
    if rule == "s3-no-default-encryption":
        desired = {"default_encryption": "AES256"}
        return (
            desired,
            [
                _change(
                    "server_side_encryption_rules",
                    evidence.get("server_side_encryption_rules"),
                    desired,
                )
            ],
            {
                "Bucket": _s3_bucket(str(finding.get("resource") or "")),
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                },
            },
        )
    if rule == "s3-no-lifecycle":
        days = options.get("s3_lifecycle_transition_days")
        if not isinstance(days, int) or isinstance(days, bool):
            raise RemediationPlanError("s3_lifecycle_transition_days must be an integer.")
        if not 1 <= days <= 3650:
            raise RemediationPlanError("s3_lifecycle_transition_days must be between 1 and 3650.")
        storage_class = str(options.get("s3_lifecycle_storage_class") or "")
        if storage_class not in S3_LIFECYCLE_STORAGE_CLASSES:
            allowed = ", ".join(S3_LIFECYCLE_STORAGE_CLASSES)
            raise RemediationPlanError(
                f"Unsupported S3 lifecycle storage class: {storage_class}. Choose one of: {allowed}."
            )
        desired = {"transition_days": days, "storage_class": storage_class}
        return (
            desired,
            [_change("lifecycle_rules", evidence.get("lifecycle_rules"), desired)],
            {
                "Bucket": _s3_bucket(str(finding.get("resource") or "")),
                "LifecycleConfiguration": {
                    "Rules": [
                        {
                            "ID": "bluearch-steward-transition-old-objects",
                            "Status": "Enabled",
                            "Filter": {"Prefix": ""},
                            "Transitions": [{"Days": days, "StorageClass": storage_class}],
                        }
                    ]
                },
            },
        )
    if rule == "s3-versioning-disabled":
        desired = {"versioning_status": "Enabled"}
        return (
            desired,
            [_change("versioning_status", evidence.get("versioning_status"), "Enabled")],
            {
                "Bucket": _s3_bucket(str(finding.get("resource") or "")),
                "VersioningConfiguration": {"Status": "Enabled"},
            },
        )
    if rule == "cloudwatch-log-retention-missing":
        days = options.get("cloudwatch_retention_days")
        if not isinstance(days, int) or isinstance(days, bool):
            raise RemediationPlanError("cloudwatch_retention_days must be an integer.")
        if days not in CLOUDWATCH_RETENTION_DAYS:
            allowed = ", ".join(str(value) for value in CLOUDWATCH_RETENTION_DAYS)
            raise RemediationPlanError(
                f"cloudwatch_retention_days must be an AWS-supported value: {allowed}."
            )
        desired = {"retention_days": days}
        return (
            desired,
            [_change("retention_days", evidence.get("retention_days"), days)],
            {
                "logGroupName": _log_group_name(str(finding.get("resource") or "")),
                "retentionInDays": days,
            },
        )
    if rule == "cloudtrail-log-validation-disabled":
        desired = {"log_file_validation_enabled": True}
        return (
            desired,
            [
                _change(
                    "log_file_validation_enabled", evidence.get("log_file_validation_enabled"), True
                )
            ],
            {
                "Name": _trail_name(str(finding.get("resource") or "")),
                "EnableLogFileValidation": True,
            },
        )
    if rule == "s3-server-access-logging-disabled":
        target_bucket, target_prefix = _logging_destination(options)
        desired = {
            "server_access_logging_enabled": True,
            "target_bucket": target_bucket,
            "target_prefix": target_prefix,
        }
        return (
            desired,
            [
                _change(
                    "server_access_logging_enabled",
                    evidence.get("server_access_logging_enabled"),
                    True,
                )
            ],
            {
                "Bucket": _s3_bucket(str(finding.get("resource") or "")),
                "TargetBucket": target_bucket,
                "TargetPrefix": target_prefix,
            },
        )
    if rule == "alb-access-logging-disabled":
        target_bucket, target_prefix = _logging_destination(options)
        target_prefix = target_prefix.rstrip("/")
        if "awslogs" in target_prefix.casefold():
            raise RemediationPlanError("The ALB logging prefix must not contain AWSLogs.")
        load_balancer_arn = str(evidence.get("load_balancer_arn") or "")
        if not load_balancer_arn:
            raise RemediationPlanError("ALB finding evidence does not include a load balancer ARN.")
        desired = {
            "access_logging_enabled": True,
            "target_bucket": target_bucket,
            "target_prefix": target_prefix,
        }
        return (
            desired,
            [_change("access_logging_enabled", evidence.get("access_logging_enabled"), True)],
            {
                "LoadBalancerArn": load_balancer_arn,
                "TargetBucket": target_bucket,
                "TargetPrefix": target_prefix,
            },
        )
    raise RemediationPlanError(f"Unsupported remediation rule: {rule}")


def _change(field: str, before: Any, after: Any) -> JSON:
    return {"field": field, "before": deepcopy(before), "after": deepcopy(after)}


def _policy_allows_log_delivery(
    policy: JSON,
    *,
    service_principal: str,
    object_arn: str,
    source_arn: str,
    account_id: str,
) -> bool:
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, dict) or str(statement.get("Effect") or "") != "Allow":
            continue
        principal = statement.get("Principal") or {}
        services = _string_values(principal.get("Service") if isinstance(principal, dict) else None)
        if service_principal not in services:
            continue
        actions = {value.casefold() for value in _string_values(statement.get("Action"))}
        if not any(fnmatchcase("s3:putobject", action) for action in actions):
            continue
        if not any(
            fnmatchcase(object_arn, resource)
            for resource in _string_values(statement.get("Resource"))
        ):
            continue
        if not _known_source_conditions_match(
            statement.get("Condition"),
            source_arn=source_arn,
            account_id=account_id,
        ):
            continue
        return True
    return False


def _known_source_conditions_match(
    condition: Any,
    *,
    source_arn: str,
    account_id: str,
) -> bool:
    if not isinstance(condition, dict):
        return True
    known = {
        "aws:sourcearn": source_arn,
        "aws:sourceaccount": account_id,
    }
    for operator, clauses in condition.items():
        if not isinstance(clauses, dict):
            continue
        normalized_operator = str(operator).casefold().removesuffix("ifexists")
        for key, expected in clauses.items():
            actual = known.get(str(key).casefold())
            if actual is None:
                continue
            patterns = _string_values(expected)
            if normalized_operator in {"arnlike", "stringlike"}:
                matches = any(fnmatchcase(actual, pattern) for pattern in patterns)
            elif normalized_operator in {"arnequals", "stringequals"}:
                matches = actual in patterns
            else:
                return False
            if not matches:
                return False
    return True


def _string_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _remediation_state(finding: JSON) -> JSON:
    rule = str(finding.get("rule_short_id") or finding.get("rule_id") or "")
    evidence = finding.get("evidence") or {}
    fields_by_rule = {
        "s3-public-bucket": ("public_policy_allows_public", "public_access_block"),
        "s3-no-default-encryption": ("server_side_encryption_rules",),
        "s3-no-lifecycle": ("lifecycle_rules",),
        "s3-versioning-disabled": ("versioning_status",),
        "cloudwatch-log-retention-missing": ("retention_days",),
        "cloudtrail-log-validation-disabled": ("log_file_validation_enabled",),
        "s3-server-access-logging-disabled": ("server_access_logging_enabled",),
        "alb-access-logging-disabled": ("access_logging_enabled", "load_balancer_arn"),
    }
    fields = fields_by_rule.get(rule)
    if fields is None:
        return deepcopy(evidence)
    return {field: deepcopy(evidence.get(field)) for field in fields}


def _plan_digest(plan: JSON) -> str:
    digestable = {key: value for key, value in plan.items() if key != "plan_digest"}
    return hashlib.sha256(_canonical_json(digestable).encode("utf-8")).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _s3_bucket(resource: str) -> str:
    if not resource.startswith("s3://"):
        raise RemediationPlanError(f"Expected an S3 resource URI, got {resource!r}.")
    bucket = resource.removeprefix("s3://").split("/", 1)[0]
    if not bucket:
        raise RemediationPlanError("S3 resource URI does not contain a bucket name.")
    return bucket


def _logging_destination(options: JSON) -> tuple[str, str]:
    bucket = str(options.get("logging_destination_bucket") or "").strip()
    prefix = str(options.get("logging_destination_prefix") or "").strip().lstrip("/")
    if not bucket:
        raise RemediationPlanError("logging_destination_bucket is required.")
    if not prefix:
        raise RemediationPlanError("logging_destination_prefix is required.")
    if len(prefix) > 512:
        raise RemediationPlanError("logging_destination_prefix must be at most 512 characters.")
    return bucket, prefix.rstrip("/") + "/"


def _bucket_region(value: Any) -> str:
    if value in {None, "", "null"}:
        return "us-east-1"
    if value == "EU":
        return "eu-west-1"
    return str(value)


def _log_group_name(resource: str) -> str:
    prefix = "cloudwatch-logs://log-group/"
    if not resource.startswith(prefix):
        raise RemediationPlanError(f"Expected a CloudWatch Logs resource URI, got {resource!r}.")
    name = "/" + unquote(resource.removeprefix(prefix)).lstrip("/")
    if name == "/":
        raise RemediationPlanError(
            "CloudWatch Logs resource URI does not contain a log group name."
        )
    return name


def _trail_name(resource: str) -> str:
    prefix = "cloudtrail://trail/"
    if not resource.startswith(prefix):
        raise RemediationPlanError(f"Expected a CloudTrail resource URI, got {resource!r}.")
    name = unquote(resource.removeprefix(prefix))
    if not name:
        raise RemediationPlanError("CloudTrail resource URI does not contain a trail name.")
    return name


def _iso(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_iso(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
