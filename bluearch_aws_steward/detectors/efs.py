from __future__ import annotations

import time
from typing import Any, Dict, List

from bluearch_aws_steward.detectors.aws_common import cost_evidence, tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSignalQuery


def scan_efs(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "efs", rule_filter)
    response = context.read(
        (
            "efs_encryption_disabled",
            "efs_lifecycle_policy_missing",
            "efs_inactive_unmounted",
            "efs_throughput_overprovisioned",
            "efs_customer_kms_key_missing",
        ),
        "efs.describe_file_systems",
    )
    file_systems = list((response or {}).get("FileSystems") or [])
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags

    for file_system in file_systems:
        if resource_is_exempt(tags_dict(file_system.get("Tags")), exclusions):
            continue
        file_system_id = str(file_system.get("FileSystemId") or "").strip()
        if not file_system_id:
            continue
        resource = f"efs://file-system/{file_system_id}"
        resource_ref = _resource_ref(file_system, file_system_id, region)

        encryption_rule = context.rule("efs_encryption_disabled")
        if encryption_rule and file_system.get("Encrypted") is not True:
            findings.append(
                finding_from_rule(
                    encryption_rule,
                    resource,
                    {
                        "file_system_id": file_system_id,
                        "encrypted": False,
                        "performance_mode": file_system.get("PerformanceMode"),
                        "throughput_mode": file_system.get("ThroughputMode"),
                    },
                    [
                        "Identify mount targets, clients, throughput requirements, and maintenance constraints.",
                        "Create a reviewed encrypted replacement file system.",
                        "Migrate and validate data before an approved cutover.",
                    ],
                    "Re-read the replacement file system and confirm Encrypted is true.",
                    resource_ref=resource_ref,
                )
            )

        lifecycle_rule = context.rule("efs_lifecycle_policy_missing")
        if lifecycle_rule:
            lifecycle = context.read(
                "efs_lifecycle_policy_missing",
                "efs.describe_lifecycle_configuration",
                FileSystemId=file_system_id,
            )
            policies = list((lifecycle or {}).get("LifecyclePolicies") or [])
            has_infrequent_access_transition = any(
                policy.get("TransitionToIA") or policy.get("TransitionToArchive")
                for policy in policies
                if isinstance(policy, dict)
            )
            if (
                context.rule("efs_lifecycle_policy_missing")
                and not has_infrequent_access_transition
            ):
                findings.append(
                    finding_from_rule(
                        lifecycle_rule,
                        resource,
                        {
                            "file_system_id": file_system_id,
                            "infrequent_access_transition_present": False,
                            "lifecycle_policy_count": len(policies),
                        },
                        [
                            "Review file access age, performance needs, and retrieval cost.",
                            "Choose an EFS infrequent-access transition appropriate for the workload.",
                            "Apply it during an approved change and monitor storage-class movement.",
                        ],
                        "Re-read the lifecycle configuration and confirm a reviewed transition is present.",
                        resource_ref=resource_ref,
                    )
                )

        kms_rule = context.rule("efs_customer_kms_key_missing")
        tags = {
            str(key).lower(): str(value).lower()
            for key, value in tags_dict(file_system.get("Tags")).items()
        }
        required_tags = {
            str(key).lower(): str(value).lower()
            for key, value in dict(
                (kms_rule.parameters if kms_rule else {}).get("requirement_tags") or {}
            ).items()
        }
        key_id = str(file_system.get("KmsKeyId") or "")
        if (
            kms_rule
            and required_tags
            and all(tags.get(key) == value for key, value in required_tags.items())
            and (not key_id or key_id.endswith("alias/aws/elasticfilesystem"))
        ):
            findings.append(
                finding_from_rule(
                    kms_rule,
                    resource,
                    {
                        "file_system_id": file_system_id,
                        "encrypted": bool(file_system.get("Encrypted")),
                        "customer_managed_kms_key_present": False,
                        "requirement_tags_matched": required_tags,
                    },
                    [
                        "Review key ownership, policy, grants, recovery, mount clients, and migration downtime.",
                        "Create an encrypted replacement using a reviewed customer-managed KMS key.",
                    ],
                    "Re-read the replacement file system and confirm KmsKeyId references the reviewed customer-managed key.",
                    resource_ref=resource_ref,
                )
            )

    _scan_efs_signals(client, context, file_systems, findings, region, exclusions)

    return build_scan_result(
        service="efs",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(file_systems),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _scan_efs_signals(
    client: AwsProvider,
    context: EvaluationContext,
    file_systems: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
    exclusions: Dict[str, str],
) -> None:
    active = {
        detector
        for detector in ("efs_inactive_unmounted", "efs_throughput_overprovisioned")
        if context.rule(detector)
    }
    candidates = [
        item
        for item in file_systems
        if item.get("FileSystemId")
        and not resource_is_exempt(tags_dict(item.get("Tags")), exclusions)
    ]
    if not active or not candidates:
        return
    days = max(int(context.rules[name].parameters.get("lookback_days") or 1) for name in active)
    queries = [
        MetricSignalQuery(
            key=f"{item['FileSystemId']}:{metric}",
            namespace="AWS/EFS",
            metric_name=metric,
            dimensions=(("FileSystemId", str(item["FileSystemId"])),),
            statistic="Average",
            lookback_days=days,
        )
        for item in candidates
        for metric in ("ClientConnections", "PercentIOLimit")
    ]
    try:
        metrics = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail(active, "cloudwatch.get_metric_data", exc.detail or str(exc))
        return
    for file_system in candidates:
        file_system_id = str(file_system["FileSystemId"])
        resource = f"efs://file-system/{file_system_id}"
        reference = _resource_ref(file_system, file_system_id, region)
        inactive_rule = context.rule("efs_inactive_unmounted")
        if inactive_rule:
            mount_response = context.read(
                "efs_inactive_unmounted",
                "efs.describe_mount_targets",
                FileSystemId=file_system_id,
            )
            mounts = list((mount_response or {}).get("MountTargets") or [])
            series = metrics[f"{file_system_id}:ClientConnections"]
            lookback = int(inactive_rule.parameters.get("lookback_days") or 30)
            if (
                context.rule("efs_inactive_unmounted")
                and not mounts
                and series.complete
                and len(series.values) >= lookback
                and not any(series.values)
            ):
                findings.append(
                    finding_from_rule(
                        inactive_rule,
                        resource,
                        {
                            "file_system_id": file_system_id,
                            "mount_targets": 0,
                            "lookback_days": lookback,
                            "client_connections": 0.0,
                            "metric_missing_interpreted_as_zero": False,
                            "cost_estimate": cost_evidence(
                                "usage_evidence",
                                "The file system has no mount targets and complete metrics show no client connections.",
                            ),
                        },
                        [
                            "Confirm ownership, backups, replication, access points, and IaC references before retirement."
                        ],
                        "After an approved change, verify backups and consumers remain healthy.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )
        throughput_rule = context.rule("efs_throughput_overprovisioned")
        utilization = metrics[f"{file_system_id}:PercentIOLimit"]
        if throughput_rule and str(file_system.get("ThroughputMode") or "") == "provisioned":
            lookback = int(throughput_rule.parameters.get("lookback_days") or 7)
            threshold = float(throughput_rule.parameters.get("maximum_utilization_percent") or 20.0)
            if (
                utilization.complete
                and len(utilization.values) >= lookback
                and max(utilization.values) < threshold
            ):
                findings.append(
                    finding_from_rule(
                        throughput_rule,
                        resource,
                        {
                            "file_system_id": file_system_id,
                            "throughput_mode": "provisioned",
                            "provisioned_throughput_mibps": file_system.get(
                                "ProvisionedThroughputInMibps"
                            ),
                            "lookback_days": lookback,
                            "observed_maximum_percent_io_limit": round(max(utilization.values), 2),
                            "threshold_percent": threshold,
                            "metric_missing_interpreted_as_zero": False,
                        },
                        [
                            "Review peak throughput, latency, burst behavior, and workload SLOs before changing throughput mode."
                        ],
                        "Re-query EFS throughput and workload health after the reviewed change.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )


def _resource_ref(file_system: Dict[str, Any], file_system_id: str, region: str) -> ResourceRef:
    owner_id = str(file_system.get("OwnerId") or "").strip() or None
    return ResourceRef(
        provider="aws",
        service="efs",
        resource_type="aws.efs.file-system",
        resource_id=file_system_id,
        region=region,
        account_id=owner_id,
        arn=(
            f"arn:aws:elasticfilesystem:{region}:{owner_id}:file-system/{file_system_id}"
            if owner_id
            else None
        ),
        display_name=file_system.get("Name") or file_system_id,
    )
