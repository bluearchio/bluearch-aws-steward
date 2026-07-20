from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import quote

from bluearch_aws_steward.detectors.aws_common import cost_evidence
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.providers.normalize import normalize_rds_instance
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSignalQuery


def scan_rds(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "rds", rule_filter)
    instances = _load_instances(client, context)
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags
    evaluated_instances = [
        instance
        for instance in instances
        if not resource_is_exempt(instance.get("tags") or {}, exclusions)
    ]

    for instance in evaluated_instances:
        identifier = str(instance.get("identifier") or "").strip()
        if not identifier:
            continue
        resource = f"rds://db/{quote(identifier, safe='._-')}"
        resource_ref = _resource_ref(instance, identifier, region)
        common_evidence = {
            "db_instance_identifier": identifier,
            "engine": instance.get("engine"),
            "engine_version": instance.get("engine_version"),
            "instance_class": instance.get("instance_class"),
            "status": instance.get("status"),
            "availability_zone": instance.get("availability_zone"),
        }

        public_rule = context.rule("rds_publicly_accessible")
        if public_rule and instance.get("publicly_accessible") is True:
            findings.append(
                finding_from_rule(
                    public_rule,
                    resource,
                    {**common_evidence, "publicly_accessible": True},
                    [
                        "Validate every application and administrator network path to the database.",
                        "Move the instance to private subnets or disable public accessibility.",
                        "Review security groups and DNS before and after the change.",
                    ],
                    "Re-read the DB instance and confirm PubliclyAccessible is false.",
                    resource_ref=resource_ref,
                )
            )

        encryption_rule = context.rule("rds_storage_unencrypted")
        if encryption_rule and instance.get("storage_encrypted") is not True:
            findings.append(
                finding_from_rule(
                    encryption_rule,
                    resource,
                    {**common_evidence, "storage_encrypted": False},
                    [
                        "Create a database snapshot and copy it with encryption enabled.",
                        "Restore a replacement encrypted instance and validate application behavior.",
                        "Cut over only with a reviewed rollback and downtime plan.",
                    ],
                    "Re-read the replacement DB instance and confirm StorageEncrypted is true.",
                    resource_ref=resource_ref,
                )
            )

        multi_az_rule = context.rule("rds_multi_az_disabled")
        if multi_az_rule and instance.get("multi_az") is not True:
            findings.append(
                finding_from_rule(
                    multi_az_rule,
                    resource,
                    {**common_evidence, "multi_az": False},
                    [
                        "Confirm the workload recovery objective requires Multi-AZ failover.",
                        "Review the additional cost and maintenance impact.",
                        "Enable Multi-AZ during an approved change window when required.",
                    ],
                    "Re-read the DB instance and confirm MultiAZ is true.",
                    resource_ref=resource_ref,
                )
            )

        gp2_rule = context.rule("rds_gp2_storage")
        if gp2_rule and str(instance.get("storage_type") or "").lower() == "gp2":
            findings.append(
                finding_from_rule(
                    gp2_rule,
                    resource,
                    {
                        **common_evidence,
                        "storage_type": "gp2",
                        "allocated_storage_gib": instance.get("allocated_storage_gib"),
                        "cost_estimate": {
                            "status": "preventive",
                            "estimated_monthly_cost_usd": None,
                            "estimated_monthly_savings_usd": 0.0,
                            "confidence": "low",
                            "basis": "Exact savings require regional pricing and workload IOPS evidence.",
                            "assumptions": [],
                        },
                    },
                    [
                        "Compare current IOPS and throughput with a candidate GP3 configuration.",
                        "Estimate regional cost using the account's actual pricing and discounts.",
                        "Modify storage only during an approved change window.",
                    ],
                    "Re-read the DB instance and confirm the reviewed StorageType is gp3.",
                    resource_ref=resource_ref,
                )
            )

        previous_rule = context.rule("rds_previous_generation_instance")
        instance_class = str(instance.get("instance_class") or "").lower()
        previous_families = {
            str(value).lower()
            for value in (previous_rule.parameters if previous_rule else {}).get(
                "previous_generation_families", ()
            )
        }
        if previous_rule and any(
            instance_class == family or instance_class.startswith(family + ".")
            for family in previous_families
        ):
            findings.append(
                finding_from_rule(
                    previous_rule,
                    resource,
                    {
                        **common_evidence,
                        "previous_generation": True,
                        "matched_previous_generation_family": next(
                            family
                            for family in previous_families
                            if instance_class == family or instance_class.startswith(family + ".")
                        ),
                    },
                    [
                        "Benchmark a current-generation DB class against CPU, memory, IOPS, network, licensing, and maintenance constraints.",
                        "Update IaC and roll out during an approved maintenance window with rollback.",
                    ],
                    "Re-read the replacement DB instance and confirm it uses the reviewed current-generation class.",
                    resource_ref=resource_ref,
                )
            )

        autoscaling_rule = context.rule("rds_storage_autoscaling_disabled")
        allocated = int(instance.get("allocated_storage_gib") or 0)
        maximum = int(instance.get("max_allocated_storage_gib") or 0)
        if autoscaling_rule and allocated > 0 and maximum <= allocated:
            findings.append(
                finding_from_rule(
                    autoscaling_rule,
                    resource,
                    {
                        **common_evidence,
                        "allocated_storage_gib": allocated,
                        "max_allocated_storage_gib": maximum or None,
                        "storage_autoscaling_enabled": False,
                    },
                    [
                        "Review engine limits, growth, free-storage alarms, IOPS, and maximum-cost exposure.",
                        "Set a reviewed maximum storage threshold through IaC or the deployment pipeline.",
                    ],
                    "Re-read the DB instance and confirm MaxAllocatedStorage exceeds AllocatedStorage.",
                    resource_ref=resource_ref,
                )
            )

    _scan_idle_instances(client, context, evaluated_instances, findings, region)
    _scan_rds_signals(client, context, evaluated_instances, findings, region)
    return build_scan_result(
        service="rds",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(evaluated_instances),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _load_instances(client: AwsProvider, context: EvaluationContext) -> List[Dict[str, Any]]:
    read_detectors = {
        "rds_idle_instance",
        "rds_previous_generation_instance",
        "rds_storage_autoscaling_disabled",
        "rds_low_cpu_rightsizing",
        "rds_high_cpu",
        "rds_read_heavy_no_replica",
    }
    active_read_detectors = read_detectors & set(context.rules)
    if active_read_detectors:
        response = context.read(active_read_detectors, "rds.describe_db_instances")
        if response is not None:
            return [normalize_rds_instance(item) for item in response.get("DBInstances") or []]
    if any(
        context.rule(detector)
        for detector in (
            "rds_publicly_accessible",
            "rds_storage_unencrypted",
            "rds_multi_az_disabled",
            "rds_gp2_storage",
        )
    ):
        return list(client.list_rds_instances())
    return []


def _scan_rds_signals(
    client: AwsProvider,
    context: EvaluationContext,
    instances: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    active = {
        detector
        for detector in (
            "rds_low_cpu_rightsizing",
            "rds_high_cpu",
            "rds_read_heavy_no_replica",
        )
        if context.rule(detector)
    }
    candidates = [
        item
        for item in instances
        if str(item.get("status") or "").lower() == "available" and item.get("identifier")
    ]
    if not active or not candidates:
        return
    days = max(int(context.rules[name].parameters.get("lookback_days") or 1) for name in active)
    queries = [
        MetricSignalQuery(
            key=f"{instance['identifier']}:{metric}:{stat.lower()}",
            namespace="AWS/RDS",
            metric_name=metric,
            dimensions=(("DBInstanceIdentifier", str(instance["identifier"])),),
            statistic=stat,
            lookback_days=days,
        )
        for instance in candidates
        for metric, stat in (
            ("CPUUtilization", "Average"),
            ("CPUUtilization", "Maximum"),
            ("ReadIOPS", "Average"),
            ("WriteIOPS", "Average"),
        )
    ]
    try:
        metrics = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail(active, "cloudwatch.get_metric_data", exc.detail or str(exc))
        return
    pending: List[Finding] = []
    for instance in candidates:
        identifier = str(instance["identifier"])
        resource = f"rds://db/{quote(identifier, safe='._-')}"
        reference = _resource_ref(instance, identifier, region)
        average_cpu = metrics[f"{identifier}:CPUUtilization:average"]
        maximum_cpu = metrics[f"{identifier}:CPUUtilization:maximum"]
        low_rule = context.rule("rds_low_cpu_rightsizing")
        if low_rule:
            lookback = int(low_rule.parameters.get("lookback_days") or 7)
            threshold = float(low_rule.parameters.get("maximum_average_cpu_percent") or 10.0)
            if (
                average_cpu.complete
                and len(average_cpu.values) >= lookback
                and max(average_cpu.values) < threshold
            ):
                pending.append(
                    finding_from_rule(
                        low_rule,
                        resource,
                        {
                            "db_instance_identifier": identifier,
                            "instance_class": instance.get("instance_class"),
                            "lookback_days": lookback,
                            "observed_maximum_daily_average_cpu_percent": round(
                                max(average_cpu.values), 2
                            ),
                            "threshold_percent": threshold,
                            "metric_missing_interpreted_as_zero": False,
                        },
                        [
                            "Review memory, storage, connections, replicas, maintenance, and peaks before rightsizing."
                        ],
                        "Re-query CPU and database health after an approved rightsizing rollout.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )
        high_rule = context.rule("rds_high_cpu")
        if high_rule:
            lookback = int(high_rule.parameters.get("lookback_days") or 7)
            threshold = float(high_rule.parameters.get("minimum_daily_cpu_percent") or 90.0)
            minimum_days = int(high_rule.parameters.get("minimum_breach_days") or 3)
            breach_days = sum(value >= threshold for value in maximum_cpu.values)
            if (
                maximum_cpu.complete
                and len(maximum_cpu.values) >= lookback
                and breach_days >= minimum_days
            ):
                pending.append(
                    finding_from_rule(
                        high_rule,
                        resource,
                        {
                            "db_instance_identifier": identifier,
                            "lookback_days": lookback,
                            "cpu_breach_days": breach_days,
                            "minimum_breach_days": minimum_days,
                            "threshold_percent": threshold,
                            "metric_missing_interpreted_as_zero": False,
                        },
                        [
                            "Inspect expensive queries, locks, connection pressure, memory, storage latency, and scaling."
                        ],
                        "Re-query CPU, latency, errors, and application health after the reviewed fix.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )
        replica_rule = context.rule("rds_read_heavy_no_replica")
        reads = metrics[f"{identifier}:ReadIOPS:average"]
        writes = metrics[f"{identifier}:WriteIOPS:average"]
        if replica_rule:
            lookback = int(replica_rule.parameters.get("lookback_days") or 7)
            minimum_reads = float(replica_rule.parameters.get("minimum_daily_read_iops") or 100.0)
            maximum_writes = float(replica_rule.parameters.get("maximum_daily_write_iops") or 20.0)
            has_replica = bool(instance.get("read_replica_identifiers"))
            if (
                not instance.get("read_replica_source_identifier")
                and not has_replica
                and reads.complete
                and writes.complete
                and len(reads.values) >= lookback
                and len(writes.values) >= lookback
                and min(reads.values) >= minimum_reads
                and max(writes.values) <= maximum_writes
            ):
                pending.append(
                    finding_from_rule(
                        replica_rule,
                        resource,
                        {
                            "db_instance_identifier": identifier,
                            "lookback_days": lookback,
                            "minimum_observed_read_iops": round(min(reads.values), 2),
                            "maximum_observed_write_iops": round(max(writes.values), 2),
                            "read_replicas": 0,
                            "metric_missing_interpreted_as_zero": False,
                        },
                        [
                            "Validate consistency, replication lag, failover, cacheability, and application routing before adding a replica."
                        ],
                        "Re-query read/write load and verify application behavior after the reviewed architecture change.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )
    findings.extend(pending)


def _scan_idle_instances(
    client: AwsProvider,
    context: EvaluationContext,
    instances: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("rds_idle_instance")
    if not rule:
        return
    lookback_days = int(rule.parameters.get("lookback_days", 7))
    maximum_connections = float(rule.parameters.get("maximum_connections", 0.0))
    candidates = [
        instance
        for instance in instances
        if str(instance.get("status") or "").lower() == "available" and instance.get("identifier")
    ]
    queries = [
        MetricSignalQuery(
            key=str(instance["identifier"]),
            namespace="AWS/RDS",
            metric_name="DatabaseConnections",
            dimensions=(("DBInstanceIdentifier", str(instance["identifier"])),),
            statistic="Maximum",
            lookback_days=lookback_days,
        )
        for instance in candidates
    ]
    try:
        metrics = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail("rds_idle_instance", "cloudwatch.get_metric_data", exc.detail or str(exc))
        return

    pending: List[Finding] = []
    for instance in candidates:
        identifier = str(instance["identifier"])
        series = metrics[identifier]
        if (
            not series.complete
            or len(series.values) < lookback_days
            or max(series.values, default=maximum_connections + 1) > maximum_connections
        ):
            continue
        pending.append(
            finding_from_rule(
                rule,
                f"rds://db/{quote(identifier, safe='._-')}",
                {
                    "db_instance_identifier": identifier,
                    "lookback_days": lookback_days,
                    "maximum_database_connections": max(series.values),
                    "metric_datapoints": len(series.values),
                    "metric_missing_interpreted_as_zero": False,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "CloudWatch reported no database connections throughout the complete lookback window.",
                    ),
                },
                [
                    "Confirm application ownership, schedules, replicas, backups, retention, and dependencies.",
                    "Estimate storage, snapshot, restart, and operational impact.",
                    "Stop or delete only through a separately approved change with rollback.",
                ],
                "After the approved change, verify dependent applications, backups, and recovery procedures.",
                resource_ref=_resource_ref(instance, identifier, region),
                evidence_source="aws_cloudwatch_metric",
            )
        )
    if context.rule("rds_idle_instance"):
        findings.extend(pending)


def _resource_ref(instance: Dict[str, Any], identifier: str, region: str) -> ResourceRef:
    arn = str(instance.get("arn") or "").strip() or None
    account_id = arn.split(":", 5)[4] if arn and arn.count(":") >= 5 else None
    return ResourceRef(
        provider="aws",
        service="rds",
        resource_type="aws.rds.db-instance",
        resource_id=identifier,
        region=region,
        account_id=account_id,
        arn=arn,
        display_name=identifier,
    )
