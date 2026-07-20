from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Sequence

from bluearch_aws_steward.detectors.aws_common import (
    age_days,
    cost_evidence,
    flattened_instances,
    tags_dict,
)
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import (
    ScanPolicy,
    effective_exempt_tags,
    effective_float,
    effective_int,
    resource_is_exempt,
)
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSeries, MetricSignalQuery


def scan_ec2(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "ec2", rule_filter)
    rules = context.rules
    volume_rule_names = {
        "ec2_unattached_ebs_volume",
        "ec2_ebs_volume_unencrypted",
        "ec2_gp2_volume_candidate",
        "ebs_magnetic_volume_overutilized",
        "ebs_iops_saturation",
    }
    volumes = client.list_ebs_volumes() if volume_rule_names & set(rules) else []
    addresses = client.list_elastic_ips() if "ec2_unassociated_elastic_ip" in rules else []
    findings: List[Finding] = []
    scan_policy = policy or ScanPolicy()
    unattached_rule = rules.get("ec2_unattached_ebs_volume")

    if unattached_rule:
        minimum_age_days = effective_int(
            unattached_rule.parameters,
            "minimum_unattached_days",
            scan_policy.ebs_min_unattached_days,
        )
        exemptions = effective_exempt_tags(unattached_rule.parameters, scan_policy)
        for volume in volumes:
            volume_id = str(volume.get("volume_id") or "").strip()
            attachments = volume.get("attachments") or []
            tags = volume.get("tags") or {}
            age_days = _age_days(volume.get("created_at"))
            if (
                not volume_id
                or volume.get("state") != "available"
                or attachments
                or age_days is None
                or age_days < minimum_age_days
                or resource_is_exempt(tags, exemptions)
            ):
                continue
            cost_estimate = _cost_estimate(volume, unattached_rule.parameters, region)
            findings.append(
                finding_from_rule(
                    unattached_rule,
                    f"ebs://{volume_id}",
                    {
                        "volume_id": volume_id,
                        "state": volume.get("state"),
                        "size_gib": volume.get("size_gib"),
                        "volume_type": volume.get("volume_type"),
                        "availability_zone": volume.get("availability_zone"),
                        "encrypted": volume.get("encrypted"),
                        "created_at": volume.get("created_at"),
                        "age_days": age_days,
                        "minimum_age_days": minimum_age_days,
                        "attachments": attachments,
                        "exemption_tags_evaluated": sorted(exemptions),
                        "cost_estimate": cost_estimate,
                    },
                    [
                        f"Confirm the volume has been intentionally unattached for at least {minimum_age_days} days.",
                        "Create a snapshot first when rollback or data recovery may be required.",
                        "Delete the volume only after explicit approval.",
                    ],
                    "Re-run describe-volumes and confirm the reviewed volume no longer exists.",
                    resource_ref=ResourceRef(
                        provider="aws",
                        service="ec2",
                        resource_type="aws.ec2.volume",
                        resource_id=volume_id,
                        region=region,
                        display_name=volume_id,
                    ),
                )
            )

    encryption_rule = rules.get("ec2_ebs_volume_unencrypted")
    if encryption_rule:
        exemptions = effective_exempt_tags(encryption_rule.parameters, scan_policy)
        for volume in volumes:
            volume_id = str(volume.get("volume_id") or "").strip()
            tags = volume.get("tags") or {}
            if (
                not volume_id
                or volume.get("encrypted") is True
                or resource_is_exempt(tags, exemptions)
            ):
                continue
            findings.append(
                finding_from_rule(
                    encryption_rule,
                    f"ebs://{volume_id}",
                    {
                        "volume_id": volume_id,
                        "state": volume.get("state"),
                        "size_gib": volume.get("size_gib"),
                        "volume_type": volume.get("volume_type"),
                        "availability_zone": volume.get("availability_zone"),
                        "encrypted": False,
                        "attachments": volume.get("attachments") or [],
                        "exemption_tags_evaluated": sorted(exemptions),
                    },
                    [
                        "Identify every instance or workload that depends on the volume.",
                        "Create a snapshot, copy it with encryption enabled, and create a replacement volume.",
                        "Validate and cut over during an approved change window with a rollback plan.",
                    ],
                    "Re-read the replacement volume and confirm Encrypted is true.",
                    resource_ref=ResourceRef(
                        provider="aws",
                        service="ec2",
                        resource_type="aws.ec2.volume",
                        resource_id=volume_id,
                        region=region,
                        display_name=volume_id,
                    ),
                )
            )

    elastic_ip_rule = rules.get("ec2_unassociated_elastic_ip")
    if elastic_ip_rule:
        exemptions = effective_exempt_tags(elastic_ip_rule.parameters, scan_policy)
        for address in addresses:
            allocation_id = str(address.get("allocation_id") or "").strip()
            tags = address.get("tags") or {}
            associated = any(
                address.get(field)
                for field in ("association_id", "instance_id", "network_interface_id")
            )
            if not allocation_id or associated or resource_is_exempt(tags, exemptions):
                continue
            findings.append(
                finding_from_rule(
                    elastic_ip_rule,
                    f"eip://{allocation_id}",
                    {
                        "allocation_id": allocation_id,
                        "public_ip": address.get("public_ip"),
                        "association_id": address.get("association_id"),
                        "instance_id": address.get("instance_id"),
                        "network_interface_id": address.get("network_interface_id"),
                        "domain": address.get("domain"),
                        "exemption_tags_evaluated": sorted(exemptions),
                        "cost_estimate": {
                            "status": "preventive",
                            "estimated_monthly_cost_usd": None,
                            "estimated_monthly_savings_usd": 0.0,
                            "confidence": "high",
                            "basis": "The address is allocated but unassociated; no regional price was embedded.",
                            "assumptions": [
                                "DNS, allowlists, recovery procedures, and future reservations were not evaluated."
                            ],
                        },
                    },
                    [
                        "Check DNS records, allowlists, recovery procedures, and planned workloads for dependencies.",
                        "Associate the address with an active resource when it is still required.",
                        "Release it only after explicit approval when no dependency remains.",
                    ],
                    "Re-run describe-addresses and confirm the allocation is associated or no longer exists.",
                    resource_ref=ResourceRef(
                        provider="aws",
                        service="ec2",
                        resource_type="aws.ec2.elastic-ip",
                        resource_id=allocation_id,
                        region=region,
                        display_name=str(address.get("public_ip") or allocation_id),
                    ),
                )
            )

    findings.extend(_scan_extended_ec2(context, volumes, region, scan_policy.exclude_tags))
    findings.extend(_evaluate_volume_expansion(context, volumes, region, scan_policy.exclude_tags))

    return build_scan_result(
        service="ec2",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(volumes)
        + len(addresses)
        + int(getattr(context, "extended_resources_scanned", 0)),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _scan_extended_ec2(
    context: EvaluationContext,
    normalized_volumes: List[Dict[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    findings: List[Finding] = []
    security_detectors = {
        "ec2_security_group_ssh_open",
        "ec2_security_group_rdp_open",
        "ec2_default_security_group_not_restricted",
        "ec2_security_group_rule_count_high",
        "ec2_unused_security_group",
    }
    group_payload = context.read(security_detectors, "ec2.describe_security_groups") or {}
    security_groups = list(group_payload.get("SecurityGroups") or [])
    findings.extend(_evaluate_security_groups(context, security_groups, region, exclusions))
    interface_payload = context.read(
        "ec2_unused_security_group", "ec2.describe_network_interfaces"
    ) or {"NetworkInterfaces": []}
    network_interfaces = list(interface_payload.get("NetworkInterfaces") or [])
    findings.extend(
        _evaluate_unused_security_groups(
            context, security_groups, network_interfaces, region, exclusions
        )
    )

    vpc_payload = context.read("vpc_flow_logs_disabled", "ec2.describe_vpcs") or {}
    flow_payload = context.read("vpc_flow_logs_disabled", "ec2.describe_flow_logs") or {}
    vpcs = list(vpc_payload.get("Vpcs") or [])
    flow_logs = list(flow_payload.get("FlowLogs") or [])
    findings.extend(_evaluate_vpc_flow_logs(context, vpcs, flow_logs, region, exclusions))

    instance_detectors = {
        "ec2_ebs_delete_on_termination_disabled",
        "ebs_orphaned_snapshot_or_ami",
        "ec2_idle_instance",
        "ec2_previous_generation_instance",
        "ec2_dev_schedule_missing",
        "ec2_low_cpu_rightsizing",
        "ec2_high_cpu",
    }
    instance_payload = context.read(instance_detectors, "ec2.describe_instances") or {}
    instances = [
        instance
        for instance in flattened_instances(instance_payload)
        if (instance.get("State") or {}).get("Name")
        in {"pending", "running", "stopping", "stopped"}
    ]
    findings.extend(_evaluate_delete_on_termination(context, instances, region, exclusions))
    findings.extend(_evaluate_idle_instances(context, instances, region, exclusions))
    findings.extend(_evaluate_instance_configuration(context, instances, region, exclusions))
    findings.extend(_evaluate_instance_cpu(context, instances, region, exclusions))
    findings.extend(
        _evaluate_orphaned_backups(
            context,
            normalized_volumes,
            instances,
            region,
            exclusions,
        )
    )

    context.extended_resources_scanned = (
        int(getattr(context, "extended_resources_scanned", 0))
        + len(security_groups)
        + len(vpcs)
        + len(instances)
        + len(network_interfaces)
    )
    return findings


def _evaluate_unused_security_groups(
    context: EvaluationContext,
    groups: Sequence[Mapping[str, Any]],
    interfaces: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    rule = context.rule("ec2_unused_security_group")
    if not rule:
        return []
    attached = {
        str(group.get("GroupId") or "")
        for interface in interfaces
        for group in interface.get("Groups") or []
    }
    findings: List[Finding] = []
    for group in groups:
        group_id = str(group.get("GroupId") or "")
        group_name = str(group.get("GroupName") or group_id)
        if (
            not group_id
            or group_name == "default"
            or group_id in attached
            or resource_is_exempt(tags_dict(group.get("Tags")), exclusions)
        ):
            continue
        findings.append(
            finding_from_rule(
                rule,
                f"ec2://security-group/{group_id}",
                {
                    "group_id": group_id,
                    "group_name": group_name,
                    "attached_network_interfaces": 0,
                    "network_interfaces_evaluated": len(interfaces),
                },
                [
                    "Search IaC, launch templates, load balancers, databases, and deployment pipelines for references.",
                    "Delete only through a separately approved change after dependency review.",
                ],
                "Re-read security groups and network interfaces and confirm the reviewed group is attached or removed.",
                resource_ref=ResourceRef(
                    "aws", "ec2", "security-group", group_id, region=region, display_name=group_name
                ),
            )
        )
    return findings


def _evaluate_instance_configuration(
    context: EvaluationContext,
    instances: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    findings: List[Finding] = []
    previous_rule = context.rule("ec2_previous_generation_instance")
    schedule_rule = context.rule("ec2_dev_schedule_missing")
    previous_families = {
        str(value).lower()
        for value in (previous_rule.parameters if previous_rule else {}).get(
            "previous_generation_families", ()
        )
    }
    environments = {
        str(value).lower()
        for value in (schedule_rule.parameters if schedule_rule else {}).get(
            "environment_values", ()
        )
    }
    schedule_keys = {
        str(value).lower()
        for value in (schedule_rule.parameters if schedule_rule else {}).get(
            "schedule_tag_keys", ()
        )
    }
    for instance in instances:
        if (instance.get("State") or {}).get("Name") != "running" or resource_is_exempt(
            tags_dict(instance.get("Tags")), exclusions
        ):
            continue
        instance_id = str(instance.get("InstanceId") or "")
        instance_type = str(instance.get("InstanceType") or "")
        family = instance_type.split(".", 1)[0].lower()
        resource = f"ec2://instance/{instance_id}"
        reference = ResourceRef("aws", "ec2", "instance", instance_id, region=region)
        if previous_rule and family in previous_families:
            findings.append(
                finding_from_rule(
                    previous_rule,
                    resource,
                    {
                        "instance_id": instance_id,
                        "instance_type": instance_type,
                        "instance_family": family,
                        "previous_generation": True,
                    },
                    [
                        "Benchmark a current-generation candidate for compatibility, CPU, memory, storage, and network performance.",
                        "Update launch templates or IaC and roll out with rollback capacity.",
                    ],
                    "Re-read the running replacement and confirm it uses the reviewed current-generation family.",
                    resource_ref=reference,
                )
            )
        if schedule_rule:
            tags = {
                str(key).lower(): str(value).lower()
                for key, value in tags_dict(instance.get("Tags")).items()
            }
            environment = tags.get("environment") or tags.get("env") or ""
            has_schedule = any(tags.get(key) for key in schedule_keys)
            if environment in environments and not has_schedule:
                findings.append(
                    finding_from_rule(
                        schedule_rule,
                        resource,
                        {
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "environment": environment,
                            "schedule_tag_present": False,
                        },
                        [
                            "Confirm owner, timezone, business hours, maintenance, and exception windows.",
                            "Add an approved schedule through IaC or account automation.",
                        ],
                        "Re-read tags and schedule automation and confirm the reviewed schedule is active.",
                        resource_ref=reference,
                    )
                )
    return findings


def _evaluate_instance_cpu(
    context: EvaluationContext,
    instances: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    active = {
        detector
        for detector in ("ec2_low_cpu_rightsizing", "ec2_high_cpu")
        if context.rule(detector)
    }
    running = [
        item
        for item in instances
        if (item.get("State") or {}).get("Name") == "running"
        and item.get("InstanceId")
        and not resource_is_exempt(tags_dict(item.get("Tags")), exclusions)
    ]
    if not active or not running:
        return []
    days = max(int(context.rules[name].parameters.get("lookback_days") or 1) for name in active)
    queries = [
        MetricSignalQuery(
            key=f"{item['InstanceId']}:{stat.lower()}",
            namespace="AWS/EC2",
            metric_name="CPUUtilization",
            dimensions=(("InstanceId", str(item["InstanceId"])),),
            statistic=stat,
            lookback_days=days,
        )
        for item in running
        for stat in ("Average", "Maximum")
    ]
    try:
        series = CloudWatchSignalAdapter(context.client).read(queries)
    except AwsProviderError as exc:
        context.fail(active, "cloudwatch.get_metric_data", exc.detail or str(exc))
        return []
    findings: List[Finding] = []
    for instance in running:
        instance_id = str(instance["InstanceId"])
        reference = ResourceRef("aws", "ec2", "instance", instance_id, region=region)
        low_rule = context.rule("ec2_low_cpu_rightsizing")
        average = series[f"{instance_id}:average"]
        if low_rule:
            lookback = int(low_rule.parameters.get("lookback_days") or 14)
            threshold = float(low_rule.parameters.get("maximum_average_cpu_percent") or 10.0)
            if (
                average.complete
                and len(average.values) >= lookback
                and max(average.values) < threshold
            ):
                findings.append(
                    finding_from_rule(
                        low_rule,
                        f"ec2://instance/{instance_id}",
                        {
                            "instance_id": instance_id,
                            "instance_type": instance.get("InstanceType"),
                            "lookback_days": lookback,
                            "observed_maximum_daily_average_cpu_percent": round(
                                max(average.values), 2
                            ),
                            "threshold_percent": threshold,
                            "metric_missing_interpreted_as_zero": False,
                        },
                        [
                            "Review memory, network, disk, burst, schedule, and peak demand before rightsizing."
                        ],
                        "Re-query CPU and workload health after an approved rightsizing rollout.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )
        high_rule = context.rule("ec2_high_cpu")
        maximum = series[f"{instance_id}:maximum"]
        if high_rule:
            lookback = int(high_rule.parameters.get("lookback_days") or 14)
            threshold = float(high_rule.parameters.get("minimum_daily_cpu_percent") or 90.0)
            minimum_days = int(high_rule.parameters.get("minimum_breach_days") or 4)
            breach_days = sum(value >= threshold for value in maximum.values)
            if maximum.complete and len(maximum.values) >= lookback and breach_days >= minimum_days:
                findings.append(
                    finding_from_rule(
                        high_rule,
                        f"ec2://instance/{instance_id}",
                        {
                            "instance_id": instance_id,
                            "instance_type": instance.get("InstanceType"),
                            "lookback_days": lookback,
                            "cpu_breach_days": breach_days,
                            "minimum_breach_days": minimum_days,
                            "threshold_percent": threshold,
                            "metric_missing_interpreted_as_zero": False,
                        },
                        [
                            "Inspect application load, process CPU, scaling, deployment changes, and downstream latency."
                        ],
                        "Re-query CPU and application health after the reviewed fix.",
                        resource_ref=reference,
                        evidence_source="aws_cloudwatch_metric",
                    )
                )
    return findings


def _evaluate_volume_expansion(
    context: EvaluationContext,
    volumes: List[Dict[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    findings: List[Finding] = []
    gp2_rule = context.rule("ec2_gp2_volume_candidate")
    for volume in volumes:
        if resource_is_exempt(volume.get("tags") or {}, exclusions):
            continue
        volume_id = str(volume.get("volume_id") or "")
        if gp2_rule and volume_id and volume.get("volume_type") == "gp2":
            findings.append(
                finding_from_rule(
                    gp2_rule,
                    f"ebs://{volume_id}",
                    {
                        "volume_id": volume_id,
                        "volume_type": "gp2",
                        "size_gib": volume.get("size_gib"),
                        "configured_iops": volume.get("iops"),
                        "cost_estimate": cost_evidence(
                            "configuration_evidence",
                            "The volume uses gp2; exact gp3 savings require regional pricing and workload IOPS evidence.",
                        ),
                    },
                    [
                        "Compare gp2 baseline and burst behavior with a reviewed gp3 IOPS and throughput configuration."
                    ],
                    "Re-read the volume after an approved migration and confirm VolumeType is gp3.",
                    resource_ref=ResourceRef("aws", "ec2", "volume", volume_id, region=region),
                )
            )

    active = {
        detector
        for detector in ("ebs_magnetic_volume_overutilized", "ebs_iops_saturation")
        if context.rule(detector)
    }
    candidates = [
        volume
        for volume in volumes
        if volume.get("volume_id") and not resource_is_exempt(volume.get("tags") or {}, exclusions)
    ]
    if not active or not candidates:
        return findings
    days = max(int(context.rules[name].parameters.get("lookback_days") or 1) for name in active)
    queries = [
        MetricSignalQuery(
            key=f"{volume['volume_id']}:{metric}",
            namespace="AWS/EBS",
            metric_name=metric,
            dimensions=(("VolumeId", str(volume["volume_id"])),),
            statistic="Sum",
            lookback_days=days,
        )
        for volume in candidates
        for metric in ("VolumeReadOps", "VolumeWriteOps")
    ]
    try:
        series = CloudWatchSignalAdapter(context.client).read(queries)
    except AwsProviderError as exc:
        context.fail(active, "cloudwatch.get_metric_data", exc.detail or str(exc))
        return findings
    for volume in candidates:
        volume_id = str(volume["volume_id"])
        reads = series[f"{volume_id}:VolumeReadOps"]
        writes = series[f"{volume_id}:VolumeWriteOps"]
        if (
            not reads.complete
            or not writes.complete
            or len(reads.values) < days
            or len(writes.values) < days
        ):
            continue
        daily_iops = [(read + write) / 86400.0 for read, write in zip(reads.values, writes.values)]
        magnetic_rule = context.rule("ebs_magnetic_volume_overutilized")
        magnetic_threshold = float(
            (magnetic_rule.parameters if magnetic_rule else {}).get("maximum_average_iops") or 100.0
        )
        if (
            magnetic_rule
            and volume.get("volume_type") == "standard"
            and max(daily_iops) > magnetic_threshold
        ):
            findings.append(
                _volume_signal_finding(
                    magnetic_rule,
                    volume,
                    region,
                    max(daily_iops),
                    magnetic_threshold,
                    "average_iops",
                )
            )
        saturation_rule = context.rule("ebs_iops_saturation")
        provisioned = float(volume.get("iops") or _baseline_iops(volume))
        saturation = max(daily_iops) / provisioned * 100.0 if provisioned > 0 else 0.0
        saturation_threshold = float(
            (saturation_rule.parameters if saturation_rule else {}).get(
                "minimum_utilization_percent"
            )
            or 95.0
        )
        if saturation_rule and provisioned > 0 and saturation >= saturation_threshold:
            findings.append(
                _volume_signal_finding(
                    saturation_rule,
                    volume,
                    region,
                    saturation,
                    saturation_threshold,
                    "iops_utilization_percent",
                )
            )
    return findings


def _baseline_iops(volume: Mapping[str, Any]) -> float:
    if volume.get("volume_type") == "gp2":
        return float(max(100, int(volume.get("size_gib") or 0) * 3))
    return 0.0


def _volume_signal_finding(
    rule: Any,
    volume: Mapping[str, Any],
    region: str,
    observed: float,
    threshold: float,
    metric: str,
) -> Finding:
    volume_id = str(volume.get("volume_id") or "")
    return finding_from_rule(
        rule,
        f"ebs://{volume_id}",
        {
            "volume_id": volume_id,
            "volume_type": volume.get("volume_type"),
            "size_gib": volume.get("size_gib"),
            "configured_iops": volume.get("iops"),
            "observed_metric": metric,
            "observed_value": round(observed, 2),
            "threshold": threshold,
            "metric_missing_interpreted_as_zero": False,
        },
        ["Validate workload peaks, queue depth, latency, IOPS, throughput, and migration risk."],
        "Re-query EBS metrics after the reviewed storage change.",
        resource_ref=ResourceRef("aws", "ec2", "volume", volume_id, region=region),
        evidence_source="aws_cloudwatch_metric",
    )


def _evaluate_security_groups(
    context: EvaluationContext,
    groups: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    findings: List[Finding] = []
    for group in groups:
        if resource_is_exempt(tags_dict(group.get("Tags")), exclusions):
            continue
        group_id = str(group.get("GroupId") or "")
        group_name = str(group.get("GroupName") or group_id)
        ingress = list(group.get("IpPermissions") or [])
        egress = list(group.get("IpPermissionsEgress") or [])
        resource = f"ec2://security-group/{group_id}"
        reference = ResourceRef(
            "aws", "ec2", "security-group", group_id, region=region, display_name=group_name
        )

        for detector, port in (
            ("ec2_security_group_ssh_open", 22),
            ("ec2_security_group_rdp_open", 3389),
        ):
            rule = context.rule(detector)
            public_ranges = _public_ranges_for_port(ingress, port)
            if rule and public_ranges:
                findings.append(
                    finding_from_rule(
                        rule,
                        resource,
                        {
                            "group_id": group_id,
                            "group_name": group_name,
                            "port": port,
                            "public_cidrs": public_ranges,
                        },
                        [
                            f"Confirm every administrative source before replacing public port {port} ingress with trusted CIDRs or managed access."
                        ],
                        f"Describe the security group and confirm port {port} is not reachable from 0.0.0.0/0 or ::/0.",
                        resource_ref=reference,
                    )
                )

        default_rule = context.rule("ec2_default_security_group_not_restricted")
        if default_rule and group_name == "default" and (ingress or egress):
            findings.append(
                finding_from_rule(
                    default_rule,
                    resource,
                    {
                        "group_id": group_id,
                        "vpc_id": group.get("VpcId"),
                        "ingress_permission_sets": len(ingress),
                        "egress_permission_sets": len(egress),
                    },
                    [
                        "Identify attached network interfaces before removing all ingress and egress from the default group."
                    ],
                    "Confirm the default security group has no ingress or egress permissions.",
                    resource_ref=reference,
                )
            )

        count_rule = context.rule("ec2_security_group_rule_count_high")
        rule_count = sum(_permission_rule_count(permission) for permission in [*ingress, *egress])
        threshold = int(
            (count_rule.parameters if count_rule else {}).get("maximum_security_group_rules") or 50
        )
        if count_rule and rule_count > threshold:
            findings.append(
                finding_from_rule(
                    count_rule,
                    resource,
                    {
                        "group_id": group_id,
                        "group_name": group_name,
                        "rule_count": rule_count,
                        "maximum_rule_count": threshold,
                    },
                    [
                        "Review duplicate, overlapping, expired, and overly broad rules before consolidating the group."
                    ],
                    "Recount expanded ingress and egress rules and confirm the total is at or below the policy threshold.",
                    resource_ref=reference,
                )
            )
    return findings


def _evaluate_vpc_flow_logs(
    context: EvaluationContext,
    vpcs: Sequence[Mapping[str, Any]],
    flow_logs: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    rule = context.rule("vpc_flow_logs_disabled")
    if not rule:
        return []
    active_vpcs = {
        str(item.get("ResourceId") or "")
        for item in flow_logs
        if item.get("FlowLogStatus") == "ACTIVE" and item.get("LogStatus") in {None, "SUCCESS"}
    }
    findings: List[Finding] = []
    for vpc in vpcs:
        if resource_is_exempt(tags_dict(vpc.get("Tags")), exclusions):
            continue
        vpc_id = str(vpc.get("VpcId") or "")
        if not vpc_id or vpc_id in active_vpcs:
            continue
        findings.append(
            finding_from_rule(
                rule,
                f"vpc://{vpc_id}",
                {"vpc_id": vpc_id, "active_flow_logs": 0, "is_default": bool(vpc.get("IsDefault"))},
                [
                    "Choose a reviewed CloudWatch Logs or S3 destination, retention, aggregation interval, and IAM role."
                ],
                "Describe flow logs and confirm an ACTIVE entry exists for the VPC.",
                resource_ref=ResourceRef("aws", "ec2", "vpc", vpc_id, region=region),
            )
        )
    return findings


def _evaluate_delete_on_termination(
    context: EvaluationContext,
    instances: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    rule = context.rule("ec2_ebs_delete_on_termination_disabled")
    if not rule:
        return []
    findings: List[Finding] = []
    for instance in instances:
        if resource_is_exempt(tags_dict(instance.get("Tags")), exclusions):
            continue
        instance_id = str(instance.get("InstanceId") or "")
        root_device = instance.get("RootDeviceName")
        root_mapping = next(
            (
                item
                for item in instance.get("BlockDeviceMappings") or []
                if item.get("DeviceName") == root_device
            ),
            None,
        )
        ebs = (root_mapping or {}).get("Ebs") or {}
        if not ebs or ebs.get("DeleteOnTermination") is not False:
            continue
        volume_id = str(ebs.get("VolumeId") or "")
        findings.append(
            finding_from_rule(
                rule,
                f"ec2://instance/{instance_id}/volume/{volume_id}",
                {
                    "instance_id": instance_id,
                    "volume_id": volume_id,
                    "device_name": root_device,
                    "delete_on_termination": False,
                    "cost_estimate": cost_evidence(
                        "preventive",
                        "The root volume can continue accruing storage cost after instance termination.",
                    ),
                },
                [
                    "Confirm backup and retention requirements before changing future termination behavior."
                ],
                "Describe the instance attribute and confirm the root mapping has DeleteOnTermination=true.",
                resource_ref=ResourceRef(
                    "aws", "ec2", "ebs-attachment", f"{instance_id}:{volume_id}", region=region
                ),
            )
        )
    return findings


def _evaluate_orphaned_backups(
    context: EvaluationContext,
    volumes: List[Dict[str, Any]],
    instances: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    rule = context.rule("ebs_orphaned_snapshot_or_ami")
    if not rule:
        return []
    snapshot_payload = (
        context.read("ebs_orphaned_snapshot_or_ami", "ec2.describe_snapshots", OwnerIds=["self"])
        or {}
    )
    image_payload = (
        context.read("ebs_orphaned_snapshot_or_ami", "ec2.describe_images", Owners=["self"]) or {}
    )
    template_payload = (
        context.read("ebs_orphaned_snapshot_or_ami", "ec2.describe_launch_templates") or {}
    )
    snapshots = list(snapshot_payload.get("Snapshots") or [])
    images = list(image_payload.get("Images") or [])
    image_ids = {str(instance.get("ImageId") or "") for instance in instances}
    for template in template_payload.get("LaunchTemplates") or []:
        template_id = template.get("LaunchTemplateId")
        if not template_id:
            continue
        versions = (
            context.read(
                "ebs_orphaned_snapshot_or_ami",
                "ec2.describe_launch_template_versions",
                LaunchTemplateId=template_id,
                Versions=["$Default", "$Latest"],
            )
            or {}
        )
        for version in versions.get("LaunchTemplateVersions") or []:
            image_ids.add(str((version.get("LaunchTemplateData") or {}).get("ImageId") or ""))
    existing_volumes = {str(volume.get("volume_id") or "") for volume in volumes}
    image_snapshots = {
        str((mapping.get("Ebs") or {}).get("SnapshotId") or "")
        for image in images
        for mapping in image.get("BlockDeviceMappings") or []
    }
    minimum_age = int(rule.parameters.get("minimum_orphan_age_days") or 90)
    findings: List[Finding] = []
    for snapshot in snapshots:
        if resource_is_exempt(tags_dict(snapshot.get("Tags")), exclusions):
            continue
        snapshot_id = str(snapshot.get("SnapshotId") or "")
        source_volume = str(snapshot.get("VolumeId") or "")
        snapshot_age = age_days(snapshot.get("StartTime"))
        if not snapshot_id or snapshot_age is None or snapshot_age < minimum_age:
            continue
        if source_volume in existing_volumes or snapshot_id in image_snapshots:
            continue
        findings.append(
            finding_from_rule(
                rule,
                f"ebs://snapshot/{snapshot_id}",
                {
                    "snapshot_id": snapshot_id,
                    "source_volume_id": source_volume or None,
                    "age_days": snapshot_age,
                    "referenced_by_owned_ami": False,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "The snapshot is older than the policy threshold and is not referenced by an owned AMI or live volume.",
                    ),
                },
                [
                    "Confirm retention, restore, compliance, and backup-policy dependencies before deletion."
                ],
                "Re-list owned snapshots and confirm the reviewed snapshot is retained intentionally or removed.",
                resource_ref=ResourceRef("aws", "ec2", "snapshot", snapshot_id, region=region),
                confidence="medium",
            )
        )
    for image in images:
        if resource_is_exempt(tags_dict(image.get("Tags")), exclusions):
            continue
        image_id = str(image.get("ImageId") or "")
        image_age = age_days(image.get("CreationDate"))
        if not image_id or image_id in image_ids or image_age is None or image_age < minimum_age:
            continue
        findings.append(
            finding_from_rule(
                rule,
                f"ec2://image/{image_id}",
                {
                    "image_id": image_id,
                    "name": image.get("Name"),
                    "age_days": image_age,
                    "referenced_by_instance_or_launch_template": False,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "The AMI is older than the policy threshold and is not referenced by a live instance or launch template.",
                    ),
                },
                [
                    "Check launch configurations, external automation, disaster recovery, and compliance before deregistration."
                ],
                "Re-list owned images and confirm the AMI is intentionally retained or deregistered.",
                resource_ref=ResourceRef(
                    "aws", "ec2", "ami", image_id, region=region, display_name=image.get("Name")
                ),
                confidence="medium",
            )
        )
    context.extended_resources_scanned = (
        int(getattr(context, "extended_resources_scanned", 0)) + len(snapshots) + len(images)
    )
    return findings


def _evaluate_idle_instances(
    context: EvaluationContext,
    instances: Sequence[Mapping[str, Any]],
    region: str,
    exclusions: Mapping[str, str],
) -> List[Finding]:
    rule = context.rule("ec2_idle_instance")
    running = [
        item
        for item in instances
        if (item.get("State") or {}).get("Name") == "running"
        and not resource_is_exempt(tags_dict(item.get("Tags")), exclusions)
    ]
    if not rule or not running:
        return []
    days = int(rule.parameters.get("lookback_days") or 14)
    queries: List[MetricSignalQuery] = []
    for instance in running:
        instance_id = str(instance.get("InstanceId") or "")
        dimensions = (("InstanceId", instance_id),)
        queries.extend(
            [
                MetricSignalQuery(
                    f"{instance_id}:cpu", "AWS/EC2", "CPUUtilization", dimensions, "Average", days
                ),
                MetricSignalQuery(
                    f"{instance_id}:network-in", "AWS/EC2", "NetworkIn", dimensions, "Sum", days
                ),
                MetricSignalQuery(
                    f"{instance_id}:network-out", "AWS/EC2", "NetworkOut", dimensions, "Sum", days
                ),
            ]
        )
    try:
        series = CloudWatchSignalAdapter(context.client).read(queries)
    except AwsProviderError as exc:
        context.fail("ec2_idle_instance", "cloudwatch.get_metric_data", exc.detail or str(exc))
        return []
    findings: List[Finding] = []
    for instance in running:
        instance_id = str(instance.get("InstanceId") or "")
        cpu = series[f"{instance_id}:cpu"]
        network_in = series[f"{instance_id}:network-in"]
        network_out = series[f"{instance_id}:network-out"]
        idle_days = _idle_ec2_days(cpu, network_in, network_out, rule.parameters)
        minimum_days = int(rule.parameters.get("minimum_idle_days") or 4)
        if idle_days is None or idle_days < minimum_days:
            continue
        findings.append(
            finding_from_rule(
                rule,
                f"ec2://instance/{instance_id}",
                {
                    "instance_id": instance_id,
                    "instance_type": instance.get("InstanceType"),
                    "idle_days": idle_days,
                    "lookback_days": days,
                    "minimum_idle_days": minimum_days,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "CloudWatch CPU and network signals stayed below the reviewed idle thresholds.",
                    ),
                },
                [
                    "Validate schedules, dependencies, burst behavior, and ownership before rightsizing or stopping the instance."
                ],
                "Re-query the same CloudWatch window after an approved change and confirm the resource state and expected demand.",
                resource_ref=ResourceRef("aws", "ec2", "instance", instance_id, region=region),
                confidence="medium",
                evidence_source="cloudwatch_metric_data",
            )
        )
    return findings


def _public_ranges_for_port(permissions: Sequence[Mapping[str, Any]], port: int) -> List[str]:
    public: set[str] = set()
    for permission in permissions:
        protocol = str(permission.get("IpProtocol") or "")
        from_port = permission.get("FromPort")
        to_port = permission.get("ToPort")
        covers = protocol == "-1" or (
            isinstance(from_port, int) and isinstance(to_port, int) and from_port <= port <= to_port
        )
        if not covers:
            continue
        public.update(
            str(item.get("CidrIp"))
            for item in permission.get("IpRanges") or []
            if item.get("CidrIp") == "0.0.0.0/0"
        )
        public.update(
            str(item.get("CidrIpv6"))
            for item in permission.get("Ipv6Ranges") or []
            if item.get("CidrIpv6") == "::/0"
        )
    return sorted(public)


def _permission_rule_count(permission: Mapping[str, Any]) -> int:
    sources = sum(
        len(permission.get(key) or [])
        for key in ("IpRanges", "Ipv6Ranges", "PrefixListIds", "UserIdGroupPairs")
    )
    return max(1, sources)


def _idle_ec2_days(
    cpu: MetricSeries,
    network_in: MetricSeries,
    network_out: MetricSeries,
    parameters: Mapping[str, Any],
) -> int | None:
    if not cpu.complete or not network_in.complete or not network_out.complete:
        return None
    cpu_by_time = dict(zip(cpu.timestamps, cpu.values))
    in_by_time = dict(zip(network_in.timestamps, network_in.values))
    out_by_time = dict(zip(network_out.timestamps, network_out.values))
    common = set(cpu_by_time) & set(in_by_time) & set(out_by_time)
    lookback_days = int(parameters.get("lookback_days") or 14)
    if len(common) < lookback_days:
        return None
    maximum_cpu = float(parameters.get("maximum_daily_cpu_percent") or 5.0)
    maximum_network = float(parameters.get("maximum_daily_network_bytes") or 5242880)
    return sum(
        1
        for timestamp in common
        if cpu_by_time[timestamp] <= maximum_cpu
        and in_by_time[timestamp] + out_by_time[timestamp] <= maximum_network
    )


def _age_days(value: object) -> int | None:
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            timestamp = float(value)
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            created_at = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            created_at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
    except (OverflowError, TypeError, ValueError):
        return None
    return max(0, int((datetime.now(timezone.utc) - created_at).total_seconds() // 86400))


def _cost_estimate(volume: dict, parameters: dict, region: str) -> dict:
    size_gib = volume.get("size_gib")
    if size_gib is None:
        return {
            "status": "insufficient",
            "estimated_monthly_cost_usd": None,
            "estimated_monthly_savings_usd": None,
            "confidence": "none",
            "basis": "Volume size was not available.",
            "assumptions": [],
        }

    rates = parameters.get("storage_cost_usd_per_gib_month") or {}
    volume_type = str(volume.get("volume_type") or "unknown")
    try:
        configured_rate = rates.get(volume_type)
        rate = (
            float(configured_rate)
            if configured_rate is not None
            else effective_float(
                parameters,
                "default_storage_cost_usd_per_gib_month",
            )
        )
        estimated_cost = round(float(size_gib) * rate, 2)
    except (TypeError, ValueError):
        return {
            "status": "insufficient",
            "estimated_monthly_cost_usd": None,
            "estimated_monthly_savings_usd": None,
            "confidence": "none",
            "basis": "Volume size or pricing rate was invalid.",
            "assumptions": [],
        }

    pricing_region = str(parameters.get("pricing_region") or "us-east-1")
    confidence = "medium" if region == pricing_region else "low"
    return {
        "status": "estimated",
        "estimated_monthly_cost_usd": estimated_cost,
        "estimated_monthly_savings_usd": estimated_cost,
        "confidence": confidence,
        "basis": "Provisioned EBS storage estimate; deleting the volume avoids its storage charge.",
        "assumptions": [
            f"volume_type={volume_type}",
            f"storage_rate_usd_per_gib_month={rate}",
            f"pricing_region={pricing_region}",
            "Provisioned IOPS, throughput, snapshots, taxes, and discounts are excluded.",
        ],
    }
