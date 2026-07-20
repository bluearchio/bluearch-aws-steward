from __future__ import annotations

import time
from typing import Any, Dict, List, Mapping
from urllib.parse import quote

from bluearch_aws_steward.detectors.aws_common import cost_evidence, tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSeries, MetricSignalQuery


def scan_dynamodb(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "dynamodb", rule_filter)
    tables = _load_tables(context, (policy or ScanPolicy()).exclude_tags)
    findings: List[Finding] = []
    _scan_standard_ia_candidates(context, tables, findings, region)
    _scan_usage_signals(client, context, tables, findings, region)
    return build_scan_result(
        service="dynamodb",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(tables),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _load_tables(
    context: EvaluationContext,
    exclusions: Mapping[str, str],
) -> List[Dict[str, Any]]:
    detectors = tuple(context.rules)
    response = context.read(detectors, "dynamodb.list_tables") or {}
    tables: List[Dict[str, Any]] = []
    for name in response.get("TableNames") or []:
        described = context.read(detectors, "dynamodb.describe_table", TableName=name) or {}
        table = dict(described.get("Table") or {})
        arn = str(table.get("TableArn") or "")
        tags_response = (
            context.read(detectors, "dynamodb.list_tags_of_resource", ResourceArn=arn)
            if arn
            else {}
        )
        tags = tags_dict((tags_response or {}).get("Tags") or [])
        if resource_is_exempt(tags, exclusions):
            continue
        table["Tags"] = tags
        tables.append(table)
    return tables


def _scan_standard_ia_candidates(
    context: EvaluationContext,
    tables: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("dynamodb_standard_ia_candidate")
    if not rule:
        return
    minimum_size = int(rule.parameters.get("minimum_size_bytes") or 1073741824)
    required_tags = {
        str(key).lower(): str(value).lower()
        for key, value in dict(rule.parameters.get("requirement_tags") or {}).items()
    }
    for table in tables:
        name = str(table.get("TableName") or "")
        tags = {
            str(key).lower(): str(value).lower() for key, value in (table.get("Tags") or {}).items()
        }
        table_class = str((table.get("TableClassSummary") or {}).get("TableClass") or "STANDARD")
        size_bytes = int(table.get("TableSizeBytes") or 0)
        if (
            not name
            or table_class != "STANDARD"
            or size_bytes < minimum_size
            or any(tags.get(key) != value for key, value in required_tags.items())
        ):
            continue
        findings.append(
            finding_from_rule(
                rule,
                _resource(name),
                {
                    "table_name": name,
                    "table_class": table_class,
                    "table_size_bytes": size_bytes,
                    "minimum_size_bytes": minimum_size,
                    "requirement_tags_matched": required_tags,
                    "cost_estimate": cost_evidence(
                        "configuration_evidence",
                        "The table is explicitly classified as infrequently accessed; exact savings require regional storage and request pricing.",
                    ),
                },
                [
                    "Validate request frequency, storage size, global tables, and account pricing.",
                    "Change table class only through an approved IaC or deployment update.",
                ],
                "Re-read DescribeTable and confirm TableClassSummary matches the reviewed class.",
                resource_ref=_resource_ref(table, name, region),
            )
        )


def _scan_usage_signals(
    client: AwsProvider,
    context: EvaluationContext,
    tables: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    signal_detectors = {
        "dynamodb_inactive_table",
        "dynamodb_on_demand_low_utilization",
        "dynamodb_read_capacity_underutilized",
        "dynamodb_write_capacity_underutilized",
    }
    active = signal_detectors & set(context.rules)
    if not active:
        return
    lookback_days = max(
        int(context.rules[name].parameters.get("lookback_days") or 1) for name in active
    )
    queries: List[MetricSignalQuery] = []
    for table in tables:
        name = str(table.get("TableName") or "")
        if not name:
            continue
        for metric_name in ("ConsumedReadCapacityUnits", "ConsumedWriteCapacityUnits"):
            queries.append(
                MetricSignalQuery(
                    key=f"{name}:{metric_name}",
                    namespace="AWS/DynamoDB",
                    metric_name=metric_name,
                    dimensions=(("TableName", name),),
                    statistic="Sum",
                    lookback_days=lookback_days,
                )
            )
    try:
        series = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail(active, "cloudwatch.get_metric_data", exc.detail or str(exc))
        return

    for table in tables:
        name = str(table.get("TableName") or "")
        if not name:
            continue
        read = series.get(f"{name}:ConsumedReadCapacityUnits")
        write = series.get(f"{name}:ConsumedWriteCapacityUnits")
        _evaluate_inactive(context, table, name, read, write, findings, region)
        _evaluate_on_demand(context, table, name, read, write, findings, region)
        _evaluate_provisioned(context, table, name, read, write, findings, region)


def _complete(series: MetricSeries | None, days: int) -> bool:
    return bool(series and series.complete and len(series.values) >= days)


def _evaluate_inactive(
    context: EvaluationContext,
    table: Dict[str, Any],
    name: str,
    read: MetricSeries | None,
    write: MetricSeries | None,
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("dynamodb_inactive_table")
    if not rule:
        return
    days = int(rule.parameters.get("lookback_days") or 30)
    if not _complete(read, days) or not _complete(write, days):
        return
    if any(read.values) or any(write.values):  # type: ignore[union-attr]
        return
    findings.append(
        finding_from_rule(
            rule,
            _resource(name),
            {
                "table_name": name,
                "lookback_days": days,
                "consumed_read_units": 0.0,
                "consumed_write_units": 0.0,
                "metric_missing_interpreted_as_zero": False,
                "cost_estimate": cost_evidence(
                    "usage_evidence",
                    "CloudWatch reported no consumed read or write units for the complete lookback window.",
                ),
            },
            [
                "Confirm consumers, streams, global tables, backups, and ownership.",
                "Export or back up data before any separately approved retirement.",
            ],
            "After an approved change, verify consumers and recovery procedures remain healthy.",
            resource_ref=_resource_ref(table, name, region),
            evidence_source="aws_cloudwatch_metric",
        )
    )


def _evaluate_on_demand(
    context: EvaluationContext,
    table: Dict[str, Any],
    name: str,
    read: MetricSeries | None,
    write: MetricSeries | None,
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("dynamodb_on_demand_low_utilization")
    billing_mode = str((table.get("BillingModeSummary") or {}).get("BillingMode") or "PROVISIONED")
    if not rule or billing_mode != "PAY_PER_REQUEST":
        return
    days = int(rule.parameters.get("lookback_days") or 14)
    maximum = float(rule.parameters.get("maximum_daily_requests") or 100.0)
    if not _complete(read, days) or not _complete(write, days):
        return
    totals = [left + right for left, right in zip(read.values, write.values)]  # type: ignore[union-attr]
    if not totals or max(totals) >= maximum:
        return
    findings.append(
        finding_from_rule(
            rule,
            _resource(name),
            {
                "table_name": name,
                "billing_mode": billing_mode,
                "lookback_days": days,
                "maximum_daily_requests": max(totals),
                "threshold_daily_requests": maximum,
                "metric_missing_interpreted_as_zero": False,
            },
            [
                "Compare on-demand and provisioned pricing using actual traffic variability and account discounts."
            ],
            "Re-read billing mode and CloudWatch traffic after any approved change.",
            resource_ref=_resource_ref(table, name, region),
            evidence_source="aws_cloudwatch_metric",
        )
    )


def _evaluate_provisioned(
    context: EvaluationContext,
    table: Dict[str, Any],
    name: str,
    read: MetricSeries | None,
    write: MetricSeries | None,
    findings: List[Finding],
    region: str,
) -> None:
    billing_mode = str((table.get("BillingModeSummary") or {}).get("BillingMode") or "PROVISIONED")
    if billing_mode != "PROVISIONED":
        return
    throughput = table.get("ProvisionedThroughput") or {}
    for detector, metric, capacity_key, dimension in (
        ("dynamodb_read_capacity_underutilized", read, "ReadCapacityUnits", "read"),
        ("dynamodb_write_capacity_underutilized", write, "WriteCapacityUnits", "write"),
    ):
        rule = context.rule(detector)
        if not rule:
            continue
        days = int(rule.parameters.get("lookback_days") or 14)
        threshold = float(rule.parameters.get("maximum_utilization_percent") or 20.0)
        provisioned = float(throughput.get(capacity_key) or 0.0)
        if provisioned <= 0 or not _complete(metric, days):
            continue
        utilization = [
            value / (provisioned * 86400.0) * 100.0
            for value in metric.values  # type: ignore[union-attr]
        ]
        if not utilization or max(utilization) >= threshold:
            continue
        findings.append(
            finding_from_rule(
                rule,
                _resource(name),
                {
                    "table_name": name,
                    "capacity_dimension": dimension,
                    "provisioned_capacity_units": provisioned,
                    "observed_maximum_utilization_percent": round(max(utilization), 4),
                    "threshold_percent": threshold,
                    "lookback_days": days,
                    "metric_missing_interpreted_as_zero": False,
                },
                [
                    "Review peaks, auto scaling, throttles, and deployment schedules before reducing provisioned capacity."
                ],
                "Re-read provisioned capacity and CloudWatch utilization after any approved change.",
                resource_ref=_resource_ref(table, name, region),
                evidence_source="aws_cloudwatch_metric",
            )
        )


def _resource(name: str) -> str:
    return f"dynamodb://table/{quote(name, safe='._-')}"


def _resource_ref(table: Dict[str, Any], name: str, region: str) -> ResourceRef:
    arn = str(table.get("TableArn") or "") or None
    account_id = arn.split(":", 5)[4] if arn and arn.count(":") >= 5 else None
    return ResourceRef(
        provider="aws",
        service="dynamodb",
        resource_type="aws.dynamodb.table",
        resource_id=name,
        region=region,
        account_id=account_id,
        arn=arn,
        display_name=name,
    )
