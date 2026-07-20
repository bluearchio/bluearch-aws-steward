from __future__ import annotations

import time
from typing import List
from urllib.parse import quote

from bluearch_aws_steward.detectors.common import (
    build_scan_result,
    finding_from_rule,
    rules_by_detector,
)
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, effective_float, effective_int
from bluearch_aws_steward.providers.base import AwsProvider


def scan_cloudwatch(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    rules = rules_by_detector("cloudwatch", rule_filter)
    log_groups = client.list_log_groups()
    findings: List[Finding] = []
    rule = rules.get("cloudwatch_log_retention_missing")

    if rule:
        scan_policy = policy or ScanPolicy()
        retention_days = effective_int(
            rule.parameters,
            "recommended_retention_days",
            scan_policy.cloudwatch_retention_days,
        )
        minimum_stored_bytes = effective_int(
            rule.parameters,
            "minimum_stored_bytes_for_cost_opportunity",
            scan_policy.cloudwatch_min_stored_bytes,
        )
        storage_rate = effective_float(rule.parameters, "storage_cost_usd_per_gb_month")
        for group in log_groups:
            name = str(group.get("name") or "").strip()
            if not name or group.get("retention_days") is not None:
                continue
            stored_bytes = int(group.get("stored_bytes") or 0)
            cost_estimate = _cost_estimate(stored_bytes, minimum_stored_bytes, storage_rate)
            arn = str(group.get("arn") or "")
            findings.append(
                finding_from_rule(
                    rule,
                    f"cloudwatch-logs://log-group/{quote(name.lstrip('/'), safe='/._-')}",
                    {
                        "log_group_name": name,
                        "retention_days": None,
                        "stored_bytes": stored_bytes,
                        "created_at": group.get("created_at"),
                        "recommended_retention_days": retention_days,
                        "minimum_stored_bytes_for_cost_opportunity": minimum_stored_bytes,
                        "cost_estimate": cost_estimate,
                    },
                    [
                        "Choose a retention period based on compliance and recovery requirements.",
                        "Export required historical logs before shortening retention.",
                        f"Set the reviewed retention period to {retention_days} days.",
                    ],
                    f"Re-read the log group and confirm retentionInDays is {retention_days}.",
                    resource_ref=ResourceRef(
                        provider="aws",
                        service="logs",
                        resource_type="aws.logs.log-group",
                        resource_id=name,
                        region=region,
                        account_id=_account_id(arn),
                        arn=arn or None,
                        display_name=name,
                    ),
                )
            )

    return build_scan_result(
        service="cloudwatch",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(log_groups),
        findings=findings,
        rules_evaluated=len(rules),
        rule_filter=rule_filter,
        started_at=started_at,
    )


def _account_id(arn: str) -> str | None:
    parts = arn.split(":", 5)
    return parts[4] or None if len(parts) > 4 else None


def _cost_estimate(stored_bytes: int, minimum_stored_bytes: int, storage_rate: float) -> dict:
    if stored_bytes < minimum_stored_bytes:
        return {
            "status": "preventive",
            "estimated_monthly_cost_usd": round((stored_bytes / (1024**3)) * storage_rate, 6),
            "estimated_monthly_savings_usd": 0.0,
            "confidence": "low",
            "basis": "Current storage is below the materiality threshold; retention prevents future accumulation.",
            "assumptions": [
                f"minimum_stored_bytes={minimum_stored_bytes}",
                f"storage_rate_usd_per_gb_month={storage_rate}",
            ],
        }

    stored_gib = stored_bytes / (1024**3)
    estimated_cost = round(stored_gib * storage_rate, 4)
    return {
        "status": "estimated",
        "estimated_monthly_cost_usd": estimated_cost,
        "estimated_monthly_savings_usd": estimated_cost,
        "confidence": "low",
        "basis": "Upper-bound storage estimate from current stored bytes.",
        "assumptions": [
            f"storage_rate_usd_per_gb_month={storage_rate}",
            "Savings depend on log age distribution and the approved retention period.",
        ],
    }
