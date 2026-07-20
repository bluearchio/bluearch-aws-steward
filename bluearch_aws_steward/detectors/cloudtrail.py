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
from bluearch_aws_steward.providers.base import AwsProvider


def scan_cloudtrail(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    rules = rules_by_detector("cloudtrail", rule_filter)
    trails = client.list_cloudtrail_trails()
    findings: List[Finding] = []

    coverage_rule = rules.get("cloudtrail_multi_region_logging_disabled")
    active_multi_region = any(
        trail.get("is_multi_region") is True and trail.get("is_logging") is True for trail in trails
    )
    if coverage_rule and not active_multi_region:
        findings.append(
            finding_from_rule(
                coverage_rule,
                f"cloudtrail://account/{region}",
                {
                    "active_multi_region_trail": False,
                    "trails_observed": len(trails),
                },
                [
                    "Review organization-level and account-level trail ownership.",
                    "Create or update a multi-region trail with a protected destination.",
                    "Confirm the selected trail is actively logging.",
                ],
                "Re-read CloudTrail configuration and confirm an IsMultiRegionTrail trail has IsLogging=true.",
                resource_ref=ResourceRef(
                    provider="aws",
                    service="cloudtrail",
                    resource_type="aws.cloudtrail.account-coverage",
                    resource_id=region,
                    region=region,
                    display_name=f"CloudTrail coverage in {region}",
                ),
            )
        )

    for trail in trails:
        name = str(trail.get("name") or "").strip()
        if not name:
            continue
        resource = f"cloudtrail://trail/{quote(name, safe='._-')}"
        trail_arn = str(trail.get("arn") or "")
        resource_ref = ResourceRef(
            provider="aws",
            service="cloudtrail",
            resource_type="aws.cloudtrail.trail",
            resource_id=name,
            region=str(trail.get("home_region") or region),
            account_id=_account_id(trail_arn),
            arn=trail_arn or None,
            display_name=name,
        )
        common_evidence = {
            "trail_name": name,
            "home_region": trail.get("home_region"),
            "is_multi_region": bool(trail.get("is_multi_region")),
            "is_organization_trail": bool(trail.get("is_organization_trail")),
            "is_logging": bool(trail.get("is_logging")),
        }

        validation_rule = rules.get("cloudtrail_log_validation_disabled")
        if validation_rule and not trail.get("log_file_validation_enabled"):
            findings.append(
                finding_from_rule(
                    validation_rule,
                    resource,
                    {**common_evidence, "log_file_validation_enabled": False},
                    ["Enable log file validation on the reviewed trail."],
                    "Re-read the trail and confirm LogFileValidationEnabled is true.",
                    resource_ref=resource_ref,
                )
            )

        kms_rule = rules.get("cloudtrail_kms_encryption_disabled")
        if kms_rule and not trail.get("kms_key_id"):
            findings.append(
                finding_from_rule(
                    kms_rule,
                    resource,
                    {**common_evidence, "kms_key_configured": False},
                    [
                        "Select a customer-managed KMS key with a least-privilege key policy.",
                        "Grant CloudTrail the required encrypt permissions.",
                        "Configure the reviewed trail to use the key.",
                    ],
                    "Re-read the trail and confirm KmsKeyId is configured.",
                    resource_ref=resource_ref,
                )
            )

        logs_rule = rules.get("cloudtrail_cloudwatch_integration_missing")
        if logs_rule and not trail.get("cloudwatch_logs_log_group_arn"):
            findings.append(
                finding_from_rule(
                    logs_rule,
                    resource,
                    {**common_evidence, "cloudwatch_logs_integration_configured": False},
                    [
                        "Choose a CloudWatch Logs group with an approved retention policy.",
                        "Create a least-privilege delivery role for CloudTrail.",
                        "Configure the trail to deliver events to the reviewed log group.",
                    ],
                    "Re-read the trail and confirm CloudWatchLogsLogGroupArn is configured.",
                    resource_ref=resource_ref,
                )
            )

    return build_scan_result(
        service="cloudtrail",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=1 + len(trails),
        findings=findings,
        rules_evaluated=len(rules),
        rule_filter=rule_filter,
        started_at=started_at,
    )


def _account_id(arn: str) -> str | None:
    parts = arn.split(":", 5)
    return parts[4] or None if len(parts) > 4 else None
