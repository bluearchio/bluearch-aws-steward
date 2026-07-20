from __future__ import annotations

import time
from typing import Any, Dict, List

from bluearch_aws_steward.detectors.aws_common import tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider


def scan_secrets_manager(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    detector = "secrets_manager_rotation_disabled"
    context = EvaluationContext(client, "secrets-manager", rule_filter)
    response = context.read(detector, "secretsmanager.list_secrets", IncludePlannedDeletion=False)
    secrets = list((response or {}).get("SecretList") or [])
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags

    for listed_secret in secrets:
        secret_id = str(listed_secret.get("ARN") or listed_secret.get("Name") or "").strip()
        if not secret_id:
            continue
        detail = context.read(detector, "secretsmanager.describe_secret", SecretId=secret_id)
        metadata = dict(detail or {})
        if metadata.get("DeletedDate") is not None:
            continue
        if resource_is_exempt(
            tags_dict(metadata.get("Tags") or listed_secret.get("Tags")), exclusions
        ):
            continue
        rule = context.rule(detector)
        if not rule or metadata.get("RotationEnabled") is True:
            continue

        arn = str(metadata.get("ARN") or listed_secret.get("ARN") or "").strip()
        name = str(metadata.get("Name") or listed_secret.get("Name") or secret_id).strip()
        rotation_rules: Dict[str, Any] = dict(metadata.get("RotationRules") or {})
        findings.append(
            finding_from_rule(
                rule,
                f"secrets-manager://secret/{name}",
                {
                    "secret_name": name,
                    "rotation_enabled": False,
                    "automatically_after_days": rotation_rules.get("AutomaticallyAfterDays"),
                    "schedule_expression_present": bool(rotation_rules.get("ScheduleExpression")),
                    "last_rotated_date": metadata.get("LastRotatedDate"),
                    "payload_retrieved": False,
                },
                [
                    "Identify every consumer and choose the supported rotation strategy.",
                    "Test rotation, rollback, and dependency refresh in a non-production environment.",
                    "Enable a reviewed schedule only after consumers are rotation-ready.",
                ],
                "Re-read DescribeSecret and confirm RotationEnabled is true and rotation succeeds.",
                resource_ref=ResourceRef(
                    provider="aws",
                    service="secrets-manager",
                    resource_type="aws.secretsmanager.secret",
                    resource_id=name,
                    region=region,
                    account_id=_account_id(arn),
                    arn=arn or None,
                    display_name=name,
                ),
            )
        )

    return build_scan_result(
        service="secrets-manager",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(secrets),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _account_id(arn: str) -> str | None:
    parts = arn.split(":", 5)
    return parts[4] if len(parts) == 6 and parts[4] else None
