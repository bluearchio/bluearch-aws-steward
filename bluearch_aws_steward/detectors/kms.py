from __future__ import annotations

import time
from typing import Any, Dict, List

from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider


def scan_kms(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    detector = "kms_key_rotation_disabled"
    context = EvaluationContext(client, "kms", rule_filter)
    response = context.read(detector, "kms.list_keys")
    keys = list((response or {}).get("Keys") or [])
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags

    for key in keys:
        key_id = str(key.get("KeyId") or "").strip()
        if not key_id:
            continue
        detail = context.read(detector, "kms.describe_key", KeyId=key_id)
        metadata = dict((detail or {}).get("KeyMetadata") or {})
        if not _eligible_for_automatic_rotation(metadata):
            continue
        tags_response = context.read(detector, "kms.list_resource_tags", KeyId=key_id)
        tags = {
            str(tag.get("TagKey")): str(tag.get("TagValue") or "")
            for tag in (tags_response or {}).get("Tags") or []
            if tag.get("TagKey") is not None
        }
        if resource_is_exempt(tags, exclusions):
            continue
        rotation = context.read(detector, "kms.get_key_rotation_status", KeyId=key_id)
        rule = context.rule(detector)
        if not rule or (rotation or {}).get("KeyRotationEnabled") is True:
            continue

        arn = str(metadata.get("Arn") or key.get("KeyArn") or "").strip()
        findings.append(
            finding_from_rule(
                rule,
                f"kms://key/{key_id}",
                {
                    "key_id": key_id,
                    "key_manager": metadata.get("KeyManager"),
                    "key_state": metadata.get("KeyState"),
                    "key_spec": metadata.get("KeySpec"),
                    "key_usage": metadata.get("KeyUsage"),
                    "origin": metadata.get("Origin"),
                    "key_rotation_enabled": False,
                    "rotation_period_days": (rotation or {}).get("RotationPeriodInDays"),
                },
                [
                    "Inventory services and applications that use the key.",
                    "Confirm that the key is eligible and select an approved rotation period.",
                    "Enable automatic rotation during an approved change window.",
                ],
                "Re-read GetKeyRotationStatus and confirm KeyRotationEnabled is true.",
                resource_ref=ResourceRef(
                    provider="aws",
                    service="kms",
                    resource_type="aws.kms.key",
                    resource_id=key_id,
                    region=region,
                    account_id=_account_id(arn),
                    arn=arn or None,
                    display_name=str(metadata.get("Description") or key_id),
                ),
            )
        )

    return build_scan_result(
        service="kms",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(keys),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _eligible_for_automatic_rotation(metadata: Dict[str, Any]) -> bool:
    return (
        metadata.get("KeyManager") == "CUSTOMER"
        and metadata.get("KeyState") == "Enabled"
        and metadata.get("KeySpec") == "SYMMETRIC_DEFAULT"
        and metadata.get("KeyUsage") == "ENCRYPT_DECRYPT"
        and metadata.get("Origin") == "AWS_KMS"
    )


def _account_id(arn: str) -> str | None:
    parts = arn.split(":", 5)
    return parts[4] if len(parts) == 6 and parts[4] else None
