from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from typing import Any, Dict, List, Optional

from bluearch_aws_steward.catalog import filter_rules
from bluearch_aws_steward.models import utc_now_iso
from bluearch_aws_steward.recommendation_queue import canonical_resource

JSON = Dict[str, Any]
SUPPORTED_FINDING_SOURCES = (
    "securityhub-asff",
    "prowler-json",
    "compute-optimizer-json",
    "cost-optimization-hub-json",
)
MAX_IMPORTED_FINDINGS = 5000
MAX_IMPORT_PAYLOAD_BYTES = 10 * 1024 * 1024


EXTERNAL_RULE_ALIASES = {
    "cloudtrail.4": "cloudtrail-log-validation-disabled",
    "cloudtrail_log_file_validation_enabled": "cloudtrail-log-validation-disabled",
    "cloudtrail_log_file_validation_is_enabled": "cloudtrail-log-validation-disabled",
    "iam_root_mfa_enabled": "iam-root-mfa-disabled",
    "s3.4": "s3-no-default-encryption",
    "s3_bucket_default_encryption": "s3-no-default-encryption",
    "s3_bucket_lifecycle_enabled": "s3-no-lifecycle",
    "s3_bucket_object_versioning": "s3-versioning-disabled",
    "s3_bucket_public_access": "s3-public-bucket",
    "s3_bucket_server_side_encryption_enabled": "s3-no-default-encryption",
    "s3_bucket_versioning_enabled": "s3-versioning-disabled",
    "s3_bucket_versioning": "s3-versioning-disabled",
    "cloudwatch_log_group_retention_policy_specific_days_enabled": "cloudwatch-log-retention-missing",
    "cloudwatch_log_group_retention_policy_enabled": "cloudwatch-log-retention-missing",
    "ec2_compute_optimizer_rightsizing": "ec2-low-cpu-rightsizing",
    "ec2_compute_optimizer_ebs": "ec2-gp2-volume-candidate",
    "lambda_compute_optimizer_memory": "lambda-memory-underutilized",
    "rds_compute_optimizer_rightsizing": "rds-low-cpu-rightsizing",
}


def _as_json(value: Any) -> JSON:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def normalize_external_findings(source: str, payload: Any) -> JSON:
    if source not in SUPPORTED_FINDING_SOURCES:
        supported = ", ".join(SUPPORTED_FINDING_SOURCES)
        raise ValueError(f"Unsupported finding source: {source}. Supported sources: {supported}")

    try:
        payload_bytes = len(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("Finding payload must contain JSON-compatible values.") from exc
    if payload_bytes > MAX_IMPORT_PAYLOAD_BYTES:
        raise ValueError(
            f"Finding payload is {payload_bytes} bytes; the limit is {MAX_IMPORT_PAYLOAD_BYTES} bytes."
        )

    records = _records(payload, source)
    if len(records) > MAX_IMPORTED_FINDINGS:
        raise ValueError(
            f"Finding payload contains {len(records)} records; the limit is {MAX_IMPORTED_FINDINGS}."
        )

    normalizers = {
        "securityhub-asff": _normalize_asff,
        "prowler-json": _normalize_prowler,
        "compute-optimizer-json": _normalize_compute_optimizer,
        "cost-optimization-hub-json": _normalize_cost_optimization_hub,
    }
    normalizer = normalizers[source]
    findings: List[JSON] = []
    skipped = {"passed": 0, "inactive": 0, "invalid": 0}
    mapped = 0
    for record in records:
        if not isinstance(record, dict):
            skipped["invalid"] += 1
            continue
        normalized, reason = normalizer(record)
        if normalized is None:
            skipped[reason or "invalid"] = skipped.get(reason or "invalid", 0) + 1
            continue
        additions = normalized if isinstance(normalized, list) else [normalized]
        if len(findings) + len(additions) > MAX_IMPORTED_FINDINGS:
            raise ValueError(
                f"Finding payload expands beyond the {MAX_IMPORTED_FINDINGS} finding limit."
            )
        findings.extend(additions)
        mapped += sum(
            1
            for addition in additions
            if (addition.get("evidence") or {}).get("mapping_status") == "mapped"
        )

    services = sorted({str(finding.get("service") or "unknown") for finding in findings})
    regions = sorted(
        {
            str((finding.get("evidence") or {}).get("source_region"))
            for finding in findings
            if (finding.get("evidence") or {}).get("source_region")
        }
    )
    generated_at = utc_now_iso()
    return {
        "schema_version": "0.2",
        "generated_at": generated_at,
        "service": services[0] if len(services) == 1 else "all",
        "provider": "aws-sdk",
        "profile": None,
        "endpoint_url": None,
        "region": regions[0] if len(regions) == 1 else "us-east-1",
        "findings": findings,
        "summary": {
            "finding_source": source,
            "records_received": len(records),
            "findings": len(findings),
            "mapped_findings": mapped,
            "unmapped_findings": len(findings) - mapped,
            "resources_scanned": 0,
            "rules_evaluated": 0,
            "scan_errors": 0,
            "skipped": skipped,
            "services_scanned": services,
            "external_snapshot": True,
            "live_revalidation_required_before_write": True,
        },
    }


def _records(payload: Any, source: str) -> List[Any]:
    if isinstance(payload, list):
        return list(payload)
    if not isinstance(payload, dict):
        raise ValueError("Finding payload must be an object or array.")
    if source == "compute-optimizer-json":
        records: List[Any] = []
        for key in (
            "instanceRecommendations",
            "volumeRecommendations",
            "lambdaFunctionRecommendations",
            "autoScalingGroupRecommendations",
        ):
            value = payload.get(key)
            if isinstance(value, list):
                for record in value:
                    if isinstance(record, dict):
                        records.append({**record, "_recommendation_kind": key})
                    else:
                        records.append(record)
        if records:
            return records
    for key in ("Findings", "findings", "items", "Items", "recommendations"):
        value = payload.get(key)
        if isinstance(value, list):
            return list(value)
    return [payload]


def _normalize_compute_optimizer(record: JSON) -> tuple[Optional[JSON], Optional[str]]:
    finding_status = str(record.get("finding") or record.get("findingReasonCodes") or "").lower()
    if finding_status in {"optimized", "unavailable"}:
        return None, "passed" if finding_status == "optimized" else "inactive"

    kind = str(record.get("_recommendation_kind") or "")
    external_rule = "ec2-compute-optimizer-rightsizing"
    service = "ec2"
    resource_type = "AwsEc2Instance"
    resource_id = record.get("instanceArn") or record.get("instanceName")
    canonical_problem = "ec2:rightsizing"
    if kind == "volumeRecommendations" or record.get("volumeArn"):
        external_rule = "ec2-compute-optimizer-ebs"
        resource_type = "AwsEc2Volume"
        resource_id = record.get("volumeArn")
        canonical_problem = "ebs:volume-optimization"
    elif kind == "lambdaFunctionRecommendations" or record.get("functionArn"):
        external_rule = "lambda-compute-optimizer-memory"
        service = "lambda"
        resource_type = "AwsLambdaFunction"
        resource_id = record.get("functionArn")
        canonical_problem = "lambda:memory-rightsizing"
    elif kind == "autoScalingGroupRecommendations" or record.get("autoScalingGroupArn"):
        external_rule = "ec2-compute-optimizer-rightsizing"
        resource_type = "AwsAutoScalingAutoScalingGroup"
        resource_id = record.get("autoScalingGroupArn")

    if not resource_id:
        return None, "invalid"
    savings = _compute_optimizer_savings(record)
    confidence = _compute_optimizer_confidence(record)
    return _normalized_finding(
        source="compute-optimizer-json",
        external_id=record.get("recommendationId") or resource_id,
        external_rule=external_rule,
        resource_id=resource_id,
        resource_type=resource_type,
        service_hint=service,
        region=_region_from_arn(resource_id),
        severity="medium" if finding_status not in {"underprovisioned"} else "high",
        title=f"AWS Compute Optimizer: {finding_status or 'optimization available'}",
        description="AWS Compute Optimizer returned an active recommendation for this resource.",
        remediation_text="Review the recommended option, workload peaks, dependencies, and rollback before changing capacity.",
        remediation_url=None,
        observed_at=record.get("lastRefreshTimestamp"),
        source_status=str(record.get("finding") or "ACTIVE"),
        source_format="aws-api-json",
        account_id=_account_from_arn(resource_id),
        extra_evidence={
            "canonical_problem": canonical_problem,
            "native_revalidation_equivalent": False,
            "performance_risk": record.get("currentPerformanceRisk"),
            "implementation_effort": "medium",
            "cost_estimate": {
                "status": "estimated" if savings is not None else "not_estimated",
                "estimated_monthly_savings_usd": savings,
                "confidence": confidence,
                "basis": "AWS Compute Optimizer projected recommendation savings.",
                "source": "aws-compute-optimizer",
            },
        },
    ), None


def _normalize_cost_optimization_hub(record: JSON) -> tuple[Optional[JSON], Optional[str]]:
    status = str(record.get("status") or "ACTIVE").upper()
    if status in {"DISMISSED", "RESOLVED", "INACTIVE"}:
        return None, "inactive"
    resource_id = record.get("resourceArn") or record.get("resourceId")
    if not resource_id:
        return None, "invalid"
    service = _cost_hub_service(record, resource_id)
    action = str(record.get("actionType") or "optimize").lower()
    canonical_problem = _cost_hub_problem(service, action)
    rule = f"{service}-cost-optimization-hub-{_slug(action)}"
    savings = _number_or_none(record.get("estimatedMonthlySavings"))
    if savings is None:
        savings = _number_or_none(
            _nested(record, "estimatedSavingsOverCostCalculationLookbackPeriod", "value")
        )
    return _normalized_finding(
        source="cost-optimization-hub-json",
        external_id=record.get("recommendationId") or resource_id,
        external_rule=rule,
        resource_id=resource_id,
        resource_type=record.get("currentResourceType") or record.get("resourceType"),
        service_hint=service,
        region=record.get("region") or _region_from_arn(resource_id),
        severity="medium",
        title=f"AWS Cost Optimization Hub: {action}",
        description="AWS Cost Optimization Hub returned an active cost recommendation.",
        remediation_text="Validate workload ownership, dependencies, performance, and rollback before applying this recommendation.",
        remediation_url=None,
        observed_at=record.get("lastRefreshTimestamp") or record.get("updatedAt"),
        source_status=status,
        source_format="aws-api-json",
        account_id=record.get("accountId") or _account_from_arn(resource_id),
        extra_evidence={
            "canonical_problem": canonical_problem,
            "recommended_action": action,
            "implementation_effort": str(record.get("implementationEffort") or "medium").lower(),
            "restart_needed": record.get("restartNeeded"),
            "rollback_possible": record.get("rollbackPossible"),
            "cost_estimate": {
                "status": "estimated" if savings is not None else "not_estimated",
                "estimated_monthly_savings_usd": savings,
                "confidence": "medium" if savings is not None else "not_available",
                "basis": "AWS Cost Optimization Hub estimated monthly savings.",
                "source": "aws-cost-optimization-hub",
            },
        },
    ), None


def _normalize_asff(record: JSON) -> tuple[Optional[List[JSON]], Optional[str]]:
    if str(record.get("RecordState") or "ACTIVE").upper() == "ARCHIVED":
        return None, "inactive"
    workflow = _as_json(record.get("Workflow"))
    if str(workflow.get("Status") or "").upper() in {"RESOLVED", "SUPPRESSED"}:
        return None, "inactive"
    compliance = _as_json(record.get("Compliance"))
    compliance_status = str(compliance.get("Status") or "").upper()
    if compliance_status == "PASSED":
        return None, "passed"
    if compliance_status in {"NOT_AVAILABLE", "NO_DATA"}:
        return None, "inactive"

    resources = _as_list(record.get("Resources"))
    resources = [
        resource for resource in resources if isinstance(resource, dict) and resource.get("Id")
    ]
    if not resources:
        return None, "invalid"
    external_rule = (
        compliance.get("SecurityControlId")
        or record.get("GeneratorId")
        or _nested(record, "ProductFields", "ControlId")
        or record.get("Id")
    )
    return [
        _normalized_finding(
            source="securityhub-asff",
            external_id=record.get("Id"),
            external_rule=external_rule,
            resource_id=resource.get("Id"),
            resource_type=resource.get("Type"),
            service_hint=_service_from_asff_type(resource.get("Type")),
            region=resource.get("Region") or record.get("Region"),
            severity=_nested(record, "Severity", "Label")
            or _nested(record, "FindingProviderFields", "Severity", "Label"),
            title=record.get("Title"),
            description=record.get("Description"),
            remediation_text=_nested(record, "Remediation", "Recommendation", "Text"),
            remediation_url=_nested(record, "Remediation", "Recommendation", "Url"),
            observed_at=record.get("LastObservedAt") or record.get("UpdatedAt"),
            source_status=compliance_status or "FAILED",
            source_format="asff",
            account_id=record.get("AwsAccountId"),
        )
        for resource in resources
    ], None


def _normalize_prowler(record: JSON) -> tuple[Optional[Any], Optional[str]]:
    metadata = _as_json(record.get("metadata"))
    if (
        metadata.get("event_code")
        or record.get("class_uid") == 2004
        or (
            isinstance(record.get("finding_info"), dict)
            and isinstance(record.get("resources"), list)
        )
    ):
        return _normalize_prowler_ocsf(record)
    return _normalize_prowler_native(record)


def _normalize_prowler_native(record: JSON) -> tuple[Optional[JSON], Optional[str]]:
    provider = str(_first(record, "PROVIDER", "provider", "Provider") or "aws").lower()
    if provider not in {"aws", "amazon web services"}:
        return None, "invalid"
    muted = _first(record, "MUTED", "muted", "Muted")
    if muted is True or str(muted or "").lower() == "true":
        return None, "inactive"
    status = str(_first(record, "STATUS", "status", "Status") or "FAIL").upper()
    if status in {"PASS", "PASSED"}:
        return None, "passed"
    if status in {"MUTED", "SUPPRESSED", "RESOLVED"}:
        return None, "inactive"

    metadata = _as_json(record.get("metadata"))
    external_rule = (
        _first(record, "CHECK_ID", "check_id", "CheckID")
        or metadata.get("CheckID")
        or metadata.get("check_id")
    )
    resource_id = _first(
        record,
        "RESOURCE_ARN",
        "resource_arn",
        "ResourceArn",
        "RESOURCE_UID",
        "resource_uid",
        "RESOURCE_ID",
        "resource_id",
    )
    service_hint = (
        _first(record, "SERVICE_NAME", "service_name", "ServiceName", "SERVICE")
        or metadata.get("ServiceName")
        or metadata.get("service_name")
    )
    if not external_rule or not resource_id:
        return None, "invalid"
    return _normalized_finding(
        source="prowler-json",
        external_id=_first(record, "FINDING_UID", "finding_uid", "uid", "UID"),
        external_rule=external_rule,
        resource_id=resource_id,
        resource_type=_first(record, "RESOURCE_TYPE", "resource_type", "ResourceType"),
        service_hint=service_hint,
        region=_first(record, "REGION", "region", "Region"),
        severity=_first(record, "SEVERITY", "severity", "Severity") or metadata.get("Severity"),
        title=_first(record, "CHECK_TITLE", "check_title", "CheckTitle")
        or metadata.get("CheckTitle"),
        description=_first(record, "STATUS_EXTENDED", "status_extended", "StatusExtended"),
        remediation_text=_first(
            record, "REMEDIATION_RECOMMENDATION_TEXT", "remediation", "Remediation"
        ),
        remediation_url=_first(record, "REMEDIATION_RECOMMENDATION_URL", "remediation_url"),
        observed_at=_first(record, "TIMESTAMP", "timestamp", "updated_at"),
        source_status=status,
        source_format="native-json",
        account_id=_first(record, "ACCOUNT_UID", "account_uid", "ACCOUNT_ID", "account_id"),
    ), None


def _normalize_prowler_ocsf(record: JSON) -> tuple[Optional[List[JSON]], Optional[str]]:
    cloud = _as_json(record.get("cloud"))
    cloud_account = _as_json(cloud.get("account"))
    provider = str(cloud.get("provider") or "aws").lower()
    if provider not in {"aws", "amazon web services"}:
        return None, "invalid"

    unmapped = _as_json(record.get("unmapped"))
    muted = unmapped.get("muted")
    if muted is True or str(muted or "").lower() == "true":
        return None, "inactive"
    status = str(record.get("status_code") or record.get("status") or "FAIL").upper()
    workflow_status = str(record.get("status") or "").upper()
    if status in {"PASS", "PASSED"}:
        return None, "passed"
    if status in {"MUTED", "SUPPRESSED", "RESOLVED"} or workflow_status in {
        "MUTED",
        "SUPPRESSED",
        "RESOLVED",
    }:
        return None, "inactive"

    metadata = _as_json(record.get("metadata"))
    finding_info = _as_json(record.get("finding_info"))
    remediation = _as_json(record.get("remediation"))
    external_rule = metadata.get("event_code")
    resources = [
        resource for resource in _as_list(record.get("resources")) if isinstance(resource, dict)
    ]
    if not external_rule or not resources:
        return None, "invalid"

    references = remediation.get("references")
    remediation_url = references[0] if isinstance(references, list) and references else None
    normalized: List[JSON] = []
    for resource in resources:
        resource_data = _as_json(resource.get("data"))
        resource_metadata = _as_json(resource_data.get("metadata"))
        resource_id = resource.get("uid") or resource_metadata.get("arn") or resource.get("name")
        if not resource_id:
            continue
        group = _as_json(resource.get("group"))
        normalized.append(
            _normalized_finding(
                source="prowler-json",
                external_id=finding_info.get("uid"),
                external_rule=external_rule,
                resource_id=resource_id,
                resource_type=resource.get("type"),
                service_hint=group.get("name"),
                region=resource.get("region") or cloud.get("region"),
                severity=record.get("severity"),
                title=finding_info.get("title"),
                description=(
                    record.get("status_detail") or record.get("message") or finding_info.get("desc")
                ),
                remediation_text=remediation.get("desc"),
                remediation_url=remediation_url,
                observed_at=(
                    record.get("time_dt")
                    or finding_info.get("created_time_dt")
                    or record.get("time")
                ),
                source_status=status,
                source_format="json-ocsf",
                account_id=(
                    cloud_account.get("uid") or cloud.get("account_uid") or cloud.get("account_id")
                ),
            )
        )
    if not normalized:
        return None, "invalid"
    return normalized, None


def _normalized_finding(
    *,
    source: str,
    external_id: Any,
    external_rule: Any,
    resource_id: Any,
    resource_type: Any,
    service_hint: Any,
    region: Any,
    severity: Any,
    title: Any,
    description: Any,
    remediation_text: Any,
    remediation_url: Any,
    observed_at: Any,
    source_status: Any,
    source_format: str,
    account_id: Any = None,
    extra_evidence: Optional[JSON] = None,
) -> JSON:
    external_rule_text = str(external_rule or "external-finding").strip()
    mapped_rule, mapping = _map_rule(external_rule_text)
    service = mapped_rule.service if mapped_rule else _normalize_service(service_hint, resource_id)
    resource = canonical_resource(resource_id, service)
    external_id_text = str(external_id or f"{external_rule_text}:{resource}")
    finding_hash = hashlib.sha256(
        f"{source}:{external_id_text}:{resource}".encode("utf-8")
    ).hexdigest()[:12]
    rule_short_id = (
        mapped_rule.short_id if mapped_rule else f"external-{source}-{_slug(external_rule_text)}"
    )
    actions = [
        (
            str(mapped_rule.remediation.get("summary") or "").strip()
            if mapped_rule
            else "Review the source finding and collect current AWS evidence before changing the resource."
        )
    ]
    region_text = str(region or "").strip() or None
    account_text = str(account_id or _account_from_arn(resource_id) or "").strip() or None
    evidence = {
        "finding_source": source,
        "source_format": source_format,
        "external_content_trust": "untrusted_data",
        "external_finding_id": external_id_text,
        "external_rule_id": external_rule_text,
        "external_title": str(title or "").strip() or None,
        "external_description": str(description or "").strip() or None,
        "external_remediation_text": str(remediation_text or "").strip() or None,
        "source_status": str(source_status or "").upper(),
        "source_region": region_text,
        "source_account_id": account_text,
        "resource_type": str(resource_type or "").strip() or None,
        "observed_at": str(observed_at or "").strip() or None,
        "mapping_status": "mapped" if mapped_rule else "unmapped",
        "mapping_method": mapping,
        "requires_live_revalidation": True,
        "remediation_url": str(remediation_url or "").strip() or None,
    }
    evidence.update(extra_evidence or {})
    return {
        "finding_id": f"steward-import-{finding_hash}",
        "rule_id": mapped_rule.id if mapped_rule else external_rule_text,
        "rule_short_id": rule_short_id,
        "service": service,
        "resource": resource,
        "resource_ref": {
            "provider": "aws",
            "service": service,
            "resource_type": str(resource_type or "").strip() or None,
            "resource_id": resource,
            "region": region_text,
            "account_id": account_text,
            "arn": str(resource_id) if str(resource_id or "").startswith("arn:") else None,
            "display_name": resource,
        },
        "severity": _severity(severity),
        "risk_detail": mapped_rule.risk_detail if mapped_rule else "security",
        "scenario": (
            mapped_rule.scenario if mapped_rule else f"External finding: {external_rule_text}"
        ),
        "evidence": evidence,
        "remediation": {
            "summary": (
                mapped_rule.remediation.get("summary")
                if mapped_rule
                else "Review the external finding and collect live AWS evidence."
            ),
            "safety_level": (
                mapped_rule.remediation.get("safety_level") if mapped_rule else "review_required"
            ),
            "requires_approval": True,
            "actions": actions,
            "verification": "Re-read the live AWS resource and confirm the mapped rule no longer matches.",
        },
    }


def _map_rule(external_rule: str) -> tuple[Any, str]:
    rules = filter_rules()
    normalized = _rule_key(external_rule)
    for rule in rules:
        if normalized in {_rule_key(rule.id), _rule_key(rule.short_id), _rule_key(rule.detector)}:
            return rule, "exact"

    alias = EXTERNAL_RULE_ALIASES.get(normalized)
    if alias:
        for rule in rules:
            if rule.short_id == alias:
                return rule, "built_in_alias"
    return None, "unmapped"


def _normalize_service(service_hint: Any, resource_id: Any) -> str:
    hint = str(service_hint or "").lower().replace("amazon", "").replace("aws", "").strip(" ._-")
    aliases = {
        "cloudwatchlogs": "cloudwatch",
        "cloudwatch logs": "cloudwatch",
        "logs": "cloudwatch",
        "elastic block store": "ec2",
        "ebs": "ec2",
        "simple storage service": "s3",
    }
    if hint in aliases:
        return aliases[hint]
    if hint:
        return hint.split()[0]
    value = str(resource_id or "")
    if value.startswith("arn:"):
        service = value.split(":", 3)[2]
        return {"logs": "cloudwatch"}.get(service, service)
    return "unknown"


def _service_from_asff_type(resource_type: Any) -> str:
    value = str(resource_type or "")
    match = re.match(r"Aws([A-Z][A-Za-z0-9]+)", value)
    token = (match.group(1) if match else value).lower()
    if token.startswith("cloudwatch"):
        return "cloudwatch"
    if token.startswith("cloudtrail"):
        return "cloudtrail"
    if token.startswith("ec2"):
        return "ec2"
    if token.startswith("rds"):
        return "rds"
    if token.startswith("lambda"):
        return "lambda"
    if token.startswith("s3"):
        return "s3"
    if token.startswith("iam"):
        return "iam"
    return token or "unknown"


def _severity(value: Any) -> str:
    normalized = str(value or "medium").lower()
    if normalized in {"informational", "info"}:
        return "low"
    return normalized if normalized in {"critical", "high", "medium", "low"} else "medium"


def _rule_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9.]+", "_", str(value or "").lower()).strip("_")


def _slug(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "finding").lower()).strip("-")[:80] or "finding"


def _first(mapping: JSON, *keys: str) -> Any:
    for key in keys:
        if mapping.get(key) is not None:
            return mapping[key]
    return None


def _nested(mapping: JSON, *keys: str) -> Any:
    value: Any = mapping
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return deepcopy(value)


def _region_from_arn(value: Any) -> Optional[str]:
    text = str(value or "")
    parts = text.split(":", 5)
    return parts[3] or None if len(parts) > 3 else None


def _account_from_arn(value: Any) -> Optional[str]:
    text = str(value or "")
    parts = text.split(":", 5)
    return parts[4] or None if len(parts) > 4 else None


def _compute_optimizer_savings(record: JSON) -> Optional[float]:
    options = (
        record.get("recommendationOptions")
        or record.get("volumeRecommendationOptions")
        or record.get("lambdaFunctionRecommendationOptions")
        or []
    )
    values: List[float] = []
    for option in options if isinstance(options, list) else []:
        if not isinstance(option, dict):
            continue
        value = _nested(
            option, "savingsOpportunityAfterDiscounts", "estimatedMonthlySavings", "value"
        )
        if value is None:
            value = _nested(option, "savingsOpportunity", "estimatedMonthlySavings", "value")
        number = _number_or_none(value)
        if number is not None:
            values.append(number)
    return max(values) if values else None


def _compute_optimizer_confidence(record: JSON) -> str:
    risk = str(record.get("currentPerformanceRisk") or "").lower()
    if risk in {"verylow", "low"}:
        return "high"
    if risk in {"medium"}:
        return "medium"
    return "low" if risk else "not_available"


def _cost_hub_service(record: JSON, resource_id: Any) -> str:
    raw = str(record.get("currentResourceType") or record.get("resourceType") or "").lower()
    if "lambda" in raw:
        return "lambda"
    if "rds" in raw or "database" in raw:
        return "rds"
    if "ebs" in raw or "volume" in raw:
        return "ec2"
    if "loadbalancer" in raw or "load_balancer" in raw:
        return "alb"
    inferred = _normalize_service(None, resource_id)
    return "ec2" if inferred in {"unknown", "autoscaling"} else inferred


def _cost_hub_problem(service: str, action: str) -> str:
    normalized = action.replace("_", "").replace("-", "")
    if normalized in {"rightsize", "rightsizing", "migrategraviton"}:
        return f"{service}:rightsizing"
    if normalized in {"stop", "terminate", "delete"}:
        return f"{service}:idle"
    if service == "ec2" and normalized in {"upgrade", "changetype"}:
        return "ebs:volume-optimization"
    return f"{service}:cost:{_slug(action)}"


def _number_or_none(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
