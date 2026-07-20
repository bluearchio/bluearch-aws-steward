"""Build one explainable recommendation queue from independent AWS signals."""

from __future__ import annotations

import hashlib
import math
from copy import deepcopy
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote

from bluearch_aws_steward.models import utc_now_iso

JSON = Dict[str, Any]

NATIVE_SOURCE = "bluearch-steward"
LIVE_SIGNAL_SOURCES = {
    "security-hub",
    "compute-optimizer",
    "cost-optimization-hub",
}
RESOLVED_VALIDATION_STATUSES = {"resolved", "resolved_or_stale", "stale"}

_SEVERITY_SCORE = {
    "critical": 30.0,
    "high": 25.0,
    "medium": 17.0,
    "low": 8.0,
    "info": 3.0,
}
_VALIDATION_SCORE = {
    "confirmed": 20.0,
    "source_current": 16.0,
    "external_unverified": 8.0,
    "unknown": 4.0,
    "resolved_or_stale": 0.0,
}
_CONFIDENCE_SCORE = {"high": 4.0, "medium": 2.5, "low": 1.0}

_CANONICAL_PROBLEMS = {
    "ec2-low-cpu-rightsizing": "ec2:rightsizing",
    "ec2-compute-optimizer-rightsizing": "ec2:rightsizing",
    "ec2-idle-instance": "ec2:idle",
    "ec2-gp2-volume-candidate": "ebs:volume-optimization",
    "ec2-compute-optimizer-ebs": "ebs:volume-optimization",
    "lambda-memory-underutilized": "lambda:memory-rightsizing",
    "lambda-memory-pressure": "lambda:memory-rightsizing",
    "lambda-compute-optimizer-memory": "lambda:memory-rightsizing",
    "rds-low-cpu-rightsizing": "rds:rightsizing",
    "rds-idle-instance": "rds:idle",
    "alb-idle-load-balancer": "alb:idle",
}


def recommendation_fingerprint(finding: JSON, scan_result: Optional[JSON] = None) -> str:
    """Return a source-independent identity for one resource/problem pair."""

    context = scan_result or {}
    account = _account_id(finding, context)
    region = _region(finding, context)
    resource = canonical_resource(finding.get("resource"), finding.get("service"))
    problem = canonical_problem(finding)
    raw = "|".join((account, region, resource.lower(), problem.lower()))
    return f"steward-rec-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def canonical_problem(finding: JSON) -> str:
    evidence = _mapping(finding.get("evidence"))
    explicit = str(evidence.get("canonical_problem") or "").strip().lower()
    if explicit:
        return explicit
    rule = str(finding.get("rule_short_id") or finding.get("rule_id") or "unknown").lower()
    return _CANONICAL_PROBLEMS.get(rule, rule)


def canonical_resource(resource: Any, service: Any = None) -> str:
    value = str(resource or "unknown").strip()
    normalized_service = str(service or "unknown").lower()
    if value.startswith(
        (
            "s3://",
            "cloudwatch-logs://",
            "cloudtrail://",
            "ebs://",
            "ec2://",
            "rds://",
            "lambda://",
            "iam://",
            "efs://",
            "ecs://",
            "alb://",
            "dynamodb://",
            "kms://",
            "secrets-manager://",
            "sns://",
            "sqs://",
            "api-gateway://",
        )
    ):
        return value.rstrip("/")
    if not value.startswith("arn:"):
        if normalized_service == "s3":
            return f"s3://{value}"
        if normalized_service == "ec2" and value.startswith("vol-"):
            return f"ebs://{value}"
        if normalized_service == "ec2" and value.startswith("i-"):
            return f"ec2://instance/{value}"
        return value

    parts = value.split(":", 5)
    arn_service = parts[2] if len(parts) > 2 else normalized_service
    suffix = parts[5] if len(parts) > 5 else value
    if arn_service == "s3":
        return f"s3://{suffix.lstrip(':')}"
    if arn_service == "logs" and ":log-group:" in value:
        name = value.split(":log-group:", 1)[1].removesuffix(":*")
        return f"cloudwatch-logs://log-group/{quote(name.lstrip('/'), safe='/._-')}"
    if arn_service == "cloudtrail" and "trail/" in suffix:
        return f"cloudtrail://trail/{quote(suffix.split('trail/', 1)[1], safe='._-')}"
    if arn_service == "ec2":
        kind, _, identifier = suffix.partition("/")
        if kind == "volume":
            return f"ebs://{identifier}"
        if kind == "instance":
            return f"ec2://instance/{identifier}"
        return f"ec2://{suffix}"
    if arn_service == "rds" and suffix.startswith("db:"):
        return f"rds://db/{quote(suffix.split(':', 1)[1], safe='._-')}"
    if arn_service == "lambda" and suffix.startswith("function:"):
        return f"lambda://function/{quote(suffix.split(':', 1)[1], safe='._-')}"
    if arn_service == "elasticfilesystem" and suffix.startswith("file-system/"):
        return f"efs://{suffix}"
    if arn_service == "elasticloadbalancing" and suffix.startswith("loadbalancer/"):
        return f"alb://{suffix}"
    if arn_service == "dynamodb" and suffix.startswith("table/"):
        return f"dynamodb://{suffix}"
    if arn_service == "secretsmanager":
        return f"secrets-manager://{suffix}"
    if arn_service == "apigateway":
        return f"api-gateway://{suffix.lstrip('/')}"
    return value


def annotate_validation(
    finding: JSON,
    status: str,
    *,
    observed_at: Optional[str] = None,
    reason: Optional[str] = None,
) -> JSON:
    annotated = deepcopy(finding)
    evidence = _mapping(annotated.get("evidence"))
    evidence["live_validation"] = {
        "status": status,
        "observed_at": observed_at or utc_now_iso(),
        "reason": reason,
    }
    annotated["evidence"] = evidence
    return annotated


def consolidate_scan_results(scan_results: Iterable[JSON]) -> JSON:
    """Merge signal snapshots into a single active, prioritized queue."""

    snapshots = [deepcopy(item) for item in scan_results if isinstance(item, dict)]
    grouped: Dict[str, List[tuple[JSON, JSON]]] = {}
    for snapshot in snapshots:
        for finding in snapshot.get("findings") or []:
            if not isinstance(finding, dict):
                continue
            fingerprint = recommendation_fingerprint(finding, snapshot)
            grouped.setdefault(fingerprint, []).append((finding, snapshot))

    active: List[JSON] = []
    resolved_groups = 0
    deduplicated = 0
    source_counts: Dict[str, int] = {}
    for fingerprint, candidates in grouped.items():
        merged = _merge_group(fingerprint, candidates)
        deduplicated += max(0, len(candidates) - 1)
        if merged is None:
            resolved_groups += 1
            continue
        active.append(merged)
        for source in merged.get("sources") or []:
            source_counts[source] = source_counts.get(source, 0) + 1

    active.sort(
        key=lambda item: (
            -float((_mapping(item.get("priority"))).get("score") or 0),
            str(item.get("service") or ""),
            str(item.get("rule_short_id") or ""),
            str(item.get("resource") or ""),
        )
    )
    generated_at = utc_now_iso()
    service_names = sorted({str(item.get("service") or "unknown") for item in active})
    base = snapshots[0] if snapshots else {}
    totals = [_mapping(snapshot.get("summary")) for snapshot in snapshots]
    validation_counts: Dict[str, int] = {}
    for finding in active:
        status = str((_mapping(finding.get("validation"))).get("status") or "unknown")
        validation_counts[status] = validation_counts.get(status, 0) + 1
    return {
        "schema_version": "0.2",
        "generated_at": generated_at,
        "service": service_names[0] if len(service_names) == 1 else "all",
        "provider": base.get("provider") or "aws-sdk",
        "profile": base.get("profile"),
        "endpoint_url": base.get("endpoint_url"),
        "region": base.get("region") or "us-east-1",
        "findings": active,
        "summary": {
            "unified_recommendation_queue": True,
            "signal_snapshots": len(snapshots),
            "signals_received": sum(len(item.get("findings") or []) for item in snapshots),
            "findings": len(active),
            "recommendations": len(active),
            "deduplicated_signals": deduplicated,
            "resolved_or_stale_recommendations": resolved_groups,
            "sources": source_counts,
            "validation_statuses": validation_counts,
            "resources_scanned": max(
                [int(summary.get("resources_scanned") or 0) for summary in totals] or [0]
            ),
            "rules_evaluated": max(
                [int(summary.get("rules_evaluated") or 0) for summary in totals] or [0]
            ),
            "scan_errors": sum(int(summary.get("scan_errors") or 0) for summary in totals),
            "service_errors": [
                error for summary in totals for error in (summary.get("service_errors") or [])
            ],
            "capability_errors": [
                error for summary in totals for error in (summary.get("capability_errors") or [])
            ],
            "rules_skipped": [
                rule for summary in totals for rule in (summary.get("rules_skipped") or [])
            ],
            "services_scanned": service_names,
            "service_summaries": next(
                (
                    dict(summary["service_summaries"])
                    for summary in totals
                    if isinstance(summary.get("service_summaries"), dict)
                ),
                {},
            ),
            "detection_coverage": _best_coverage(totals),
            "persistent_inventory": False,
            "source_of_truth": "live AWS point-in-time evidence",
        },
    }


def _merge_group(fingerprint: str, candidates: List[tuple[JSON, JSON]]) -> Optional[JSON]:
    ranked = sorted(candidates, key=lambda item: _candidate_rank(item[0], item[1]))
    primary, primary_scan = ranked[0]
    provenance = [_provenance(finding, scan) for finding, scan in candidates]
    current = [
        (finding, scan)
        for finding, scan in candidates
        if _validation_status(finding, scan) not in RESOLVED_VALIDATION_STATUSES
    ]
    if not current:
        return None
    primary, primary_scan = sorted(current, key=lambda item: _candidate_rank(item[0], item[1]))[0]

    merged = deepcopy(primary)
    merged["finding_id"] = fingerprint
    merged["recommendation_fingerprint"] = fingerprint
    merged["resource"] = canonical_resource(primary.get("resource"), primary.get("service"))
    merged["canonical_problem"] = canonical_problem(primary)
    sources = sorted({item["source"] for item in provenance})
    merged["sources"] = sources
    merged["source_count"] = len(sources)
    merged["source_finding_ids"] = sorted(
        {str(item["source_finding_id"]) for item in provenance if item.get("source_finding_id")}
    )
    status = _group_validation_status(current)
    merged["validation"] = {
        "status": status,
        "observed_at": max(
            (str(item.get("observed_at") or "") for item in provenance),
            default=str(primary_scan.get("generated_at") or utc_now_iso()),
        ),
        "source_disagreement": len(current) != len(candidates),
        "resolved_sources": sum(
            _validation_status(finding, scan) in RESOLVED_VALIDATION_STATUSES
            for finding, scan in candidates
        ),
    }
    evidence = _mapping(merged.get("evidence"))
    evidence["provenance"] = provenance
    evidence["canonical_problem"] = merged["canonical_problem"]
    evidence["live_validation"] = merged["validation"]
    evidence["source_count"] = len(sources)
    merged["evidence"] = evidence
    merged["priority"] = priority_score(merged)
    return merged


def priority_score(finding: JSON) -> JSON:
    evidence = _mapping(finding.get("evidence"))
    validation = _mapping(finding.get("validation"))
    severity = str(finding.get("severity") or "medium").lower()
    validation_status = str(validation.get("status") or "unknown")
    risk = _SEVERITY_SCORE.get(severity, 10.0)
    confidence = _VALIDATION_SCORE.get(validation_status, 4.0)

    estimate = _mapping(evidence.get("cost_estimate"))
    savings = _number(estimate.get("estimated_monthly_savings_usd"))
    savings_score = min(20.0, 5.0 * math.log10(1.0 + max(0.0, savings))) if savings else 0.0
    confidence += _CONFIDENCE_SCORE.get(str(estimate.get("confidence") or "").lower(), 0.0)
    confidence = min(20.0, confidence)

    remediation = _mapping(finding.get("remediation"))
    safety = str(remediation.get("safety_level") or "review_required").lower()
    readiness = {
        "low_risk": 15.0,
        "guarded": 12.0,
        "planning_only": 8.0,
        "review_required": 5.0,
    }.get(safety, 5.0)
    corroboration = min(10.0, max(0, int(finding.get("source_count") or 1) - 1) * 5.0)
    effort = str(evidence.get("implementation_effort") or "medium").lower()
    effort_score = {"very_low": 5.0, "low": 4.0, "medium": 2.0, "high": 0.0}.get(effort, 2.0)
    components = {
        "risk": round(risk, 2),
        "freshness_and_confidence": round(confidence, 2),
        "estimated_savings": round(savings_score, 2),
        "remediation_readiness": round(readiness, 2),
        "corroboration": round(corroboration, 2),
        "implementation_effort": round(effort_score, 2),
    }
    return {
        "score": round(min(100.0, sum(components.values())), 2),
        "scale": "0-100",
        "components": components,
        "explanation": (
            "Risk, current evidence, savings, remediation readiness, independent corroboration, "
            "and implementation effort contribute to this deterministic score."
        ),
    }


def _candidate_rank(finding: JSON, scan: JSON) -> tuple[Any, ...]:
    status = _validation_status(finding, scan)
    status_rank = {
        "confirmed": 0,
        "source_current": 1,
        "external_unverified": 2,
        "unknown": 3,
        "resolved_or_stale": 4,
    }.get(status, 3)
    source = _source(finding, scan)
    source_rank = 0 if source == NATIVE_SOURCE else (1 if source in LIVE_SIGNAL_SOURCES else 2)
    mapping_rank = (
        0
        if str((_mapping(finding.get("evidence"))).get("mapping_status"))
        in {
            "native",
            "mapped",
        }
        else 1
    )
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(
        str(finding.get("severity") or "medium").lower(), 4
    )
    return (
        status_rank,
        source_rank,
        mapping_rank,
        severity_rank,
        str(finding.get("finding_id") or ""),
    )


def _source(finding: JSON, scan: JSON) -> str:
    evidence = _mapping(finding.get("evidence"))
    source = str(
        evidence.get("finding_source")
        or _mapping(scan.get("summary")).get("finding_source")
        or NATIVE_SOURCE
    )
    return source


def _validation_status(finding: JSON, scan: JSON) -> str:
    evidence = _mapping(finding.get("evidence"))
    validation = _mapping(evidence.get("live_validation"))
    if validation.get("status"):
        return str(validation["status"])
    source = _source(finding, scan)
    if source == NATIVE_SOURCE:
        return "confirmed"
    if source in LIVE_SIGNAL_SOURCES:
        return "source_current"
    return "external_unverified"


def _group_validation_status(candidates: List[tuple[JSON, JSON]]) -> str:
    statuses = {_validation_status(finding, scan) for finding, scan in candidates}
    for status in ("confirmed", "source_current", "external_unverified", "unknown"):
        if status in statuses:
            return status
    return "unknown"


def _provenance(finding: JSON, scan: JSON) -> JSON:
    evidence = _mapping(finding.get("evidence"))
    source = _source(finding, scan)
    validation = _validation_status(finding, scan)
    return {
        "source": source,
        "source_finding_id": evidence.get("external_finding_id") or finding.get("finding_id"),
        "source_rule_id": evidence.get("external_rule_id")
        or finding.get("rule_short_id")
        or finding.get("rule_id"),
        "source_status": evidence.get("source_status") or "ACTIVE",
        "observed_at": evidence.get("observed_at") or scan.get("generated_at"),
        "freshness": validation,
        "trust": evidence.get("external_content_trust") or "trusted_local_detector",
        "mapping_status": evidence.get("mapping_status") or "native",
    }


def _account_id(finding: JSON, scan: JSON) -> str:
    resource_ref = _mapping(finding.get("resource_ref"))
    evidence = _mapping(finding.get("evidence"))
    value = (
        resource_ref.get("account_id")
        or evidence.get("source_account_id")
        or evidence.get("account_id")
        or scan.get("account_id")
        or "unknown-account"
    )
    return str(value)


def _region(finding: JSON, scan: JSON) -> str:
    service = str(finding.get("service") or "")
    if service in {"iam", "route53", "organizations"}:
        return "global"
    resource_ref = _mapping(finding.get("resource_ref"))
    evidence = _mapping(finding.get("evidence"))
    value = (
        resource_ref.get("region")
        or evidence.get("source_region")
        or evidence.get("region")
        or scan.get("region")
        or "unknown-region"
    )
    return str(value)


def _best_coverage(summaries: List[JSON]) -> JSON:
    candidates: List[JSON] = []
    for summary in summaries:
        coverage = summary.get("detection_coverage")
        if isinstance(coverage, dict):
            candidates.append(dict(coverage))
    return deepcopy(candidates[0]) if candidates else {}


def _mapping(value: Any) -> JSON:
    return dict(value) if isinstance(value, dict) else {}


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _parse_time(value: Any) -> datetime:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return datetime.min.replace(tzinfo=timezone.utc)
