from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, List, Tuple

from bluearch_aws_steward.catalog import filter_rules
from bluearch_aws_steward.models import (
    Finding,
    RemediationPlan,
    ResourceRef,
    Rule,
    ScanResult,
    utc_now_iso,
)


def rules_by_detector(service: str, rule_filter: str | None) -> Dict[str, Rule]:
    selected_rules = filter_rules(service=service)
    filters = parse_rule_filter(rule_filter)
    if filters:
        selected_rules = [
            rule for rule in selected_rules if filters & {rule.short_id, rule.id, rule.detector}
        ]
        if not selected_rules:
            allowed = ", ".join(sorted(rule.short_id for rule in filter_rules(service=service)))
            raise ValueError(
                f"No {service} rules matched rule_filter={rule_filter!r}. Supported rules: {allowed}"
            )
    return {rule.detector: rule for rule in selected_rules}


def supported_rules_by_detector(
    client: object,
    service: str,
    rule_filter: str | None,
) -> Tuple[Dict[str, Rule], List[Dict[str, Any]]]:
    selected = rules_by_detector(service, rule_filter)
    capability_loader = getattr(client, "capabilities", None)
    available = set(capability_loader()) if callable(capability_loader) else set()
    supported: Dict[str, Rule] = {}
    skipped: List[Dict[str, Any]] = []
    for detector, rule in selected.items():
        required = set(rule.capabilities)
        missing = sorted(required - available)
        if required and missing:
            skipped.append(
                {
                    "rule": rule.short_id,
                    "reason": "unsupported_provider_capability",
                    "missing_capabilities": missing,
                }
            )
        else:
            supported[detector] = rule
    return supported, skipped


def parse_rule_filter(rule_filter: str | None) -> set[str]:
    if not rule_filter:
        return set()
    return {part.strip() for part in rule_filter.split(",") if part.strip()}


def finding_from_rule(
    rule: Rule,
    resource: str,
    evidence: Dict[str, Any],
    actions: List[str],
    verification: str,
    *,
    resource_ref: ResourceRef | None = None,
    confidence: str = "high",
    evidence_source: str = "aws_control_plane",
) -> Finding:
    finding_key = f"{rule.id}:{resource}"
    finding_hash = hashlib.sha256(finding_key.encode("utf-8")).hexdigest()[:12]
    observed_at = utc_now_iso()
    structured_evidence = dict(evidence)
    structured_evidence.setdefault(
        "observation",
        {
            "observed_at": observed_at,
            "confidence": confidence,
            "source": evidence_source,
        },
    )
    return Finding(
        finding_id=f"steward-{finding_hash}",
        rule_id=rule.id,
        rule_short_id=rule.short_id,
        service=rule.service,
        resource=resource,
        severity=rule.severity,
        risk_detail=rule.risk_detail,
        scenario=rule.scenario,
        evidence=structured_evidence,
        remediation=RemediationPlan(
            summary=rule.remediation["summary"],
            safety_level=rule.remediation["safety_level"],
            requires_approval=bool(rule.remediation["requires_approval"]),
            actions=actions,
            verification=verification,
        ),
        resource_ref=resource_ref,
    )


def build_scan_result(
    *,
    service: str,
    provider: str,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    resources_scanned: int,
    findings: List[Finding],
    rules_evaluated: int,
    rule_filter: str | None,
    started_at: float,
    rules_skipped: List[Dict[str, Any]] | None = None,
    capability_errors: List[Dict[str, Any]] | None = None,
) -> ScanResult:
    return ScanResult(
        schema_version="0.2",
        generated_at=utc_now_iso(),
        service=service,
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        findings=findings,
        summary={
            "resources_scanned": resources_scanned,
            "resources_matched": len({finding.resource for finding in findings}),
            "findings": len(findings),
            "rules_evaluated": rules_evaluated,
            "rule_filter": rule_filter,
            "scan_errors": 0,
            "scan_error_samples": [],
            "rules_skipped": list(rules_skipped or []),
            "capability_errors": list(capability_errors or []),
            "duration_seconds": round(time.monotonic() - started_at, 2),
        },
    )
