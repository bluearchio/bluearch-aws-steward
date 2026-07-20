"""Local report model and renderers for completed Steward assessments."""

from __future__ import annotations

import csv
import html
import io
import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

from bluearch_aws_steward import __version__
from bluearch_aws_steward.catalog import load_rules
from bluearch_aws_steward.models import REPORT_PROFILES
from bluearch_aws_steward.result_query import (
    complete_result_items,
    item_matches_filters,
    normalize_filters,
)

JSON = Dict[str, Any]
RenderedReport = str | bytes
REPORT_FORMATS = ("json", "markdown", "html", "csv", "sarif", "pdf")


def build_report_model(
    result: JSON,
    *,
    include_clean_resources: bool = False,
    filters: JSON | None = None,
    report_profile: str = "technical",
    include_all_findings: bool = True,
) -> JSON:
    if report_profile not in REPORT_PROFILES:
        raise ValueError(
            f"Unsupported report profile: {report_profile}. Supported: {', '.join(REPORT_PROFILES)}"
        )
    summary = dict(result.get("summary") or {})
    complete_items = complete_result_items(result)
    normalized_filters = normalize_filters(filters or {})
    filtered_items = [
        item for item in complete_items if item_matches_filters(item, normalized_filters)
    ]
    raw_items = filtered_items if include_all_findings else filtered_items[:100]
    rule_lookup = {rule_key: rule for rule in load_rules() for rule_key in (rule.short_id, rule.id)}
    items = [_normalize_report_finding(item, rule_lookup) for item in raw_items]
    resource_context: JSON = {}
    for item in items:
        candidate = item.get("resource_ref")
        if isinstance(candidate, dict):
            resource_context = dict(candidate)
            break
    severity_counts = Counter(str(item.get("severity") or "unknown").lower() for item in items)
    service_counts = Counter(str(item.get("service") or "unknown") for item in items)
    rule_counts = Counter(
        str(item.get("rule") or item.get("rule_id") or "unknown") for item in items
    )
    cost_estimates = [dict(item.get("cost_estimate") or {}) for item in items]
    available_cost_estimates = [
        estimate
        for estimate in cost_estimates
        if isinstance(estimate.get("estimated_monthly_savings_usd"), (int, float))
        and not isinstance(estimate.get("estimated_monthly_savings_usd"), bool)
    ]
    cost_confidence_counts = Counter(
        str(estimate.get("confidence") or "not_available") for estimate in cost_estimates
    )
    return {
        "schema_version": "report-0.1",
        "report_type": "bluearch-aws-steward-assessment",
        "report_profile": report_profile,
        "generated_at": result.get("observed_at") or result.get("generated_at"),
        "provider": result.get("provider") or resource_context.get("provider"),
        "profile": result.get("profile"),
        "account_id": result.get("account_id") or resource_context.get("account_id"),
        "region": result.get("region") or resource_context.get("region"),
        "service": result.get("service"),
        "point_in_time": True,
        "read_only": True,
        "include_clean_resources": include_clean_resources,
        "include_all_findings": include_all_findings,
        "filters": normalized_filters,
        "summary": {
            "findings": len(items),
            "complete_assessment_findings": len(complete_items),
            "filtered_findings": len(filtered_items),
            "report_truncated": len(items) < len(filtered_items),
            "resources": len({str(item.get("resource")) for item in items if item.get("resource")}),
            "by_severity": dict(sorted(severity_counts.items())),
            "by_service": dict(sorted(service_counts.items())),
            "by_rule": dict(sorted(rule_counts.items())),
            "estimated_monthly_savings_usd": round(
                sum(
                    float(estimate["estimated_monthly_savings_usd"])
                    for estimate in available_cost_estimates
                ),
                2,
            ),
            "cost_estimates_available": len(available_cost_estimates),
            "cost_estimates_unavailable": len(cost_estimates) - len(available_cost_estimates),
            "cost_confidence": dict(sorted(cost_confidence_counts.items())),
            "resources_scanned": int(summary.get("resources_scanned") or 0),
            "rules_evaluated": int(summary.get("rules_evaluated") or 0),
            "scan_errors": int(summary.get("scan_errors") or 0),
            "detection_coverage": summary.get("detection_coverage") or {},
            "service_errors": summary.get("service_errors") or [],
            "rules_skipped": summary.get("rules_skipped") or [],
            "capability_errors": summary.get("capability_errors") or [],
            "unified_recommendation_queue": bool(summary.get("unified_recommendation_queue")),
            "signals_received": int(summary.get("signals_received") or 0),
            "deduplicated_signals": int(summary.get("deduplicated_signals") or 0),
            "resolved_or_stale_recommendations": int(
                summary.get("resolved_or_stale_recommendations") or 0
            ),
            "sources": summary.get("sources") or {},
            "validation_statuses": summary.get("validation_statuses") or {},
            "incomplete_sources": summary.get("incomplete_sources") or [],
        },
        "findings": items,
        "limitations": [
            "This report represents a point-in-time AWS assessment.",
            "Only resources matched by evaluated rules are listed.",
            "Unevaluated catalog rules are not treated as passing.",
            "Report filters do not trigger another AWS assessment.",
            "No AWS write actions were applied by report generation.",
        ],
    }


def _normalize_report_finding(item: JSON, rule_lookup: Dict[str, Any]) -> JSON:
    normalized = dict(item)
    rule_key = str(item.get("rule") or item.get("rule_id") or "")
    rule = rule_lookup.get(rule_key)
    catalog_description = str(getattr(rule, "scenario", "") or "")
    matching_criteria = str(
        item.get("why") or item.get("scenario") or catalog_description or "See observed evidence."
    )
    risk_detail = str(
        item.get("risk_detail") or item.get("risk") or getattr(rule, "risk_detail", "") or ""
    )
    raw_evidence = item.get("evidence")
    evidence: JSON = dict(raw_evidence) if isinstance(raw_evidence, dict) else {}
    raw_observation = evidence.get("observation")
    observation: JSON = dict(raw_observation) if isinstance(raw_observation, dict) else {}
    raw_cost_estimate = item.get("cost_estimate") or evidence.get("cost_estimate")
    cost_estimate = _normalize_cost_estimate(raw_cost_estimate)
    validation: JSON = dict(item["validation"]) if isinstance(item.get("validation"), dict) else {}
    priority: JSON = dict(item["priority"]) if isinstance(item.get("priority"), dict) else {}
    sources = [str(source) for source in (item.get("sources") or [])]

    normalized.update(
        {
            "catalog_rule_id": str(getattr(rule, "id", "") or item.get("rule_id") or ""),
            "rule_description": catalog_description or matching_criteria,
            "matching_criteria": matching_criteria,
            "scenario": str(item.get("scenario") or matching_criteria),
            "risk_detail": risk_detail,
            "observed_evidence": _summarize_evidence(evidence),
            "evidence_observed_at": observation.get("observed_at"),
            "evidence_source": observation.get("source"),
            "evidence_confidence": observation.get("confidence"),
            "cost_estimate": cost_estimate,
            "cost_estimate_status": cost_estimate["status"],
            "estimated_monthly_savings_usd": cost_estimate["estimated_monthly_savings_usd"],
            "cost_confidence": cost_estimate["confidence"],
            "cost_estimate_basis": cost_estimate["basis"],
            "recommendation_fingerprint": item.get("recommendation_fingerprint"),
            "sources": sources,
            "source_count": len(sources) or int(item.get("source_count") or 1),
            "validation_status": validation.get("status") or "unknown",
            "freshness_observed_at": validation.get("observed_at"),
            "source_disagreement": bool(validation.get("source_disagreement")),
            "priority_score": priority.get("score"),
            "priority_components": priority.get("components") or {},
        }
    )
    return normalized


def _normalize_cost_estimate(value: Any) -> JSON:
    estimate = dict(value) if isinstance(value, dict) else {}
    savings = estimate.get("estimated_monthly_savings_usd")
    return {
        **estimate,
        "status": str(
            estimate.get("status") or ("estimated" if savings is not None else "not_estimated")
        ),
        "estimated_monthly_savings_usd": savings,
        "confidence": str(estimate.get("confidence") or "not_available"),
        "basis": str(
            estimate.get("basis")
            or estimate.get("reason")
            or (
                "Account-specific cost evidence was available."
                if savings is not None
                else "No supported account-specific cost signal was available for this finding."
            )
        ),
    }


def _summarize_evidence(evidence: JSON) -> str:
    return "; ".join(
        f"{key}={_compact_value(value)}"
        for key, value in sorted(evidence.items())
        if key != "observation"
    )


def _compact_value(value: Any) -> str:
    if isinstance(value, bool):
        return str(value).lower()
    if value is None:
        return "null"
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return str(value)


def render_report(model: JSON, report_format: str) -> RenderedReport:
    if report_format not in REPORT_FORMATS:
        raise ValueError(
            f"Unsupported report format: {report_format}. Supported: {', '.join(REPORT_FORMATS)}"
        )
    if report_format == "json":
        return json.dumps(model, indent=2, sort_keys=True, default=str)
    if report_format == "markdown":
        return _render_markdown(model)
    if report_format == "html":
        return _render_html(model)
    if report_format == "csv":
        return _render_csv(model)
    if report_format == "sarif":
        return _render_sarif(model)
    from bluearch_aws_steward.pdf_report import render_pdf_report

    return render_pdf_report(model)


def write_report(
    model: JSON,
    report_format: str,
    output_path: str | None,
    rendered: RenderedReport | None = None,
) -> str | None:
    if not output_path:
        return None
    path = Path(output_path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    content = rendered if rendered is not None else render_report(model, report_format)
    if isinstance(content, bytes):
        with path.open("xb") as stream:
            stream.write(content)
    else:
        with path.open("x", encoding="utf-8") as stream:
            stream.write(content)
    return str(path)


def _render_markdown(model: JSON) -> str:
    summary = model["summary"]
    coverage = summary["detection_coverage"]
    lines = [
        "# BlueArch AWS Steward Assessment",
        "",
        "This is a point-in-time, read-only assessment report.",
        "",
        f"- Generated: `{model.get('generated_at') or 'unknown'}`",
        f"- Region: `{model.get('region') or 'unknown'}`",
        f"- Provider: `{model.get('provider') or 'unknown'}`",
        f"- Resources scanned: **{summary['resources_scanned']}**",
        f"- Findings: **{summary['findings']}**",
        f"- Rules evaluated: **{summary['rules_evaluated']}**",
        f"- Estimated monthly savings: **USD {summary['estimated_monthly_savings_usd']:.2f}**",
        (
            f"- Cost estimates available: **{summary['cost_estimates_available']}**; "
            f"unavailable: **{summary['cost_estimates_unavailable']}**"
        ),
        "",
        "## Severity",
        "",
    ]
    lines.extend(f"- **{key.title()}**: {value}" for key, value in summary["by_severity"].items())
    lines.extend(["", "## Findings", ""])
    if not model["findings"]:
        lines.append("No resources matched the evaluated rules.")
    for item in model["findings"]:
        lines.extend(
            [
                f"### {item.get('rule') or item.get('rule_id') or 'Unknown rule'}",
                f"- Resource: `{item.get('resource') or 'unknown'}`",
                f"- Service: `{item.get('service') or 'unknown'}`",
                f"- Severity: **{item.get('severity') or 'unknown'}**",
                f"- Priority: **{item.get('priority_score') if item.get('priority_score') is not None else 'not scored'}**",
                f"- Sources: `{', '.join(item.get('sources') or []) or 'bluearch-steward'}`",
                f"- Live validation: `{item.get('validation_status') or 'unknown'}`",
                f"- Why matched: {item.get('matching_criteria') or 'not reported'}",
                f"- Evidence: `{item.get('observed_evidence') or 'not reported'}`",
                f"- Evidence confidence: `{item.get('evidence_confidence') or 'not_available'}`",
                f"- Risk: {item.get('risk_detail') or item.get('scenario') or 'See evidence.'}",
                (
                    "- Estimated monthly savings: "
                    + (
                        f"USD {float(item['estimated_monthly_savings_usd']):.2f}"
                        if item.get("estimated_monthly_savings_usd") is not None
                        else "not estimated"
                    )
                ),
                f"- Cost confidence: `{item.get('cost_confidence') or 'not_available'}`",
                f"- Cost estimate basis: {item.get('cost_estimate_basis') or 'not reported'}",
                f"- Recommended fix: {(item.get('remediation') or {}).get('summary') or 'not reported'}",
                (
                    "- Individual approval required: "
                    f"**{str(bool((item.get('remediation') or {}).get('requires_approval', True))).lower()}**"
                ),
                "",
            ]
        )
    lines.extend(
        ["## Coverage", "", f"```json\n{json.dumps(coverage, indent=2, sort_keys=True)}\n```", ""]
    )
    lines.extend(["## Limitations", "", *[f"- {text}" for text in model["limitations"]], ""])
    return "\n".join(lines)


def _render_html(model: JSON) -> str:
    summary = model["summary"]
    rows = []
    for item in model["findings"]:
        savings = item.get("estimated_monthly_savings_usd")
        cost_display = (
            f"USD {float(savings):.2f} ({item.get('cost_confidence') or 'not_available'})"
            if savings is not None
            else f"not estimated ({item.get('cost_confidence') or 'not_available'})"
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('severity') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('service') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('rule') or item.get('rule_id') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('resource') or 'unknown'))}</td>"
            f"<td>{html.escape(', '.join(item.get('sources') or []) or 'bluearch-steward')} / {html.escape(str(item.get('validation_status') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('priority_score') if item.get('priority_score') is not None else 'not scored'))}</td>"
            f"<td>{html.escape(str(item.get('risk_detail') or 'not reported'))}</td>"
            f"<td>{html.escape(str(item.get('observed_evidence') or 'not reported'))}</td>"
            f"<td>{html.escape(cost_display)}</td>"
            "</tr>"
        )
    severity = "".join(
        f"<li><strong>{html.escape(key.title())}</strong>: {value}</li>"
        for key, value in summary["by_severity"].items()
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>BlueArch AWS Steward Assessment</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d8dee9;padding:.55rem;text-align:left}}th{{background:#edf2f7}}.summary{{display:flex;gap:2rem;flex-wrap:wrap}}.metric{{font-size:1.4rem}}.note{{color:#536174}}</style></head>
<body><h1>BlueArch AWS Steward Assessment</h1><p class="note">Point-in-time, read-only report generated at {html.escape(str(model.get("generated_at") or "unknown"))}. Region: {html.escape(str(model.get("region") or "unknown"))}.</p>
<section class="summary"><div class="metric">Findings <strong>{summary["findings"]}</strong></div><div class="metric">Resources <strong>{summary["resources"]}</strong></div><div class="metric">Rules <strong>{summary["rules_evaluated"]}</strong></div><div class="metric">Estimated monthly savings <strong>USD {summary["estimated_monthly_savings_usd"]:.2f}</strong></div></section>
<h2>Severity</h2><ul>{severity}</ul><h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Service</th><th>Rule</th><th>Resource</th><th>Sources / freshness</th><th>Priority</th><th>Risk</th><th>Evidence</th><th>Savings / confidence</th></tr></thead><tbody>{"".join(rows) or '<tr><td colspan="9">No matched resources.</td></tr>'}</tbody></table>
<h2>Limitations</h2><ul>{"".join(f"<li>{html.escape(str(note))}</li>" for note in model["limitations"])}</ul></body></html>"""


def _render_csv(model: JSON) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "generated_at",
            "provider",
            "account_id",
            "region",
            "observed_at",
            "evidence_source",
            "evidence_confidence",
            "recommendation_fingerprint",
            "sources",
            "source_count",
            "validation_status",
            "freshness_observed_at",
            "source_disagreement",
            "priority_score",
            "priority_components",
            "severity",
            "service",
            "catalog_rule_id",
            "rule",
            "rule_description",
            "matching_criteria",
            "resource",
            "resource_type",
            "resource_arn",
            "observed_evidence",
            "cost_estimate_status",
            "estimated_monthly_savings_usd",
            "cost_confidence",
            "cost_estimate_basis",
            "risk",
            "value",
            "remediation_summary",
            "remediation_actions",
            "verification",
            "safety_level",
            "requires_approval",
            "apply_supported",
        ]
    )
    for item in model["findings"]:
        resource_ref = (
            item.get("resource_ref") if isinstance(item.get("resource_ref"), dict) else {}
        )
        remediation = item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
        apply = item.get("apply") if isinstance(item.get("apply"), dict) else {}
        writer.writerow(
            [
                model.get("generated_at", ""),
                model.get("provider", ""),
                resource_ref.get("account_id") or model.get("account_id", ""),
                model.get("region", ""),
                item.get("evidence_observed_at", ""),
                item.get("evidence_source", ""),
                item.get("evidence_confidence", ""),
                item.get("recommendation_fingerprint", ""),
                " | ".join(item.get("sources") or []),
                item.get("source_count", ""),
                item.get("validation_status", ""),
                item.get("freshness_observed_at", ""),
                _compact_value(item.get("source_disagreement")),
                item.get("priority_score", ""),
                _compact_value(item.get("priority_components")),
                item.get("severity", ""),
                item.get("service", ""),
                item.get("catalog_rule_id", ""),
                item.get("rule") or item.get("rule_id", ""),
                item.get("rule_description", ""),
                item.get("matching_criteria", ""),
                item.get("resource", ""),
                resource_ref.get("resource_type", ""),
                resource_ref.get("arn", ""),
                item.get("observed_evidence", ""),
                item.get("cost_estimate_status", ""),
                item.get("estimated_monthly_savings_usd", ""),
                item.get("cost_confidence", ""),
                item.get("cost_estimate_basis", ""),
                item.get("risk_detail", ""),
                item.get("value", ""),
                remediation.get("summary", ""),
                " | ".join(str(action) for action in remediation.get("actions") or []),
                remediation.get("verification", ""),
                remediation.get("safety_level", ""),
                _compact_value(remediation.get("requires_approval")),
                _compact_value(apply.get("supported")),
            ]
        )
    return output.getvalue()


def _render_sarif(model: JSON) -> str:
    results: List[JSON] = []
    for item in model["findings"]:
        rule = str(item.get("rule") or item.get("rule_id") or "bluearch-unknown")
        results.append(
            {
                "ruleId": rule,
                "level": _sarif_level(str(item.get("severity") or "warning")),
                "message": {"text": str(item.get("risk_detail") or item.get("scenario") or rule)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(item.get("resource") or "unknown")}
                        }
                    }
                ],
                "properties": {
                    "observedEvidence": item.get("observed_evidence"),
                    "evidenceConfidence": item.get("evidence_confidence") or "not_available",
                    "risk": item.get("risk_detail"),
                    "estimatedMonthlySavingsUsd": item.get("estimated_monthly_savings_usd"),
                    "costConfidence": item.get("cost_confidence") or "not_available",
                    "recommendationFingerprint": item.get("recommendation_fingerprint"),
                    "sources": item.get("sources") or [],
                    "validationStatus": item.get("validation_status") or "unknown",
                    "priorityScore": item.get("priority_score"),
                    "remediationRequiresApproval": bool(
                        (item.get("remediation") or {}).get("requires_approval", True)
                    ),
                    "applySupported": bool((item.get("apply") or {}).get("supported")),
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "BlueArch AWS Steward", "version": __version__}},
                "invocations": [{"properties": {"region": model.get("region")}}],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity == "medium":
        return "warning"
    return "note"
