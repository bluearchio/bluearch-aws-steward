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
EXECUTIVE_FINDING_LIMIT = 10


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
    contextual = result.get("assessment_mode") == "architectural_review"
    contextual_limitations = list(result.get("limitations") or []) if contextual else []
    presented_items = items
    findings_truncated = False
    if report_profile == "executive" and len(items) > EXECUTIVE_FINDING_LIMIT:
        presented_items = sorted(
            items,
            key=lambda item: -float(item.get("priority_score") or 0.0),
        )[:EXECUTIVE_FINDING_LIMIT]
        findings_truncated = True
    return {
        "schema_version": "report-0.1",
        "report_type": "bluearch-aws-steward-assessment",
        "report_profile": report_profile,
        "grouped_solutions": sorted(
            deepcopy_json(result.get("grouped_solutions") or []),
            key=lambda group: -float(group.get("priority_score") or 0.0),
        ),
        "generated_at": result.get("observed_at") or result.get("generated_at"),
        "provider": result.get("provider") or resource_context.get("provider"),
        "profile": result.get("profile"),
        "account_id": result.get("account_id") or resource_context.get("account_id"),
        "region": result.get("region") or resource_context.get("region"),
        "service": result.get("service"),
        "assessment_mode": result.get("assessment_mode"),
        "operation": result.get("operation"),
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
        "findings": presented_items,
        "findings_truncated": findings_truncated,
        "focus": deepcopy_json(result.get("focus") or {}) if contextual else {},
        "architecture_neighborhood": deepcopy_json(result.get("architecture_neighborhood") or {})
        if contextual
        else {},
        "context_questions": deepcopy_json(result.get("context_questions") or {})
        if contextual
        else {},
        "well_architected_review": deepcopy_json(result.get("well_architected_review") or {})
        if contextual
        else {},
        "recommendations": deepcopy_json(result.get("recommendations") or []) if contextual else [],
        "hidden_relevant_concerns": deepcopy_json(result.get("hidden_relevant_concerns") or [])
        if contextual
        else [],
        "evidence_ledger": deepcopy_json(result.get("evidence_ledger") or {}) if contextual else {},
        "excluded_scope": deepcopy_json(result.get("excluded_scope") or {}) if contextual else {},
        "limitations": contextual_limitations
        + [
            "This report represents a point-in-time AWS assessment.",
            "Only resources matched by evaluated rules are listed.",
            "Unevaluated catalog rules are not treated as passing.",
            "Report filters do not trigger another AWS assessment.",
            "No AWS write actions were applied by report generation.",
        ],
    }


def deepcopy_json(value: Any) -> Any:
    return json.loads(json.dumps(value, default=str))


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
    if model.get("assessment_mode") == "architectural_review":
        lines.extend(_contextual_markdown(model))
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
    lines.extend(
        [
            "## Limitations",
            "",
            *[f"- {_limitation_text(value)}" for value in model["limitations"]],
            "",
        ]
    )
    return "\n".join(lines)


def _contextual_markdown(model: JSON) -> List[str]:
    focus = (model.get("focus") or {}).get("resources") or []
    selected_knowledge = (model.get("focus") or {}).get("selected_knowledge") or []
    graph = model.get("architecture_neighborhood") or {}
    review = model.get("well_architected_review") or {}
    ledger = model.get("evidence_ledger") or {}
    excluded = model.get("excluded_scope") or {}
    lines = [
        "",
        "## Contextual Architecture Review",
        "",
        f"- Assessment mode: `{model.get('assessment_mode') or 'architectural_review'}`",
        f"- Operation: `{model.get('operation') or 'review'}`",
    ]
    lines.extend(
        f"- Focus: `{item.get('arn') or item.get('resource_id') or 'unknown'}` ({item.get('service') or 'unknown'})"
        for item in focus
    )
    lines.extend(
        [
            f"- Architecture neighborhood: **{len(graph.get('nodes') or [])} nodes**, **{len(graph.get('edges') or [])} relationships**",
            f"- Read operations: **{ledger.get('operation_count', 0)}/{ledger.get('operation_budget', 0)}**",
            f"- Excluded services: `{', '.join(excluded.get('services') or []) or 'none'}`",
            f"- Selected knowledge packs: `{', '.join(str(item.get('service')) for item in selected_knowledge) or 'none'}`",
            "",
            "### Observed Relationships",
            "",
        ]
    )
    if graph.get("edges"):
        for edge in graph.get("edges") or []:
            lines.append(
                "- "
                f"`{edge.get('source_node_id')}` --{edge.get('relationship_type')}--> "
                f"`{edge.get('target_node_id')}` "
                f"(source={edge.get('source')}, confidence={edge.get('confidence')})"
            )
    else:
        lines.append(
            "- No relationship was observed. This does not prove that no dependency exists."
        )
    lines.extend(["", "### Well-Architected Practice Ledger", ""])
    for pillar in review.get("pillars") or []:
        counts = pillar.get("status_counts") or {}
        lines.append(f"#### {str(pillar.get('pillar') or 'unknown').replace('_', ' ').title()}")
        lines.append(
            "- Statuses: " + ", ".join(f"{key}={value}" for key, value in counts.items() if value)
        )
        for practice in pillar.get("practices") or []:
            lines.extend(
                [
                    f"- `{practice.get('practice_id')}` **{practice.get('status')}**: "
                    f"{practice.get('title') or 'Untitled practice'}",
                    f"  Source: {practice.get('source_url') or 'not available'}; "
                    f"catalog `{practice.get('catalog_revision') or 'unknown'}`; "
                    f"reviewed `{practice.get('reviewed_at') or 'unknown'}`.",
                ]
            )
    unknowns = (model.get("context_questions") or {}).get("unknown_facts") or []
    if unknowns:
        lines.extend(["", f"Unknown context: `{', '.join(unknowns)}`"])
    concerns = model.get("hidden_relevant_concerns") or []
    if concerns:
        lines.extend(["", "### High-Impact Cross-Pillar Concerns", ""])
        lines.extend(
            f"- **{item.get('severity')}** `{item.get('rule')}` on `{item.get('resource')}`"
            for item in concerns
        )
    return lines


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
    contextual_html = _contextual_html(model)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>BlueArch AWS Steward Assessment</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#172033}}table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #d8dee9;padding:.55rem;text-align:left}}th{{background:#edf2f7}}.summary{{display:flex;gap:2rem;flex-wrap:wrap}}.metric{{font-size:1.4rem}}.note{{color:#536174}}</style></head>
<body><h1>BlueArch AWS Steward Assessment</h1><p class="note">Point-in-time, read-only report generated at {html.escape(str(model.get("generated_at") or "unknown"))}. Region: {html.escape(str(model.get("region") or "unknown"))}.</p>
<section class="summary"><div class="metric">Findings <strong>{summary["findings"]}</strong></div><div class="metric">Resources <strong>{summary["resources"]}</strong></div><div class="metric">Rules <strong>{summary["rules_evaluated"]}</strong></div><div class="metric">Estimated monthly savings <strong>USD {summary["estimated_monthly_savings_usd"]:.2f}</strong></div></section>
{contextual_html}<h2>Severity</h2><ul>{severity}</ul><h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Service</th><th>Rule</th><th>Resource</th><th>Sources / freshness</th><th>Priority</th><th>Risk</th><th>Evidence</th><th>Savings / confidence</th></tr></thead><tbody>{"".join(rows) or '<tr><td colspan="9">No matched resources.</td></tr>'}</tbody></table>
<h2>Limitations</h2><ul>{"".join(f"<li>{html.escape(_limitation_text(note))}</li>" for note in model["limitations"])}</ul></body></html>"""


def _contextual_html(model: JSON) -> str:
    if model.get("assessment_mode") != "architectural_review":
        return ""
    focus = (model.get("focus") or {}).get("resources") or []
    graph = model.get("architecture_neighborhood") or {}
    review = model.get("well_architected_review") or {}
    selected_knowledge = (model.get("focus") or {}).get("selected_knowledge") or []
    ledger = model.get("evidence_ledger") or {}
    excluded = model.get("excluded_scope") or {}
    focus_items = "".join(
        f"<li><code>{html.escape(str(item.get('arn') or item.get('resource_id') or 'unknown'))}</code> ({html.escape(str(item.get('service') or 'unknown'))})</li>"
        for item in focus
    )
    practice_rows = "".join(
        "<tr>"
        f"<td>{html.escape(str(practice.get('practice_id') or 'unknown'))}</td>"
        f"<td>{html.escape(str(pillar.get('pillar') or 'unknown'))}</td>"
        f"<td>{html.escape(str(practice.get('status') or 'unknown'))}</td>"
        f"<td>{html.escape(', '.join(practice.get('matched_native_rules') or []))}</td>"
        f"<td>{html.escape(str(practice.get('source_url') or 'not available'))}</td>"
        "</tr>"
        for pillar in review.get("pillars") or []
        for practice in pillar.get("practices") or []
    )
    return (
        "<h2>Contextual Architecture Review</h2>"
        f"<p><strong>Assessment mode:</strong> {html.escape(str(model.get('assessment_mode') or 'architectural_review'))}</p>"
        f"<p><strong>Operation:</strong> {html.escape(str(model.get('operation') or 'review'))}</p>"
        f"<ul>{focus_items}</ul>"
        f"<p>{len(graph.get('nodes') or [])} nodes and {len(graph.get('edges') or [])} observed relationships. "
        "An unobserved relationship is not proof that no dependency exists.</p>"
        f"<p><strong>Read operations:</strong> {ledger.get('operation_count', 0)}/{ledger.get('operation_budget', 0)}. "
        f"<strong>Selected packs:</strong> {html.escape(', '.join(str(item.get('service')) for item in selected_knowledge) or 'none')}. "
        f"<strong>Excluded services:</strong> {html.escape(', '.join(excluded.get('services') or []) or 'none')}.</p>"
        "<table><thead><tr><th>Practice</th><th>Pillar</th><th>Status</th><th>Matched rules</th><th>Source</th></tr></thead>"
        f"<tbody>{practice_rows}</tbody></table>"
    )


def _render_csv(model: JSON) -> str:
    output = io.StringIO()
    fields = [
        "record_type",
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
        "assessment_mode",
        "operation",
        "well_architected_practices",
        "business_impact",
        "recommendation_confidence",
        "missing_context",
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
        "practice_id",
        "practice_title",
        "practice_pillar",
        "practice_status",
        "practice_source_url",
        "catalog_revision",
        "reviewed_at",
        "applicability",
        "practice_evidence",
    ]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for item in model["findings"]:
        resource_ref = (
            item.get("resource_ref") if isinstance(item.get("resource_ref"), dict) else {}
        )
        remediation = item.get("remediation") if isinstance(item.get("remediation"), dict) else {}
        apply = item.get("apply") if isinstance(item.get("apply"), dict) else {}
        writer.writerow(
            {
                "record_type": "finding",
                "generated_at": model.get("generated_at", ""),
                "provider": model.get("provider", ""),
                "account_id": resource_ref.get("account_id") or model.get("account_id", ""),
                "region": model.get("region", ""),
                "observed_at": item.get("evidence_observed_at", ""),
                "evidence_source": item.get("evidence_source", ""),
                "evidence_confidence": item.get("evidence_confidence", ""),
                "recommendation_fingerprint": item.get("recommendation_fingerprint", ""),
                "sources": " | ".join(item.get("sources") or []),
                "source_count": item.get("source_count", ""),
                "validation_status": item.get("validation_status", ""),
                "freshness_observed_at": item.get("freshness_observed_at", ""),
                "source_disagreement": _compact_value(item.get("source_disagreement")),
                "priority_score": item.get("priority_score", ""),
                "priority_components": _compact_value(item.get("priority_components")),
                "severity": item.get("severity", ""),
                "service": item.get("service", ""),
                "assessment_mode": model.get("assessment_mode", ""),
                "operation": model.get("operation", ""),
                "well_architected_practices": " | ".join(
                    item.get("well_architected_practices") or []
                ),
                "business_impact": item.get("business_impact", ""),
                "recommendation_confidence": item.get("confidence", ""),
                "missing_context": " | ".join(item.get("missing_context") or []),
                "catalog_rule_id": item.get("catalog_rule_id", ""),
                "rule": item.get("rule") or item.get("rule_id", ""),
                "rule_description": item.get("rule_description", ""),
                "matching_criteria": item.get("matching_criteria", ""),
                "resource": item.get("resource", ""),
                "resource_type": resource_ref.get("resource_type", ""),
                "resource_arn": resource_ref.get("arn", ""),
                "observed_evidence": item.get("observed_evidence", ""),
                "cost_estimate_status": item.get("cost_estimate_status", ""),
                "estimated_monthly_savings_usd": item.get("estimated_monthly_savings_usd", ""),
                "cost_confidence": item.get("cost_confidence", ""),
                "cost_estimate_basis": item.get("cost_estimate_basis", ""),
                "risk": item.get("risk_detail", ""),
                "value": item.get("value", ""),
                "remediation_summary": remediation.get("summary", ""),
                "remediation_actions": " | ".join(
                    str(action) for action in remediation.get("actions") or []
                ),
                "verification": remediation.get("verification", ""),
                "safety_level": remediation.get("safety_level", ""),
                "requires_approval": _compact_value(remediation.get("requires_approval")),
                "apply_supported": _compact_value(apply.get("supported")),
            }
        )
    if model.get("assessment_mode") == "architectural_review":
        for pillar in (model.get("well_architected_review") or {}).get("pillars") or []:
            for practice in pillar.get("practices") or []:
                writer.writerow(
                    {
                        "record_type": "well_architected_practice",
                        "generated_at": model.get("generated_at", ""),
                        "provider": model.get("provider", ""),
                        "account_id": model.get("account_id", ""),
                        "region": model.get("region", ""),
                        "service": practice.get("service", ""),
                        "assessment_mode": model.get("assessment_mode", ""),
                        "operation": model.get("operation", ""),
                        "practice_id": practice.get("practice_id", ""),
                        "practice_title": practice.get("title", ""),
                        "practice_pillar": pillar.get("pillar", ""),
                        "practice_status": practice.get("status", ""),
                        "practice_source_url": practice.get("source_url", ""),
                        "catalog_revision": practice.get("catalog_revision", ""),
                        "reviewed_at": practice.get("reviewed_at", ""),
                        "applicability": _compact_value(practice.get("applicability")),
                        "practice_evidence": _compact_value(practice.get("evidence")),
                    }
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
                    "assessmentMode": model.get("assessment_mode"),
                    "wellArchitectedPractices": item.get("well_architected_practices") or [],
                    "businessImpact": item.get("business_impact"),
                    "recommendationConfidence": item.get("confidence"),
                    "missingContext": item.get("missing_context") or [],
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "BlueArch AWS Steward", "version": __version__}},
                "invocations": [
                    {
                        "properties": {
                            "region": model.get("region"),
                            "assessmentMode": model.get("assessment_mode"),
                            "focus": model.get("focus") or {},
                            "operation": model.get("operation"),
                            "architectureNeighborhood": model.get("architecture_neighborhood")
                            or {},
                            "wellArchitectedReview": model.get("well_architected_review") or {},
                            "hiddenRelevantConcerns": model.get("hidden_relevant_concerns") or [],
                            "excludedScope": model.get("excluded_scope") or {},
                            "evidenceLedger": model.get("evidence_ledger") or {},
                            "limitations": model.get("limitations") or [],
                        }
                    }
                ],
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


def _limitation_text(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("message") or value.get("detail") or json.dumps(value, sort_keys=True))
    return str(value)
