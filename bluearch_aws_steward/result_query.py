"""Filter and paginate complete ephemeral assessment results without AWS reads."""

from __future__ import annotations

import base64
import hashlib
import json
from collections import Counter
from typing import Any, Callable, Dict, Iterable, List, Optional

JSON = Dict[str, Any]
RESULT_SORTS = ("priority", "severity", "service", "rule", "resource")
DEFAULT_PAGE_SIZE = 25
MAX_PAGE_SIZE = 200
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def complete_result_items(result: JSON) -> List[JSON]:
    for key in ("complete_opportunities", "opportunities", "complete_findings", "findings"):
        items = result.get(key)
        if isinstance(items, list):
            return [dict(item) for item in items if isinstance(item, dict)]
    return []


def query_assessment_results(
    result: JSON,
    *,
    filters: Optional[JSON] = None,
    sort: str = "priority",
    page_size: int = DEFAULT_PAGE_SIZE,
    cursor: Optional[str] = None,
) -> JSON:
    normalized_filters = normalize_filters(filters or {})
    if sort not in RESULT_SORTS:
        raise ValueError(f"Unsupported result sort: {sort}. Supported: {', '.join(RESULT_SORTS)}")
    page_size = max(1, min(int(page_size), MAX_PAGE_SIZE))

    all_items = complete_result_items(result)
    filtered = [item for item in all_items if item_matches_filters(item, normalized_filters)]
    filtered.sort(key=lambda item: _sort_key(item, sort))

    signature = _query_signature(normalized_filters, sort)
    offset = _decode_cursor(cursor, signature) if cursor else 0
    page = filtered[offset : offset + page_size]
    next_offset = offset + len(page)
    next_cursor = _encode_cursor(next_offset, signature) if next_offset < len(filtered) else None
    summary = result.get("summary") or {}

    return {
        "summary": {
            "complete_assessment_findings": len(all_items),
            "filtered_findings": len(filtered),
            "returned_findings": len(page),
            "page_size": page_size,
            "has_more": next_cursor is not None,
            "incomplete": bool(summary.get("incomplete")),
            "incomplete_reason": summary.get("incomplete_reason"),
        },
        "filters": normalized_filters,
        "sort": sort,
        "findings": page,
        "next_cursor": next_cursor,
        "facets": build_facets(all_items),
        "filtered_facets": build_facets(filtered),
        "detection_coverage": summary.get("detection_coverage") or {},
        "rules_skipped": summary.get("rules_skipped") or [],
        "capability_errors": summary.get("capability_errors") or [],
        "service_errors": summary.get("service_errors") or [],
        "suggested_actions": suggested_actions(all_items),
        "aws_reads_performed": 0,
        "write_actions_applied": False,
    }


def normalize_filters(filters: JSON) -> JSON:
    supported = {
        "services": "service",
        "severities": "severity",
        "rules": "rule",
        "objectives": "objective",
        "sources": "source",
        "validation_statuses": "validation_status",
    }
    normalized: JSON = {}
    for plural, singular in supported.items():
        value = filters.get(plural, filters.get(singular))
        values = _string_values(value)
        if values:
            normalized[plural] = values
    if "remediation_supported" in filters:
        value = filters["remediation_supported"]
        if not isinstance(value, bool):
            raise ValueError("remediation_supported must be a boolean.")
        normalized["remediation_supported"] = value
    return normalized


def item_matches_filters(item: JSON, filters: JSON) -> bool:
    if filters.get("services") and str(item.get("service") or "") not in filters["services"]:
        return False
    if (
        filters.get("severities")
        and str(item.get("severity") or "").lower() not in filters["severities"]
    ):
        return False
    if filters.get("rules"):
        rule = str(item.get("rule") or item.get("rule_short_id") or item.get("rule_id") or "")
        if rule not in filters["rules"]:
            return False
    if filters.get("objectives") and not set(filters["objectives"]).intersection(
        _item_objectives(item)
    ):
        return False
    if filters.get("sources") and not set(filters["sources"]).intersection(
        {str(source).lower() for source in (item.get("sources") or [])}
    ):
        return False
    validation_status = str((item.get("validation") or {}).get("status") or "unknown").lower()
    if (
        filters.get("validation_statuses")
        and validation_status not in filters["validation_statuses"]
    ):
        return False
    if "remediation_supported" in filters:
        supported = bool((item.get("apply") or {}).get("supported"))
        if supported is not filters["remediation_supported"]:
            return False
    return True


def build_facets(items: Iterable[JSON]) -> JSON:
    items = list(items)
    objectives: Counter[str] = Counter()
    for item in items:
        objectives.update(_item_objectives(item))
    return {
        "severities": _counter(items, lambda item: str(item.get("severity") or "unknown").lower()),
        "services": _counter(items, lambda item: str(item.get("service") or "unknown")),
        "rules": _counter(
            items,
            lambda item: str(
                item.get("rule") or item.get("rule_short_id") or item.get("rule_id") or "unknown"
            ),
        ),
        "objectives": dict(sorted(objectives.items())),
        "sources": _multi_counter(items, lambda item: item.get("sources") or []),
        "validation_statuses": _counter(
            items,
            lambda item: str((item.get("validation") or {}).get("status") or "unknown"),
        ),
        "remediation_supported": {
            "true": sum(bool((item.get("apply") or {}).get("supported")) for item in items),
            "false": sum(not bool((item.get("apply") or {}).get("supported")) for item in items),
        },
    }


def suggested_actions(items: Iterable[JSON]) -> List[JSON]:
    items = list(items)
    actions = [
        {"label": "Top priorities", "arguments": {"sort": "priority", "page_size": 25}},
        {
            "label": "Safe remediations",
            "arguments": {"filters": {"remediation_supported": True}, "sort": "priority"},
        },
        {"label": "Explore by service", "arguments": {"sort": "service", "page_size": 25}},
        {
            "label": "Complete PDF",
            "tool": "bluearch_export_report",
            "arguments": {
                "format": "pdf",
                "report_profile": "complete",
                "include_all_findings": True,
            },
        },
        {
            "label": "Export CSV",
            "tool": "bluearch_export_report",
            "arguments": {
                "format": "csv",
                "report_profile": "technical",
                "include_all_findings": True,
            },
        },
    ]
    if any(not bool((item.get("apply") or {}).get("supported")) for item in items):
        actions.insert(
            2,
            {
                "label": "Fix in IaC",
                "arguments": {"filters": {"remediation_supported": False}, "sort": "priority"},
            },
        )
    return actions


def _string_values(value: Any) -> List[str]:
    if value is None:
        return []
    raw = value if isinstance(value, (list, tuple, set)) else [value]
    return list(dict.fromkeys(str(item).strip().lower() for item in raw if str(item).strip()))


def _item_objectives(item: JSON) -> List[str]:
    values = item.get("matched_objectives")
    if isinstance(values, list):
        return [str(value) for value in values if value and value != "all"]
    value = str(item.get("objective") or "").strip()
    return [value] if value and value != "all" else []


def _counter(items: Iterable[JSON], key: Callable[[JSON], str]) -> JSON:
    return dict(sorted(Counter(key(item) for item in items).items()))


def _multi_counter(items: Iterable[JSON], key: Callable[[JSON], Iterable[Any]]) -> JSON:
    values: Counter[str] = Counter()
    for item in items:
        values.update(str(value) for value in key(item))
    return dict(sorted(values.items()))


def _sort_key(item: JSON, sort: str) -> tuple[Any, ...]:
    severity = _SEVERITY_RANK.get(str(item.get("severity") or "").lower(), 99)
    service = str(item.get("service") or "")
    rule = str(item.get("rule") or item.get("rule_short_id") or item.get("rule_id") or "")
    resource = str(item.get("resource") or "")
    remediation = 0 if bool((item.get("apply") or {}).get("supported")) else 1
    savings = (item.get("cost_estimate") or {}).get("estimated_monthly_savings_usd")
    savings_rank = -float(savings) if isinstance(savings, (int, float)) else 0.0
    if sort == "severity":
        return severity, service, rule, resource
    if sort == "service":
        return service, severity, rule, resource
    if sort == "rule":
        return rule, severity, service, resource
    if sort == "resource":
        return resource, severity, service, rule
    priority = (item.get("priority") or {}).get("score")
    priority_rank = -float(priority) if isinstance(priority, (int, float)) else 0.0
    return priority_rank, severity, remediation, savings_rank, service, rule, resource


def _query_signature(filters: JSON, sort: str) -> str:
    encoded = json.dumps({"filters": filters, "sort": sort}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:16]


def _encode_cursor(offset: int, signature: str) -> str:
    payload = json.dumps({"v": 1, "offset": offset, "query": signature}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _decode_cursor(cursor: str, signature: str) -> int:
    try:
        padding = "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(cursor + padding).decode("utf-8"))
        if payload.get("v") != 1 or payload.get("query") != signature:
            raise ValueError
        offset = int(payload["offset"])
        if offset < 0:
            raise ValueError
        return offset
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(
            "Invalid or stale result cursor; restart pagination without a cursor."
        ) from exc
