from __future__ import annotations

import json
import re
from collections import Counter
from importlib import resources
from typing import Any, Dict, Iterable, List

from bluearch_aws_steward.catalog import filter_rules
from bluearch_aws_steward.catalog_sync import EVALUATION_MODES
from bluearch_aws_steward.detectors.common import parse_rule_filter

CatalogRule = Dict[str, Any]


def load_catalog_rules() -> List[CatalogRule]:
    with (
        resources.files("bluearch_aws_steward")
        .joinpath("catalog/full_rules.json")
        .open(
            "r",
            encoding="utf-8",
        ) as handle
    ):
        payload = json.load(handle)
    return [dict(rule) for rule in payload["rules"]]


def search_catalog_rules(
    *,
    service: str | None = None,
    query: str | None = None,
    evaluation_mode: str | None = None,
    automated_only: bool = False,
) -> List[CatalogRule]:
    if evaluation_mode and evaluation_mode not in EVALUATION_MODES:
        allowed = ", ".join(EVALUATION_MODES)
        raise ValueError(
            f"Unsupported evaluation_mode={evaluation_mode!r}. Supported modes: {allowed}"
        )

    rules: Iterable[CatalogRule] = load_catalog_rules()
    if service:
        service_key = normalize_service_key(service)
        rules = [
            rule
            for rule in rules
            if service_key
            in {
                normalize_service_key(rule.get("service")),
                normalize_service_key(rule.get("service_name")),
            }
        ]
    if evaluation_mode:
        rules = [
            rule for rule in rules if (rule.get("evaluation") or {}).get("mode") == evaluation_mode
        ]
    if automated_only:
        rules = [rule for rule in rules if bool((rule.get("evaluation") or {}).get("automated"))]
    if query:
        needle = query.casefold()
        rules = [rule for rule in rules if needle in _search_text(rule)]
    return list(rules)


def catalog_coverage(*, service: str | None = None, query: str | None = None) -> Dict[str, Any]:
    rules = search_catalog_rules(service=service, query=query)
    mode_counts = Counter((rule.get("evaluation") or {}).get("mode") for rule in rules)
    service_counts = Counter(str(rule.get("service") or "unknown") for rule in rules)
    automated = mode_counts.get("native", 0)
    return {
        "catalog_rule_count": len(rules),
        "catalog_service_count": len(service_counts),
        "automated_rule_count": automated,
        "unevaluated_rule_count": max(0, len(rules) - automated),
        "automation_percentage": round((automated / len(rules) * 100), 2) if rules else 0.0,
        "rules_by_evaluation_mode": {mode: mode_counts.get(mode, 0) for mode in EVALUATION_MODES},
        "rules_by_service": dict(sorted(service_counts.items())),
    }


def build_scan_detection_coverage(
    *,
    requested_service: str,
    services_requested: List[str],
    rule_filter: str | None,
    automated_rules_evaluated: int,
    scan_errors: int,
) -> Dict[str, Any]:
    all_catalog_rules = load_catalog_rules()
    selected_executable = [
        rule for service in services_requested for rule in filter_rules(service=service)
    ]
    filters = parse_rule_filter(rule_filter)
    if filters:
        selected_executable = [
            rule
            for rule in selected_executable
            if filters & {rule.id, rule.short_id, rule.detector}
        ]
        executable_ids = {rule.id for rule in selected_executable}
        catalog_scope = [rule for rule in all_catalog_rules if rule.get("id") in executable_ids]
        scope_kind = "executable_rule_filter"
    elif requested_service == "all":
        catalog_scope = all_catalog_rules
        scope_kind = "full_catalog"
    else:
        requested_key = normalize_service_key(requested_service)
        catalog_scope = [
            rule
            for rule in all_catalog_rules
            if requested_key
            in {
                normalize_service_key(rule.get("service")),
                normalize_service_key(rule.get("service_name")),
            }
        ]
        scope_kind = "service_catalog"

    mode_counts = Counter((rule.get("evaluation") or {}).get("mode") for rule in catalog_scope)
    catalog_rule_count = len(catalog_scope)
    automated_available = len(selected_executable)
    evaluated = max(0, min(int(automated_rules_evaluated), automated_available))
    complete = catalog_rule_count == evaluated and scan_errors == 0
    return {
        "scope": scope_kind,
        "requested_service": requested_service,
        "services_requested": list(services_requested),
        "catalog_rules_in_scope": catalog_rule_count,
        "automated_rules_available": automated_available,
        "automated_rules_evaluated": evaluated,
        "automated_rules_not_evaluated": max(0, automated_available - evaluated),
        "unevaluated_catalog_rules": max(0, catalog_rule_count - evaluated),
        "catalog_evaluation_percentage": round((evaluated / catalog_rule_count * 100), 2)
        if catalog_rule_count
        else 0.0,
        "rules_by_evaluation_mode": {mode: mode_counts.get(mode, 0) for mode in EVALUATION_MODES},
        "complete_catalog_evaluation": complete,
        "result_interpretation": (
            "All catalog rules in the requested scope were evaluated."
            if complete
            else "Findings and clean results apply only to automated_rules_evaluated; remaining catalog rules are unevaluated."
        ),
    }


def normalize_service_key(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().casefold()).strip("-")


def _search_text(rule: CatalogRule) -> str:
    fields = (
        rule.get("id"),
        rule.get("service"),
        rule.get("service_name"),
        rule.get("scenario"),
        rule.get("alert_criteria"),
        rule.get("recommendation_action"),
        rule.get("risk_detail"),
        rule.get("description"),
        rule.get("category"),
        rule.get("notes"),
        rule.get("pillars"),
        rule.get("external_refs"),
        rule.get("compliance_mappings"),
        rule.get("detection_methods"),
        rule.get("tags"),
        rule.get("evaluation"),
    )
    return json.dumps(fields, sort_keys=True, default=str).casefold()
