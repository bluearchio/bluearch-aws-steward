from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from importlib import resources
from typing import Any, Dict, Iterable, List

from bluearch_aws_steward.catalog import load_rules
from bluearch_aws_steward.catalog_registry import load_catalog_rules
from bluearch_aws_steward.relationships import relationship_collector_services
from bluearch_aws_steward.scanner import AWS_SCAN_SERVICES

JSON = Dict[str, Any]
PACK_SCHEMA_VERSION = "knowledge-packs-0.1"
PRACTICE_STATUSES = (
    "risk",
    "aligned",
    "requires_input",
    "unknown",
    "not_applicable",
    "not_evaluated",
)
REVIEW_OPERATIONS = ("create", "update", "review", "delete", "troubleshoot", "optimize")


class KnowledgePackError(ValueError):
    """Raised when a bundled contextual-review pack is internally inconsistent."""


def load_knowledge_packs() -> JSON:
    with (
        resources.files("bluearch_aws_steward")
        .joinpath("knowledge/packs.json")
        .open("r", encoding="utf-8") as handle
    ):
        return json.load(handle)


def catalog_revision() -> str:
    payload = (
        resources.files("bluearch_aws_steward").joinpath("catalog/full_rules.json").read_bytes()
    )
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def waf_practice_index() -> Dict[str, JSON]:
    revision = catalog_revision()
    packs = load_knowledge_packs()
    reviewed_at = str(packs.get("reviewed_at") or "unknown")
    grouped: Dict[str, List[JSON]] = {}
    for row in load_catalog_rules():
        for practice_id in (row.get("external_refs") or {}).get("well_architected") or []:
            grouped.setdefault(str(practice_id), []).append(row)

    index: Dict[str, JSON] = {}
    for practice_id, rows in grouped.items():
        references = list(
            dict.fromkeys(
                str(reference)
                for row in rows
                for reference in (row.get("references") or [])
                if str(reference).startswith("https://")
            )
        )
        source_url = next(
            (
                reference
                for reference in references
                if "docs.aws.amazon.com/wellarchitected" in reference
            ),
            references[0] if references else None,
        )
        pillars = sorted(
            {str(pillar) for row in rows for pillar in (row.get("pillars") or []) if pillar}
        )
        index[practice_id] = {
            "practice_id": practice_id,
            "title": _practice_title(rows),
            "pillars": pillars,
            "source_url": source_url,
            "catalog_revision": revision,
            "reviewed_at": reviewed_at,
            "catalog_rows": len(rows),
        }
    return index


def profile_for_service(service: str) -> JSON:
    packs = load_knowledge_packs()
    profile = (packs.get("profiles") or {}).get(service)
    if not isinstance(profile, dict):
        raise KnowledgePackError(f"No contextual knowledge profile exists for service={service!r}.")
    result = deepcopy(profile)
    result.update(
        {
            "service": service,
            "pack_release": packs.get("release"),
            "pack_schema_version": packs.get("schema_version"),
            "reviewed_at": packs.get("reviewed_at"),
            "catalog_revision": catalog_revision(),
            "native_rules": [rule.short_id for rule in load_rules() if rule.service == service],
        }
    )
    return result


def question_definitions(question_ids: Iterable[str]) -> List[JSON]:
    questions = load_knowledge_packs().get("questions") or {}
    result = []
    for question_id in question_ids:
        definition = questions.get(question_id)
        if not isinstance(definition, dict):
            raise KnowledgePackError(f"Unknown contextual question: {question_id}")
        result.append({"id": question_id, **deepcopy(definition)})
    return result


def knowledge_pack_manifest() -> JSON:
    packs = load_knowledge_packs()
    rules = load_rules()
    practices = waf_practice_index()
    mappings = native_rule_waf_mappings()
    profiles = packs.get("profiles") or {}
    return {
        "schema_version": packs.get("schema_version"),
        "release": packs.get("release"),
        "reviewed_at": packs.get("reviewed_at"),
        "catalog_revision": catalog_revision(),
        "runtime_scopes": sorted(profiles),
        "runtime_scope_count": len(profiles),
        "native_rule_count": len(rules),
        "waf_catalog_row_count": sum(
            1
            for row in load_catalog_rules()
            if (row.get("external_refs") or {}).get("well_architected")
        ),
        "waf_practice_count": len(practices),
        "mapped_native_rules": sum(1 for value in mappings.values() if value["practice_ids"]),
        "intentionally_unmapped_native_rules": sum(
            1 for value in mappings.values() if not value["practice_ids"]
        ),
        "families": deepcopy(packs.get("families") or {}),
        "rule_mappings": mappings,
    }


def validate_knowledge_packs() -> JSON:
    packs = load_knowledge_packs()
    errors: List[str] = []
    if packs.get("schema_version") != PACK_SCHEMA_VERSION:
        errors.append(
            f"schema_version must be {PACK_SCHEMA_VERSION!r}, got {packs.get('schema_version')!r}"
        )
    if tuple(packs.get("operations") or ()) != REVIEW_OPERATIONS:
        errors.append("knowledge-pack operations do not match the public review operation contract")

    profiles = packs.get("profiles") or {}
    expected_services = set(AWS_SCAN_SERVICES)
    actual_services = set(profiles)
    if actual_services != expected_services:
        errors.append(
            "profile scopes differ from executable scopes: "
            f"missing={sorted(expected_services - actual_services)}, "
            f"unexpected={sorted(actual_services - expected_services)}"
        )
    collector_services = set(relationship_collector_services())
    if collector_services != expected_services:
        errors.append(
            "relationship collector scopes differ from executable scopes: "
            f"missing={sorted(expected_services - collector_services)}, "
            f"unexpected={sorted(collector_services - expected_services)}"
        )

    questions = packs.get("questions") or {}
    practices = waf_practice_index()
    families = packs.get("families") or {}
    native_by_service: Dict[str, set[str]] = {}
    for rule in load_rules():
        native_by_service.setdefault(rule.service, set()).add(rule.short_id)

    required_profile_fields = {
        "family",
        "operations",
        "applicability",
        "resource_types",
        "required_facts",
        "waf_practices",
        "relationship_collectors",
        "evidence_requirements",
        "business_impact",
        "safe_correction",
        "verification",
    }
    for service, profile in profiles.items():
        missing_fields = sorted(required_profile_fields - set(profile))
        if missing_fields:
            errors.append(f"{service}: missing fields {missing_fields}")
        family = profile.get("family")
        if family not in families:
            errors.append(f"{service}: unknown family {family!r}")
        elif service not in (families[family].get("services") or []):
            errors.append(f"{service}: family {family!r} does not declare this service")
        unknown_questions = sorted(set(profile.get("required_facts") or []) - set(questions))
        if unknown_questions:
            errors.append(f"{service}: unknown questions {unknown_questions}")
        unknown_practices = sorted(set(profile.get("waf_practices") or []) - set(practices))
        if unknown_practices:
            errors.append(f"{service}: unknown WAF practices {unknown_practices}")
        if not native_by_service.get(service):
            errors.append(f"{service}: no native rules are registered")
        unsupported_operations = sorted(
            set(profile.get("operations") or []) - set(REVIEW_OPERATIONS)
        )
        if unsupported_operations or not profile.get("operations"):
            errors.append(f"{service}: invalid operations {unsupported_operations}")
        applicability = profile.get("applicability") or {}
        if applicability.get("default") != "applicable":
            errors.append(f"{service}: applicability.default must be 'applicable'")
        for predicate in applicability.get("predicates") or []:
            predicate_practices = set(predicate.get("practice_ids") or [])
            if not predicate_practices or not predicate_practices.issubset(
                set(profile.get("waf_practices") or [])
            ):
                errors.append(f"{service}: applicability predicate references invalid practices")
            if predicate.get("fact") not in questions:
                errors.append(f"{service}: applicability predicate references an unknown fact")
            if predicate.get("operator") not in {"in", "not_in"}:
                errors.append(f"{service}: applicability predicate has an invalid operator")

    mappings = native_rule_waf_mappings()
    native_ids = {rule.short_id for rule in load_rules()}
    if set(mappings) != native_ids:
        errors.append("native rule coverage manifest does not account for every native rule")
    for short_id, mapping in mappings.items():
        unknown = sorted(set(mapping["practice_ids"]) - set(practices))
        if unknown:
            errors.append(f"{short_id}: unknown mapped WAF practices {unknown}")
        profile_practices = set((profiles.get(mapping["service"]) or {}).get("waf_practices") or [])
        missing_from_profile = sorted(set(mapping["practice_ids"]) - profile_practices)
        if missing_from_profile:
            errors.append(
                f"{short_id}: mapped WAF practices are absent from the service profile "
                f"{missing_from_profile}"
            )
        if not mapping["practice_ids"] and not mapping.get("unmapped_reason"):
            errors.append(f"{short_id}: unmapped rule has no explicit reason")

    if errors:
        raise KnowledgePackError("Invalid contextual knowledge packs:\n- " + "\n- ".join(errors))
    return knowledge_pack_manifest()


def native_rule_waf_mappings() -> Dict[str, JSON]:
    full_by_id = {row.get("id"): row for row in load_catalog_rules()}
    mappings: Dict[str, JSON] = {}
    for rule in load_rules():
        catalog_row = full_by_id.get(rule.id) or {}
        direct = list(
            dict.fromkeys(
                str(value)
                for value in (catalog_row.get("external_refs") or {}).get("well_architected") or []
            )
        )
        inferred = [] if direct else _semantic_practice_mapping(rule.short_id, rule.objectives)
        practice_ids = direct or inferred
        mappings[rule.short_id] = {
            "rule_id": rule.id,
            "service": rule.service,
            "practice_ids": practice_ids,
            "mapping_kind": "catalog_direct"
            if direct
            else "steward_reviewed"
            if inferred
            else "unmapped",
            "unmapped_reason": (
                None
                if practice_ids
                else "No direct Well-Architected practice is specific enough for this detector."
            ),
        }
    return mappings


def _semantic_practice_mapping(short_id: str, objectives: Iterable[str]) -> List[str]:
    text = short_id.casefold()
    candidates: List[str] = []
    patterns = (
        (r"public|open|authorization-missing|wildcard-trust|full-admin", "SEC05-BP01"),
        (r"access-key|mfa|password-policy|support-role", "SEC02-BP01"),
        (
            r"attached-directly|execution-role|shared-execution-role|unsafe-task|privilege",
            "SEC03-BP02",
        ),
        (r"encrypt|kms|secret", "SEC08-BP01"),
        (r"logging|log-retention|xray|tracing|flow-logs", "OPS04-BP02"),
        (r"versioning|replication|multi-az|backup|object-lock|disruption", "REL09-BP01"),
        (
            r"unhealthy|health-degraded|restart-loop|unschedulable|high-error|timeout-rate",
            "REL11-BP01",
        ),
        (r"idle|unused|unattached|unassociated|inactive|orphaned", "COST04-BP05"),
        (r"rightsizing|underutilized|overprovisioned|gp2|previous-generation", "COST06-BP02"),
        (r"cpu|memory|iops|throughput|throttling|capacity|read-heavy", "PERF02-BP02"),
        (r"lifecycle|retention|standard-ia|intelligent-tiering|schedule", "COST05-BP02"),
        (r"endpoint|security-group|tls|https-listener", "SEC05-BP02"),
        (r"version-support|version-skew|ami-outdated|addon-update|platform-version", "OPS05-BP01"),
    )
    for pattern, practice_id in patterns:
        if re.search(pattern, text):
            candidates.append(practice_id)
    if not candidates:
        objective_defaults = {
            "security": "SEC06-BP01",
            "reliability": "REL07-BP02",
            "operations": "OPS04-BP01",
            "cost_optimization": "COST06-BP02",
            "performance_efficiency": "PERF02-BP01",
        }
        explicit = [
            objective_defaults[value] for value in objectives if value in objective_defaults
        ]
        if len(explicit) == 1:
            candidates.extend(explicit)
    return list(dict.fromkeys(candidates[:2]))


def _practice_title(rows: List[JSON]) -> str:
    for row in rows:
        description = str(row.get("description") or "").strip()
        match = re.match(r"[A-Z]+\d+-BP\d+:\s*(.+?)(?:\.|$)", description)
        if match:
            return match.group(1).strip()
    for row in rows:
        scenario = str(row.get("scenario") or "").strip()
        if scenario:
            return scenario
    return "AWS Well-Architected best practice"
