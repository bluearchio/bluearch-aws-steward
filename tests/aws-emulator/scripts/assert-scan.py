#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--actual", required=True)
    parser.add_argument("--expected")
    parser.add_argument("--expect-no-findings", action="store_true")
    args = parser.parse_args()

    actual = _load_json(Path(args.actual))
    findings = actual.get("findings", [])

    if args.expect_no_findings:
        if findings:
            _fail(f"Expected no findings, got {len(findings)}:\n{_pretty(findings)}")
        print("Scan assertion passed: no findings.")
        return 0

    if not args.expected:
        _fail("Use --expected or --expect-no-findings.")

    expected = _load_json(Path(args.expected))
    expected_findings = expected.get("expected_findings", [])
    expected_clean_resources = expected.get("expected_clean_resources", [])

    _assert_expected_findings(
        findings,
        expected_findings,
        allow_additional=bool(expected.get("allow_additional_findings")),
    )
    _assert_expected_rule_ids(
        findings,
        expected.get("expected_rule_ids"),
        all_active=bool(expected.get("expected_all_active_rules")),
        active_services=expected.get("expected_active_rule_services"),
    )
    _assert_expected_summary(actual.get("summary") or {}, expected.get("expected_summary") or {})
    _assert_expected_summary_minimum(
        actual.get("summary") or {}, expected.get("expected_summary_minimum") or {}
    )

    _assert_clean_resources(findings, expected_clean_resources)
    _assert_remediation_plans(findings)
    _assert_structured_evidence(findings)

    print(f"Scan assertion passed: {len(findings)} findings matched expected fixture output.")
    return 0


def _assert_expected_findings(
    findings: List[Dict[str, Any]],
    expected_findings: List[Dict[str, Any]],
    *,
    allow_additional: bool = False,
) -> None:
    mismatches = []
    for item in expected_findings:
        matches = [finding for finding in findings if _finding_matches(finding, item)]
        minimum_count = item.get("minimum_count")
        expected_count = int(item.get("count", 1))
        count_matches = (
            len(matches) >= int(minimum_count)
            if minimum_count is not None
            else len(matches) == expected_count
        )
        if not count_matches:
            mismatches.append(
                {
                    "fixture_id": item.get("fixture_id"),
                    "rule_id": item.get("rule_id"),
                    "resource": item.get("resource") or item.get("resource_pattern"),
                    "expected_count": expected_count,
                    "minimum_count": minimum_count,
                    "actual_count": len(matches),
                }
            )

    extra = [
        finding
        for finding in findings
        if not any(_finding_matches(finding, item) for item in expected_findings)
    ]
    if mismatches:
        _fail(
            f"Expected finding mismatches: {_pretty(mismatches)}\nActual findings:\n{_pretty(findings)}"
        )
    if extra and not allow_additional:
        _fail(f"Unexpected findings:\n{_pretty(extra)}\nActual findings:\n{_pretty(findings)}")


def _finding_matches(finding: Dict[str, Any], expected: Dict[str, Any]) -> bool:
    if expected.get("rule_id") is not None and finding.get("rule_id") != expected.get("rule_id"):
        return False
    if expected.get("rule_short_id") is not None and finding.get("rule_short_id") != expected.get(
        "rule_short_id"
    ):
        return False
    if not _resource_matches(str(finding.get("resource") or ""), expected):
        return False
    evidence = finding.get("evidence") or {}
    return all(
        _nested_value(evidence, path) == value
        for path, value in (expected.get("expected_evidence") or {}).items()
    )


def _resource_matches(resource: str, expected: Dict[str, Any]) -> bool:
    exact = expected.get("resource")
    if exact is not None:
        return resource == exact
    pattern = expected.get("resource_pattern")
    if pattern is not None:
        return re.fullmatch(str(pattern), resource) is not None
    _fail(f"Expected finding is missing resource or resource_pattern: {_pretty(expected)}")
    return False


def _nested_value(value: Any, path: str) -> Any:
    current = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _assert_expected_rule_ids(
    findings: List[Dict[str, Any]],
    expected_rule_ids: Any,
    *,
    all_active: bool = False,
    active_services: Any = None,
) -> None:
    if expected_rule_ids is None and not all_active:
        return
    actual = {str(finding.get("rule_id")) for finding in findings}
    expected = (
        _active_rule_ids(active_services)
        if all_active
        else {str(rule_id) for rule_id in expected_rule_ids}
    )
    if actual != expected:
        _fail(
            "Finding rule coverage mismatch: "
            f"missing={sorted(expected - actual)} extra={sorted(actual - expected)}"
        )


def _assert_expected_summary(summary: Dict[str, Any], expected_summary: Dict[str, Any]) -> None:
    mismatches = []
    for path, expected in expected_summary.items():
        actual = _nested_value(summary, path)
        if actual != expected:
            mismatches.append({"path": path, "expected": expected, "actual": actual})
    if mismatches:
        _fail(
            f"Scan summary mismatches: {_pretty(mismatches)}\nActual summary:\n{_pretty(summary)}"
        )


def _assert_expected_summary_minimum(
    summary: Dict[str, Any], expected_summary: Dict[str, Any]
) -> None:
    mismatches = []
    for path, minimum in expected_summary.items():
        actual = _nested_value(summary, path)
        if not isinstance(actual, (int, float)) or actual < minimum:
            mismatches.append({"path": path, "minimum": minimum, "actual": actual})
    if mismatches:
        _fail(
            "Scan summary minimum mismatches: "
            f"{_pretty(mismatches)}\nActual summary:\n{_pretty(summary)}"
        )


def _active_rule_ids(services: Any = None) -> set[str]:
    catalog = (
        Path(__file__).resolve().parents[3] / "bluearch_aws_steward" / "catalog" / "rules.json"
    )
    payload = _load_json(catalog)
    allowed = {str(service) for service in services} if isinstance(services, list) else None
    return {
        str(rule["id"])
        for rule in payload.get("rules", [])
        if allowed is None or str(rule.get("service")) in allowed
    }


def _assert_clean_resources(
    findings: List[Dict[str, Any]], expected_clean_resources: List[Dict[str, Any]]
) -> None:
    finding_resources = {str(finding["resource"]) for finding in findings}
    dirty_clean_resources = []
    for item in expected_clean_resources:
        matches = sorted(
            resource for resource in finding_resources if _resource_matches(resource, item)
        )
        dirty_clean_resources.extend(matches)
    if dirty_clean_resources:
        _fail(
            "Expected clean resources to pass, but findings were emitted for: "
            f"{sorted(set(dirty_clean_resources))}"
        )


def _assert_remediation_plans(findings: List[Dict[str, Any]]) -> None:
    missing: List[Tuple[str, str]] = []
    for finding in findings:
        remediation = finding.get("remediation") or {}
        if not remediation.get("requires_approval"):
            missing.append((finding["finding_id"], "requires_approval"))
        if not remediation.get("actions"):
            missing.append((finding["finding_id"], "actions"))
        if not remediation.get("verification"):
            missing.append((finding["finding_id"], "verification"))
    if missing:
        _fail(f"Findings missing remediation contract fields: {missing}")


def _assert_structured_evidence(findings: List[Dict[str, Any]]) -> None:
    missing: List[Tuple[str, str]] = []
    for finding in findings:
        finding_id = str(finding.get("finding_id") or "unknown")
        if not finding.get("resource"):
            missing.append((finding_id, "resource"))
        reference = finding.get("resource_ref") or {}
        for field in ("provider", "service", "resource_type", "resource_id"):
            if not reference.get(field):
                missing.append((finding_id, f"resource_ref.{field}"))
        observation = (finding.get("evidence") or {}).get("observation") or {}
        for field in ("observed_at", "confidence", "source"):
            if not observation.get(field):
                missing.append((finding_id, f"evidence.observation.{field}"))
    if missing:
        _fail(f"Findings missing structured evidence fields: {missing}")


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _pretty(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True)


def _fail(message: str) -> None:
    print(message, file=sys.stderr)
    raise SystemExit(1)


if __name__ == "__main__":
    raise SystemExit(main())
