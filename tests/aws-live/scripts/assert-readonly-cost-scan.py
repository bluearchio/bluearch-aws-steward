#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cloudwatch", required=True)
    parser.add_argument("--ec2", required=True)
    parser.add_argument("--provider", required=True)
    args = parser.parse_args()

    cloudwatch = _load(Path(args.cloudwatch))
    ec2 = _load(Path(args.ec2))
    errors = []
    errors.extend(
        _validate_scan(cloudwatch, "cloudwatch", "cloudwatch-log-retention-missing", args.provider)
    )
    errors.extend(_validate_scan(ec2, "ec2", "ec2-unattached-ebs-volume", args.provider))

    for finding in cloudwatch.get("findings", []):
        estimate = (finding.get("evidence") or {}).get("cost_estimate") or {}
        if estimate.get("status") not in {"estimated", "preventive"}:
            errors.append(
                f"CloudWatch finding missing cost evidence status: {finding.get('finding_id')}"
            )

    for finding in ec2.get("findings", []):
        evidence = finding.get("evidence") or {}
        age_days = evidence.get("age_days")
        minimum_age_days = evidence.get("minimum_age_days")
        if age_days is None or minimum_age_days is None or int(age_days) < int(minimum_age_days):
            errors.append(f"EBS finding violates minimum age: {finding.get('finding_id')}")
        if (evidence.get("cost_estimate") or {}).get("status") != "estimated":
            errors.append(f"EBS finding missing cost estimate: {finding.get('finding_id')}")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print(
        "Read-only live cost scan passed: "
        f"provider={args.provider}, "
        f"cloudwatch_resources={cloudwatch['summary']['resources_scanned']}, "
        f"cloudwatch_findings={len(cloudwatch.get('findings', []))}, "
        f"ec2_resources={ec2['summary']['resources_scanned']}, "
        f"ec2_findings={len(ec2.get('findings', []))}"
    )
    return 0


def _validate_scan(payload: Dict[str, Any], service: str, rule: str, provider: str) -> list[str]:
    errors = []
    if payload.get("service") != service:
        errors.append(f"Expected service={service}, got {payload.get('service')}")
    if payload.get("provider") != provider:
        errors.append(f"Expected provider={provider}, got {payload.get('provider')}")
    summary = payload.get("summary") or {}
    if int(summary.get("scan_errors") or 0) != 0:
        errors.append(f"{service} scan reported errors: {summary.get('scan_error_samples')}")
    if int(summary.get("rules_evaluated") or 0) != 1:
        errors.append(
            f"{service} scan evaluated unexpected rule count: {summary.get('rules_evaluated')}"
        )
    unexpected = [
        finding.get("rule_short_id")
        for finding in payload.get("findings", [])
        if finding.get("rule_short_id") != rule
    ]
    if unexpected:
        errors.append(f"{service} scan returned unexpected rules: {unexpected}")
    return errors


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
