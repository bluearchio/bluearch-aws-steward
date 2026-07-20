#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--actual", required=True)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()

    payload = json.loads(Path(args.actual).read_text(encoding="utf-8"))
    findings = payload.get("findings", [])
    pairs = {(finding["rule_short_id"], finding["resource"]) for finding in findings}

    required = {
        ("s3-no-lifecycle", f"s3://{args.prefix}-no-lifecycle"),
        ("s3-versioning-disabled", f"s3://{args.prefix}-versioning-disabled"),
    }
    missing = sorted(required - pairs)
    if missing:
        print(f"Missing required AWS live findings: {missing}", file=sys.stderr)
        print(json.dumps(findings, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    secure_resource = f"s3://{args.prefix}-secure"
    secure_findings = [finding for finding in findings if finding["resource"] == secure_resource]
    if secure_findings:
        print(f"Secure control bucket produced findings: {secure_resource}", file=sys.stderr)
        print(json.dumps(secure_findings, indent=2, sort_keys=True), file=sys.stderr)
        return 1

    print(
        f"AWS live scan assertion passed: {len(findings)} finding(s), required live findings present."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
