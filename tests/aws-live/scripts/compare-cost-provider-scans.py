#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", required=True)
    args = parser.parse_args()
    artifact_dir = Path(args.artifact_dir)

    errors = []
    for service in ["cloudwatch", "ec2"]:
        cli = _load(artifact_dir / f"scan.{service}.aws-cli.json")
        sdk = _load(artifact_dir / f"scan.{service}.aws-sdk.json")
        if cli.get("summary", {}).get("resources_scanned") != sdk.get("summary", {}).get(
            "resources_scanned"
        ):
            errors.append(f"{service} provider resource counts differ")
        if _finding_identities(cli) != _finding_identities(sdk):
            errors.append(f"{service} provider findings differ")

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    print("AWS CLI and AWS SDK live cost scans have matching resource counts and findings.")
    return 0


def _finding_identities(payload: Dict[str, Any]) -> list[tuple[str, str]]:
    return sorted(
        (str(finding.get("rule_short_id")), str(finding.get("resource")))
        for finding in payload.get("findings", [])
    )


def _load(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    raise SystemExit(main())
