from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Sequence

from bluearch_aws_steward.providers.operations import READ_OPERATIONS, iam_action_for_operation
from bluearch_aws_steward.remediation import REMEDIATION_MANIFEST

JSON = Dict[str, Any]
READ_POLICY_PATH = Path(__file__).resolve().parents[1] / "iam" / "read-policy.json"
REMEDIATION_POLICY_PATH = Path(__file__).resolve().parents[1] / "iam" / "remediation-policy.json"


def read_actions() -> list[str]:
    return sorted(iam_action_for_operation(operation) for operation in READ_OPERATIONS)


def remediation_actions() -> list[str]:
    return sorted(
        {
            str(action)
            for manifest in REMEDIATION_MANIFEST.values()
            for action in manifest.get("iam_actions") or []
        }
    )


def build_policy(actions: Iterable[str], *, sid: str) -> JSON:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": sid,
                "Effect": "Allow",
                "Action": sorted(set(actions)),
                "Resource": "*",
            }
        ],
    }


def build_read_policy(actions: Iterable[str]) -> JSON:
    action_set = set(actions)
    ssm_actions = sorted(action_set & {"ssm:GetParameter"})
    global_actions = sorted(action_set - set(ssm_actions))
    statements: list[JSON] = []
    if global_actions:
        statements.append(
            {
                "Sid": "BlueArchStewardReadOnly",
                "Effect": "Allow",
                "Action": global_actions,
                "Resource": "*",
            }
        )
    if ssm_actions:
        statements.append(
            {
                "Sid": "BlueArchStewardReadEksAmiMetadata",
                "Effect": "Allow",
                "Action": ssm_actions,
                "Resource": "arn:aws:ssm:*::parameter/aws/service/eks/optimized-ami/*",
            }
        )
    return {"Version": "2012-10-17", "Statement": statements}


def generated_policies() -> Dict[Path, JSON]:
    return {
        READ_POLICY_PATH: build_read_policy(read_actions()),
        REMEDIATION_POLICY_PATH: build_policy(
            remediation_actions(),
            sid="BlueArchStewardApprovedRemediation",
        ),
    }


def write_policies() -> None:
    for path, payload in generated_policies().items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def policies_match() -> bool:
    for path, expected in generated_policies().items():
        try:
            actual = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return False
        if actual != expected:
            return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate least-privilege Steward IAM policy artifacts."
    )
    parser.add_argument(
        "--check", action="store_true", help="Fail when generated policies are out of sync."
    )
    arguments = parser.parse_args(argv)
    if arguments.check:
        return 0 if policies_match() else 1
    write_policies()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
