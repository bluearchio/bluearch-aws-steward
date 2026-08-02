#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

import boto3

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_DIR = ROOT / "tests/aws-eks-live/.artifacts"
JSON = Dict[str, Any]


def run(artifact_dir: Path) -> JSON:
    values = _read_json(artifact_dir / "terraform.tfvars.json")
    session = boto3.Session(
        profile_name=values.get("aws_profile") or None,
        region_name=values["region"],
    )
    run_id = str(values["run_id"])
    prefix = f"bluearch-steward-eks-{run_id}"
    remaining: list[JSON] = []

    tagging = session.client("resourcegroupstaggingapi")
    token = ""
    while True:
        parameters: JSON = {
            "TagFilters": [{"Key": "bluearch.io/run-id", "Values": [run_id]}],
            "ResourcesPerPage": 100,
        }
        if token:
            parameters["PaginationToken"] = token
        response = tagging.get_resources(**parameters)
        remaining.extend(
            {"kind": "tagged_resource", "resource": item.get("ResourceARN")}
            for item in response.get("ResourceTagMappingList") or []
        )
        token = str(response.get("PaginationToken") or "")
        if not token:
            break

    eks = session.client("eks")
    clusters = list(eks.list_clusters().get("clusters") or [])
    remaining.extend(
        {"kind": "eks_cluster", "resource": name}
        for name in clusters
        if str(name).startswith(prefix)
    )

    iam = session.client("iam")
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        remaining.extend(
            {"kind": "iam_role", "resource": role.get("Arn")}
            for role in page.get("Roles") or []
            if str(role.get("RoleName") or "").startswith(prefix)
        )

    budget_names = []
    try:
        account_id = session.client("sts").get_caller_identity()["Account"]
        budgets = session.client("budgets", region_name="us-east-1")
        token = None
        while True:
            parameters: JSON = {"AccountId": account_id, "MaxResults": 100}
            if token:
                parameters["NextToken"] = token
            response = budgets.describe_budgets(**parameters)
            budget_names.extend(
                str(item.get("BudgetName"))
                for item in response.get("Budgets") or []
                if str(item.get("BudgetName") or "").startswith(prefix)
            )
            token = str(response.get("NextToken") or "") or None
            if not token:
                break
    except Exception as exc:  # cleanup must report incomplete verification instead of hiding it
        remaining.append({"kind": "budget_verification_error", "resource": str(exc)})
    remaining.extend({"kind": "budget", "resource": name} for name in budget_names)

    kubeconfigs = sorted(str(path) for path in artifact_dir.glob("*-*.kubeconfig"))
    remaining.extend({"kind": "kubeconfig", "resource": path} for path in kubeconfigs)
    receipt = {
        "status": "clean" if not remaining else "cleanup_incomplete",
        "run_id": run_id,
        "remaining_resources": remaining,
        "remaining_count": len(remaining),
        "read_only_verification": True,
    }
    (artifact_dir / "cleanup-receipt.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if remaining:
        raise RuntimeError(json.dumps(receipt, indent=2, sort_keys=True))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return receipt


def _read_json(path: Path) -> JSON:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    args = parser.parse_args()
    run(args.artifact_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
