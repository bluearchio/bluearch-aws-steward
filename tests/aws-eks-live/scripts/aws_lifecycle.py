#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_DIR = ROOT / "tests/aws-eks-live/.artifacts"
JSON = Dict[str, Any]
BROKEN_NODEGROUP_AMI_TYPE = "AL2023_x86_64_STANDARD"
EXTERNAL_DELETE_TIMEOUT_MINUTES = 30


def enable_guardduty(artifact_dir: Path) -> JSON:
    session, region = _session(artifact_dir)
    client = session.client("guardduty", region_name=region)
    state_path = artifact_dir / "guardduty-state.json"
    existing = _reusable_guardduty_state(state_path)
    if existing is not None:
        return existing

    baseline = _read_json(artifact_dir / "preflight.json").get("guardduty_baseline") or {}
    detector_ids = list(client.list_detectors().get("DetectorIds") or [])
    created = False
    if detector_ids:
        detector_id = str(detector_ids[0])
    else:
        response = client.create_detector(
            Enable=True,
            FindingPublishingFrequency="FIFTEEN_MINUTES",
            Features=[
                {
                    "Name": "EKS_RUNTIME_MONITORING",
                    "Status": "ENABLED",
                    "AdditionalConfiguration": [
                        {"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}
                    ],
                }
            ],
            Tags=_tags(artifact_dir),
        )
        detector_id = str(response["DetectorId"])
        created = True
    client.update_detector(
        DetectorId=detector_id,
        Enable=True,
        Features=[
            {
                "Name": "EKS_RUNTIME_MONITORING",
                "Status": "ENABLED",
                "AdditionalConfiguration": [{"Name": "EKS_ADDON_MANAGEMENT", "Status": "DISABLED"}],
            }
        ],
    )
    state = {
        "detector_id": detector_id,
        "created_by_lab": created,
        "baseline": baseline,
        "runtime_monitoring_enabled_for_healthy_control": True,
    }
    _write_json(state_path, state)
    _append_ledger(artifact_dir, "guardduty.update_detector", "provisioner")
    return state


def _reusable_guardduty_state(state_path: Path) -> Optional[JSON]:
    if not state_path.exists():
        return None
    state = _read_json(state_path)
    return None if state.get("restored") else state


def disable_guardduty_runtime(artifact_dir: Path) -> JSON:
    session, region = _session(artifact_dir)
    state = _read_json(artifact_dir / "guardduty-state.json")
    detector_id = str(state["detector_id"])
    session.client("guardduty", region_name=region).update_detector(
        DetectorId=detector_id,
        Enable=True,
        Features=[{"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"}],
    )
    state["runtime_monitoring_disabled_for_vulnerable_test"] = True
    _write_json(artifact_dir / "guardduty-state.json", state)
    _append_ledger(artifact_dir, "guardduty.update_detector", "provisioner")
    return state


def restore_guardduty(artifact_dir: Path) -> JSON:
    state_path = artifact_dir / "guardduty-state.json"
    if not state_path.exists():
        return {"status": "nothing_to_restore"}
    session, region = _session(artifact_dir)
    client = session.client("guardduty", region_name=region)
    state = _read_json(state_path)
    detector_id = str(state["detector_id"])
    if state.get("created_by_lab"):
        try:
            client.delete_detector(DetectorId=detector_id)
        except client.exceptions.BadRequestException:
            pass
        _append_ledger(artifact_dir, "guardduty.delete_detector", "provisioner")
        state["restored"] = True
        state["restore_action"] = "deleted_lab_detector"
        _write_json(state_path, state)
        return state

    original = next(
        (
            item
            for item in (state.get("baseline") or {}).get("detectors") or []
            if str(item.get("detector_id")) == detector_id
        ),
        None,
    )
    if original:
        features = [
            {
                "Name": item["name"],
                "Status": item["status"],
                **(
                    {"AdditionalConfiguration": item["additional_configuration"]}
                    if item.get("additional_configuration")
                    else {}
                ),
            }
            for item in original.get("features") or []
            if item.get("name") and item.get("status")
        ]
        parameters: JSON = {
            "DetectorId": detector_id,
            "Enable": str(original.get("status") or "ENABLED").upper() == "ENABLED",
        }
        if features:
            parameters["Features"] = features
        client.update_detector(**parameters)
        _append_ledger(artifact_dir, "guardduty.update_detector", "provisioner")
    state["restored"] = True
    state["restore_action"] = "restored_previous_configuration"
    _write_json(state_path, state)
    return state


def create_external_fixtures(artifact_dir: Path) -> JSON:
    session, region = _session(artifact_dir)
    outputs = _outputs(artifact_dir)
    client = session.client("eks", region_name=region)
    cluster_name = outputs["vulnerable_cluster_name"]
    tags = _tags(artifact_dir)
    writes = []

    try:
        client.describe_nodegroup(clusterName=cluster_name, nodegroupName="broken-ng")
    except client.exceptions.ResourceNotFoundException:
        client.create_nodegroup(
            clusterName=cluster_name,
            nodegroupName="broken-ng",
            scalingConfig={"minSize": 1, "maxSize": 1, "desiredSize": 1},
            subnets=[outputs["broken_subnet_id"]],
            nodeRole=outputs["node_role_arn"],
            amiType=BROKEN_NODEGROUP_AMI_TYPE,
            instanceTypes=["t3.medium"],
            tags=tags,
        )
        writes.append("eks.create_nodegroup")

    try:
        client.describe_addon(clusterName=cluster_name, addonName="adot")
    except client.exceptions.ResourceNotFoundException:
        client.create_addon(
            clusterName=cluster_name,
            addonName="adot",
            resolveConflicts="OVERWRITE",
            tags=tags,
        )
        writes.append("eks.create_addon")

    preflight = _read_json(artifact_dir / "preflight.json")
    timeout_minutes = int(preflight.get("nodegroup_degrade_timeout_minutes") or 45)
    nodegroup = _wait_for_degraded_nodegroup(
        client,
        cluster_name,
        timeout_minutes=timeout_minutes,
    )
    addon = _wait_for_unhealthy_addon(client, cluster_name)
    for operation in writes:
        _append_ledger(artifact_dir, operation, "provisioner")
    receipt = {"broken_nodegroup": nodegroup, "unhealthy_addon": addon, "writes": writes}
    _write_json(artifact_dir / "external-fixtures.json", receipt)
    return receipt


def delete_external_fixtures(artifact_dir: Path) -> JSON:
    if not (artifact_dir / "terraform-outputs.json").exists():
        return {"status": "terraform_outputs_missing"}
    session, region = _session(artifact_dir)
    outputs = _outputs(artifact_dir)
    client = session.client("eks", region_name=region)
    cluster_name = outputs["vulnerable_cluster_name"]
    deleted = []
    requested: list[tuple[str, str]] = []
    for kind, name, operation in (
        ("addon", "adot", "eks.delete_addon"),
        ("nodegroup", "broken-ng", "eks.delete_nodegroup"),
    ):
        try:
            if kind == "addon":
                client.delete_addon(clusterName=cluster_name, addonName=name, preserve=False)
            else:
                client.delete_nodegroup(clusterName=cluster_name, nodegroupName=name)
        except client.exceptions.ResourceNotFoundException:
            continue
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise
        deleted.append(operation)
        requested.append((kind, name))
        _append_ledger(artifact_dir, operation, "provisioner")
    _wait_for_external_deletions(
        client,
        cluster_name,
        requested,
        timeout_minutes=EXTERNAL_DELETE_TIMEOUT_MINUTES,
    )
    return {"status": "deleted", "operations": deleted}


def _wait_for_degraded_nodegroup(
    client: Any,
    cluster_name: str,
    *,
    timeout_minutes: int,
) -> JSON:
    deadline = time.monotonic() + timeout_minutes * 60
    while time.monotonic() < deadline:
        nodegroup = client.describe_nodegroup(clusterName=cluster_name, nodegroupName="broken-ng")[
            "nodegroup"
        ]
        issues = (nodegroup.get("health") or {}).get("issues") or []
        if issues or nodegroup.get("status") in {"CREATE_FAILED", "DEGRADED"}:
            return {"status": nodegroup.get("status"), "health_issues": issues}
        time.sleep(20)
    raise RuntimeError(f"broken-ng did not become degraded within {timeout_minutes} minutes")


def _wait_for_external_deletions(
    client: Any,
    cluster_name: str,
    resources: list[tuple[str, str]],
    *,
    timeout_minutes: int,
) -> None:
    pending = set(resources)
    deadline = time.monotonic() + timeout_minutes * 60
    while pending and time.monotonic() < deadline:
        for kind, name in tuple(pending):
            try:
                if kind == "addon":
                    client.describe_addon(clusterName=cluster_name, addonName=name)
                else:
                    client.describe_nodegroup(clusterName=cluster_name, nodegroupName=name)
            except client.exceptions.ResourceNotFoundException:
                pending.remove((kind, name))
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    pending.remove((kind, name))
                else:
                    raise
        if pending:
            time.sleep(20)
    if pending:
        names = ", ".join(f"{kind}/{name}" for kind, name in sorted(pending))
        raise RuntimeError(
            f"External EKS fixtures were not deleted within {timeout_minutes} minutes: {names}"
        )


def _wait_for_unhealthy_addon(client: Any, cluster_name: str) -> JSON:
    deadline = time.monotonic() + 20 * 60
    while time.monotonic() < deadline:
        addon = client.describe_addon(clusterName=cluster_name, addonName="adot")["addon"]
        issues = (addon.get("health") or {}).get("issues") or []
        if issues or addon.get("status") in {"CREATE_FAILED", "DEGRADED"}:
            return {"status": addon.get("status"), "health_issues": issues}
        if addon.get("status") == "ACTIVE":
            raise RuntimeError(
                "ADOT became healthy without cert-manager; the real unhealthy add-on fixture did not reproduce."
            )
        time.sleep(15)
    raise RuntimeError("ADOT did not expose a real unhealthy state within 20 minutes")


def _session(artifact_dir: Path) -> tuple[boto3.Session, str]:
    values = _read_json(artifact_dir / "terraform.tfvars.json")
    return (
        boto3.Session(
            profile_name=str(values["aws_profile"]) if values.get("aws_profile") else None,
            region_name=str(values["region"]),
        ),
        str(values["region"]),
    )


def _outputs(artifact_dir: Path) -> JSON:
    raw = _read_json(artifact_dir / "terraform-outputs.json")
    return {key: value.get("value") for key, value in raw.items()}


def _tags(artifact_dir: Path) -> Dict[str, str]:
    values = _read_json(artifact_dir / "terraform.tfvars.json")
    return {
        "bluearch.io/run-id": str(values["run_id"]),
        "bluearch.io/purpose": "steward-eks-live-validation",
        "bluearch.io/owner": str(values["owner"]),
        "bluearch.io/expires-at": str(values["expires_at"]),
    }


def _append_ledger(artifact_dir: Path, operation: str, actor: str) -> None:
    path = artifact_dir / "provisioner-write-ledger.json"
    payload = _read_json(path) if path.exists() else {"operations": []}
    payload["operations"].append({"operation": operation, "actor": actor})
    _write_json(path, payload)


def _read_json(path: Path) -> JSON:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: JSON) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "action",
        choices=[
            "enable-guardduty",
            "disable-guardduty-runtime",
            "restore-guardduty",
            "create-external-fixtures",
            "delete-external-fixtures",
        ],
    )
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    args = parser.parse_args()
    functions = {
        "enable-guardduty": enable_guardduty,
        "disable-guardduty-runtime": disable_guardduty_runtime,
        "restore-guardduty": restore_guardduty,
        "create-external-fixtures": create_external_fixtures,
        "delete-external-fixtures": delete_external_fixtures,
    }
    print(json.dumps(functions[args.action](args.artifact_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
