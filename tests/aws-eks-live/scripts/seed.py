#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import time
from pathlib import Path
from typing import Any, Dict

from aws_lifecycle import create_external_fixtures, enable_guardduty

ROOT = Path(__file__).resolve().parents[3]
LAB_DIR = ROOT / "tests/aws-eks-live"
DEFAULT_ARTIFACT_DIR = LAB_DIR / ".artifacts"
JSON = Dict[str, Any]


def run(artifact_dir: Path) -> JSON:
    values = _read_json(artifact_dir / "terraform.tfvars.json")
    outputs = {
        key: value.get("value")
        for key, value in _read_json(artifact_dir / "terraform-outputs.json").items()
    }
    profile = str(values["aws_profile"]) if values.get("aws_profile") else None
    region = str(values["region"])
    healthy = str(outputs["healthy_cluster_name"])
    vulnerable = str(outputs["vulnerable_cluster_name"])
    healthy_kubeconfig = artifact_dir / "healthy-admin.kubeconfig"
    vulnerable_kubeconfig = artifact_dir / "vulnerable-admin.kubeconfig"
    _update_kubeconfig(profile, region, healthy, "healthy-admin", healthy_kubeconfig)
    _update_kubeconfig(profile, region, vulnerable, "vulnerable-admin", vulnerable_kubeconfig)

    rendered = artifact_dir / "rendered-manifests"
    rendered.mkdir(parents=True, exist_ok=True)
    images = _read_json(artifact_dir / "fixture-images.json")
    healthy_manifest = _render_manifest("healthy.yaml", rendered, images)
    vulnerable_manifest = _render_manifest("vulnerable.yaml", rendered, images)
    rbac = LAB_DIR / "manifests/steward-rbac.yaml"
    for kubeconfig in (healthy_kubeconfig, vulnerable_kubeconfig):
        _kubectl(kubeconfig, "apply", "-f", str(rbac))
    _kubectl(healthy_kubeconfig, "apply", "-f", str(healthy_manifest))
    _kubectl(vulnerable_kubeconfig, "apply", "-f", str(vulnerable_manifest))
    _kubectl(
        healthy_kubeconfig,
        "wait",
        "--for=condition=Available",
        "deployment/healthy-api",
        "-n",
        "bluearch-eks-healthy",
        "--timeout=10m",
    )
    for deployment in (
        "missing-requests-api",
        "missing-memory-limit-api",
        "missing-probes-api",
        "unprotected-api",
        "privileged-worker",
        "cpu-pressure-api",
        "overprovisioned-api",
        "runtime-healthy-api",
    ):
        _kubectl(
            vulnerable_kubeconfig,
            "wait",
            "--for=condition=Available",
            f"deployment/{deployment}",
            "-n",
            "bluearch-eks-lab",
            "--timeout=12m",
        )
    _wait_for_restart_count(vulnerable_kubeconfig, "crashloop-api", minimum=5)
    _wait_for_unschedulable(vulnerable_kubeconfig, "unschedulable-api", minimum_seconds=300)

    guardduty = enable_guardduty(artifact_dir)
    external = create_external_fixtures(artifact_dir)
    receipt = {
        "status": "seeded",
        "healthy_cluster": healthy,
        "vulnerable_cluster": vulnerable,
        "healthy_kubeconfig": str(healthy_kubeconfig),
        "vulnerable_kubeconfig": str(vulnerable_kubeconfig),
        "guardduty": guardduty,
        "external_fixtures": external,
        "fixture_images_pinned": all("@sha256:" in value for value in images.values()),
        "mcp_writes": 0,
    }
    _write_json(artifact_dir / "seed-receipt.json", receipt)
    return receipt


def _update_kubeconfig(
    profile: str | None,
    region: str,
    cluster: str,
    alias: str,
    path: Path,
) -> None:
    command = [
        "aws",
        "eks",
        "update-kubeconfig",
        "--region",
        region,
        "--name",
        cluster,
        "--alias",
        alias,
        "--kubeconfig",
        str(path),
    ]
    if profile:
        command[3:3] = ["--profile", profile]
    subprocess.run(command, check=True)


def _render_manifest(name: str, output_dir: Path, images: JSON) -> Path:
    source = (LAB_DIR / "manifests" / name).read_text(encoding="utf-8")
    rendered = (
        source.replace("__NGINX_IMAGE__", str(images["nginx"]))
        .replace("__BUSYBOX_IMAGE__", str(images["busybox"]))
        .replace("__PYTHON_IMAGE__", str(images["python"]))
    )
    if "__" in rendered:
        raise RuntimeError(f"Unresolved manifest token in {name}")
    path = output_dir / name
    path.write_text(rendered, encoding="utf-8")
    return path


def _kubectl(kubeconfig: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", "--kubeconfig", str(kubeconfig), *arguments],
        check=True,
        text=True,
        capture_output=True,
    )


def _wait_for_restart_count(kubeconfig: Path, prefix: str, minimum: int) -> None:
    deadline = time.monotonic() + 15 * 60
    while time.monotonic() < deadline:
        response = _kubectl(
            kubeconfig,
            "get",
            "pods",
            "-n",
            "bluearch-eks-lab",
            "-l",
            f"app={prefix}",
            "-o",
            "json",
        )
        pods = json.loads(response.stdout).get("items") or []
        restarts = sum(
            int(status.get("restartCount") or 0)
            for pod in pods
            for status in (pod.get("status") or {}).get("containerStatuses") or []
        )
        if restarts >= minimum:
            return
        time.sleep(15)
    raise RuntimeError(f"{prefix} did not reach {minimum} restarts")


def _wait_for_unschedulable(kubeconfig: Path, prefix: str, minimum_seconds: int) -> None:
    deadline = time.monotonic() + minimum_seconds + 5 * 60
    first_seen: float | None = None
    while time.monotonic() < deadline:
        response = _kubectl(
            kubeconfig,
            "get",
            "pods",
            "-n",
            "bluearch-eks-lab",
            "-l",
            f"app={prefix}",
            "-o",
            "json",
        )
        pods = json.loads(response.stdout).get("items") or []
        unschedulable = any(
            condition.get("type") == "PodScheduled"
            and condition.get("status") == "False"
            and condition.get("reason") == "Unschedulable"
            for pod in pods
            for condition in (pod.get("status") or {}).get("conditions") or []
        )
        if unschedulable:
            first_seen = first_seen or time.monotonic()
            if time.monotonic() - first_seen >= minimum_seconds:
                return
        else:
            first_seen = None
        time.sleep(15)
    raise RuntimeError(f"{prefix} did not remain Unschedulable for {minimum_seconds} seconds")


def _read_json(path: Path) -> JSON:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: JSON) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    args = parser.parse_args()
    print(json.dumps(run(args.artifact_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
