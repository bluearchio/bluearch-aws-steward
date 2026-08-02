#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from phase import FixtureProxy, McpProcess, _query_all, _wait_for_assessment  # noqa: E402

JSON = Dict[str, Any]
CONTROL_PLANE_RULE = "eks-public-endpoint-open"
WORKLOAD_RULE = "k8s-workload-missing-resource-requests"
AMBIGUOUS_RULE = "k8s-pod-restart-loop"
FORMATS = (
    "terraform",
    "cloudformation",
    "eksctl",
    "kubernetes-yaml",
    "helm",
    "kustomize",
)


def _assess(mcp: McpProcess, rules: tuple[str, ...]) -> tuple[str, list[JSON]]:
    started = mcp.call(
        "bluearch_assess",
        {
            "provider": "aws-sdk",
            "endpoint_url": mcp.endpoint_url,
            "region": mcp.region,
            "service": "eks",
            "objective": "all",
            "assessment_mode": "full_report",
            "scope_confirmed": True,
            "rule_filter": ",".join(rules),
            "kubernetes_context": "kind-bluearch-eks-lab",
            "eks_cluster_name": "bluearch-eks-vulnerable",
            "kubernetes_namespaces": ["bluearch-eks-lab", "kube-system"],
            "kubernetes_metrics_file": str(ROOT / "tests/eks-lab/metrics.json"),
            "eks_fixture_map": str(ROOT / "tests/eks-lab/fixture-map.yml"),
            "max_returned_resources": 100,
            "max_returned_findings": 100,
            "prompt": "Build a read-only EKS remediation validation snapshot. Do not apply changes.",
        },
    )
    assessment_id = str(started["assessment_id"])
    status = _wait_for_assessment(mcp, assessment_id)
    if status.get("status") != "completed":
        raise AssertionError(json.dumps(status, indent=2, sort_keys=True))
    return assessment_id, _query_all(mcp, assessment_id)


def _finding(findings: list[JSON], rule: str, marker: str) -> JSON:
    return next(
        item
        for item in findings
        if item.get("rule") == rule and marker in str(item.get("resource") or "")
    )


def _generate_and_validate(
    mcp: McpProcess,
    assessment_id: str,
    finding: JSON,
    patch_format: str,
) -> JSON:
    inputs: JSON = {}
    if patch_format in {"terraform", "cloudformation", "eksctl"}:
        inputs = {"public_access_cidrs": ["10.0.0.0/8"], "region": mcp.region}
    generated = mcp.call(
        "bluearch_generate_iac_patch",
        {
            "assessment_id": assessment_id,
            "finding_id": finding["opportunity_id"],
            "format": patch_format,
            "inputs": inputs,
        },
    )
    if generated.get("status") != "generated":
        raise AssertionError(json.dumps(generated, indent=2, sort_keys=True))
    validated = mcp.call("bluearch_validate_iac_patch", {"patch": generated})
    if validated.get("status") != "valid":
        raise AssertionError(json.dumps(validated, indent=2, sort_keys=True))
    if validated.get("write_actions_applied") is not False:
        raise AssertionError(json.dumps(validated, indent=2, sort_keys=True))
    return {"generated": generated, "validated": validated}


def _apply_disposable_kind_patch(generated: JSON) -> None:
    content = str((generated.get("files") or {}).get("patch.json") or "")
    if not content:
        raise AssertionError("Generated Kubernetes patch did not contain patch.json")
    with tempfile.TemporaryDirectory(prefix="bluearch-eks-lab-remediation-") as directory:
        patch_path = Path(directory) / "patch.json"
        patch_path.write_text(content, encoding="utf-8")
        subprocess.run(
            [
                "kubectl",
                "--context",
                "kind-bluearch-eks-lab",
                "-n",
                "bluearch-eks-lab",
                "patch",
                "deployment",
                "missing-requests-api",
                "--type=strategic",
                f"--patch-file={patch_path}",
            ],
            check=True,
            timeout=30,
        )
    subprocess.run(
        [
            "kubectl",
            "--context",
            "kind-bluearch-eks-lab",
            "-n",
            "bluearch-eks-lab",
            "rollout",
            "status",
            "deployment/missing-requests-api",
            "--timeout=120s",
        ],
        check=True,
        timeout=130,
    )


def run(endpoint_url: str, region: str, artifact_dir: Path) -> JSON:
    proxy = FixtureProxy(endpoint_url).start()
    mcp = McpProcess(proxy.endpoint_url, region)
    receipt: JSON = {"formats": {}, "mcp_write_operations": 0}
    try:
        mcp.initialize()
        assessment_id, findings = _assess(
            mcp,
            (CONTROL_PLANE_RULE, WORKLOAD_RULE, AMBIGUOUS_RULE),
        )
        control_plane = _finding(findings, CONTROL_PLANE_RULE, "bluearch-eks-vulnerable")
        workload = _finding(findings, WORKLOAD_RULE, "/deployment/missing-requests-api")
        ambiguous = _finding(findings, AMBIGUOUS_RULE, "/pod/crashloop-api-")

        generated_documents: dict[str, JSON] = {}
        for patch_format in FORMATS:
            selected = (
                control_plane
                if patch_format in {"terraform", "cloudformation", "eksctl"}
                else workload
            )
            result = _generate_and_validate(mcp, assessment_id, selected, patch_format)
            generated_documents[patch_format] = result["generated"]
            receipt["formats"][patch_format] = {
                "generated": True,
                "validated": True,
                "validation_level": result["validated"].get("validation_level"),
                "source_files_modified": result["validated"].get("source_files_modified"),
                "cluster_writes_performed": result["validated"].get("cluster_writes_performed"),
            }

        input_required = mcp.call(
            "bluearch_generate_iac_patch",
            {
                "assessment_id": assessment_id,
                "finding_id": ambiguous["opportunity_id"],
                "format": "kubernetes-yaml",
                "inputs": {},
            },
        )
        if input_required.get("status") != "input_required":
            raise AssertionError(json.dumps(input_required, indent=2, sort_keys=True))
        receipt["ambiguous_patch_requires_input"] = True

        _apply_disposable_kind_patch(generated_documents["kubernetes-yaml"])
        verified_assessment_id, verified_findings = _assess(mcp, (WORKLOAD_RULE,))
        receipt.update(
            {
                "assessment_id": assessment_id,
                "verified_assessment_id": verified_assessment_id,
                "finding_removed_after_lab_apply": not any(
                    item.get("rule") == WORKLOAD_RULE
                    and "/deployment/missing-requests-api" in str(item.get("resource") or "")
                    for item in verified_findings
                ),
                "workload_ready": True,
                "mcp_source_files_modified": False,
                "mcp_cluster_writes": 0,
            }
        )
        if not receipt["finding_removed_after_lab_apply"]:
            raise AssertionError(json.dumps(verified_findings, indent=2, sort_keys=True))
        return receipt
    finally:
        mcp.close()
        proxy.close()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "remediation-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--artifact-dir", default=str(ROOT / "tests/eks-lab/.artifacts"))
    args = parser.parse_args()
    receipt = run(args.endpoint_url, args.region, Path(args.artifact_dir))
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
