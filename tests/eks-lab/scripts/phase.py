#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

ROOT = Path(__file__).resolve().parents[3]
EMULATOR_SCRIPTS = ROOT / "tests" / "aws-emulator" / "scripts"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(EMULATOR_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(EMULATOR_SCRIPTS))

from fixture_proxy import FixtureProxy  # noqa: E402

JSON = Dict[str, Any]
PHASE_RULES = {
    "0": [],
    "1": [
        "eks-public-endpoint-open",
        "eks-private-endpoint-disabled",
        "eks-control-plane-logging-incomplete",
        "eks-version-support-risk",
        "eks-guardduty-runtime-monitoring-disabled",
    ],
    "2": [
        "eks-nodegroup-version-skew",
        "eks-nodegroup-ami-outdated",
        "eks-nodegroup-health-degraded",
        "eks-managed-addon-unhealthy",
        "eks-managed-addon-update-available",
    ],
    "3": [
        "k8s-workload-missing-resource-requests",
        "k8s-workload-missing-memory-limit",
        "k8s-workload-missing-probes",
        "k8s-workload-disruption-unprotected",
        "k8s-workload-dangerous-privileges",
    ],
    "4": [
        "k8s-pod-restart-loop",
        "k8s-pod-unschedulable",
        "k8s-pod-cpu-limit-pressure",
        "k8s-pod-memory-pressure",
        "eks-workload-overprovisioned",
    ],
}
EXPECTED_RESOURCE = {
    "eks-public-endpoint-open": "eks://cluster/bluearch-eks-vulnerable",
    "eks-private-endpoint-disabled": "eks://cluster/bluearch-eks-vulnerable",
    "eks-control-plane-logging-incomplete": "eks://cluster/bluearch-eks-vulnerable",
    "eks-version-support-risk": "eks://cluster/bluearch-eks-vulnerable",
    "eks-guardduty-runtime-monitoring-disabled": "guardduty://us-east-1/eks-runtime-monitoring",
    "eks-nodegroup-version-skew": "/nodegroup/skew-ng",
    "eks-nodegroup-ami-outdated": "/nodegroup/old-ami-ng",
    "eks-nodegroup-health-degraded": "/nodegroup/degraded-ng",
    "eks-managed-addon-unhealthy": "/addon/vpc-cni",
    "eks-managed-addon-update-available": "/addon/coredns",
    "k8s-workload-missing-resource-requests": "/deployment/missing-requests-api",
    "k8s-workload-missing-memory-limit": "/deployment/missing-memory-limit-api",
    "k8s-workload-missing-probes": "/deployment/missing-probes-api",
    "k8s-workload-disruption-unprotected": "/deployment/unprotected-api",
    "k8s-workload-dangerous-privileges": "/deployment/privileged-worker",
    "k8s-pod-restart-loop": "/pod/crashloop-api-",
    "k8s-pod-unschedulable": "/pod/unschedulable-api-",
    "k8s-pod-cpu-limit-pressure": "/pod/cpu-pressure-api-",
    "k8s-pod-memory-pressure": "/pod/memory-pressure-api-",
    "eks-workload-overprovisioned": "/deployment/overprovisioned-api",
}
HEALTHY_MARKERS = {
    "1": ["bluearch-eks-healthy"],
    "2": ["healthy-ng", "/addon/kube-proxy"],
    "3": ["/deployment/healthy-api"],
    "4": ["/pod/runtime-healthy-api-", "/deployment/balanced-api"],
}
EXPECTED_EVIDENCE = {
    "eks-public-endpoint-open": "unrestricted_cidrs",
    "eks-private-endpoint-disabled": "endpoint_private_access",
    "eks-control-plane-logging-incomplete": "missing_log_types",
    "eks-version-support-risk": "support_risk",
    "eks-guardduty-runtime-monitoring-disabled": "runtime_monitoring_enabled",
    "eks-nodegroup-version-skew": "minor_version_skew",
    "eks-nodegroup-ami-outdated": "recommended_release_version",
    "eks-nodegroup-health-degraded": "health_issues",
    "eks-managed-addon-unhealthy": "health_issues",
    "eks-managed-addon-update-available": "compatible_default_version",
    "k8s-workload-missing-resource-requests": "containers",
    "k8s-workload-missing-memory-limit": "containers_missing_memory_limit",
    "k8s-workload-missing-probes": "containers",
    "k8s-workload-disruption-unprotected": "matching_pdb_count",
    "k8s-workload-dangerous-privileges": "dangerous_privileges",
    "k8s-pod-restart-loop": "affected_containers",
    "k8s-pod-unschedulable": "condition",
    "k8s-pod-cpu-limit-pressure": "p95_percent",
    "k8s-pod-memory-pressure": "oom_killed_containers",
    "eks-workload-overprovisioned": "container_recommendations",
}


class McpProcess:
    def __init__(self, endpoint_url: str, region: str) -> None:
        environment = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",  # pragma: allowlist secret
            "AWS_SESSION_TOKEN": "test",
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
            "PYTHONUNBUFFERED": "1",
        }
        self.process = subprocess.Popen(
            [sys.executable, "-m", "bluearch_aws_steward.mcp"],
            cwd=ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request_id = 0
        self.endpoint_url = endpoint_url
        self.region = region

    def initialize(self) -> JSON:
        return self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "bluearch-eks-lab", "version": "0.8.0b1"},
            },
        )["result"]

    def call(self, name: str, arguments: JSON) -> JSON:
        response = self._request("tools/call", {"name": name, "arguments": arguments})
        result = response["result"]
        if result.get("isError"):
            raise AssertionError(result["content"][0]["text"])
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=3)
        if self.process.returncode not in {0, None}:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP exited with {self.process.returncode}: {stderr}")

    def _request(self, method: str, params: JSON) -> JSON:
        self.request_id += 1
        if not self.process.stdin or not self.process.stdout:
            raise RuntimeError("MCP pipes are unavailable")
        payload = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP closed unexpectedly: {stderr}")
        return json.loads(line)


def run_phase(phase: str, endpoint_url: str, region: str, artifact_dir: Path) -> list[JSON]:
    rules = PHASE_RULES[phase]
    if phase == "0":
        rules = [
            "k8s-workload-missing-resource-requests",
            "k8s-workload-missing-memory-limit",
            "k8s-workload-missing-probes",
            "k8s-workload-disruption-unprotected",
            "k8s-workload-dangerous-privileges",
        ]
    if phase == "4":
        _wait_for_runtime_fixtures()
    proxy = FixtureProxy(endpoint_url).start()
    mcp = McpProcess(proxy.endpoint_url, region)
    receipts: list[JSON] = []
    try:
        initialized = mcp.initialize()
        _expect(initialized["serverInfo"]["name"] == "bluearch-aws-steward", initialized)
        namespaces = (
            ["bluearch-eks-phase-0"] if phase == "0" else ["bluearch-eks-lab", "kube-system"]
        )
        started = mcp.call(
            "bluearch_assess",
            {
                "provider": "aws-sdk",
                "endpoint_url": proxy.endpoint_url,
                "region": region,
                "service": "eks",
                "objective": "all",
                "assessment_mode": "full_report",
                "scope_confirmed": True,
                "rule_filter": ",".join(rules),
                "kubernetes_context": "kind-bluearch-eks-lab",
                "eks_cluster_name": "bluearch-eks-vulnerable",
                "kubernetes_namespaces": namespaces,
                "kubernetes_metrics_file": str(ROOT / "tests/eks-lab/metrics.json"),
                "eks_fixture_map": str(ROOT / "tests/eks-lab/fixture-map.yml"),
                "max_returned_resources": 100,
                "max_returned_findings": 100,
                "prompt": "Run the read-only EKS lab assessment, show only matched resources, and do not apply changes.",
            },
        )
        assessment_id = str(started["assessment_id"])
        status = _wait_for_assessment(mcp, assessment_id)
        _expect(status.get("status") == "completed", status)
        findings = _query_all(mcp, assessment_id)
        if phase == "0":
            _expect(findings == [], findings)
            dossier = mcp.call(
                "bluearch_investigate_resource",
                {
                    "assessment_id": assessment_id,
                    "resource": (
                        "k8s://kind-bluearch-eks-lab/bluearch-eks-phase-0/deployment/healthy-api"
                    ),
                },
            )
            diagnosis = dossier.get("operational_diagnosis") or {}
            observations = dossier.get("confirmed_observations") or {}
            receipts.append(
                {
                    "phase": 0,
                    "healthy_workload_findings": 0,
                    "investigation_completed": dossier.get("status") == "completed",
                    "inside_cluster_evidence_collected": bool(
                        dossier.get("inside_cluster_evidence_collected")
                    ),
                    "expected_evidence_confirmed": bool(
                        observations.get("workload") and observations.get("pods")
                    ),
                    "root_cause_confirmed": diagnosis.get("root_cause_confirmed"),
                    "unsupported_claims": [],
                    "kubernetes_read_operations": dossier.get("kubernetes_read_operations") or [],
                    "write_operations": int(dossier.get("write_operations") or 0),
                }
            )
            _expect(receipts[0]["investigation_completed"] is True, receipts[0])
            _expect(receipts[0]["inside_cluster_evidence_collected"] is True, receipts[0])
            _expect(receipts[0]["expected_evidence_confirmed"] is True, receipts[0])
            _expect(receipts[0]["root_cause_confirmed"] is False, receipts[0])
            _expect(bool(receipts[0]["kubernetes_read_operations"]), receipts[0])
            _expect(receipts[0]["write_operations"] == 0, receipts[0])
            return receipts

        returned_rules = {str(item.get("rule")) for item in findings}
        _expect(
            returned_rules == set(rules),
            {"returned": sorted(returned_rules), "expected": rules, "findings": findings},
        )
        for marker in HEALTHY_MARKERS.get(phase, []):
            _expect(
                not any(marker in str(item.get("resource")) for item in findings),
                {"healthy_marker": marker, "findings": findings},
            )

        for rule in rules:
            expected_resource = EXPECTED_RESOURCE[rule]
            selected = next(
                item
                for item in findings
                if item.get("rule") == rule and expected_resource in str(item.get("resource"))
            )
            dossier = mcp.call(
                "bluearch_investigate_resource",
                {"assessment_id": assessment_id, "finding_id": selected["opportunity_id"]},
            )
            evidence = selected.get("evidence") or {}
            expected_key = EXPECTED_EVIDENCE[rule]
            unsupported_claims = _unsupported_claims(rule, dossier)
            receipt = {
                "rule": rule,
                "resource": selected.get("resource"),
                "vulnerable_resource_detected": True,
                "healthy_resource_absent": True,
                "investigation_completed": dossier.get("status") == "completed",
                "inside_cluster_evidence_collected": bool(
                    dossier.get("inside_cluster_evidence_collected")
                ),
                "expected_evidence_confirmed": expected_key in evidence,
                "unsupported_claims": unsupported_claims,
                "write_operations": int(evidence.get("kubernetes_write_operations") or 0),
            }
            _expect(
                all(
                    receipt[key] is True
                    for key in (
                        "vulnerable_resource_detected",
                        "healthy_resource_absent",
                        "investigation_completed",
                        "inside_cluster_evidence_collected",
                        "expected_evidence_confirmed",
                    )
                ),
                receipt,
            )
            _expect(receipt["unsupported_claims"] == [], receipt)
            _expect(receipt["write_operations"] == 0, receipt)
            _expect(dossier.get("write_actions_applied") is False, dossier)
            receipts.append(receipt)
        return receipts
    finally:
        mcp.close()
        proxy.close()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / f"phase-{phase}-receipts.json").write_text(
            json.dumps(receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )


def _wait_for_assessment(mcp: McpProcess, assessment_id: str) -> JSON:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        status = mcp.call("bluearch_get_scan_status", {"assessment_id": assessment_id})
        if status.get("status") in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(0.2)
    raise AssertionError(f"Assessment timed out: {assessment_id}")


def _query_all(mcp: McpProcess, assessment_id: str) -> list[JSON]:
    values: list[JSON] = []
    cursor: Optional[str] = None
    while True:
        arguments: JSON = {"assessment_id": assessment_id, "page_size": 100, "sort": "priority"}
        if cursor:
            arguments["cursor"] = cursor
        page = mcp.call("bluearch_query_results", arguments)
        values.extend(page.get("findings") or [])
        cursor = page.get("next_cursor")
        if not cursor:
            return values


def _unsupported_claims(rule: str, dossier: JSON) -> list[str]:
    diagnosis = dossier.get("operational_diagnosis") or {}
    if rule == "k8s-pod-cpu-limit-pressure" and diagnosis.get("root_cause_confirmed"):
        return ["CPU utilization against a limit was presented as confirmed throttling."]
    if rule == "eks-workload-overprovisioned":
        evidence = dossier.get("current_state") or {}
        if evidence.get("hpa_saturated") is True:
            return ["Rightsizing was recommended while HPA was saturated."]
    return []


def _wait_for_runtime_fixtures() -> None:
    deadline = time.monotonic() + 420
    last_state: JSON = {}
    while time.monotonic() < deadline:
        result = subprocess.run(
            [
                "kubectl",
                "--context",
                "kind-bluearch-eks-lab",
                "-n",
                "bluearch-eks-lab",
                "get",
                "pods",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if result.returncode != 0:
            last_state = {"kubectl_error": result.stderr}
            time.sleep(2)
            continue
        payload = json.loads(result.stdout)
        pods = payload.get("items") or []
        crash_ready = any(
            str((pod.get("metadata") or {}).get("name") or "").startswith("crashloop-api-")
            and any(
                ((status.get("state") or {}).get("waiting") or {}).get("reason")
                == "CrashLoopBackOff"
                for status in (pod.get("status") or {}).get("containerStatuses") or []
            )
            for pod in pods
        )
        memory_ready = any(
            str((pod.get("metadata") or {}).get("name") or "").startswith("memory-pressure-api-")
            and any(
                ((status.get("lastState") or {}).get("terminated") or {}).get("reason")
                == "OOMKilled"
                for status in (pod.get("status") or {}).get("containerStatuses") or []
            )
            for pod in pods
        )
        unsched_age = max(
            (
                _condition_age_minutes(condition.get("lastTransitionTime"))
                for pod in pods
                if str((pod.get("metadata") or {}).get("name") or "").startswith(
                    "unschedulable-api-"
                )
                for condition in (pod.get("status") or {}).get("conditions") or []
                if condition.get("type") == "PodScheduled"
                and condition.get("status") == "False"
                and condition.get("reason") == "Unschedulable"
            ),
            default=0.0,
        )
        last_state = {
            "crashloop_ready": crash_ready,
            "memory_oom_ready": memory_ready,
            "unschedulable_minutes": round(unsched_age, 2),
        }
        if crash_ready and memory_ready and unsched_age >= 5.0:
            return
        time.sleep(2)
    raise AssertionError(f"Runtime fixtures did not stabilize: {json.dumps(last_state)}")


def _condition_age_minutes(value: Any) -> float:
    if not value:
        return 0.0
    observed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return max(0.0, (datetime.now(timezone.utc) - observed).total_seconds() / 60.0)


def _expect(condition: bool, evidence: Any) -> None:
    if not condition:
        raise AssertionError(json.dumps(evidence, indent=2, default=str, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=["0", "1", "2", "3", "4", "full"], required=True)
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--artifact-dir", default=str(ROOT / "tests/eks-lab/.artifacts"))
    arguments = parser.parse_args()
    phases: Iterable[str] = (
        ("0", "1", "2", "3", "4") if arguments.phase == "full" else (arguments.phase,)
    )
    all_receipts: list[JSON] = []
    for phase in phases:
        all_receipts.extend(
            run_phase(phase, arguments.endpoint_url, arguments.region, Path(arguments.artifact_dir))
        )
    if arguments.phase == "full":
        _expect(len([item for item in all_receipts if item.get("rule")]) == 20, all_receipts)
        output = Path(arguments.artifact_dir) / "full-receipts.json"
        output.write_text(
            json.dumps(all_receipts, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    print(
        json.dumps(
            {"phase": arguments.phase, "receipts": len(all_receipts), "status": "passed"}, indent=2
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
