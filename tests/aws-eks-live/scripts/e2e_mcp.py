#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable

import boto3
from aws_lifecycle import disable_guardduty_runtime, restore_guardduty

ROOT = Path(__file__).resolve().parents[3]
LAB_DIR = ROOT / "tests/aws-eks-live"
DEFAULT_ARTIFACT_DIR = LAB_DIR / ".artifacts"
JSON = Dict[str, Any]

EKS_RULES = (
    "eks-public-endpoint-open",
    "eks-private-endpoint-disabled",
    "eks-control-plane-logging-incomplete",
    "eks-version-support-risk",
    "eks-guardduty-runtime-monitoring-disabled",
    "eks-nodegroup-version-skew",
    "eks-nodegroup-ami-outdated",
    "eks-nodegroup-health-degraded",
    "eks-managed-addon-unhealthy",
    "eks-managed-addon-update-available",
    "k8s-workload-missing-resource-requests",
    "k8s-workload-missing-memory-limit",
    "k8s-workload-missing-probes",
    "k8s-workload-disruption-unprotected",
    "k8s-workload-dangerous-privileges",
    "k8s-pod-restart-loop",
    "k8s-pod-unschedulable",
    "k8s-pod-cpu-limit-pressure",
    "k8s-pod-memory-pressure",
    "eks-workload-overprovisioned",
)

EXPECTED_RESOURCE = {
    "eks-public-endpoint-open": "{cluster}",
    "eks-private-endpoint-disabled": "{cluster}",
    "eks-control-plane-logging-incomplete": "{cluster}",
    "eks-version-support-risk": "{cluster}",
    "eks-guardduty-runtime-monitoring-disabled": "guardduty://",
    "eks-nodegroup-version-skew": "/nodegroup/skew-ng",
    "eks-nodegroup-ami-outdated": "/nodegroup/old-ami-ng",
    "eks-nodegroup-health-degraded": "/nodegroup/broken-ng",
    "eks-managed-addon-unhealthy": "/addon/adot",
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


class McpProcess:
    def __init__(
        self,
        python: Path,
        environment: Dict[str, str],
        *,
        working_directory: Path,
    ) -> None:
        self.process = subprocess.Popen(
            [str(python), "-m", "bluearch_aws_steward.mcp"],
            cwd=working_directory,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request_id = 0

    def initialize(self) -> JSON:
        return self._request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "bluearch-eks-aws-live", "version": "1"},
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
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=5)
        if self.process.returncode not in {0, None}:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP exited with {self.process.returncode}: {stderr}")

    def _request(self, method: str, params: JSON) -> JSON:
        self.request_id += 1
        if not self.process.stdin or not self.process.stdout:
            raise RuntimeError("MCP stdio is unavailable")
        request = {"jsonrpc": "2.0", "id": self.request_id, "method": method, "params": params}
        self.process.stdin.write(json.dumps(request) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP closed unexpectedly: {stderr}")
        return json.loads(line)


def run(stage: str, artifact_dir: Path) -> JSON:
    started_at = datetime.now(timezone.utc)
    values = _read_json(artifact_dir / "terraform.tfvars.json")
    outputs = _outputs(artifact_dir)
    if stage != "connection":
        _wait_for_container_insights(values, outputs)
    runtime_python = _build_runtime(artifact_dir)
    credentials = _assume_mcp_role(values, outputs)
    environment = _mcp_environment(values, credentials)
    kubeconfigs = _mcp_kubeconfigs(artifact_dir, values, outputs, environment)
    receipt: JSON = {
        "connection": {},
        "rules": {},
        "investigations": {},
        "stage": stage,
        "mcp_aws_writes": 0,
        "mcp_kubernetes_writes": 0,
        "unsupported_claims": [],
        "sensitive_reads": [],
    }
    mcp = McpProcess(runtime_python, environment, working_directory=artifact_dir)
    guardduty_changed = False
    try:
        initialized = mcp.initialize()
        _expect(initialized["serverInfo"]["name"] == "bluearch-aws-steward", initialized)
        receipt["runtime"] = {
            "server_version": initialized["serverInfo"].get("version"),
            "python": str(runtime_python),
            "installed_wheel": True,
            "editable_install": False,
        }
        receipt["connection"] = _validate_connections(
            mcp, values, outputs, kubeconfigs, artifact_dir
        )
        if stage == "connection":
            return _finalize(receipt, artifact_dir)

        healthy_id, healthy = _assessment(
            mcp,
            values,
            cluster_name=outputs["healthy_cluster_name"],
            kubeconfig=kubeconfigs["healthy"],
            context="healthy-mcp",
            namespaces=["bluearch-eks-healthy", "kube-system"],
            rules=EKS_RULES,
        )
        healthy_findings = _query_all(mcp, healthy_id)
        healthy_summary = (healthy.get("result") or {}).get("summary") or {}
        _write_json(
            artifact_dir / "healthy-scan-diagnostic.json",
            {
                "assessment_id": healthy_id,
                "findings": healthy_findings,
                "result": healthy,
                "summary": healthy_summary,
            },
        )
        _expect(healthy_findings == [], {"healthy_findings": healthy_findings})
        _expect(int(healthy_summary.get("rules_evaluated") or 0) == 20, healthy_summary)
        receipt["healthy_controls_matched"] = 0
        receipt["healthy_rules_evaluated"] = 20

        disable_guardduty_runtime(artifact_dir)
        guardduty_changed = True
        for rule in EKS_RULES:
            assessment_id, result = _assessment(
                mcp,
                values,
                cluster_name=outputs["vulnerable_cluster_name"],
                kubeconfig=kubeconfigs["vulnerable"],
                context="vulnerable-mcp",
                namespaces=["bluearch-eks-lab", "kube-system"],
                rules=(rule,),
            )
            findings = _query_all(mcp, assessment_id)
            diagnostic_dir = artifact_dir / "rule-diagnostics"
            diagnostic_dir.mkdir(parents=True, exist_ok=True)
            _write_json(
                diagnostic_dir / f"{rule}.json",
                {
                    "assessment_id": assessment_id,
                    "findings": findings,
                    "result": result,
                },
            )
            expected = EXPECTED_RESOURCE[rule].format(cluster=outputs["vulnerable_cluster_name"])
            selected = next(
                (
                    item
                    for item in findings
                    if item.get("rule") == rule and expected in str(item.get("resource") or "")
                ),
                None,
            )
            _expect(selected is not None, {"rule": rule, "findings": findings})
            summary = (result.get("result") or {}).get("summary") or {}
            _expect(int(summary.get("rules_evaluated") or 0) == 1, summary)
            receipt["rules"][rule] = {
                "assessment_id": assessment_id,
                "resource": selected.get("resource"),
                "vulnerable_resource_detected": True,
                "healthy_resource_absent": True,
                "rule_evaluated": True,
            }

        full_id, full_result = _assessment(
            mcp,
            values,
            cluster_name=outputs["vulnerable_cluster_name"],
            kubeconfig=kubeconfigs["vulnerable"],
            context="vulnerable-mcp",
            namespaces=["bluearch-eks-lab", "kube-system"],
            rules=EKS_RULES,
            include_partial_probe=True,
        )
        full_findings = _query_all(mcp, full_id)
        full_rules = {str(item.get("rule") or "") for item in full_findings}
        _expect(full_rules == set(EKS_RULES), {"expected": EKS_RULES, "actual": full_rules})
        summary = (full_result.get("result") or {}).get("summary") or {}
        _expect(int(summary.get("rules_evaluated") or 0) == 20, summary)
        receipt["assessment_id"] = full_id
        receipt["rules_evaluated"] = 20
        receipt["rule_receipts_passed"] = len(receipt["rules"])
        eks_summary = (
            ((full_result.get("result") or {}).get("summary") or {})
            .get("service_summaries", {})
            .get("eks", {})
        )
        receipt["internal_steward_ledger"] = {
            "aws_read_operations": eks_summary.get("aws_read_operations") or [],
            "aws_write_operations": int(eks_summary.get("aws_write_operations") or 0),
            "kubernetes_read_operations": eks_summary.get("kubernetes_read_operations") or [],
            "kubernetes_write_operations": int(eks_summary.get("kubernetes_write_operations") or 0),
            "sensitive_fields_read": eks_summary.get("sensitive_fields_read") or [],
        }
        _expect(receipt["internal_steward_ledger"]["aws_read_operations"], eks_summary)
        _expect(receipt["internal_steward_ledger"]["kubernetes_read_operations"], eks_summary)
        _expect(receipt["internal_steward_ledger"]["aws_write_operations"] == 0, eks_summary)
        _expect(
            receipt["internal_steward_ledger"]["kubernetes_write_operations"] == 0,
            eks_summary,
        )
        _expect(not receipt["internal_steward_ledger"]["sensitive_fields_read"], eks_summary)
        if stage == "rules":
            return _finalize(receipt, artifact_dir)

        for rule in EKS_RULES:
            finding = next(item for item in full_findings if item.get("rule") == rule)
            dossier = mcp.call(
                "bluearch_investigate_resource",
                {"assessment_id": full_id, "finding_id": finding["opportunity_id"]},
            )
            evidence_collected = bool(dossier.get("inside_cluster_evidence_collected"))
            write_operations = int(dossier.get("write_operations") or 0)
            sensitive = dossier.get("sensitive_fields_read") or []
            _expect(dossier.get("status") == "completed", {rule: dossier})
            _expect(evidence_collected, {rule: dossier})
            _expect(write_operations == 0, {rule: dossier})
            _expect(not sensitive, {rule: dossier})
            receipt["investigations"][rule] = {
                "investigation_completed": True,
                "inside_cluster_evidence_collected": True,
                "unsupported_claims": dossier.get("unsupported_claims") or [],
                "write_operations": 0,
            }
            receipt["unsupported_claims"].extend(dossier.get("unsupported_claims") or [])
            receipt["sensitive_reads"].extend(sensitive)
        receipt["investigations_completed"] = len(receipt["investigations"])
        if stage == "investigate":
            return _finalize(receipt, artifact_dir)

        report_dir = artifact_dir / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        for report_format in ("json", "pdf"):
            path = report_dir / f"eks-aws-live-{full_id}.{report_format}"
            exported = mcp.call(
                "bluearch_export_report",
                {
                    "assessment_id": full_id,
                    "format": report_format,
                    "report_profile": "complete",
                    "include_all_findings": True,
                    "output_path": str(path),
                },
            )
            _expect(path.is_file() and path.stat().st_size > 0, exported)
            receipt.setdefault("reports", {})[report_format] = {
                "path": str(path),
                "bytes": path.stat().st_size,
            }

        audit = _audit_mcp_activity(
            values,
            outputs,
            started_at=started_at,
            access_key_id=str(credentials["AccessKeyId"]),
            role_session_name="bluearch-steward-eks-validation",
        )
        receipt["audit"] = audit
        receipt["mcp_aws_writes"] = len(audit["aws_write_events"])
        receipt["mcp_kubernetes_writes"] = len(audit["kubernetes_write_events"])
        receipt["sensitive_reads"].extend(audit["sensitive_kubernetes_reads"])
        _expect(receipt["mcp_aws_writes"] == 0, audit)
        _expect(receipt["mcp_kubernetes_writes"] == 0, audit)
        _expect(not receipt["sensitive_reads"], audit)
        return _finalize(receipt, artifact_dir)
    finally:
        mcp.close()
        if guardduty_changed:
            restore_guardduty(artifact_dir)


def _validate_connections(
    mcp: McpProcess,
    values: JSON,
    outputs: JSON,
    kubeconfigs: Dict[str, Path],
    artifact_dir: Path,
) -> JSON:
    common = {"region": values["region"]}
    vulnerable = mcp.call(
        "bluearch_validate_eks_connection",
        {
            **common,
            "eks_cluster_name": outputs["vulnerable_cluster_name"],
            "kubeconfig": str(kubeconfigs["vulnerable"]),
            "kubernetes_context": "vulnerable-mcp",
            "kubernetes_namespaces": ["bluearch-eks-lab", "kube-system"],
        },
    )
    connection = vulnerable.get("connection") or {}
    for key in (
        "aws_identity_validated",
        "context_cluster_match",
        "endpoint_match",
        "certificate_authority_match",
        "kubernetes_api_reachable",
        "provider_allowlist_confirmed",
    ):
        _expect(connection.get(key) is True, vulnerable)

    healthy = mcp.call(
        "bluearch_validate_eks_connection",
        {
            **common,
            "eks_cluster_name": outputs["healthy_cluster_name"],
            "kubeconfig": str(kubeconfigs["healthy"]),
            "kubernetes_context": "healthy-mcp",
            "kubernetes_namespaces": ["bluearch-eks-healthy", "kube-system"],
        },
    )
    _expect(healthy.get("status") == "ready", healthy)

    negative = mcp.call(
        "bluearch_validate_eks_connection",
        {
            **common,
            "eks_cluster_name": outputs["vulnerable_cluster_name"],
            "kubeconfig": str(kubeconfigs["healthy"]),
            "kubernetes_context": "healthy-mcp",
        },
    )
    _expect(negative.get("status") == "input_required", negative)
    _expect(negative.get("reason") == "eks_context_cluster_mismatch", negative)
    rbac = _validate_rbac(
        Path(_read_json(artifact_dir / "seed-receipt.json")["vulnerable_kubeconfig"])
    )
    _expect(rbac["allowlisted_reads_allowed"], rbac)
    _expect(rbac["sensitive_reads_denied"], rbac)
    _expect(rbac["writes_denied"], rbac)
    return {
        "aws_identity_validated": True,
        "context_cluster_match": True,
        "endpoint_ca_match": True,
        "kubernetes_api_reachable": True,
        "rbac_allowlist_confirmed": True,
        "negative_context_mismatch_rejected": True,
        "healthy_connection_validated": True,
        "operations": vulnerable.get("operations") or {},
    }


def _assessment(
    mcp: McpProcess,
    values: JSON,
    *,
    cluster_name: str,
    kubeconfig: Path,
    context: str,
    namespaces: list[str],
    rules: Iterable[str],
    include_partial_probe: bool = False,
) -> tuple[str, JSON]:
    started = mcp.call(
        "bluearch_assess",
        {
            "provider": "aws-sdk",
            "region": values["region"],
            "service": "eks",
            "objective": "all",
            "assessment_mode": "full_report",
            "scope_confirmed": True,
            "rule_filter": ",".join(rules),
            "eks_cluster_name": cluster_name,
            "kubeconfig": str(kubeconfig),
            "kubernetes_context": context,
            "kubernetes_namespaces": namespaces,
            "kubernetes_metrics_source": "auto",
            "kubernetes_metrics_file": str(LAB_DIR / "historical-metrics.json"),
            "max_returned_resources": 200,
            "max_returned_findings": 200,
            "prompt": (
                "Run the read-only EKS validation assessment, show only matched resources, "
                "and do not apply changes."
            ),
        },
    )
    _expect(started.get("status") in {"queued", "running"}, started)
    assessment_id = str(started["assessment_id"])
    partial_observed = False
    deadline = time.monotonic() + 20 * 60
    while time.monotonic() < deadline:
        status = mcp.call("bluearch_get_scan_status", {"assessment_id": assessment_id})
        if include_partial_probe and status.get("status") == "running":
            partial = mcp.call(
                "bluearch_get_scan_results",
                {
                    "assessment_id": assessment_id,
                    "include_partial": True,
                    "generate_pdf_report": False,
                },
            )
            partial_observed = partial_observed or partial.get("status") in {
                "running",
                "not_ready",
                "completed",
            }
        if status.get("status") == "completed":
            break
        if status.get("status") in {"failed", "cancelled"}:
            raise AssertionError(status)
        time.sleep(1)
    else:
        raise TimeoutError(f"Assessment did not finish: {assessment_id}")
    result = mcp.call(
        "bluearch_get_scan_results",
        {"assessment_id": assessment_id, "generate_pdf_report": False},
    )
    if include_partial_probe:
        _expect(partial_observed, {"assessment_id": assessment_id})
    return assessment_id, result


def _query_all(mcp: McpProcess, assessment_id: str) -> list[JSON]:
    items: list[JSON] = []
    cursor: str | None = None
    while True:
        arguments: JSON = {
            "assessment_id": assessment_id,
            "sort": "priority",
            "page_size": 200,
        }
        if cursor:
            arguments["cursor"] = cursor
        response = mcp.call("bluearch_query_results", arguments)
        items.extend(response.get("findings") or [])
        cursor = str(response.get("next_cursor") or "") or None
        if not cursor:
            return items


def _build_runtime(artifact_dir: Path) -> Path:
    runtime = artifact_dir / "runtime"
    dist = artifact_dir / "dist"
    shutil.rmtree(runtime, ignore_errors=True)
    shutil.rmtree(dist, ignore_errors=True)
    dist.mkdir(parents=True, exist_ok=True)
    subprocess.run(["uv", "build", "--wheel", "--out-dir", str(dist)], cwd=ROOT, check=True)
    wheel = next(dist.glob("bluearch_aws_steward-*.whl"))
    subprocess.run(["uv", "venv", "--python", "3.11", str(runtime)], check=True)
    python = runtime / "bin/python"
    requirement = f"bluearch-aws-steward @ {wheel.resolve().as_uri()}"
    subprocess.run(
        ["uv", "pip", "install", "--python", str(python), requirement],
        check=True,
    )
    runtime_path = subprocess.run(
        [
            str(python),
            "-c",
            "from pathlib import Path; import bluearch_aws_steward as s; print(Path(s.__file__).resolve())",
        ],
        check=True,
        text=True,
        capture_output=True,
        cwd=artifact_dir,
    ).stdout.strip()
    _expect("site-packages" in runtime_path, {"runtime_path": runtime_path})
    return python


def _assume_mcp_role(values: JSON, outputs: JSON) -> JSON:
    session = boto3.Session(
        profile_name=values.get("aws_profile") or None,
        region_name=values["region"],
    )
    response = session.client("sts").assume_role(
        RoleArn=outputs["mcp_read_role_arn"],
        RoleSessionName="bluearch-steward-eks-validation",
        DurationSeconds=3600,
    )
    return response["Credentials"]


def _mcp_environment(values: JSON, credentials: JSON) -> Dict[str, str]:
    environment = dict(os.environ)
    environment.pop("AWS_PROFILE", None)
    environment.pop("AWS_DEFAULT_PROFILE", None)
    environment.update(
        {
            "AWS_ACCESS_KEY_ID": str(credentials["AccessKeyId"]),
            "AWS_SECRET_ACCESS_KEY": str(credentials["SecretAccessKey"]),
            "AWS_SESSION_TOKEN": str(credentials["SessionToken"]),
            "AWS_DEFAULT_REGION": str(values["region"]),
            "AWS_REGION": str(values["region"]),
            "AWS_EC2_METADATA_DISABLED": "true",
            "PYTHONUNBUFFERED": "1",
        }
    )
    return environment


def _mcp_kubeconfigs(
    artifact_dir: Path,
    values: JSON,
    outputs: JSON,
    environment: Dict[str, str],
) -> Dict[str, Path]:
    result = {}
    for kind in ("healthy", "vulnerable"):
        path = artifact_dir / f"{kind}-mcp.kubeconfig"
        subprocess.run(
            [
                "aws",
                "eks",
                "update-kubeconfig",
                "--region",
                str(values["region"]),
                "--name",
                str(outputs[f"{kind}_cluster_name"]),
                "--alias",
                f"{kind}-mcp",
                "--kubeconfig",
                str(path),
            ],
            env=environment,
            check=True,
        )
        result[kind] = path
    return result


def _wait_for_container_insights(values: JSON, outputs: JSON) -> None:
    session = boto3.Session(
        profile_name=values.get("aws_profile") or None,
        region_name=values["region"],
    )
    client = session.client("cloudwatch")
    checks = (
        (outputs["healthy_cluster_name"], "bluearch-eks-healthy", "healthy-api", "cpu"),
        (outputs["healthy_cluster_name"], "bluearch-eks-healthy", "healthy-api", "memory"),
        (outputs["vulnerable_cluster_name"], "bluearch-eks-lab", "cpu-pressure-api", "cpu"),
        (outputs["vulnerable_cluster_name"], "bluearch-eks-lab", "memory-pressure-api", "memory"),
    )
    deadline = time.monotonic() + 25 * 60
    while time.monotonic() < deadline:
        complete = all(
            _container_insights_datapoints(
                client,
                cluster=cluster,
                namespace=namespace,
                pod_prefix=pod_prefix,
                kind=kind,
            )
            >= 6
            for cluster, namespace, pod_prefix, kind in checks
        )
        if complete:
            return
        time.sleep(30)
    raise RuntimeError("Container Insights did not publish six real datapoints for every control")


def _container_insights_datapoints(
    client: Any,
    *,
    cluster: str,
    namespace: str,
    pod_prefix: str,
    kind: str,
) -> int:
    metric_name = f"pod_{kind}_utilization_over_pod_limit"
    metrics: list[JSON] = []
    token: str | None = None
    while True:
        parameters: JSON = {
            "Namespace": "ContainerInsights",
            "MetricName": metric_name,
            "Dimensions": [
                {"Name": "ClusterName", "Value": cluster},
                {"Name": "Namespace", "Value": namespace},
            ],
        }
        if token:
            parameters["NextToken"] = token
        response = client.list_metrics(**parameters)
        metrics.extend(response.get("Metrics") or [])
        token = str(response.get("NextToken") or "") or None
        if not token:
            break

    best = 0
    for metric in metrics:
        dimensions = metric.get("Dimensions") or []
        dimension_map = {
            str(item.get("Name") or ""): str(item.get("Value") or "") for item in dimensions
        }
        if not dimension_map.get("PodName", "").startswith(pod_prefix):
            continue
        response = client.get_metric_statistics(
            Namespace="ContainerInsights",
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=datetime.now(timezone.utc) - timedelta(hours=1),
            EndTime=datetime.now(timezone.utc),
            Period=60,
            Statistics=["Average"],
        )
        best = max(best, len(response.get("Datapoints") or []))
    return best


def _validate_rbac(admin_kubeconfig: Path) -> JSON:
    base = [
        "kubectl",
        "--kubeconfig",
        str(admin_kubeconfig),
        "auth",
        "can-i",
        "--as=bluearch-steward-probe",
        "--as-group=bluearch-steward-readers",
    ]

    def can_i(*arguments: str) -> bool:
        response = subprocess.run([*base, *arguments], text=True, capture_output=True, check=False)
        return response.stdout.strip().lower() == "yes"

    return {
        "allowlisted_reads_allowed": can_i("list", "pods", "--all-namespaces"),
        "sensitive_reads_denied": not can_i("get", "secrets", "--all-namespaces")
        and not can_i("get", "pods", "--subresource=log", "--all-namespaces")
        and not can_i("create", "pods", "--subresource=exec", "--all-namespaces")
        and not can_i("create", "pods", "--subresource=portforward", "--all-namespaces")
        and not can_i("get", "pods", "--subresource=proxy", "--all-namespaces"),
        "writes_denied": not can_i("create", "deployments", "--all-namespaces")
        and not can_i("patch", "pods", "--all-namespaces")
        and not can_i("delete", "pods", "--all-namespaces"),
    }


def _audit_mcp_activity(
    values: JSON,
    outputs: JSON,
    *,
    started_at: datetime,
    access_key_id: str,
    role_session_name: str,
) -> JSON:
    session = boto3.Session(
        profile_name=values.get("aws_profile") or None,
        region_name=values["region"],
    )
    cloudtrail = session.client("cloudtrail")
    logs = session.client("logs")
    deadline = time.monotonic() + 10 * 60
    aws_events: list[JSON] = []
    kubernetes_events: list[JSON] = []
    while time.monotonic() < deadline:
        aws_events = _lookup_cloudtrail_events(
            cloudtrail,
            access_key_id=access_key_id,
            started_at=started_at,
        )
        kubernetes_events = _lookup_kubernetes_audit_events(
            logs,
            outputs=outputs,
            role_session_name=role_session_name,
            started_at=started_at,
        )
        if aws_events and kubernetes_events:
            break
        time.sleep(20)

    read_prefixes = ("Describe", "Get", "List", "Lookup")
    aws_write_events = sorted(
        {
            str(event.get("EventName") or "")
            for event in aws_events
            if str(event.get("EventName") or "")
            and not str(event.get("EventName") or "").startswith(read_prefixes)
        }
    )
    write_verbs = {"create", "update", "patch", "delete", "deletecollection"}
    kubernetes_write_events = [
        {
            "verb": event.get("verb"),
            "resource": (event.get("objectRef") or {}).get("resource"),
            "subresource": (event.get("objectRef") or {}).get("subresource"),
        }
        for event in kubernetes_events
        if str(event.get("verb") or "").lower() in write_verbs
    ]
    sensitive_kubernetes_reads = [
        {
            "verb": event.get("verb"),
            "resource": (event.get("objectRef") or {}).get("resource"),
            "subresource": (event.get("objectRef") or {}).get("subresource"),
        }
        for event in kubernetes_events
        if str((event.get("objectRef") or {}).get("resource") or "") == "secrets"
        or str((event.get("objectRef") or {}).get("subresource") or "")
        in {"log", "exec", "proxy", "portforward"}
    ]
    return {
        "aws_events_observed": len(aws_events),
        "kubernetes_events_observed": len(kubernetes_events),
        "aws_write_events": aws_write_events,
        "kubernetes_write_events": kubernetes_write_events,
        "sensitive_kubernetes_reads": sensitive_kubernetes_reads,
    }


def _lookup_cloudtrail_events(
    client: Any,
    *,
    access_key_id: str,
    started_at: datetime,
) -> list[JSON]:
    events: list[JSON] = []
    token: str | None = None
    while True:
        parameters: JSON = {
            "LookupAttributes": [{"AttributeKey": "AccessKeyId", "AttributeValue": access_key_id}],
            "StartTime": started_at - timedelta(minutes=2),
            "EndTime": datetime.now(timezone.utc) + timedelta(minutes=1),
            "MaxResults": 50,
        }
        if token:
            parameters["NextToken"] = token
        response = client.lookup_events(**parameters)
        events.extend(response.get("Events") or [])
        token = str(response.get("NextToken") or "") or None
        if not token:
            return events


def _lookup_kubernetes_audit_events(
    client: Any,
    *,
    outputs: JSON,
    role_session_name: str,
    started_at: datetime,
) -> list[JSON]:
    events: list[JSON] = []
    for cluster in (outputs["healthy_cluster_name"], outputs["vulnerable_cluster_name"]):
        token: str | None = None
        while True:
            parameters: JSON = {
                "logGroupName": f"/aws/eks/{cluster}/cluster",
                "startTime": int((started_at - timedelta(minutes=2)).timestamp() * 1000),
                "filterPattern": f'"{role_session_name}"',
            }
            if token:
                parameters["nextToken"] = token
            response = client.filter_log_events(**parameters)
            for event in response.get("events") or []:
                try:
                    payload = json.loads(str(event.get("message") or "{}"))
                except json.JSONDecodeError:
                    continue
                events.append(payload)
            next_token = str(response.get("nextToken") or "") or None
            if not next_token or next_token == token:
                break
            token = next_token
    return events


def _finalize(receipt: JSON, artifact_dir: Path) -> JSON:
    receipt["unsupported_claims"] = sorted(set(receipt.get("unsupported_claims") or []))
    receipt["sensitive_reads"] = sorted(set(receipt.get("sensitive_reads") or []))
    stage_complete = True
    if receipt["stage"] in {"rules", "investigate", "full"}:
        stage_complete = (
            int(receipt.get("rules_evaluated") or 0) == 20
            and int(receipt.get("rule_receipts_passed") or 0) == 20
            and int(receipt.get("healthy_controls_matched") or 0) == 0
        )
    if receipt["stage"] in {"investigate", "full"}:
        stage_complete = stage_complete and int(receipt.get("investigations_completed") or 0) == 20
    if receipt["stage"] == "full":
        audit = receipt.get("audit") or {}
        internal = receipt.get("internal_steward_ledger") or {}
        stage_complete = (
            stage_complete
            and set(receipt.get("reports") or {}) == {"json", "pdf"}
            and int(audit.get("aws_events_observed") or 0) > 0
            and int(audit.get("kubernetes_events_observed") or 0) > 0
            and bool(internal.get("aws_read_operations"))
            and bool(internal.get("kubernetes_read_operations"))
        )
    receipt["passed"] = (
        stage_complete
        and all(
            receipt.get("connection", {}).get(key) is True
            for key in (
                "aws_identity_validated",
                "context_cluster_match",
                "endpoint_ca_match",
                "kubernetes_api_reachable",
                "rbac_allowlist_confirmed",
            )
        )
        and not receipt["unsupported_claims"]
        and not receipt["sensitive_reads"]
        and int(receipt.get("mcp_aws_writes") or 0) == 0
        and int(receipt.get("mcp_kubernetes_writes") or 0) == 0
    )
    path = artifact_dir / f"{receipt['stage']}-receipt.json"
    _write_json(path, receipt)
    return receipt


def _outputs(artifact_dir: Path) -> JSON:
    raw = _read_json(artifact_dir / "terraform-outputs.json")
    return {key: value.get("value") for key, value in raw.items()}


def _read_json(path: Path) -> JSON:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: JSON) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )


def _expect(condition: bool, evidence: Any) -> None:
    if not condition:
        raise AssertionError(json.dumps(evidence, indent=2, sort_keys=True, default=str))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stage", choices=("connection", "rules", "investigate", "full"), default="full"
    )
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    args = parser.parse_args()
    receipt = run(args.stage, args.artifact_dir)
    print(json.dumps({"status": "passed", **receipt}, indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
