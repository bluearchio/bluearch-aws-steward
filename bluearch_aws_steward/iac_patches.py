from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

JSON = Dict[str, Any]
IAC_PATCH_FORMATS = (
    "terraform",
    "cloudformation",
    "eksctl",
    "kubernetes-yaml",
    "helm",
    "kustomize",
)

_AMBIGUOUS_RULES = {
    "k8s-pod-restart-loop",
    "k8s-pod-unschedulable",
    "k8s-pod-cpu-limit-pressure",
    "k8s-pod-memory-pressure",
    "eks-nodegroup-health-degraded",
    "eks-managed-addon-unhealthy",
}


def generate_iac_patch(finding: JSON, patch_format: str, inputs: Optional[JSON] = None) -> JSON:
    if patch_format not in IAC_PATCH_FORMATS:
        raise ValueError(f"Unsupported IaC patch format: {patch_format}")
    inputs = dict(inputs or {})
    rule = str(finding.get("rule_short_id") or finding.get("rule") or "")
    resource = str(finding.get("resource") or "")
    if rule in _AMBIGUOUS_RULES and not inputs.get("approved_change"):
        return {
            "status": "input_required",
            "rule": rule,
            "resource": resource,
            "format": patch_format,
            "message": "Observed runtime evidence does not select one safe infrastructure change.",
            "required_inputs": ["approved_change"],
            "possible_responses": _runtime_change_options(rule),
            "read_only": True,
            "write_actions_applied": False,
        }

    namespace, kind, name = _kubernetes_identity(finding)
    content: str
    files: JSON
    if patch_format in {"kubernetes-yaml", "kustomize", "helm"}:
        document = _kubernetes_patch_document(rule, namespace, kind, name, finding, inputs)
        if document.get("status") == "input_required":
            return document
        content = json.dumps(document, indent=2, sort_keys=True) + "\n"
        files = {"patch.json": content}
        if patch_format == "helm":
            values = {"bluearchSteward": {"rule": rule, "patch": document}}
            content = json.dumps(values, indent=2, sort_keys=True) + "\n"
            files = {"values.bluearch-steward.json": content}
        elif patch_format == "kustomize":
            kustomization = {
                "apiVersion": "kustomize.config.k8s.io/v1beta1",
                "kind": "Kustomization",
                "patches": [{"path": "patch.json"}],
            }
            files = {
                "patch.json": content,
                "kustomization.yaml": json.dumps(kustomization, indent=2, sort_keys=True) + "\n",
            }
    elif patch_format == "terraform":
        content = _terraform_patch(rule, name or "cluster", inputs)
        files = {"bluearch_steward_patch.tf": content}
    elif patch_format == "cloudformation":
        content = json.dumps(_cloudformation_patch(rule, inputs), indent=2, sort_keys=True) + "\n"
        files = {"bluearch-steward-patch.json": content}
    else:
        content = (
            json.dumps(_eksctl_patch(rule, name or "cluster", inputs), indent=2, sort_keys=True)
            + "\n"
        )
        files = {"bluearch-steward-eksctl.json": content}

    digest = _digest(files)
    return {
        "schema_version": "0.1",
        "status": "generated",
        "rule": rule,
        "resource": resource,
        "format": patch_format,
        "patch_digest": digest,
        "files": files,
        "diff": _planning_diff(files),
        "explanation": "Planning-only patch fragment generated from confirmed finding evidence.",
        "source_mapping": "unresolved",
        "requires_source_owner_review": True,
        "requires_explicit_approval": True,
        "read_only": True,
        "write_actions_applied": False,
    }


def validate_iac_patch(document: JSON) -> JSON:
    if document.get("status") != "generated":
        raise ValueError("Only a generated IaC patch can be validated.")
    patch_format = str(document.get("format") or "")
    files = document.get("files") or {}
    if patch_format not in IAC_PATCH_FORMATS or not isinstance(files, dict) or not files:
        raise ValueError("IaC patch document is incomplete.")
    expected_digest = str(document.get("patch_digest") or "")
    actual_digest = _digest(files)
    if actual_digest != expected_digest:
        raise ValueError("IaC patch digest does not match its files.")

    safe_files: JSON = {}
    for name, content in files.items():
        safe_name = _validated_patch_filename(name)
        if not isinstance(content, str):
            raise ValueError(f"IaC patch file {safe_name!r} must contain text.")
        safe_files[safe_name] = content

    checks: list[JSON] = []
    for name, content in safe_files.items():
        if name.endswith(".json"):
            json.loads(str(content))
            checks.append({"check": f"json:{name}", "status": "passed"})
        elif name == "kustomization.yaml":
            json.loads(str(content))
            checks.append({"check": "kustomize_structure", "status": "passed"})
    if patch_format == "terraform":
        value = "\n".join(safe_files.values())
        if value.count("{") != value.count("}"):
            raise ValueError("Terraform patch has unbalanced braces.")
        checks.append({"check": "terraform_structure", "status": "passed"})

    external = _external_validation(patch_format, safe_files)
    checks.extend(external["checks"])
    return {
        "schema_version": "0.1",
        "status": "valid",
        "format": patch_format,
        "patch_digest": actual_digest,
        "checks": checks,
        "validation_level": external["validation_level"],
        "validated_in_temporary_directory": True,
        "source_files_modified": False,
        "cluster_writes_performed": 0,
        "write_actions_applied": False,
    }


def _external_validation(patch_format: str, files: Mapping[str, Any]) -> JSON:
    command: list[str] | None = None
    validation_level = "structural"
    with tempfile.TemporaryDirectory(prefix="bluearch-steward-patch-") as directory:
        root = Path(directory)
        for name, content in files.items():
            destination = (root / _validated_patch_filename(name)).resolve()
            if destination.parent != root.resolve():
                raise ValueError("IaC patch files must remain inside the validation directory.")
            destination.write_text(str(content), encoding="utf-8")
        if patch_format == "terraform" and shutil.which("terraform"):
            command = ["terraform", "fmt", "-check", "-diff", str(root)]
            validation_level = "tool_syntax"
        elif patch_format == "kubernetes-yaml" and shutil.which("kubectl"):
            command = [
                "kubectl",
                "apply",
                "--dry-run=client",
                "--validate=false",
                "-f",
                str(root / "patch.json"),
                "-o",
                "name",
            ]
            validation_level = "client_dry_run"
        if command is None:
            return {"validation_level": validation_level, "checks": []}
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            raise ValueError(
                f"IaC validation failed for {patch_format}: {(result.stderr or result.stdout)[:1000]}"
            )
        return {
            "validation_level": validation_level,
            "checks": [{"check": "external_tool", "status": "passed", "command": command[:2]}],
        }


def _validated_patch_filename(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("IaC patch filenames must be strings.")
    name = value.strip()
    if not name or len(name) > 128 or "\x00" in name:
        raise ValueError("IaC patch filename is invalid.")
    if Path(name).is_absolute() or Path(name).name != name or "/" in name or "\\" in name:
        raise ValueError("IaC patch filenames must be simple basenames.")
    if name in {".", ".."}:
        raise ValueError("IaC patch filename is invalid.")
    return name


def _kubernetes_patch_document(
    rule: str,
    namespace: str,
    kind: str,
    name: str,
    finding: JSON,
    inputs: JSON,
) -> JSON:
    if not name:
        return {
            "status": "input_required",
            "message": "Kubernetes workload identity is required.",
            "required_inputs": ["namespace", "kind", "name"],
            "read_only": True,
            "write_actions_applied": False,
        }
    if rule == "k8s-workload-disruption-unprotected":
        return {
            "apiVersion": "policy/v1",
            "kind": "PodDisruptionBudget",
            "metadata": {"name": f"{name}-availability", "namespace": namespace},
            "spec": {
                "minAvailable": inputs.get("min_available", 1),
                "selector": {"matchLabels": _workload_labels(finding) or {"app": name}},
            },
        }
    container = str(inputs.get("container") or _first_container(finding) or "app")
    container_patch: JSON = {"name": container}
    if rule == "k8s-workload-missing-resource-requests":
        container_patch["resources"] = {
            "requests": {
                "cpu": str(inputs.get("cpu_request") or "100m"),
                "memory": str(inputs.get("memory_request") or "128Mi"),
            }
        }
    elif rule == "k8s-workload-missing-memory-limit":
        container_patch["resources"] = {
            "limits": {"memory": str(inputs.get("memory_limit") or "256Mi")}
        }
    elif rule == "k8s-workload-missing-probes":
        if not inputs.get("probe_port"):
            return {
                "status": "input_required",
                "message": "Application-specific probe port and path are required.",
                "required_inputs": ["probe_port", "probe_path"],
                "possible_responses": [
                    {"id": "http_health", "label": "HTTP health endpoint"},
                    {"id": "tcp_readiness", "label": "TCP readiness only"},
                ],
                "read_only": True,
                "write_actions_applied": False,
            }
        probe = {
            "httpGet": {
                "path": str(inputs.get("probe_path") or "/health"),
                "port": int(inputs["probe_port"]),
            },
            "initialDelaySeconds": int(inputs.get("initial_delay_seconds") or 5),
            "periodSeconds": int(inputs.get("period_seconds") or 10),
        }
        container_patch.update(readinessProbe=probe, livenessProbe=probe)
    elif rule == "k8s-workload-dangerous-privileges":
        container_patch["securityContext"] = {
            "allowPrivilegeEscalation": False,
            "privileged": False,
            "readOnlyRootFilesystem": True,
        }
    elif rule in {
        "eks-workload-overprovisioned",
        "k8s-pod-cpu-limit-pressure",
        "k8s-pod-memory-pressure",
    }:
        approved = inputs.get("approved_change") or {}
        if not isinstance(approved, dict) or not approved:
            return {
                "status": "input_required",
                "message": "Select reviewed request and limit values before generating a patch.",
                "required_inputs": ["approved_change"],
                "read_only": True,
                "write_actions_applied": False,
            }
        container_patch["resources"] = approved
    else:
        return {
            "status": "input_required",
            "message": "This rule requires a source-specific patch decision.",
            "required_inputs": ["approved_change"],
            "read_only": True,
            "write_actions_applied": False,
        }
    return {
        "apiVersion": "apps/v1",
        "kind": kind or "Deployment",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"template": {"spec": {"containers": [container_patch]}}},
    }


def _terraform_patch(rule: str, name: str, inputs: JSON) -> str:
    cidrs = inputs.get("public_access_cidrs") or ["10.0.0.0/8"]
    logs = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
    return (
        f"# Planning fragment for {rule}; map this to the owning resource before use.\n"
        f'resource "aws_eks_cluster" "{_identifier(name)}" {{\n'
        f"  name                      = {json.dumps(name)}\n"
        f"  enabled_cluster_log_types = {json.dumps(logs)}\n"
        "  vpc_config {\n"
        "    endpoint_private_access = true\n"
        "    endpoint_public_access  = true\n"
        f"    public_access_cidrs     = {json.dumps(cidrs)}\n"
        "  }\n"
        "}\n"
    )


def _cloudformation_patch(rule: str, inputs: JSON) -> JSON:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": f"Planning fragment for {rule}; merge into the owning template.",
        "Resources": {
            "TargetCluster": {
                "Type": "AWS::EKS::Cluster",
                "Properties": {
                    "EnabledClusterLoggingTypes": [
                        "api",
                        "audit",
                        "authenticator",
                        "controllerManager",
                        "scheduler",
                    ],
                    "ResourcesVpcConfig": {
                        "EndpointPrivateAccess": True,
                        "EndpointPublicAccess": True,
                        "PublicAccessCidrs": inputs.get("public_access_cidrs") or ["10.0.0.0/8"],
                    },
                },
            }
        },
    }


def _eksctl_patch(rule: str, name: str, inputs: JSON) -> JSON:
    return {
        "apiVersion": "eksctl.io/v1alpha5",
        "kind": "ClusterConfig",
        "metadata": {"name": name, "region": str(inputs.get("region") or "us-east-1")},
        "privateCluster": {"enabled": True},
        "cloudWatch": {
            "clusterLogging": {
                "enableTypes": ["api", "audit", "authenticator", "controllerManager", "scheduler"]
            }
        },
        "bluearchSteward": {"planningRule": rule},
    }


def _kubernetes_identity(finding: JSON) -> tuple[str, str, str]:
    ref = finding.get("resource_ref") or {}
    resource_id = str(ref.get("resource_id") or "")
    parts = resource_id.split("/", 2)
    if len(parts) == 3:
        return parts[0], parts[1], parts[2]
    resource = str(finding.get("resource") or "")
    match = resource.split("/", 5)
    if resource.startswith("k8s://") and len(match) >= 6:
        return match[3], match[4].title(), match[5]
    return "default", "Deployment", str(ref.get("display_name") or ref.get("resource_id") or "")


def _first_container(finding: JSON) -> str:
    evidence = finding.get("evidence") or {}
    inside = evidence.get("inside_cluster_context") or {}
    workload = inside.get("workload") or {}
    containers = workload.get("containers") or []
    return str((containers[0] if containers else {}).get("name") or "")


def _workload_labels(finding: JSON) -> JSON:
    evidence = finding.get("evidence") or {}
    inside = evidence.get("inside_cluster_context") or {}
    workload = inside.get("workload") or {}
    name = str(workload.get("name") or "")
    return {"app": name} if name else {}


def _runtime_change_options(rule: str) -> list[JSON]:
    return [
        {
            "id": "application_fix",
            "label": "Application or image fix",
            "description": f"Use when code or image evidence explains {rule}.",
        },
        {
            "id": "resource_fix",
            "label": "Resource or scaling fix",
            "description": "Use when complete metrics and autoscaling evidence support capacity changes.",
        },
        {
            "id": "scheduling_fix",
            "label": "Scheduling constraint fix",
            "description": "Use when the scheduler message identifies the blocking constraint.",
        },
    ]


def _identifier(value: str) -> str:
    normalized = "".join(character if character.isalnum() else "_" for character in value)
    return normalized.strip("_") or "target"


def _digest(files: Mapping[str, Any]) -> str:
    payload = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _planning_diff(files: Mapping[str, Any]) -> str:
    lines: list[str] = []
    for name, content in sorted(files.items()):
        lines.append(f"--- /dev/null\n+++ b/{name}")
        lines.extend(f"+{line}" for line in str(content).splitlines())
    return "\n".join(lines) + "\n"
