from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Set

from bluearch_aws_steward.aws_endpoints import is_loopback_aws_endpoint

JSON = Dict[str, Any]

KUBERNETES_READ_OPERATIONS = frozenset(
    {
        "apps.list_daemon_sets",
        "apps.list_deployments",
        "apps.list_stateful_sets",
        "autoscaling.list_horizontal_pod_autoscalers",
        "core.list_events",
        "core.list_namespaces",
        "core.list_nodes",
        "core.list_pods",
        "core.list_services",
        "networking.list_ingresses",
        "policy.list_pod_disruption_budgets",
    }
)

DEFAULT_EXCLUDED_NAMESPACES = frozenset({"kube-node-lease", "kube-public"})


class KubernetesProviderError(RuntimeError):
    pass


@dataclass(frozen=True)
class KubernetesProviderConfig:
    kubeconfig: Optional[str] = None
    context: Optional[str] = None
    namespaces: tuple[str, ...] = ()
    excluded_namespaces: tuple[str, ...] = tuple(DEFAULT_EXCLUDED_NAMESPACES)
    metrics_file: Optional[str] = None
    fixture_map: Optional[str] = None
    expected_cluster_name: Optional[str] = None
    expected_endpoint: Optional[str] = None
    expected_certificate_authority_data: Optional[str] = None
    require_loopback_endpoint: bool = False


class KubernetesProvider:
    """Allowlisted, read-only Kubernetes snapshot provider.

    The provider intentionally has no generic API dispatch method. This makes
    Secrets, logs, exec, proxy, port-forward, and every write operation
    unreachable from Steward even if the caller has broader RBAC permissions.
    """

    def __init__(self, config: KubernetesProviderConfig, *, clients: Any = None) -> None:
        self.config = config
        self._clients = clients or self._load_clients()
        self.operations: List[str] = []
        self.write_operations = 0

    def capabilities(self) -> Set[str]:
        return set(KUBERNETES_READ_OPERATIONS)

    def snapshot(self) -> JSON:
        namespaces = self._namespace_scope()
        nodes = self._read("core.list_nodes", self._clients.core.list_node).items
        workloads: List[JSON] = []
        workload_calls = (
            (
                "Deployment",
                "apps.list_deployments",
                self._clients.apps.list_deployment_for_all_namespaces,
            ),
            (
                "StatefulSet",
                "apps.list_stateful_sets",
                self._clients.apps.list_stateful_set_for_all_namespaces,
            ),
            (
                "DaemonSet",
                "apps.list_daemon_sets",
                self._clients.apps.list_daemon_set_for_all_namespaces,
            ),
        )
        for kind, operation, call in workload_calls:
            response = self._read(operation, call)
            workloads.extend(
                _workload(item, kind)
                for item in response.items
                if _namespace_allowed(_namespace(item), namespaces)
            )

        pods = self._read("core.list_pods", self._clients.core.list_pod_for_all_namespaces).items
        services = self._read(
            "core.list_services", self._clients.core.list_service_for_all_namespaces
        ).items
        events = self._read(
            "core.list_events", self._clients.core.list_event_for_all_namespaces
        ).items
        pdbs = self._read(
            "policy.list_pod_disruption_budgets",
            self._clients.policy.list_pod_disruption_budget_for_all_namespaces,
        ).items
        hpas = self._read(
            "autoscaling.list_horizontal_pod_autoscalers",
            self._clients.autoscaling.list_horizontal_pod_autoscaler_for_all_namespaces,
        ).items
        ingresses = self._read(
            "networking.list_ingresses",
            self._clients.networking.list_ingress_for_all_namespaces,
        ).items

        return {
            "context": self._clients.context,
            "connection": {
                "kubeconfig_cluster": getattr(self._clients, "kubeconfig_cluster", None),
                "endpoint": getattr(self._clients, "endpoint", None),
                "certificate_authority_sha256": getattr(
                    self._clients, "certificate_authority_sha256", None
                ),
                "context_cluster_match": bool(
                    getattr(self._clients, "context_cluster_match", False)
                ),
                "endpoint_match": bool(getattr(self._clients, "endpoint_match", False)),
                "certificate_authority_match": bool(
                    getattr(self._clients, "certificate_authority_match", False)
                ),
            },
            "namespaces": sorted(namespaces),
            "nodes": [_node(item) for item in nodes],
            "workloads": sorted(workloads, key=_resource_sort_key),
            "pods": sorted(
                (_pod(item) for item in pods if _namespace_allowed(_namespace(item), namespaces)),
                key=_resource_sort_key,
            ),
            "services": sorted(
                (
                    _service(item)
                    for item in services
                    if _namespace_allowed(_namespace(item), namespaces)
                ),
                key=_resource_sort_key,
            ),
            "events": sorted(
                (
                    _event(item)
                    for item in events
                    if _namespace_allowed(_namespace(item), namespaces)
                ),
                key=lambda item: (item.get("namespace") or "", item.get("last_observed_at") or ""),
            ),
            "pod_disruption_budgets": sorted(
                (_pdb(item) for item in pdbs if _namespace_allowed(_namespace(item), namespaces)),
                key=_resource_sort_key,
            ),
            "horizontal_pod_autoscalers": sorted(
                (_hpa(item) for item in hpas if _namespace_allowed(_namespace(item), namespaces)),
                key=_resource_sort_key,
            ),
            "ingresses": sorted(
                (
                    _ingress(item)
                    for item in ingresses
                    if _namespace_allowed(_namespace(item), namespaces)
                ),
                key=_resource_sort_key,
            ),
            "metrics": _load_metrics(self.config.metrics_file),
            "fixture_map": _load_fixture_map(self.config.fixture_map),
            "read_operations": list(self.operations),
            "write_operations": self.write_operations,
            "sensitive_fields_read": [],
        }

    def _namespace_scope(self) -> Set[str]:
        response = self._read("core.list_namespaces", self._clients.core.list_namespace)
        discovered = {str(item.metadata.name) for item in response.items}
        requested = set(self.config.namespaces)
        excluded = set(self.config.excluded_namespaces)
        scope = discovered & requested if requested else discovered
        return scope - excluded

    def _read(self, operation: str, call: Any) -> Any:
        if operation not in KUBERNETES_READ_OPERATIONS:
            raise KubernetesProviderError(f"Kubernetes operation is not allowlisted: {operation}")
        self.operations.append(operation)
        try:
            return call(watch=False)
        except TypeError:
            try:
                return call()
            except Exception as exc:  # pragma: no cover - translated dependency surface
                raise KubernetesProviderError(f"{operation} failed: {exc}") from exc
        except Exception as exc:  # pragma: no cover - translated dependency surface
            raise KubernetesProviderError(f"{operation} failed: {exc}") from exc

    def _load_clients(self) -> Any:
        try:
            client = import_module("kubernetes.client")
            config = import_module("kubernetes.config")
            contexts, active = config.list_kube_config_contexts(config_file=self.config.kubeconfig)
            context_name = self.config.context or _active_context_name(active)
            available = {str(item.get("name")) for item in contexts or []}
            if context_name and context_name not in available:
                raise KubernetesProviderError(
                    f"Kubernetes context {context_name!r} was not found in the selected kubeconfig."
                )
            binding = _kubeconfig_binding(
                self.config.kubeconfig,
                context_name,
                expected_cluster_name=self.config.expected_cluster_name,
                expected_endpoint=self.config.expected_endpoint,
                expected_certificate_authority_data=(
                    self.config.expected_certificate_authority_data
                ),
                require_loopback_endpoint=self.config.require_loopback_endpoint,
            )
            _validate_kubeconfig_authentication(
                self.config.kubeconfig,
                context_name,
                expected_cluster_name=self.config.expected_cluster_name,
            )
            config.load_kube_config(
                config_file=self.config.kubeconfig,
                context=context_name,
                persist_config=False,
            )
        except ModuleNotFoundError as exc:
            raise KubernetesProviderError(
                "EKS workload assessment requires the Kubernetes runtime included "
                "with BlueArch AWS Steward. Reinstall the package with: "
                "python -m pip install --upgrade --force-reinstall bluearch-aws-steward"
            ) from exc
        except KubernetesProviderError:
            raise
        except Exception as exc:
            raise KubernetesProviderError(
                f"Unable to load Kubernetes configuration: {exc}"
            ) from exc

        return _KubernetesClients(
            context=context_name,
            core=client.CoreV1Api(),
            apps=client.AppsV1Api(),
            policy=client.PolicyV1Api(),
            autoscaling=client.AutoscalingV2Api(),
            networking=client.NetworkingV1Api(),
            kubeconfig_cluster=binding["kubeconfig_cluster"],
            endpoint=binding["endpoint"],
            certificate_authority_sha256=binding["certificate_authority_sha256"],
            context_cluster_match=binding["context_cluster_match"],
            endpoint_match=binding["endpoint_match"],
            certificate_authority_match=binding["certificate_authority_match"],
        )


@dataclass(frozen=True)
class _KubernetesClients:
    context: Optional[str]
    core: Any
    apps: Any
    policy: Any
    autoscaling: Any
    networking: Any
    kubeconfig_cluster: Optional[str] = None
    endpoint: Optional[str] = None
    certificate_authority_sha256: Optional[str] = None
    context_cluster_match: bool = False
    endpoint_match: bool = False
    certificate_authority_match: bool = False


def _active_context_name(active: Any) -> Optional[str]:
    return str((active or {}).get("name") or "") or None


def _kubeconfig_binding(
    configured_path: Optional[str],
    context_name: Optional[str],
    *,
    expected_cluster_name: Optional[str],
    expected_endpoint: Optional[str],
    expected_certificate_authority_data: Optional[str],
    require_loopback_endpoint: bool = False,
) -> JSON:
    path = _kubeconfig_path(configured_path)
    payload = _load_kubeconfig_document(path)

    contexts = {
        str(item.get("name") or ""): item.get("context") or {}
        for item in payload.get("contexts") or []
        if isinstance(item, dict)
    }
    selected = contexts.get(str(context_name or ""))
    if not isinstance(selected, dict):
        raise KubernetesProviderError(
            f"Kubernetes context {context_name!r} was not found in kubeconfig {path}."
        )
    kubeconfig_cluster = str(selected.get("cluster") or "")
    clusters = {
        str(item.get("name") or ""): item.get("cluster") or {}
        for item in payload.get("clusters") or []
        if isinstance(item, dict)
    }
    cluster = clusters.get(kubeconfig_cluster)
    if not isinstance(cluster, dict):
        raise KubernetesProviderError(
            f"Kubeconfig cluster {kubeconfig_cluster!r} referenced by {context_name!r} was not found."
        )

    endpoint = str(cluster.get("server") or "").rstrip("/")
    if require_loopback_endpoint and not is_loopback_aws_endpoint(endpoint):
        raise KubernetesProviderError(
            "EKS lab fixture maps require a loopback Kubernetes API endpoint."
        )
    if cluster.get("certificate-authority"):
        raise KubernetesProviderError(
            "Kubeconfig certificate authorities must be embedded as certificate-authority-data."
        )
    ca_bytes = _certificate_authority_bytes(cluster, path.parent)
    ca_sha256 = hashlib.sha256(ca_bytes).hexdigest() if ca_bytes else None
    expected_ca = _decode_certificate_authority(expected_certificate_authority_data)
    expected_ca_sha256 = hashlib.sha256(expected_ca).hexdigest() if expected_ca else None
    endpoint_match = not expected_endpoint or endpoint == str(expected_endpoint).rstrip("/")
    certificate_authority_match = not expected_ca_sha256 or ca_sha256 == expected_ca_sha256
    context_cluster_match = endpoint_match and certificate_authority_match
    if expected_cluster_name and not context_cluster_match:
        reasons = []
        if not endpoint_match:
            reasons.append("API endpoint differs from eks:DescribeCluster")
        if not certificate_authority_match:
            reasons.append("certificate authority fingerprint differs from eks:DescribeCluster")
        raise KubernetesProviderError(
            f"Kubernetes context {context_name!r} does not match EKS cluster "
            f"{expected_cluster_name!r}: {', '.join(reasons)}."
        )
    return {
        "kubeconfig_cluster": kubeconfig_cluster,
        "endpoint": endpoint,
        "certificate_authority_sha256": ca_sha256,
        "context_cluster_match": context_cluster_match,
        "endpoint_match": endpoint_match,
        "certificate_authority_match": certificate_authority_match,
    }


def _validate_kubeconfig_authentication(
    configured_path: Optional[str],
    context_name: Optional[str],
    *,
    expected_cluster_name: Optional[str],
) -> None:
    path = _kubeconfig_path(configured_path)
    payload = _load_kubeconfig_document(path)
    contexts = {
        str(item.get("name") or ""): item.get("context") or {}
        for item in payload.get("contexts") or []
        if isinstance(item, dict)
    }
    selected = contexts.get(str(context_name or ""))
    if not isinstance(selected, dict):
        raise KubernetesProviderError(
            f"Kubernetes context {context_name!r} was not found in kubeconfig {path}."
        )
    user_name = str(selected.get("user") or "")
    users = {
        str(item.get("name") or ""): item.get("user") or {}
        for item in payload.get("users") or []
        if isinstance(item, dict)
    }
    user = users.get(user_name)
    if not isinstance(user, dict):
        raise KubernetesProviderError(
            f"Kubeconfig user {user_name!r} referenced by {context_name!r} was not found."
        )

    file_backed_fields = ("client-certificate", "client-key", "tokenFile")
    if any(user.get(field) for field in file_backed_fields):
        raise KubernetesProviderError(
            "Kubeconfig authentication must not load certificate, key, or token files. "
            "Use embedded credential data or aws eks get-token."
        )
    if user.get("auth-provider"):
        raise KubernetesProviderError("Kubeconfig auth-provider plugins are not supported.")

    exec_config = user.get("exec")
    if not exec_config:
        if expected_cluster_name:
            raise KubernetesProviderError(
                "Verified EKS access requires the kubeconfig aws eks get-token authentication plugin."
            )
        return
    static_credential_fields = (
        "client-certificate-data",
        "client-key-data",
        "password",
        "token",
        "username",
    )
    if any(user.get(field) for field in static_credential_fields):
        raise KubernetesProviderError(
            "Verified EKS access cannot combine aws eks get-token with static kubeconfig credentials."
        )
    if not isinstance(exec_config, dict):
        raise KubernetesProviderError("Kubeconfig exec authentication is invalid.")
    if str(exec_config.get("command") or "") not in {"aws", "aws.exe"}:
        raise KubernetesProviderError(
            "Kubeconfig exec authentication is restricted to aws eks get-token."
        )
    args = exec_config.get("args") or []
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        raise KubernetesProviderError("Kubeconfig exec arguments are invalid.")
    if expected_cluster_name is None:
        raise KubernetesProviderError(
            "Kubeconfig exec authentication is not allowed for emulator fixture mappings."
        )
    if not _contains_subsequence(args, ("eks", "get-token")):
        raise KubernetesProviderError(
            "Kubeconfig exec authentication is restricted to aws eks get-token."
        )
    cluster_name = _argument_value(args, "--cluster-name")
    if cluster_name != expected_cluster_name:
        raise KubernetesProviderError(
            "Kubeconfig aws eks get-token cluster name does not match the selected EKS cluster."
        )
    if any(flag in args for flag in ("--endpoint-url", "--no-verify-ssl", "--ca-bundle")):
        raise KubernetesProviderError(
            "Kubeconfig aws exec authentication cannot override the AWS endpoint or TLS trust."
        )
    allowed_environment = {"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION"}
    environment = exec_config.get("env") or []
    if not isinstance(environment, list) or any(
        not isinstance(item, dict) or str(item.get("name") or "") not in allowed_environment
        for item in environment
    ):
        raise KubernetesProviderError(
            "Kubeconfig aws exec authentication contains unsupported environment overrides."
        )


def _load_kubeconfig_document(path: Path) -> JSON:
    try:
        yaml = import_module("yaml")
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except ModuleNotFoundError as exc:
        raise KubernetesProviderError(
            "Kubeconfig validation requires PyYAML, which is included with BlueArch "
            "AWS Steward. Reinstall the package with: python -m pip install "
            "--upgrade --force-reinstall bluearch-aws-steward"
        ) from exc
    except (OSError, ValueError) as exc:
        raise KubernetesProviderError(f"Unable to read kubeconfig {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise KubernetesProviderError(f"Kubeconfig {path} must contain a mapping.")
    return payload


def _contains_subsequence(values: List[str], expected: tuple[str, ...]) -> bool:
    size = len(expected)
    return any(tuple(values[index : index + size]) == expected for index in range(len(values)))


def _argument_value(arguments: List[str], name: str) -> Optional[str]:
    try:
        index = arguments.index(name)
    except ValueError:
        return None
    return arguments[index + 1] if index + 1 < len(arguments) else None


def _kubeconfig_path(configured_path: Optional[str]) -> Path:
    if configured_path:
        path = Path(configured_path).expanduser()
    else:
        candidates = [item for item in os.environ.get("KUBECONFIG", "").split(os.pathsep) if item]
        if len(candidates) > 1:
            raise KubernetesProviderError(
                "Multiple KUBECONFIG files are not supported for verified EKS access; "
                "pass one explicit kubeconfig path."
            )
        path = Path(candidates[0]).expanduser() if candidates else Path.home() / ".kube/config"
    if not path.is_file():
        raise KubernetesProviderError(f"Kubeconfig file was not found: {path}")
    return path


def _certificate_authority_bytes(cluster: JSON, base_directory: Path) -> bytes:
    encoded = cluster.get("certificate-authority-data")
    if encoded:
        return _decode_certificate_authority(str(encoded))
    configured_path = str(cluster.get("certificate-authority") or "").strip()
    if not configured_path:
        return b""
    path = Path(configured_path).expanduser()
    if not path.is_absolute():
        path = base_directory / path
    try:
        return path.read_bytes()
    except OSError as exc:
        raise KubernetesProviderError(f"Unable to read kubeconfig CA file {path}: {exc}") from exc


def _decode_certificate_authority(value: Optional[str]) -> bytes:
    if not value:
        return b""
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise KubernetesProviderError("Kubeconfig certificate-authority-data is invalid.") from exc


def _namespace(item: Any) -> str:
    return str(getattr(getattr(item, "metadata", None), "namespace", None) or "default")


def _namespace_allowed(namespace: str, allowed: Set[str]) -> bool:
    return namespace in allowed


def _metadata(item: Any) -> JSON:
    metadata = getattr(item, "metadata", None)
    return {
        "name": str(getattr(metadata, "name", None) or ""),
        "namespace": str(getattr(metadata, "namespace", None) or "default"),
        "uid": str(getattr(metadata, "uid", None) or ""),
        "labels": {
            str(key): str(value) for key, value in (getattr(metadata, "labels", None) or {}).items()
        },
        "annotations": _safe_annotations(getattr(metadata, "annotations", None) or {}),
        "created_at": _timestamp(getattr(metadata, "creation_timestamp", None)),
        "owner_references": [
            {
                "api_version": str(getattr(owner, "api_version", None) or ""),
                "kind": str(getattr(owner, "kind", None) or ""),
                "name": str(getattr(owner, "name", None) or ""),
                "uid": str(getattr(owner, "uid", None) or ""),
                "controller": bool(getattr(owner, "controller", False)),
            }
            for owner in (getattr(metadata, "owner_references", None) or [])
        ],
    }


def _safe_annotations(annotations: Mapping[str, Any]) -> JSON:
    allowed_prefixes = (
        "alb.ingress.kubernetes.io/",
        "service.beta.kubernetes.io/aws-load-balancer-",
        "bluearch.io/",
    )
    return {
        str(key): str(value)[:500]
        for key, value in annotations.items()
        if str(key).startswith(allowed_prefixes)
    }


def _workload(item: Any, kind: str) -> JSON:
    metadata = _metadata(item)
    spec = getattr(item, "spec", None)
    template = getattr(spec, "template", None)
    template_spec = getattr(template, "spec", None)
    template_metadata = getattr(template, "metadata", None)
    status = getattr(item, "status", None)
    selector = _selector(getattr(spec, "selector", None))
    return {
        **metadata,
        "kind": kind,
        "replicas": _int_or_none(getattr(spec, "replicas", None)),
        "available_replicas": _int_or_none(getattr(status, "available_replicas", None)),
        "ready_replicas": _int_or_none(getattr(status, "ready_replicas", None)),
        "updated_replicas": _int_or_none(getattr(status, "updated_replicas", None)),
        "selector": selector,
        "pod_labels": {
            str(key): str(value)
            for key, value in (getattr(template_metadata, "labels", None) or {}).items()
        },
        "host_network": bool(getattr(template_spec, "host_network", False)),
        "host_pid": bool(getattr(template_spec, "host_pid", False)),
        "host_ipc": bool(getattr(template_spec, "host_ipc", False)),
        "node_selector": {
            str(key): str(value)
            for key, value in (getattr(template_spec, "node_selector", None) or {}).items()
        },
        "containers": [
            _container(value) for value in getattr(template_spec, "containers", None) or []
        ],
        "host_path_volumes": [
            str(getattr(volume, "name", None) or "")
            for volume in getattr(template_spec, "volumes", None) or []
            if getattr(volume, "host_path", None) is not None
        ],
        "environment_values_redacted": True,
    }


def _container(container: Any) -> JSON:
    resources = getattr(container, "resources", None)
    security = getattr(container, "security_context", None)
    capabilities = getattr(security, "capabilities", None)
    return {
        "name": str(getattr(container, "name", None) or ""),
        "image": str(getattr(container, "image", None) or ""),
        "ports": [
            {
                "name": str(getattr(port, "name", None) or "") or None,
                "container_port": _int_or_none(getattr(port, "container_port", None)),
                "protocol": str(getattr(port, "protocol", None) or "TCP"),
            }
            for port in getattr(container, "ports", None) or []
        ],
        "requests": _quantities(getattr(resources, "requests", None) or {}),
        "limits": _quantities(getattr(resources, "limits", None) or {}),
        "readiness_probe": _probe(getattr(container, "readiness_probe", None)),
        "liveness_probe": _probe(getattr(container, "liveness_probe", None)),
        "startup_probe": _probe(getattr(container, "startup_probe", None)),
        "security_context": {
            "privileged": bool(getattr(security, "privileged", False)),
            "allow_privilege_escalation": getattr(security, "allow_privilege_escalation", None),
            "run_as_non_root": getattr(security, "run_as_non_root", None),
            "read_only_root_filesystem": getattr(security, "read_only_root_filesystem", None),
            "capabilities_add": sorted(
                str(value) for value in getattr(capabilities, "add", None) or []
            ),
        },
        "environment_variable_names": sorted(
            str(getattr(value, "name", None) or "")
            for value in getattr(container, "env", None) or []
            if getattr(value, "name", None)
        ),
        "environment_values_redacted": True,
    }


def _probe(probe: Any) -> Optional[JSON]:
    if probe is None:
        return None
    handler = "unknown"
    port: Any = None
    path: Any = None
    if getattr(probe, "http_get", None) is not None:
        handler = "http_get"
        port = getattr(probe.http_get, "port", None)
        path = getattr(probe.http_get, "path", None)
    elif getattr(probe, "tcp_socket", None) is not None:
        handler = "tcp_socket"
        port = getattr(probe.tcp_socket, "port", None)
    elif getattr(probe, "grpc", None) is not None:
        handler = "grpc"
        port = getattr(probe.grpc, "port", None)
    elif getattr(probe, "exec", None) is not None:
        handler = "exec_command_redacted"
    return {
        "handler": handler,
        "port": port,
        "path": str(path)[:200] if path is not None else None,
        "initial_delay_seconds": _int_or_none(getattr(probe, "initial_delay_seconds", None)),
        "period_seconds": _int_or_none(getattr(probe, "period_seconds", None)),
        "timeout_seconds": _int_or_none(getattr(probe, "timeout_seconds", None)),
        "failure_threshold": _int_or_none(getattr(probe, "failure_threshold", None)),
    }


def _pod(item: Any) -> JSON:
    metadata = _metadata(item)
    spec = getattr(item, "spec", None)
    status = getattr(item, "status", None)
    return {
        **metadata,
        "kind": "Pod",
        "phase": str(getattr(status, "phase", None) or ""),
        "node_name": str(getattr(spec, "node_name", None) or "") or None,
        "node_selector": {
            str(key): str(value)
            for key, value in (getattr(spec, "node_selector", None) or {}).items()
        },
        "conditions": [_condition(value) for value in getattr(status, "conditions", None) or []],
        "container_statuses": [
            _container_status(value) for value in getattr(status, "container_statuses", None) or []
        ],
        "containers": [_container(value) for value in getattr(spec, "containers", None) or []],
        "environment_values_redacted": True,
    }


def _condition(value: Any) -> JSON:
    return {
        "type": str(getattr(value, "type", None) or ""),
        "status": str(getattr(value, "status", None) or ""),
        "reason": str(getattr(value, "reason", None) or "") or None,
        "message": str(getattr(value, "message", None) or "")[:500] or None,
        "last_transition_time": _timestamp(getattr(value, "last_transition_time", None)),
    }


def _container_status(value: Any) -> JSON:
    state = getattr(value, "state", None)
    last_state = getattr(value, "last_state", None)
    return {
        "name": str(getattr(value, "name", None) or ""),
        "ready": bool(getattr(value, "ready", False)),
        "restart_count": int(getattr(value, "restart_count", 0) or 0),
        "waiting": _state_detail(getattr(state, "waiting", None)),
        "terminated": _state_detail(getattr(state, "terminated", None)),
        "last_terminated": _state_detail(getattr(last_state, "terminated", None)),
    }


def _state_detail(value: Any) -> Optional[JSON]:
    if value is None:
        return None
    return {
        "reason": str(getattr(value, "reason", None) or "") or None,
        "message": str(getattr(value, "message", None) or "")[:500] or None,
        "exit_code": _int_or_none(getattr(value, "exit_code", None)),
        "signal": _int_or_none(getattr(value, "signal", None)),
        "started_at": _timestamp(getattr(value, "started_at", None)),
        "finished_at": _timestamp(getattr(value, "finished_at", None)),
    }


def _node(item: Any) -> JSON:
    metadata = _metadata(item)
    status = getattr(item, "status", None)
    labels = metadata["labels"]
    return {
        **metadata,
        "kind": "Node",
        "node_group": labels.get("eks.amazonaws.com/nodegroup"),
        "instance_type": labels.get("node.kubernetes.io/instance-type"),
        "zone": labels.get("topology.kubernetes.io/zone"),
        "conditions": [_condition(value) for value in getattr(status, "conditions", None) or []],
        "capacity": _quantities(getattr(status, "capacity", None) or {}),
        "allocatable": _quantities(getattr(status, "allocatable", None) or {}),
        "taints": [
            {
                "key": str(getattr(value, "key", None) or ""),
                "value": str(getattr(value, "value", None) or "") or None,
                "effect": str(getattr(value, "effect", None) or ""),
            }
            for value in getattr(getattr(item, "spec", None), "taints", None) or []
        ],
    }


def _service(item: Any) -> JSON:
    metadata = _metadata(item)
    spec = getattr(item, "spec", None)
    return {
        **metadata,
        "kind": "Service",
        "type": str(getattr(spec, "type", None) or "ClusterIP"),
        "selector": {
            str(key): str(value) for key, value in (getattr(spec, "selector", None) or {}).items()
        },
        "ports": [
            {
                "name": str(getattr(value, "name", None) or "") or None,
                "port": _int_or_none(getattr(value, "port", None)),
                "target_port": str(getattr(value, "target_port", None) or "") or None,
                "protocol": str(getattr(value, "protocol", None) or "TCP"),
            }
            for value in getattr(spec, "ports", None) or []
        ],
    }


def _event(item: Any) -> JSON:
    metadata = _metadata(item)
    involved = getattr(item, "involved_object", None)
    return {
        **metadata,
        "kind": "Event",
        "type": str(getattr(item, "type", None) or ""),
        "reason": str(getattr(item, "reason", None) or "") or None,
        "message": str(getattr(item, "message", None) or "")[:500] or None,
        "count": int(getattr(item, "count", 0) or 0),
        "first_observed_at": _timestamp(getattr(item, "first_timestamp", None)),
        "last_observed_at": _timestamp(getattr(item, "last_timestamp", None)),
        "involved_object": {
            "kind": str(getattr(involved, "kind", None) or ""),
            "namespace": str(getattr(involved, "namespace", None) or "default"),
            "name": str(getattr(involved, "name", None) or ""),
            "uid": str(getattr(involved, "uid", None) or ""),
        },
    }


def _pdb(item: Any) -> JSON:
    metadata = _metadata(item)
    spec = getattr(item, "spec", None)
    status = getattr(item, "status", None)
    return {
        **metadata,
        "kind": "PodDisruptionBudget",
        "selector": _selector(getattr(spec, "selector", None)),
        "min_available": str(getattr(spec, "min_available", None) or "") or None,
        "max_unavailable": str(getattr(spec, "max_unavailable", None) or "") or None,
        "disruptions_allowed": _int_or_none(getattr(status, "disruptions_allowed", None)),
        "current_healthy": _int_or_none(getattr(status, "current_healthy", None)),
        "desired_healthy": _int_or_none(getattr(status, "desired_healthy", None)),
    }


def _hpa(item: Any) -> JSON:
    metadata = _metadata(item)
    spec = getattr(item, "spec", None)
    status = getattr(item, "status", None)
    target = getattr(spec, "scale_target_ref", None)
    return {
        **metadata,
        "kind": "HorizontalPodAutoscaler",
        "target": {
            "kind": str(getattr(target, "kind", None) or ""),
            "name": str(getattr(target, "name", None) or ""),
        },
        "min_replicas": _int_or_none(getattr(spec, "min_replicas", None)),
        "max_replicas": _int_or_none(getattr(spec, "max_replicas", None)),
        "current_replicas": _int_or_none(getattr(status, "current_replicas", None)),
        "desired_replicas": _int_or_none(getattr(status, "desired_replicas", None)),
        "conditions": [_condition(value) for value in getattr(status, "conditions", None) or []],
    }


def _ingress(item: Any) -> JSON:
    metadata = _metadata(item)
    status = getattr(item, "status", None)
    load_balancer = getattr(status, "load_balancer", None)
    return {
        **metadata,
        "kind": "Ingress",
        "load_balancer_addresses": sorted(
            {
                str(getattr(value, "hostname", None) or getattr(value, "ip", None) or "")
                for value in getattr(load_balancer, "ingress", None) or []
                if getattr(value, "hostname", None) or getattr(value, "ip", None)
            }
        ),
    }


def _selector(value: Any) -> JSON:
    if value is None:
        return {}
    return {
        "match_labels": {
            str(key): str(item)
            for key, item in (getattr(value, "match_labels", None) or {}).items()
        },
        "match_expressions": [
            {
                "key": str(getattr(item, "key", None) or ""),
                "operator": str(getattr(item, "operator", None) or ""),
                "values": sorted(str(entry) for entry in getattr(item, "values", None) or []),
            }
            for item in getattr(value, "match_expressions", None) or []
        ],
    }


def _quantities(values: Mapping[str, Any]) -> JSON:
    return {str(key): str(value) for key, value in values.items()}


def _timestamp(value: Any) -> Optional[str]:
    if value is None:
        return None
    formatter = getattr(value, "isoformat", None)
    return str(formatter() if callable(formatter) else value).replace("+00:00", "Z")


def _int_or_none(value: Any) -> Optional[int]:
    return int(value) if value is not None else None


def _resource_sort_key(item: Mapping[str, Any]) -> tuple[str, str, str]:
    return (
        str(item.get("namespace") or ""),
        str(item.get("kind") or ""),
        str(item.get("name") or ""),
    )


def _load_metrics(path: Optional[str]) -> JSON:
    if not path:
        return {}
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KubernetesProviderError(
            f"Unable to load synthetic metrics file {source}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise KubernetesProviderError("Kubernetes metrics fixture must be a JSON object.")
    return payload


def _load_fixture_map(path: Optional[str]) -> JSON:
    if not path:
        return {}
    source = Path(path).expanduser().resolve()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise KubernetesProviderError(f"Unable to load EKS fixture map {source}: {exc}") from exc
    if not isinstance(payload, dict):
        raise KubernetesProviderError("EKS fixture map must be a JSON-compatible YAML object.")
    return payload
