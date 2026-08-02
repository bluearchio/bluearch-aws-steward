from __future__ import annotations

import math
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from bluearch_aws_steward.aws_endpoints import is_loopback_aws_endpoint
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, Rule, ScanResult
from bluearch_aws_steward.policy import ScanPolicy
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.providers.eks_metrics import collect_eks_pod_metrics, merge_eks_metrics
from bluearch_aws_steward.providers.kubernetes import (
    KubernetesProvider,
    KubernetesProviderConfig,
    KubernetesProviderError,
)

JSON = Dict[str, Any]

AWS_CLUSTER_DETECTORS = (
    "eks_public_endpoint_open",
    "eks_private_endpoint_disabled",
    "eks_control_plane_logging_incomplete",
    "eks_version_support_risk",
)
AWS_NODEGROUP_DETECTORS = (
    "eks_nodegroup_version_skew",
    "eks_nodegroup_ami_outdated",
    "eks_nodegroup_health_degraded",
)
AWS_ADDON_DETECTORS = (
    "eks_managed_addon_unhealthy",
    "eks_managed_addon_update_available",
)
KUBERNETES_DETECTORS = (
    "k8s_workload_missing_resource_requests",
    "k8s_workload_missing_memory_limit",
    "k8s_workload_missing_probes",
    "k8s_workload_disruption_unprotected",
    "k8s_workload_dangerous_privileges",
    "k8s_pod_restart_loop",
    "k8s_pod_unschedulable",
    "k8s_pod_cpu_limit_pressure",
    "k8s_pod_memory_pressure",
    "eks_workload_overprovisioned",
)

_DANGEROUS_CAPABILITIES = {
    "ALL",
    "BPF",
    "DAC_READ_SEARCH",
    "NET_ADMIN",
    "NET_RAW",
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
}


def scan_eks(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-sdk",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
    kubernetes_provider: KubernetesProvider | None = None,
    kubeconfig: str | None = None,
    kubernetes_context: str | None = None,
    kubernetes_namespaces: Sequence[str] | None = None,
    kubernetes_excluded_namespaces: Sequence[str] | None = None,
    kubernetes_metrics_file: str | None = None,
    kubernetes_metrics_source: str = "auto",
    eks_fixture_map: str | None = None,
    eks_cluster_name: str | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "eks", rule_filter)
    findings: List[Finding] = []
    resource_skips: List[JSON] = []
    clusters: List[JSON] = []
    nodegroups: List[JSON] = []
    addons: List[JSON] = []
    kubernetes_correlation_error: str | None = None

    aws_detectors = tuple(
        name
        for name in (
            *AWS_CLUSTER_DETECTORS,
            "eks_guardduty_runtime_monitoring_disabled",
            *AWS_NODEGROUP_DETECTORS,
            *AWS_ADDON_DETECTORS,
        )
        if context.rule(name)
    )
    if aws_detectors:
        clusters = _collect_clusters(context, aws_detectors, eks_cluster_name)
        _evaluate_clusters(context, clusters, findings, region)
        _evaluate_guardduty(context, clusters, findings, region)
        nodegroups = _collect_nodegroups(context, clusters)
        _evaluate_nodegroups(context, clusters, nodegroups, findings, resource_skips, region)
        addons = _collect_addons(context, clusters)
        _evaluate_addons(context, clusters, addons, findings, region)

    snapshot: JSON = {}
    k8s_detectors = [name for name in KUBERNETES_DETECTORS if context.rule(name)]
    kubernetes_access_requested = bool(kubernetes_provider or kubeconfig or kubernetes_context)
    correlation_requested = bool(aws_detectors and kubernetes_access_requested)
    if kubernetes_access_requested and kubernetes_provider is None and not eks_cluster_name:
        context.fail(
            k8s_detectors,
            "kubernetes.cluster_binding",
            "eks_cluster_name is required when kubeconfig or kubernetes_context is used.",
        )
    elif k8s_detectors and not kubernetes_access_requested:
        context.fail(
            k8s_detectors,
            "kubernetes.context",
            "Explicit kubernetes_context or kubeconfig is required for inside-cluster reads.",
        )
    elif eks_fixture_map and not is_loopback_aws_endpoint(endpoint_url):
        message = "EKS fixture maps are allowed only with a loopback AWS emulator endpoint."
        if k8s_detectors:
            context.fail(k8s_detectors, "kubernetes.fixture_map", message)
        else:
            kubernetes_correlation_error = message
    elif k8s_detectors or correlation_requested:
        try:
            selected_cluster = _selected_cluster(clusters, eks_cluster_name)
            selected_kubernetes_provider = kubernetes_provider or KubernetesProvider(
                KubernetesProviderConfig(
                    kubeconfig=kubeconfig,
                    context=kubernetes_context,
                    namespaces=tuple(kubernetes_namespaces or ()),
                    excluded_namespaces=tuple(
                        kubernetes_excluded_namespaces
                        if kubernetes_excluded_namespaces is not None
                        else ("kube-node-lease", "kube-public")
                    ),
                    metrics_file=kubernetes_metrics_file,
                    fixture_map=eks_fixture_map,
                    expected_cluster_name=(eks_cluster_name if not eks_fixture_map else None),
                    expected_endpoint=(
                        (selected_cluster or {}).get("endpoint") if not eks_fixture_map else None
                    ),
                    expected_certificate_authority_data=(
                        ((selected_cluster or {}).get("certificateAuthority") or {}).get("data")
                        if not eks_fixture_map
                        else None
                    ),
                    require_loopback_endpoint=bool(eks_fixture_map),
                )
            )
            snapshot = selected_kubernetes_provider.snapshot()
        except KubernetesProviderError as exc:
            if k8s_detectors:
                context.fail(k8s_detectors, "kubernetes.snapshot", str(exc))
            else:
                kubernetes_correlation_error = str(exc)
        else:
            _attach_live_metrics(
                context,
                client,
                snapshot,
                cluster_name=eks_cluster_name,
                source=kubernetes_metrics_source,
                metrics_file=kubernetes_metrics_file,
            )
            if k8s_detectors:
                _evaluate_kubernetes(context, snapshot, findings, region)
            _attach_cluster_correlations(findings, clusters, nodegroups, addons, snapshot)

    resources_scanned = (
        len(clusters)
        + len(nodegroups)
        + len(addons)
        + len(snapshot.get("workloads") or [])
        + len(snapshot.get("pods") or [])
    )
    result = build_scan_result(
        service="eks",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=resources_scanned,
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )
    result.summary.update(
        {
            "eks_clusters_scanned": len(clusters),
            "eks_nodegroups_scanned": len(nodegroups),
            "eks_addons_scanned": len(addons),
            "kubernetes_workloads_scanned": len(snapshot.get("workloads") or []),
            "kubernetes_pods_scanned": len(snapshot.get("pods") or []),
            "kubernetes_context": snapshot.get("context"),
            "eks_cluster_name": eks_cluster_name,
            "kubernetes_connection": snapshot.get("connection") or {},
            "kubernetes_metric_collection": snapshot.get("metric_collection") or {},
            "aws_read_operations": _provider_operations(client),
            "aws_write_operations": 0,
            "kubernetes_read_operations": snapshot.get("read_operations") or [],
            "kubernetes_write_operations": int(snapshot.get("write_operations") or 0),
            "sensitive_fields_read": snapshot.get("sensitive_fields_read") or [],
            "resource_skips": resource_skips,
            "kubernetes_correlation_error": kubernetes_correlation_error,
        }
    )
    return result


def _provider_operations(client: AwsProvider) -> List[str]:
    operations_executed = getattr(client, "operations_executed", None)
    if not callable(operations_executed):
        return []
    return list(operations_executed())


def _collect_clusters(
    context: EvaluationContext,
    detectors: Sequence[str],
    cluster_name: str | None,
) -> List[JSON]:
    if cluster_name:
        names = [cluster_name]
    else:
        response = context.read(detectors, "eks.list_clusters") or {}
        names = [str(name) for name in response.get("clusters") or []]
    clusters: List[JSON] = []
    for name in names:
        detail = context.read(detectors, "eks.describe_cluster", name=name) or {}
        cluster = detail.get("cluster")
        if isinstance(cluster, dict):
            clusters.append(cluster)
    return clusters


def _selected_cluster(clusters: Sequence[JSON], cluster_name: str | None) -> JSON | None:
    if not cluster_name:
        return clusters[0] if len(clusters) == 1 else None
    return next(
        (cluster for cluster in clusters if str(cluster.get("name") or "") == cluster_name),
        None,
    )


def _attach_live_metrics(
    context: EvaluationContext,
    client: AwsProvider,
    snapshot: JSON,
    *,
    cluster_name: str | None,
    source: str,
    metrics_file: str | None,
) -> None:
    normalized = str(source or "auto").strip().lower()
    if normalized not in {"auto", "cloudwatch", "file", "none"}:
        raise ValueError("kubernetes_metrics_source must be one of: auto, cloudwatch, file, none.")
    if normalized == "none":
        snapshot["metrics"] = {}
        snapshot["metric_collection"] = {"source": "none"}
        return
    if normalized == "file" or (normalized == "auto" and metrics_file and not cluster_name):
        if not metrics_file:
            context.fail(
                (
                    "k8s_pod_cpu_limit_pressure",
                    "k8s_pod_memory_pressure",
                    "eks_workload_overprovisioned",
                ),
                "kubernetes.metrics_file",
                "kubernetes_metrics_file is required when kubernetes_metrics_source=file.",
            )
            return
        _mark_historical_metrics_synthetic(snapshot)
        snapshot["metric_collection"] = {
            "source": "file",
            "historical_evidence_provenance": "synthetic_historical_validation",
        }
        return
    if not cluster_name:
        if normalized == "cloudwatch":
            context.fail(
                ("k8s_pod_cpu_limit_pressure", "k8s_pod_memory_pressure"),
                "cloudwatch.get_metric_data",
                "eks_cluster_name is required for Container Insights metrics.",
            )
        return

    include_cpu = bool(context.rule("k8s_pod_cpu_limit_pressure"))
    include_memory = bool(context.rule("k8s_pod_memory_pressure"))
    if not include_cpu and not include_memory:
        return
    try:
        live, metadata = collect_eks_pod_metrics(
            client,
            snapshot,
            cluster_name=cluster_name,
            include_cpu=include_cpu,
            include_memory=include_memory,
        )
    except AwsProviderError as exc:
        context.fail(
            tuple(
                detector
                for detector, enabled in (
                    ("k8s_pod_cpu_limit_pressure", include_cpu),
                    ("k8s_pod_memory_pressure", include_memory),
                )
                if enabled
            ),
            "cloudwatch.get_metric_data",
            exc.detail or str(exc),
        )
        return
    snapshot["metrics"] = merge_eks_metrics(snapshot.get("metrics") or {}, live)
    if metrics_file:
        _mark_historical_metrics_synthetic(snapshot)
        metadata["historical_evidence_provenance"] = "synthetic_historical_validation"
    snapshot["metric_collection"] = metadata
    series_by_kind = metadata.get("series_by_kind") or {}
    if snapshot.get("pods"):
        if include_cpu and int(series_by_kind.get("cpu") or 0) == 0:
            context.fail(
                "k8s_pod_cpu_limit_pressure",
                "cloudwatch.get_metric_data",
                "Container Insights returned no CPU-limit series; absence was not treated as zero.",
            )
        if include_memory and int(series_by_kind.get("memory") or 0) == 0:
            context.fail(
                "k8s_pod_memory_pressure",
                "cloudwatch.get_metric_data",
                "Container Insights returned no memory-limit series; absence was not treated as zero.",
            )


def _mark_historical_metrics_synthetic(snapshot: JSON) -> None:
    metrics = snapshot.get("metrics") or {}
    for value in (metrics.get("workloads") or {}).values():
        if isinstance(value, dict):
            value["metric_source"] = "synthetic_historical_validation"


def _evaluate_clusters(
    context: EvaluationContext,
    clusters: Sequence[JSON],
    findings: List[Finding],
    region: str,
) -> None:
    version_rule = context.rule("eks_version_support_risk")
    version_support: Dict[str, JSON] = {}
    if version_rule:
        try:
            response = (
                context.read("eks_version_support_risk", "eks.describe_cluster_versions") or {}
            )
            version_support = {
                str(item.get("clusterVersion") or ""): item
                for item in response.get("clusterVersions") or []
                if isinstance(item, dict)
            }
        except AwsProviderError as exc:  # pragma: no cover - context translates normal providers
            context.fail("eks_version_support_risk", "eks.describe_cluster_versions", str(exc))

    for cluster in clusters:
        name = str(cluster.get("name") or "unknown")
        resource = f"eks://cluster/{name}"
        ref = _eks_ref("aws.eks.cluster", name, region, cluster.get("arn"))
        vpc = cluster.get("resourcesVpcConfig") or {}
        public_enabled = bool(vpc.get("endpointPublicAccess"))
        private_enabled = bool(vpc.get("endpointPrivateAccess"))
        cidrs = [str(value) for value in vpc.get("publicAccessCidrs") or []]
        open_cidrs = sorted(set(cidrs) & {"0.0.0.0/0", "::/0"})

        rule = context.rule("eks_public_endpoint_open")
        if rule and public_enabled and open_cidrs:
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "endpoint_public_access": public_enabled,
                        "endpoint_private_access": private_enabled,
                        "public_access_cidrs": cidrs,
                        "unrestricted_cidrs": open_cidrs,
                    },
                    "Restrict endpoint access only after validating an alternative administration path.",
                )
            )

        rule = context.rule("eks_private_endpoint_disabled")
        if rule and public_enabled and not private_enabled:
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "endpoint_public_access": public_enabled,
                        "endpoint_private_access": private_enabled,
                        "public_access_cidrs": cidrs,
                    },
                    "Confirm private network reachability before enabling private-only access.",
                )
            )

        rule = context.rule("eks_control_plane_logging_incomplete")
        if rule:
            enabled = _enabled_cluster_log_types(cluster.get("logging") or {})
            required = set(rule.parameters.get("required_log_types") or ())
            missing = sorted(required - enabled)
            if missing:
                findings.append(
                    _eks_finding(
                        rule,
                        resource,
                        ref,
                        {
                            "enabled_log_types": sorted(enabled),
                            "missing_log_types": missing,
                            "security_critical_logs_missing": sorted(
                                set(missing) & {"audit", "authenticator"}
                            ),
                        },
                        "Re-read the cluster logging configuration and confirm all reviewed types are enabled.",
                    )
                )

        if version_rule:
            version = str(cluster.get("version") or "")
            support = version_support.get(version) or {}
            risk = _version_risk(support, version_rule)
            if risk:
                findings.append(
                    _eks_finding(
                        version_rule,
                        resource,
                        ref,
                        {
                            "cluster_version": version,
                            "support_status": support.get("versionStatus") or support.get("status"),
                            "end_of_standard_support": _iso(
                                support.get("endOfStandardSupportDate")
                            ),
                            "end_of_extended_support": _iso(
                                support.get("endOfExtendedSupportDate")
                            ),
                            **risk,
                        },
                        "Re-read version support and verify cluster, add-on, node, and workload compatibility.",
                    )
                )


def _evaluate_guardduty(
    context: EvaluationContext,
    clusters: Sequence[JSON],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("eks_guardduty_runtime_monitoring_disabled")
    if not rule or not clusters:
        return
    response = (
        context.read("eks_guardduty_runtime_monitoring_disabled", "guardduty.list_detectors") or {}
    )
    detector_ids = list(response.get("DetectorIds") or [])
    enabled = False
    feature_evidence: List[JSON] = []
    for detector_id in detector_ids:
        detail = (
            context.read(
                "eks_guardduty_runtime_monitoring_disabled",
                "guardduty.get_detector",
                DetectorId=detector_id,
            )
            or {}
        )
        for feature in detail.get("Features") or []:
            name = str(feature.get("Name") or "")
            if name in {"EKS_RUNTIME_MONITORING", "RUNTIME_MONITORING"}:
                status = str(feature.get("Status") or "")
                feature_evidence.append({"name": name, "status": status})
                enabled = enabled or status == "ENABLED"
    if enabled:
        return
    detector_id = str(detector_ids[0]) if detector_ids else "not-configured"
    findings.append(
        _eks_finding(
            rule,
            f"guardduty://{region}/eks-runtime-monitoring",
            _eks_ref("aws.guardduty.detector", detector_id, region, None),
            {
                "detector_count": len(detector_ids),
                "runtime_monitoring_features": feature_evidence,
                "runtime_monitoring_enabled": False,
                "regional_control": True,
                "clusters_in_scope": sorted(str(item.get("name") or "") for item in clusters),
            },
            "Re-read the regional GuardDuty detector and confirm runtime monitoring is enabled.",
        )
    )


def _collect_nodegroups(context: EvaluationContext, clusters: Sequence[JSON]) -> List[JSON]:
    active = [name for name in AWS_NODEGROUP_DETECTORS if context.rule(name)]
    if not active:
        return []
    nodegroups: List[JSON] = []
    for cluster in clusters:
        cluster_name = str(cluster.get("name") or "")
        response = context.read(active, "eks.list_nodegroups", clusterName=cluster_name) or {}
        for name in response.get("nodegroups") or []:
            detail = (
                context.read(
                    active,
                    "eks.describe_nodegroup",
                    clusterName=cluster_name,
                    nodegroupName=name,
                )
                or {}
            )
            nodegroup = detail.get("nodegroup")
            if isinstance(nodegroup, dict):
                nodegroups.append(nodegroup)
    return nodegroups


def _evaluate_nodegroups(
    context: EvaluationContext,
    clusters: Sequence[JSON],
    nodegroups: Sequence[JSON],
    findings: List[Finding],
    resource_skips: List[JSON],
    region: str,
) -> None:
    cluster_versions = {
        str(cluster.get("name") or ""): str(cluster.get("version") or "") for cluster in clusters
    }
    for nodegroup in nodegroups:
        cluster_name = str(nodegroup.get("clusterName") or "")
        name = str(nodegroup.get("nodegroupName") or "unknown")
        resource = f"eks://cluster/{cluster_name}/nodegroup/{name}"
        ref = _eks_ref("aws.eks.nodegroup", name, region, nodegroup.get("nodegroupArn"))
        version = str(nodegroup.get("version") or "")
        cluster_version = cluster_versions.get(cluster_name, "")

        rule = context.rule("eks_nodegroup_version_skew")
        if rule and _minor_version(version) != _minor_version(cluster_version):
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "cluster_name": cluster_name,
                        "cluster_version": cluster_version,
                        "nodegroup_version": version,
                        "minor_version_skew": _version_distance(cluster_version, version),
                    },
                    "Confirm node versions align with the cluster after a reviewed rolling update.",
                )
            )

        rule = context.rule("eks_nodegroup_health_degraded")
        issues = list((nodegroup.get("health") or {}).get("issues") or [])
        if rule and issues:
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "cluster_name": cluster_name,
                        "status": nodegroup.get("status"),
                        "health_issues": [
                            {
                                "code": item.get("code"),
                                "message": item.get("message"),
                                "resource_ids": list(item.get("resourceIds") or []),
                            }
                            for item in issues
                        ],
                    },
                    "Confirm AWS health issues and affected Kubernetes nodes are resolved.",
                )
            )

        rule = context.rule("eks_nodegroup_ami_outdated")
        if not rule:
            continue
        ami_type = str(nodegroup.get("amiType") or "")
        if ami_type == "CUSTOM":
            resource_skips.append(
                {
                    "resource": resource,
                    "rule": rule.short_id,
                    "reason": "custom_ami_requires_provenance_review",
                }
            )
            continue
        current_release = str(nodegroup.get("releaseVersion") or "")
        latest_release = str(nodegroup.get("latestReleaseVersion") or "")
        if not latest_release:
            parameter_name = _ami_parameter_name(version, ami_type)
            if parameter_name:
                response = (
                    context.read(
                        "eks_nodegroup_ami_outdated",
                        "ssm.get_parameter",
                        Name=parameter_name,
                    )
                    or {}
                )
                latest_release = str((response.get("Parameter") or {}).get("Value") or "")
        if current_release and latest_release and current_release != latest_release:
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "cluster_name": cluster_name,
                        "ami_type": ami_type,
                        "current_release_version": current_release,
                        "recommended_release_version": latest_release,
                        "custom_ami": False,
                    },
                    "Confirm nodes report the reviewed AMI release after a safe rolling update.",
                )
            )


def _collect_addons(context: EvaluationContext, clusters: Sequence[JSON]) -> List[JSON]:
    active = [name for name in AWS_ADDON_DETECTORS if context.rule(name)]
    if not active:
        return []
    addons: List[JSON] = []
    for cluster in clusters:
        cluster_name = str(cluster.get("name") or "")
        response = context.read(active, "eks.list_addons", clusterName=cluster_name) or {}
        for name in response.get("addons") or []:
            detail = (
                context.read(
                    active,
                    "eks.describe_addon",
                    clusterName=cluster_name,
                    addonName=name,
                )
                or {}
            )
            addon = detail.get("addon")
            if isinstance(addon, dict):
                addon["_cluster_version"] = cluster.get("version")
                addons.append(addon)
    return addons


def _evaluate_addons(
    context: EvaluationContext,
    clusters: Sequence[JSON],
    addons: Sequence[JSON],
    findings: List[Finding],
    region: str,
) -> None:
    del clusters
    for addon in addons:
        cluster_name = str(addon.get("clusterName") or "")
        name = str(addon.get("addonName") or "unknown")
        resource = f"eks://cluster/{cluster_name}/addon/{name}"
        ref = _eks_ref("aws.eks.addon", name, region, addon.get("addonArn"))
        status = str(addon.get("status") or "")
        issues = list((addon.get("health") or {}).get("issues") or [])

        rule = context.rule("eks_managed_addon_unhealthy")
        if rule and (
            status in {"DEGRADED", "CREATE_FAILED", "UPDATE_FAILED", "DELETE_FAILED"} or issues
        ):
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "cluster_name": cluster_name,
                        "addon_name": name,
                        "addon_version": addon.get("addonVersion"),
                        "status": status,
                        "health_issues": issues,
                    },
                    "Confirm the managed add-on and its kube-system pods are healthy.",
                )
            )

        rule = context.rule("eks_managed_addon_update_available")
        if not rule:
            continue
        response = (
            context.read(
                "eks_managed_addon_update_available",
                "eks.describe_addon_versions",
                addonName=name,
                kubernetesVersion=str(addon.get("_cluster_version") or ""),
            )
            or {}
        )
        default_version = _default_addon_version(response)
        current_version = str(addon.get("addonVersion") or "")
        if default_version and current_version and default_version != current_version:
            findings.append(
                _eks_finding(
                    rule,
                    resource,
                    ref,
                    {
                        "cluster_name": cluster_name,
                        "addon_name": name,
                        "current_version": current_version,
                        "compatible_default_version": default_version,
                        "status": status,
                        "current_health_issues": issues,
                        "update_available_does_not_imply_unhealthy": True,
                    },
                    "Confirm the installed add-on is compatible and healthy after a reviewed update.",
                )
            )


def _evaluate_kubernetes(
    context: EvaluationContext,
    snapshot: JSON,
    findings: List[Finding],
    region: str,
) -> None:
    workloads = list(snapshot.get("workloads") or [])
    pods = list(snapshot.get("pods") or [])
    services = list(snapshot.get("services") or [])
    pdbs = list(snapshot.get("pod_disruption_budgets") or [])
    hpas = list(snapshot.get("horizontal_pod_autoscalers") or [])
    events = list(snapshot.get("events") or [])
    metrics = snapshot.get("metrics") or {}
    workload_by_pod = {_pod_key(pod): _owner_workload(pod, workloads) for pod in pods}

    for workload in workloads:
        if _resource_exempt(workload):
            continue
        resource = _k8s_resource(snapshot, workload)
        ref = _k8s_ref(snapshot, workload, region)
        containers = list(workload.get("containers") or [])
        base = _workload_context(workload, pods, services, pdbs, hpas, events)

        rule = context.rule("k8s_workload_missing_resource_requests")
        missing_requests = [
            {
                "container": container.get("name"),
                "missing": sorted({"cpu", "memory"} - set(container.get("requests") or {})),
            }
            for container in containers
            if {"cpu", "memory"} - set(container.get("requests") or {})
        ]
        if rule and missing_requests:
            findings.append(
                _k8s_finding(rule, resource, ref, base, {"containers": missing_requests}, snapshot)
            )

        rule = context.rule("k8s_workload_missing_memory_limit")
        missing_memory = [
            str(container.get("name") or "")
            for container in containers
            if not (container.get("limits") or {}).get("memory")
        ]
        if rule and missing_memory:
            findings.append(
                _k8s_finding(
                    rule,
                    resource,
                    ref,
                    base,
                    {"containers_missing_memory_limit": missing_memory},
                    snapshot,
                )
            )

        rule = context.rule("k8s_workload_missing_probes")
        missing_probes = [
            {
                "container": container.get("name"),
                "missing": [
                    name
                    for name in ("readiness_probe", "liveness_probe")
                    if not container.get(name)
                ],
            }
            for container in containers
            if not container.get("readiness_probe") or not container.get("liveness_probe")
        ]
        if rule and missing_probes:
            findings.append(
                _k8s_finding(rule, resource, ref, base, {"containers": missing_probes}, snapshot)
            )

        rule = context.rule("k8s_workload_disruption_unprotected")
        if rule and _requires_pdb(workload, services) and not _matching_pdbs(workload, pdbs):
            findings.append(
                _k8s_finding(
                    rule,
                    resource,
                    ref,
                    base,
                    {
                        "replicas": workload.get("replicas"),
                        "associated_service_count": len(_matching_services(workload, services)),
                        "matching_pdb_count": 0,
                    },
                    snapshot,
                )
            )

        rule = context.rule("k8s_workload_dangerous_privileges")
        dangerous = _dangerous_privileges(workload)
        if rule and dangerous:
            findings.append(
                _k8s_finding(
                    rule, resource, ref, base, {"dangerous_privileges": dangerous}, snapshot
                )
            )

        rule = context.rule("eks_workload_overprovisioned")
        workload_metrics = _metrics_for(metrics, "workloads", workload)
        if rule:
            overprovisioned = _overprovisioned_evidence(rule, workload, workload_metrics, hpas)
            if overprovisioned:
                findings.append(_k8s_finding(rule, resource, ref, base, overprovisioned, snapshot))

    for pod in pods:
        if _resource_exempt(pod):
            continue
        resource = _k8s_resource(snapshot, pod)
        ref = _k8s_ref(snapshot, pod, region)
        workload = workload_by_pod.get(_pod_key(pod))
        base = _pod_context(pod, workload, snapshot)

        rule = context.rule("k8s_pod_restart_loop")
        restart_evidence = _restart_evidence(rule, pod) if rule else None
        if rule and restart_evidence:
            findings.append(_k8s_finding(rule, resource, ref, base, restart_evidence, snapshot))

        rule = context.rule("k8s_pod_unschedulable")
        unschedulable = _unschedulable_evidence(rule, pod) if rule else None
        if rule and unschedulable:
            findings.append(_k8s_finding(rule, resource, ref, base, unschedulable, snapshot))

        pod_metrics = _metrics_for(metrics, "pods", pod)
        rule = context.rule("k8s_pod_cpu_limit_pressure")
        cpu_pressure = _pressure_evidence(rule, pod, pod_metrics, "cpu") if rule else None
        if rule and cpu_pressure:
            findings.append(_k8s_finding(rule, resource, ref, base, cpu_pressure, snapshot))

        rule = context.rule("k8s_pod_memory_pressure")
        memory_pressure = _memory_pressure_evidence(rule, pod, pod_metrics) if rule else None
        if rule and memory_pressure:
            findings.append(_k8s_finding(rule, resource, ref, base, memory_pressure, snapshot))


def _k8s_finding(
    rule: Rule,
    resource: str,
    ref: ResourceRef,
    context: JSON,
    evidence: JSON,
    snapshot: JSON,
) -> Finding:
    return finding_from_rule(
        rule,
        resource,
        {
            **evidence,
            "cluster_context": snapshot.get("context"),
            "inside_cluster_context": context,
            "kubernetes_read_operations": snapshot.get("read_operations") or [],
            "kubernetes_write_operations": int(snapshot.get("write_operations") or 0),
            "sensitive_fields_read": snapshot.get("sensitive_fields_read") or [],
            "environment_values_redacted": True,
        },
        [
            "Review the observed state, application requirements, dependencies, and rollout safety.",
            "Generate and validate an IaC patch before requesting approval for any change.",
        ],
        "Repeat the focused assessment and confirm the finding is gone while the workload remains Ready.",
        resource_ref=ref,
        evidence_source="kubernetes_api",
    )


def _eks_finding(
    rule: Rule,
    resource: str,
    ref: ResourceRef,
    evidence: JSON,
    verification: str,
) -> Finding:
    return finding_from_rule(
        rule,
        resource,
        evidence,
        [
            "Investigate cluster reachability, workload health, dependencies, and disruption risk.",
            "Generate a reviewed IaC or configuration patch; do not mutate the live cluster automatically.",
        ],
        verification,
        resource_ref=ref,
    )


def _attach_cluster_correlations(
    findings: Iterable[Finding],
    clusters: Sequence[JSON],
    nodegroups: Sequence[JSON],
    addons: Sequence[JSON],
    snapshot: JSON,
) -> None:
    cluster_map = snapshot.get("fixture_map") or {}
    context_name = str(snapshot.get("context") or "")
    configured_clusters = cluster_map.get("clusters") or {}
    nodes = list(snapshot.get("nodes") or [])
    workloads = list(snapshot.get("workloads") or [])
    pods = list(snapshot.get("pods") or [])
    pdbs = list(snapshot.get("pod_disruption_budgets") or [])
    for finding in findings:
        if not finding.resource.startswith(("eks://", "guardduty://")):
            continue
        cluster_name = _cluster_name_from_resource(finding.resource)
        if finding.resource.startswith("guardduty://"):
            cluster_name = str((finding.evidence.get("clusters_in_scope") or [""])[0])
        mapping = configured_clusters.get(cluster_name) or {}
        mapped_context = str(mapping.get("context") or context_name)
        if mapped_context and context_name and mapped_context != context_name:
            finding.evidence["inside_cluster_reachable"] = False
            finding.evidence["inside_cluster_uncertainty"] = (
                "Mapped Kubernetes context is not active."
            )
            continue
        nodegroup_name = _nodegroup_name_from_resource(finding.resource)
        selected_nodes = [
            node for node in nodes if not nodegroup_name or node.get("node_group") == nodegroup_name
        ]
        node_names = {node.get("name") for node in selected_nodes}
        selected_pods = [
            pod for pod in pods if not nodegroup_name or pod.get("node_name") in node_names
        ]
        selected_workloads = [
            workload
            for workload in workloads
            if not nodegroup_name
            or any(
                _labels_match(workload.get("selector") or {}, pod.get("labels") or {})
                for pod in selected_pods
            )
        ]
        addon_name = _addon_name_from_resource(finding.resource)
        if addon_name:
            selected_pods = [
                pod
                for pod in pods
                if pod.get("namespace") == "kube-system"
                and addon_name.replace("vpc-cni", "aws-node") in str(pod.get("name") or "")
            ]
        finding.evidence["inside_cluster_reachable"] = True
        finding.evidence["inside_cluster_context"] = {
            "context": context_name,
            "cluster_name": cluster_name,
            "nodes_observed": len(selected_nodes),
            "workloads_observed": len(selected_workloads),
            "pods_observed": len(selected_pods),
            "ready_pods": sum(1 for pod in selected_pods if _pod_ready(pod)),
            "pdbs_observed": len(pdbs),
            "affected_nodes": [node.get("name") for node in selected_nodes[:20]],
            "affected_workloads": [
                f"{item.get('namespace')}/{item.get('kind')}/{item.get('name')}"
                for item in selected_workloads[:20]
            ],
            "affected_pods": [
                f"{item.get('namespace')}/{item.get('name')}" for item in selected_pods[:20]
            ],
        }
        finding.evidence["kubernetes_read_operations"] = snapshot.get("read_operations") or []
        finding.evidence["kubernetes_write_operations"] = int(snapshot.get("write_operations") or 0)
        finding.evidence["sensitive_fields_read"] = snapshot.get("sensitive_fields_read") or []


def _workload_context(
    workload: JSON,
    pods: Sequence[JSON],
    services: Sequence[JSON],
    pdbs: Sequence[JSON],
    hpas: Sequence[JSON],
    events: Sequence[JSON],
) -> JSON:
    selected_pods = [
        pod
        for pod in pods
        if pod.get("namespace") == workload.get("namespace")
        and _labels_match(workload.get("selector") or {}, pod.get("labels") or {})
    ]
    return {
        "workload": {
            "namespace": workload.get("namespace"),
            "kind": workload.get("kind"),
            "name": workload.get("name"),
            "replicas": workload.get("replicas"),
            "available_replicas": workload.get("available_replicas"),
            "ready_replicas": workload.get("ready_replicas"),
            "containers": workload.get("containers"),
        },
        "pods": [_minimal_pod(pod) for pod in selected_pods[:20]],
        "services": _matching_services(workload, services),
        "pod_disruption_budgets": _matching_pdbs(workload, pdbs),
        "horizontal_pod_autoscalers": _matching_hpas(workload, hpas),
        "events": _events_for(events, workload, selected_pods),
        "environment_values_redacted": True,
    }


def _pod_context(pod: JSON, workload: Optional[JSON], snapshot: JSON) -> JSON:
    events = [
        event
        for event in snapshot.get("events") or []
        if (event.get("involved_object") or {}).get("uid") == pod.get("uid")
        or (
            (event.get("involved_object") or {}).get("namespace") == pod.get("namespace")
            and (event.get("involved_object") or {}).get("name") == pod.get("name")
        )
    ]
    return {
        "pod": _minimal_pod(pod),
        "workload": (
            {
                "namespace": workload.get("namespace"),
                "kind": workload.get("kind"),
                "name": workload.get("name"),
                "replicas": workload.get("replicas"),
            }
            if workload
            else None
        ),
        "node": next(
            (
                node
                for node in snapshot.get("nodes") or []
                if node.get("name") == pod.get("node_name")
            ),
            None,
        ),
        "events": events[-20:],
        "environment_values_redacted": True,
    }


def _minimal_pod(pod: JSON) -> JSON:
    return {
        "namespace": pod.get("namespace"),
        "name": pod.get("name"),
        "phase": pod.get("phase"),
        "node_name": pod.get("node_name"),
        "conditions": pod.get("conditions"),
        "container_statuses": pod.get("container_statuses"),
        "containers": pod.get("containers"),
        "environment_values_redacted": True,
    }


def _restart_evidence(rule: Rule, pod: JSON) -> Optional[JSON]:
    minimum = int(rule.parameters.get("minimum_recent_restarts") or 5)
    affected: List[JSON] = []
    for status in pod.get("container_statuses") or []:
        waiting = status.get("waiting") or {}
        last = status.get("last_terminated") or {}
        restart_count = int(status.get("restart_count") or 0)
        if waiting.get("reason") == "CrashLoopBackOff" or restart_count >= minimum:
            affected.append(
                {
                    "container": status.get("name"),
                    "waiting_reason": waiting.get("reason"),
                    "waiting_message": waiting.get("message"),
                    "restart_count": restart_count,
                    "last_termination": last,
                    "restart_window_confirmed": waiting.get("reason") == "CrashLoopBackOff",
                }
            )
    return {"affected_containers": affected} if affected else None


def _unschedulable_evidence(rule: Rule, pod: JSON) -> Optional[JSON]:
    minimum = int(rule.parameters.get("minimum_unschedulable_minutes") or 5)
    for condition in pod.get("conditions") or []:
        if (
            condition.get("type") == "PodScheduled"
            and condition.get("status") == "False"
            and condition.get("reason") == "Unschedulable"
        ):
            age = _age_minutes(condition.get("last_transition_time"))
            if age is None or age < minimum:
                return None
            return {
                "condition": condition,
                "unschedulable_minutes": round(age, 1),
                "node_selector": pod.get("node_selector") or {},
                "requests": {
                    str(container.get("name") or ""): container.get("requests") or {}
                    for container in pod.get("containers") or []
                },
                "scheduler_reason_required_for_root_cause": True,
            }
    return None


def _pressure_evidence(rule: Rule, pod: JSON, metrics: JSON, kind: str) -> Optional[JSON]:
    threshold = float(rule.parameters.get("threshold_percent") or 80.0)
    periods = int(rule.parameters.get("periods") or 6)
    minimum = int(rule.parameters.get("minimum_breach_periods") or 5)
    values = [float(value) for value in metrics.get(f"{kind}_limit_percent") or []]
    if len(values) < periods:
        return None
    recent = values[-periods:]
    breaches = sum(1 for value in recent if value >= threshold)
    if breaches < minimum:
        return None
    return {
        "metric": f"{kind}_usage_as_percent_of_limit",
        "datapoints": recent,
        "datapoint_count": len(recent),
        "breach_count": breaches,
        "threshold_percent": threshold,
        "p95_percent": round(_percentile(recent, 0.95), 2),
        "throttling_confirmed": False if kind == "cpu" else None,
        "absence_of_metrics_interpreted_as_zero": False,
        "hpa": metrics.get("hpa"),
    }


def _memory_pressure_evidence(rule: Rule, pod: JSON, metrics: JSON) -> Optional[JSON]:
    oom = [
        {
            "container": status.get("name"),
            "last_termination": status.get("last_terminated"),
            "restart_count": status.get("restart_count"),
        }
        for status in pod.get("container_statuses") or []
        if (status.get("last_terminated") or {}).get("reason") == "OOMKilled"
    ]
    metric = _pressure_evidence(rule, pod, metrics, "memory")
    if not oom and not metric:
        return None
    return {
        "oom_killed_containers": oom,
        "memory_metric_evidence": metric,
        "node_memory_pressure": metrics.get("node_memory_pressure"),
        "absence_of_metrics_interpreted_as_zero": False,
    }


def _overprovisioned_evidence(
    rule: Rule,
    workload: JSON,
    metrics: JSON,
    hpas: Sequence[JSON],
) -> Optional[JSON]:
    lookback = float(metrics.get("lookback_days") or 0)
    completeness = float(metrics.get("completeness_percent") or 0)
    if lookback < float(rule.parameters.get("lookback_days") or 14):
        return None
    if completeness < float(rule.parameters.get("minimum_completeness_percent") or 70):
        return None
    matching_hpas = _matching_hpas(workload, hpas)
    if any(
        int(item.get("desired_replicas") or 0) >= int(item.get("max_replicas") or 1)
        for item in matching_hpas
    ):
        return None
    safety_margin = float(rule.parameters.get("safety_margin") or 1.4)
    recommendations: List[JSON] = []
    for container in workload.get("containers") or []:
        name = str(container.get("name") or "")
        current = metrics.get("containers", {}).get(name) or {}
        cpu_p95 = _float_or_none(current.get("cpu_p95_millicores"))
        memory_p95 = _float_or_none(current.get("memory_p95_bytes"))
        cpu_request = _cpu_millicores((container.get("requests") or {}).get("cpu"))
        memory_request = _memory_bytes((container.get("requests") or {}).get("memory"))
        proposed_cpu = math.ceil(cpu_p95 * safety_margin) if cpu_p95 is not None else None
        proposed_memory = math.ceil(memory_p95 * safety_margin) if memory_p95 is not None else None
        if (
            proposed_cpu is not None and cpu_request is not None and proposed_cpu < cpu_request
        ) or (
            proposed_memory is not None
            and memory_request is not None
            and proposed_memory < memory_request
        ):
            recommendations.append(
                {
                    "container": name,
                    "current_cpu_request_millicores": cpu_request,
                    "cpu_p95_millicores": cpu_p95,
                    "reviewed_cpu_request_millicores": proposed_cpu,
                    "current_memory_request_bytes": memory_request,
                    "memory_p95_bytes": memory_p95,
                    "reviewed_memory_request_bytes": proposed_memory,
                }
            )
    if not recommendations:
        return None
    return {
        "lookback_days": lookback,
        "completeness_percent": completeness,
        "safety_margin": safety_margin,
        "container_recommendations": recommendations,
        "hpa_saturated": False,
        "estimated_monthly_savings_usd": metrics.get("estimated_monthly_savings_usd"),
        "savings_confidence": metrics.get("savings_confidence") or "unknown",
        "metric_source": metrics.get("metric_source") or "unknown",
        "absence_of_metrics_interpreted_as_zero": False,
    }


def _dangerous_privileges(workload: JSON) -> List[JSON]:
    results: List[JSON] = []
    if workload.get("host_network"):
        results.append({"scope": "pod", "field": "hostNetwork", "value": True})
    if workload.get("host_pid"):
        results.append({"scope": "pod", "field": "hostPID", "value": True})
    if workload.get("host_ipc"):
        results.append({"scope": "pod", "field": "hostIPC", "value": True})
    for volume in workload.get("host_path_volumes") or []:
        results.append({"scope": "pod", "field": "hostPath", "volume": volume})
    for container in workload.get("containers") or []:
        security = container.get("security_context") or {}
        if security.get("privileged"):
            results.append(
                {
                    "scope": "container",
                    "container": container.get("name"),
                    "field": "privileged",
                    "value": True,
                }
            )
        if security.get("allow_privilege_escalation") is True:
            results.append(
                {
                    "scope": "container",
                    "container": container.get("name"),
                    "field": "allowPrivilegeEscalation",
                    "value": True,
                }
            )
        dangerous_caps = sorted(
            set(security.get("capabilities_add") or []) & _DANGEROUS_CAPABILITIES
        )
        if dangerous_caps:
            results.append(
                {
                    "scope": "container",
                    "container": container.get("name"),
                    "field": "capabilities.add",
                    "values": dangerous_caps,
                }
            )
    return results


def _requires_pdb(workload: JSON, services: Sequence[JSON]) -> bool:
    replicas = int(workload.get("replicas") or 0)
    return (
        workload.get("kind") in {"Deployment", "StatefulSet"}
        and replicas >= 2
        and bool(_matching_services(workload, services))
    )


def _matching_services(workload: JSON, services: Sequence[JSON]) -> List[JSON]:
    return [
        {
            "namespace": item.get("namespace"),
            "name": item.get("name"),
            "type": item.get("type"),
            "ports": item.get("ports"),
        }
        for item in services
        if item.get("namespace") == workload.get("namespace")
        and _plain_selector_matches(item.get("selector") or {}, workload.get("pod_labels") or {})
    ]


def _matching_pdbs(workload: JSON, pdbs: Sequence[JSON]) -> List[JSON]:
    return [
        item
        for item in pdbs
        if item.get("namespace") == workload.get("namespace")
        and _labels_match(item.get("selector") or {}, workload.get("pod_labels") or {})
    ]


def _matching_hpas(workload: JSON, hpas: Sequence[JSON]) -> List[JSON]:
    return [
        item
        for item in hpas
        if item.get("namespace") == workload.get("namespace")
        and (item.get("target") or {}).get("kind") == workload.get("kind")
        and (item.get("target") or {}).get("name") == workload.get("name")
    ]


def _events_for(events: Sequence[JSON], workload: JSON, pods: Sequence[JSON]) -> List[JSON]:
    uids = {workload.get("uid"), *(pod.get("uid") for pod in pods)}
    return [item for item in events if (item.get("involved_object") or {}).get("uid") in uids][-20:]


def _owner_workload(pod: JSON, workloads: Sequence[JSON]) -> Optional[JSON]:
    labels = pod.get("labels") or {}
    candidates = [
        workload
        for workload in workloads
        if workload.get("namespace") == pod.get("namespace")
        and _labels_match(workload.get("selector") or {}, labels)
    ]
    return candidates[0] if len(candidates) == 1 else None


def _labels_match(selector: JSON, labels: Mapping[str, Any]) -> bool:
    match_labels = selector.get("match_labels") or {}
    if not _plain_selector_matches(match_labels, labels):
        return False
    for expression in selector.get("match_expressions") or []:
        key = str(expression.get("key") or "")
        values = {str(value) for value in expression.get("values") or []}
        actual = str(labels.get(key) or "")
        operator = expression.get("operator")
        if operator == "In" and actual not in values:
            return False
        if operator == "NotIn" and actual in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return bool(match_labels or selector.get("match_expressions"))


def _plain_selector_matches(selector: Mapping[str, Any], labels: Mapping[str, Any]) -> bool:
    return bool(selector) and all(
        str(labels.get(key)) == str(value) for key, value in selector.items()
    )


def _enabled_cluster_log_types(logging: JSON) -> set[str]:
    enabled: set[str] = set()
    for item in logging.get("clusterLogging") or []:
        if item.get("enabled"):
            enabled.update(str(value) for value in item.get("types") or [])
    return enabled


def _version_risk(support: JSON, rule: Rule) -> Optional[JSON]:
    status = str(support.get("versionStatus") or support.get("status") or "").upper()
    extended = "EXTENDED" in status
    support_end = support.get("endOfStandardSupportDate")
    days = _days_until(support_end)
    warning_days = int(rule.parameters.get("support_warning_days") or 90)
    if not extended and (days is None or days > warning_days):
        return None
    return {
        "extended_support": extended,
        "days_until_standard_support_end": days,
        "support_risk": "extended_support" if extended else "approaching_support_end",
    }


def _default_addon_version(response: JSON) -> str:
    for addon in response.get("addons") or []:
        for version in addon.get("addonVersions") or []:
            for compatibility in version.get("compatibilities") or []:
                if compatibility.get("defaultVersion") is True:
                    return str(version.get("addonVersion") or "")
    return ""


def _ami_parameter_name(version: str, ami_type: str) -> Optional[str]:
    normalized_ami_type = ami_type.upper()
    paths = {
        "AL2_X86_64": "amazon-linux-2",
        "AL2_X86_64_GPU": "amazon-linux-2-gpu",
        "AL2_ARM_64": "amazon-linux-2-arm64",
        "AL2023_X86_64_STANDARD": "amazon-linux-2023/x86_64/standard",
        "AL2023_ARM_64_STANDARD": "amazon-linux-2023/arm64/standard",
        "AL2023_X86_64_NVIDIA": "amazon-linux-2023/x86_64/nvidia",
        "AL2023_ARM_64_NVIDIA": "amazon-linux-2023/arm64/nvidia",
        "AL2023_X86_64_NEURON": "amazon-linux-2023/x86_64/neuron",
        "BOTTLEROCKET_X86_64": "bottlerocket/x86_64",
        "BOTTLEROCKET_ARM_64": "bottlerocket/arm64",
    }
    family = paths.get(normalized_ami_type)
    return (
        f"/aws/service/eks/optimized-ami/{version}/{family}/recommended/release_version"
        if family and version
        else None
    )


def _metrics_for(metrics: JSON, collection: str, resource: JSON) -> JSON:
    key = f"{resource.get('namespace')}/{resource.get('name')}"
    values = metrics.get(collection) or {}
    value = values.get(key) or {}
    if not value and collection == "pods":
        namespace = str(resource.get("namespace") or "")
        pod_name = str(resource.get("name") or "")
        for fixture_key, fixture_value in values.items():
            prefix = str(fixture_key)
            if prefix.endswith("-") and f"{namespace}/{pod_name}".startswith(prefix):
                value = fixture_value
                break
    return value if isinstance(value, dict) else {}


def _resource_exempt(resource: JSON) -> bool:
    if resource.get("namespace") in {"kube-system", "kube-public", "kube-node-lease"}:
        return True
    labels = resource.get("labels") or {}
    return str(labels.get("bluearch.io/steward-exempt") or "").lower() == "true"


def _eks_ref(resource_type: str, name: str, region: str, arn: Any) -> ResourceRef:
    return ResourceRef(
        "aws",
        "eks",
        resource_type,
        name,
        region=region,
        arn=str(arn) if arn else None,
        display_name=name,
    )


def _k8s_ref(snapshot: JSON, resource: JSON, region: str) -> ResourceRef:
    resource_id = f"{resource.get('namespace')}/{resource.get('kind')}/{resource.get('name')}"
    return ResourceRef(
        "kubernetes",
        "eks",
        f"kubernetes.{str(resource.get('kind') or '').lower()}",
        resource_id,
        region=region,
        display_name=str(resource.get("name") or ""),
    )


def _k8s_resource(snapshot: JSON, resource: JSON) -> str:
    context = str(snapshot.get("context") or "current")
    return f"k8s://{context}/{resource.get('namespace')}/{str(resource.get('kind') or '').lower()}/{resource.get('name')}"


def _pod_key(pod: JSON) -> str:
    return f"{pod.get('namespace')}/{pod.get('name')}"


def _cluster_name_from_resource(resource: str) -> str:
    parts = resource.split("/")
    return parts[3] if len(parts) > 3 else ""


def _nodegroup_name_from_resource(resource: str) -> str:
    match = re.search(r"/nodegroup/([^/]+)$", resource)
    return match.group(1) if match else ""


def _addon_name_from_resource(resource: str) -> str:
    match = re.search(r"/addon/([^/]+)$", resource)
    return match.group(1) if match else ""


def _pod_ready(pod: JSON) -> bool:
    return any(
        item.get("type") == "Ready" and item.get("status") == "True"
        for item in pod.get("conditions") or []
    )


def _minor_version(value: str) -> tuple[int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)", value)
    return (int(match.group(1)), int(match.group(2))) if match else None


def _version_distance(left: str, right: str) -> Optional[int]:
    left_value = _minor_version(left)
    right_value = _minor_version(right)
    if not left_value or not right_value or left_value[0] != right_value[0]:
        return None
    return left_value[1] - right_value[1]


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    formatter = getattr(value, "isoformat", None)
    return str(formatter() if callable(formatter) else value).replace("+00:00", "Z")


def _days_until(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (parsed - datetime.now(timezone.utc)).days


def _age_minutes(value: Any) -> Optional[float]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - parsed).total_seconds() / 60.0)


def _percentile(values: Sequence[float], percentile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    index = (len(ordered) - 1) * percentile
    lower = math.floor(index)
    upper = math.ceil(index)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (index - lower)


def _cpu_millicores(value: Any) -> Optional[float]:
    if value is None:
        return None
    text = str(value)
    if text.endswith("m"):
        return float(text[:-1])
    if text.endswith("n"):
        return float(text[:-1]) / 1_000_000
    return float(text) * 1000


def _memory_bytes(value: Any) -> Optional[float]:
    if value is None:
        return None
    text = str(value)
    match = re.match(r"^([0-9.]+)([KMGTE]i?|m)?$", text)
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2) or ""
    factors = {
        "": 1,
        "K": 1e3,
        "M": 1e6,
        "G": 1e9,
        "T": 1e12,
        "E": 1e15,
        "Ki": 2**10,
        "Mi": 2**20,
        "Gi": 2**30,
        "Ti": 2**40,
        "Ei": 2**50,
        "m": 0.001,
    }
    return number * factors[unit]


def _float_or_none(value: Any) -> Optional[float]:
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
