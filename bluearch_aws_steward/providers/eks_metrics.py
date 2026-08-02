from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Tuple

from bluearch_aws_steward.providers.base import AwsProvider
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSignalQuery

JSON = Dict[str, Any]

CONTAINER_INSIGHTS_NAMESPACE = "ContainerInsights"


def collect_eks_pod_metrics(
    provider: AwsProvider,
    snapshot: Mapping[str, Any],
    *,
    cluster_name: str,
    include_cpu: bool,
    include_memory: bool,
) -> Tuple[JSON, JSON]:
    """Read bounded EKS pod metric series without treating absent data as zero."""

    queries: List[MetricSignalQuery] = []
    key_map: Dict[str, Tuple[str, str]] = {}
    pods = list(snapshot.get("pods") or [])
    workloads = list(snapshot.get("workloads") or [])
    for pod in pods:
        namespace = str(pod.get("namespace") or "")
        pod_name = str(pod.get("name") or "")
        if not namespace or not pod_name:
            continue
        workload_name = _workload_name(pod, workloads) or pod_name
        dimensions = (
            ("ClusterName", cluster_name),
            ("Namespace", namespace),
            ("PodName", workload_name),
        )
        if include_cpu:
            key = f"cpu:{namespace}/{pod_name}"
            queries.append(
                MetricSignalQuery(
                    key=key,
                    namespace=CONTAINER_INSIGHTS_NAMESPACE,
                    metric_name="pod_cpu_utilization_over_pod_limit",
                    dimensions=dimensions,
                    statistic="Average",
                    lookback_days=1,
                    period_seconds=60,
                )
            )
            key_map[key] = (f"{namespace}/{pod_name}", "cpu_limit_percent")
        if include_memory:
            key = f"memory:{namespace}/{pod_name}"
            queries.append(
                MetricSignalQuery(
                    key=key,
                    namespace=CONTAINER_INSIGHTS_NAMESPACE,
                    metric_name="pod_memory_utilization_over_pod_limit",
                    dimensions=dimensions,
                    statistic="Average",
                    lookback_days=1,
                    period_seconds=60,
                )
            )
            key_map[key] = (f"{namespace}/{pod_name}", "memory_limit_percent")

    returned = CloudWatchSignalAdapter(provider).read(queries)
    metrics: JSON = {"pods": {}}
    series_returned = 0
    series_by_kind = {"cpu": 0, "memory": 0}
    missing: List[str] = []
    for key, (resource_key, field) in key_map.items():
        series = returned[key]
        if not series.values:
            missing.append(key)
            continue
        series_returned += 1
        series_by_kind[key.split(":", 1)[0]] += 1
        target = metrics["pods"].setdefault(resource_key, {})
        target[field] = list(series.values)
        target[f"{field}_timestamps"] = list(series.timestamps)
        target["metric_source"] = "cloudwatch_container_insights"
        target["absence_of_metrics_interpreted_as_zero"] = False

    return metrics, {
        "source": "cloudwatch",
        "namespace": CONTAINER_INSIGHTS_NAMESPACE,
        "queries_requested": len(queries),
        "series_returned": series_returned,
        "series_by_kind": series_by_kind,
        "missing_series": sorted(missing),
        "absence_of_metrics_interpreted_as_zero": False,
    }


def merge_eks_metrics(base: Mapping[str, Any], live: Mapping[str, Any]) -> JSON:
    merged: JSON = {
        "pods": {
            str(key): dict(value)
            for key, value in (base.get("pods") or {}).items()
            if isinstance(value, Mapping)
        },
        "workloads": {
            str(key): dict(value)
            for key, value in (base.get("workloads") or {}).items()
            if isinstance(value, Mapping)
        },
    }
    for collection in ("pods", "workloads"):
        for key, value in (live.get(collection) or {}).items():
            if not isinstance(value, Mapping):
                continue
            merged[collection].setdefault(str(key), {}).update(dict(value))
    return merged


def _workload_name(pod: Mapping[str, Any], workloads: Iterable[Mapping[str, Any]]) -> str:
    namespace = str(pod.get("namespace") or "")
    labels = pod.get("labels") or {}
    for workload in workloads:
        if str(workload.get("namespace") or "") != namespace:
            continue
        selector = workload.get("selector") or {}
        if _labels_match(selector, labels):
            return str(workload.get("name") or "")
    return ""


def _labels_match(selector: Mapping[str, Any], labels: Mapping[str, Any]) -> bool:
    match_labels = selector.get("match_labels")
    match_expressions = selector.get("match_expressions")
    if match_labels is None and match_expressions is None:
        match_labels = selector
        match_expressions = ()
    if not match_labels and not match_expressions:
        return False
    if any(str(labels.get(key)) != str(value) for key, value in (match_labels or {}).items()):
        return False
    for expression in match_expressions or ():
        key = str(expression.get("key") or "")
        values = {str(value) for value in expression.get("values") or ()}
        actual = str(labels.get(key) or "")
        operator = str(expression.get("operator") or "")
        if operator == "In" and actual not in values:
            return False
        if operator == "NotIn" and actual in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True
