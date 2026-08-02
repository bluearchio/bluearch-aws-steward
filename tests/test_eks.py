from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Set
from unittest.mock import patch

from bluearch_aws_steward.detectors.eks import _ami_parameter_name, scan_eks
from bluearch_aws_steward.investigation import investigate_finding
from bluearch_aws_steward.providers.eks_metrics import collect_eks_pod_metrics
from bluearch_aws_steward.providers.operations import READ_OPERATIONS

JSON = Dict[str, Any]


def _load_aws_eks_live_module(filename: str) -> Any:
    module_path = Path(__file__).resolve().parent / "aws-eks-live" / "scripts" / filename
    spec = importlib.util.spec_from_file_location("aws_eks_live_" + module_path.stem, module_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"Unable to load {module_path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(module_path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class EksAwsLabLifecycleTests(unittest.TestCase):
    def test_restored_guardduty_state_is_not_reused(self) -> None:
        lifecycle = _load_aws_eks_live_module("aws_lifecycle.py")
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "guardduty-state.json"
            state_path.write_text(
                json.dumps({"detector_id": "stale", "restored": True}),
                encoding="utf-8",
            )
            self.assertIsNone(lifecycle._reusable_guardduty_state(state_path))

            state_path.write_text(
                json.dumps({"detector_id": "active", "restored": False}),
                encoding="utf-8",
            )
            self.assertEqual(
                lifecycle._reusable_guardduty_state(state_path),
                {"detector_id": "active", "restored": False},
            )

    def test_live_harness_reads_query_results_findings(self) -> None:
        e2e = _load_aws_eks_live_module("e2e_mcp.py")

        class FakeMcp:
            def __init__(self) -> None:
                self.calls = 0

            def call(self, tool: str, arguments: JSON) -> JSON:
                if tool != "bluearch_query_results" or arguments.get("page_size") != 200:
                    raise AssertionError({"tool": tool, "arguments": arguments})
                self.calls += 1
                if self.calls == 1:
                    return {
                        "findings": [{"finding_id": "first"}],
                        "next_cursor": "next",
                    }
                return {"findings": [{"finding_id": "second"}], "next_cursor": None}

        self.assertEqual(
            [item["finding_id"] for item in e2e._query_all(FakeMcp(), "assessment")],
            ["first", "second"],
        )


class EksFixtureAwsProvider:
    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def read(self, operation: str, **parameters: Any) -> JSON:
        handler = getattr(self, "_" + operation.replace(".", "_"), None)
        if handler is None:
            raise AssertionError(f"Unexpected operation: {operation} {parameters}")
        return handler(parameters)

    def _eks_list_clusters(self, _: JSON) -> JSON:
        return {"clusters": ["fixture-vulnerable"]}

    def _eks_describe_cluster(self, _: JSON) -> JSON:
        return {
            "cluster": {
                "name": "fixture-vulnerable",
                "arn": "arn:aws:eks:us-east-1:000000000000:cluster/fixture-vulnerable",
                "version": "1.30",
                "resourcesVpcConfig": {
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                    "publicAccessCidrs": ["0.0.0.0/0", "::/0"],
                },
                "logging": {"clusterLogging": [{"types": ["api", "scheduler"], "enabled": True}]},
            }
        }

    def _eks_describe_cluster_versions(self, _: JSON) -> JSON:
        return {
            "clusterVersions": [
                {
                    "clusterVersion": "1.30",
                    "versionStatus": "EXTENDED_SUPPORT",
                    "endOfStandardSupportDate": "2025-01-01T00:00:00Z",
                    "endOfExtendedSupportDate": "2026-01-01T00:00:00Z",
                }
            ]
        }

    def _guardduty_list_detectors(self, _: JSON) -> JSON:
        return {"DetectorIds": []}

    def _eks_list_nodegroups(self, _: JSON) -> JSON:
        return {"nodegroups": ["skew-ng", "old-ami-ng", "degraded-ng", "custom-ng"]}

    def _eks_describe_nodegroup(self, parameters: JSON) -> JSON:
        name = parameters["nodegroupName"]
        values = {
            "skew-ng": {
                "version": "1.28",
                "releaseVersion": "1.28.1-current",
                "latestReleaseVersion": "1.28.1-current",
                "amiType": "AL2_X86_64",
                "health": {"issues": []},
            },
            "old-ami-ng": {
                "version": "1.30",
                "releaseVersion": "1.30.0-old",
                "amiType": "AL2023_x86_64_STANDARD",
                "health": {"issues": []},
            },
            "degraded-ng": {
                "version": "1.30",
                "releaseVersion": "1.30.0-current",
                "latestReleaseVersion": "1.30.0-current",
                "amiType": "AL2_X86_64",
                "health": {
                    "issues": [
                        {
                            "code": "NodeCreationFailure",
                            "message": "Fixture health issue",
                            "resourceIds": ["i-fixture"],
                        }
                    ]
                },
            },
            "custom-ng": {
                "version": "1.30",
                "releaseVersion": "custom-1",
                "amiType": "CUSTOM",
                "health": {"issues": []},
            },
        }[name]
        return {
            "nodegroup": {
                "clusterName": "fixture-vulnerable",
                "nodegroupName": name,
                "nodegroupArn": f"arn:aws:eks:us-east-1:000000000000:nodegroup/fixture-vulnerable/{name}/fixture",
                "status": "DEGRADED" if name == "degraded-ng" else "ACTIVE",
                **values,
            }
        }

    def _ssm_get_parameter(self, parameters: JSON) -> JSON:
        expected = (
            "/aws/service/eks/optimized-ami/1.30/amazon-linux-2023/"
            "x86_64/standard/recommended/release_version"
        )
        if parameters["Name"] != expected:
            raise AssertionError({"expected": expected, "actual": parameters["Name"]})
        return {"Parameter": {"Value": "1.30.0-new"}}

    def _eks_list_addons(self, _: JSON) -> JSON:
        return {"addons": ["vpc-cni", "coredns", "kube-proxy"]}

    def _eks_describe_addon(self, parameters: JSON) -> JSON:
        name = parameters["addonName"]
        return {
            "addon": {
                "clusterName": "fixture-vulnerable",
                "addonName": name,
                "addonArn": f"arn:aws:eks:us-east-1:000000000000:addon/fixture-vulnerable/{name}/fixture",
                "addonVersion": "v1-old" if name == "coredns" else "v1-current",
                "status": "DEGRADED" if name == "vpc-cni" else "ACTIVE",
                "health": {
                    "issues": [{"code": "AddonIssue", "message": "Fixture"}]
                    if name == "vpc-cni"
                    else []
                },
            }
        }

    def _eks_describe_addon_versions(self, parameters: JSON) -> JSON:
        name = parameters["addonName"]
        version = "v1-new" if name == "coredns" else "v1-current"
        return {
            "addons": [
                {
                    "addonName": name,
                    "addonVersions": [
                        {
                            "addonVersion": version,
                            "compatibilities": [{"defaultVersion": True}],
                        }
                    ],
                }
            ]
        }


class StaticKubernetesProvider:
    def __init__(self, snapshot: JSON) -> None:
        self.value = snapshot

    def snapshot(self) -> JSON:
        return copy.deepcopy(self.value)


class EksRuleTests(unittest.TestCase):
    def test_explicit_cluster_name_avoids_account_wide_cluster_listing(self) -> None:
        operations = []

        class TargetedProvider(EksFixtureAwsProvider):
            def read(self, operation: str, **parameters: Any) -> JSON:
                operations.append((operation, parameters))
                if operation == "eks.list_clusters":
                    raise AssertionError("Explicit cluster scans must not list every cluster")
                if operation == "eks.describe_cluster":
                    return {
                        "cluster": {
                            "name": parameters["name"],
                            "version": "1.36",
                            "resourcesVpcConfig": {
                                "endpointPublicAccess": True,
                                "endpointPrivateAccess": True,
                                "publicAccessCidrs": ["10.0.0.0/8"],
                            },
                            "logging": {"clusterLogging": []},
                        }
                    }
                return super().read(operation, **parameters)

            def operations_executed(self) -> list[str]:
                return [operation for operation, _ in operations]

        result = scan_eks(
            TargetedProvider(),
            profile=None,
            endpoint_url=None,
            region="us-east-1",
            rule_filter="eks-public-endpoint-open",
            eks_cluster_name="selected-cluster",
        )

        self.assertEqual(result.findings, [])
        self.assertIn(
            ("eks.describe_cluster", {"name": "selected-cluster"}),
            operations,
        )
        self.assertNotIn("eks.list_clusters", [operation for operation, _ in operations])
        self.assertEqual(result.summary["aws_read_operations"], ["eks.describe_cluster"])

    def test_al2023_ami_parameter_uses_the_official_ssm_family(self) -> None:
        self.assertEqual(
            _ami_parameter_name("1.36", "AL2023_x86_64_STANDARD"),
            (
                "/aws/service/eks/optimized-ami/1.36/amazon-linux-2023/"
                "x86_64/standard/recommended/release_version"
            ),
        )

    def test_container_insights_queries_use_the_documented_pod_dimensions(self) -> None:
        class MetricProvider:
            def __init__(self) -> None:
                self.queries: list[JSON] = []

            def read(self, operation: str, **parameters: Any) -> JSON:
                self.assert_operation(operation)
                self.queries = parameters["MetricDataQueries"]
                return {
                    "MetricDataResults": [
                        {
                            "Id": query["Id"],
                            "StatusCode": "Complete",
                            "Values": [91, 92, 93, 94, 95, 96],
                            "Timestamps": ["2026-07-21T00:00:00Z"] * 6,
                        }
                        for query in self.queries
                    ]
                }

            def assert_operation(self, operation: str) -> None:
                if operation != "cloudwatch.get_metric_data":
                    raise AssertionError(operation)

        provider = MetricProvider()
        snapshot = {
            "pods": [
                {
                    "namespace": "bluearch-eks-lab",
                    "name": "cpu-pressure-api-abc123",
                    "labels": {"app": "cpu-pressure-api"},
                }
            ],
            "workloads": [
                {
                    "namespace": "bluearch-eks-lab",
                    "name": "cpu-pressure-api",
                    "selector": {
                        "match_labels": {"app": "cpu-pressure-api"},
                        "match_expressions": [],
                    },
                }
            ],
        }

        metrics, metadata = collect_eks_pod_metrics(
            provider,
            snapshot,
            cluster_name="selected-cluster",
            include_cpu=True,
            include_memory=True,
        )

        dimensions = provider.queries[0]["MetricStat"]["Metric"]["Dimensions"]
        self.assertEqual(
            dimensions,
            [
                {"Name": "ClusterName", "Value": "selected-cluster"},
                {"Name": "Namespace", "Value": "bluearch-eks-lab"},
                {"Name": "PodName", "Value": "cpu-pressure-api"},
            ],
        )
        self.assertEqual(metadata["series_by_kind"], {"cpu": 1, "memory": 1})
        self.assertFalse(metadata["absence_of_metrics_interpreted_as_zero"])
        self.assertIn("bluearch-eks-lab/cpu-pressure-api-abc123", metrics["pods"])

    def test_kubernetes_rules_require_an_explicit_context(self) -> None:
        with patch("bluearch_aws_steward.detectors.eks.KubernetesProvider") as provider:
            result = scan_eks(
                EksFixtureAwsProvider(),
                profile=None,
                endpoint_url=None,
                region="us-east-1",
                rule_filter="k8s-pod-unschedulable",
            )

        provider.assert_not_called()
        self.assertEqual(result.findings, [])
        self.assertEqual(result.summary["rules_evaluated"], 0)
        self.assertEqual(result.summary["kubernetes_read_operations"], [])
        self.assertEqual(result.summary["kubernetes_write_operations"], 0)
        self.assertEqual(
            result.summary["capability_errors"][0]["operation"],
            "kubernetes.context",
        )

    def test_all_twenty_rules_detect_only_vulnerable_fixtures(self) -> None:
        result = scan_eks(
            EksFixtureAwsProvider(),
            profile=None,
            endpoint_url="http://127.0.0.1:4566",
            region="us-east-1",
            kubernetes_provider=StaticKubernetesProvider(_snapshot()),
        )

        rules = {finding.rule_short_id for finding in result.findings}
        self.assertEqual(len(result.findings), 20)
        self.assertEqual(len(rules), 20)
        self.assertTrue(all("healthy" not in finding.resource for finding in result.findings))
        self.assertEqual(result.summary["rules_evaluated"], 20)
        self.assertEqual(result.summary["kubernetes_write_operations"], 0)
        self.assertEqual(result.summary["sensitive_fields_read"], [])
        self.assertEqual(
            result.summary["resource_skips"],
            [
                {
                    "resource": "eks://cluster/fixture-vulnerable/nodegroup/custom-ng",
                    "rule": "eks-nodegroup-ami-outdated",
                    "reason": "custom_ami_requires_provenance_review",
                }
            ],
        )

    def test_unschedulable_investigation_confirms_scheduler_constraint_only(self) -> None:
        result = scan_eks(
            EksFixtureAwsProvider(),
            profile=None,
            endpoint_url="http://127.0.0.1:4566",
            region="us-east-1",
            rule_filter="k8s-pod-unschedulable",
            kubernetes_provider=StaticKubernetesProvider(_snapshot()),
        )
        finding = result.findings[0].to_dict()
        dossier = investigate_finding(
            EksFixtureAwsProvider(),
            finding,
            aws_context={"region": "us-east-1", "provider": "aws-sdk"},
        )

        diagnosis = dossier["operational_diagnosis"]
        self.assertTrue(diagnosis["root_cause_confirmed"])
        self.assertEqual(diagnosis["root_cause_scope"], "scheduler_constraint")
        self.assertTrue(dossier["inside_cluster_evidence_collected"])
        self.assertEqual(dossier["kubernetes_reads_performed"], 11)
        self.assertFalse(dossier["write_actions_applied"])


def _snapshot() -> JSON:
    healthy = _workload("healthy-api")
    missing_requests = _workload("missing-requests-api")
    missing_requests["containers"][0]["requests"] = {}
    missing_memory = _workload("missing-memory-limit-api")
    missing_memory["containers"][0]["limits"].pop("memory")
    missing_probes = _workload("missing-probes-api")
    missing_probes["containers"][0]["readiness_probe"] = None
    missing_probes["containers"][0]["liveness_probe"] = None
    unprotected = _workload("unprotected-api", replicas=2)
    privileged = _workload("privileged-worker")
    privileged["containers"][0]["security_context"]["privileged"] = True
    overprovisioned = _workload("overprovisioned-api")
    runtime_workloads = [
        _workload("crashloop-api"),
        _workload("unschedulable-api"),
        _workload("cpu-pressure-api"),
        _workload("memory-pressure-api"),
        _workload("runtime-healthy-api"),
    ]
    workloads = [
        healthy,
        missing_requests,
        missing_memory,
        missing_probes,
        unprotected,
        privileged,
        overprovisioned,
        *runtime_workloads,
    ]
    old = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    pods = [_pod("healthy-api", ready=True)]
    pods.extend(
        [
            _pod("crashloop-api", waiting="CrashLoopBackOff", restarts=8, terminated="Error"),
            _pod(
                "unschedulable-api",
                phase="Pending",
                ready=False,
                scheduled=False,
                scheduled_at=old,
                scheduler_message="0/2 nodes are available: node selector did not match.",
            ),
            _pod("cpu-pressure-api"),
            _pod("memory-pressure-api", restarts=2, terminated="OOMKilled"),
            _pod("runtime-healthy-api"),
        ]
    )
    return {
        "context": "kind-bluearch-eks-lab",
        "namespaces": ["bluearch-eks-lab", "kube-system"],
        "nodes": [
            {
                "name": "fixture-worker",
                "node_group": "degraded-ng",
                "conditions": [{"type": "Ready", "status": "True"}],
                "labels": {"eks.amazonaws.com/nodegroup": "degraded-ng"},
            }
        ],
        "workloads": workloads,
        "pods": pods,
        "services": [
            _service("healthy-api"),
            _service("unprotected-api"),
            _service("missing-probes-api"),
        ],
        "events": [
            {
                "namespace": "bluearch-eks-lab",
                "reason": "FailedScheduling",
                "message": "0/2 nodes are available: node selector did not match.",
                "involved_object": {
                    "namespace": "bluearch-eks-lab",
                    "name": "unschedulable-api-pod",
                    "uid": "pod-unschedulable-api",
                },
            }
        ],
        "pod_disruption_budgets": [
            {
                "namespace": "bluearch-eks-lab",
                "name": "healthy-api",
                "selector": {"match_labels": {"app": "healthy-api"}, "match_expressions": []},
                "disruptions_allowed": 1,
            }
        ],
        "horizontal_pod_autoscalers": [],
        "ingresses": [],
        "metrics": {
            "pods": {
                "bluearch-eks-lab/cpu-pressure-api-pod": {
                    "cpu_limit_percent": [82, 84, 86, 88, 90, 92]
                },
                "bluearch-eks-lab/memory-pressure-api-pod": {
                    "memory_limit_percent": [91, 92, 93, 94, 95, 96]
                },
                "bluearch-eks-lab/runtime-healthy-api-pod": {
                    "cpu_limit_percent": [20, 25, 30, 35, 25, 20],
                    "memory_limit_percent": [30, 35, 40, 45, 40, 35],
                },
            },
            "workloads": {
                "bluearch-eks-lab/overprovisioned-api": {
                    "lookback_days": 14,
                    "completeness_percent": 100,
                    "estimated_monthly_savings_usd": 12.4,
                    "savings_confidence": "high",
                    "containers": {
                        "app": {
                            "cpu_p95_millicores": 50,
                            "memory_p95_bytes": 67108864,
                        }
                    },
                }
            },
        },
        "fixture_map": {"clusters": {"fixture-vulnerable": {"context": "kind-bluearch-eks-lab"}}},
        "read_operations": [
            "core.list_namespaces",
            "core.list_nodes",
            "apps.list_deployments",
            "apps.list_stateful_sets",
            "apps.list_daemon_sets",
            "core.list_pods",
            "core.list_services",
            "core.list_events",
            "policy.list_pod_disruption_budgets",
            "autoscaling.list_horizontal_pod_autoscalers",
            "networking.list_ingresses",
        ],
        "write_operations": 0,
        "sensitive_fields_read": [],
    }


def _workload(name: str, replicas: int = 1) -> JSON:
    return {
        "namespace": "bluearch-eks-lab",
        "name": name,
        "uid": f"workload-{name}",
        "kind": "Deployment",
        "labels": {},
        "pod_labels": {"app": name},
        "selector": {"match_labels": {"app": name}, "match_expressions": []},
        "replicas": replicas,
        "available_replicas": replicas,
        "ready_replicas": replicas,
        "host_network": False,
        "host_pid": False,
        "host_ipc": False,
        "host_path_volumes": [],
        "containers": [
            {
                "name": "app",
                "requests": {"cpu": "500m", "memory": "512Mi"},
                "limits": {"cpu": "1", "memory": "1Gi"},
                "readiness_probe": {"handler": "http_get", "port": 8080},
                "liveness_probe": {"handler": "http_get", "port": 8080},
                "security_context": {
                    "privileged": False,
                    "allow_privilege_escalation": False,
                    "capabilities_add": [],
                },
                "environment_values_redacted": True,
            }
        ],
    }


def _pod(
    workload: str,
    *,
    phase: str = "Running",
    ready: bool = True,
    scheduled: bool = True,
    scheduled_at: str | None = None,
    scheduler_message: str | None = None,
    waiting: str | None = None,
    restarts: int = 0,
    terminated: str | None = None,
) -> JSON:
    return {
        "namespace": "bluearch-eks-lab",
        "name": f"{workload}-pod",
        "uid": f"pod-{workload}",
        "kind": "Pod",
        "labels": {"app": workload},
        "phase": phase,
        "node_name": "fixture-worker" if scheduled else None,
        "node_selector": {"fixture": "missing"} if not scheduled else {},
        "conditions": [
            {"type": "Ready", "status": "True" if ready else "False"},
            {
                "type": "PodScheduled",
                "status": "True" if scheduled else "False",
                "reason": None if scheduled else "Unschedulable",
                "message": scheduler_message,
                "last_transition_time": scheduled_at,
            },
        ],
        "container_statuses": [
            {
                "name": "app",
                "ready": ready,
                "restart_count": restarts,
                "waiting": {"reason": waiting, "message": "fixture"} if waiting else None,
                "terminated": None,
                "last_terminated": (
                    {"reason": terminated, "exit_code": 137 if terminated == "OOMKilled" else 1}
                    if terminated
                    else None
                ),
            }
        ],
        "containers": _workload(workload)["containers"],
    }


def _service(name: str) -> JSON:
    return {
        "namespace": "bluearch-eks-lab",
        "name": name,
        "kind": "Service",
        "type": "ClusterIP",
        "selector": {"app": name},
        "ports": [{"port": 80, "target_port": "8080"}],
    }


if __name__ == "__main__":
    unittest.main()
