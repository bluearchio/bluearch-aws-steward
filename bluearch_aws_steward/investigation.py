from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, Mapping, Optional

from bluearch_aws_steward.detectors.aws_common import age_days, tags_dict
from bluearch_aws_steward.models import utc_now_iso
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.providers.operations import iam_action_for_operation

JSON = Dict[str, Any]

SUPPORTED_DELETION_RULES = {
    "ec2-unattached-ebs-volume",
    "ec2-unassociated-elastic-ip",
    "ecs-inactive-task-definition",
    "efs-inactive-unmounted",
    "lambda-unused-function",
    "rds-idle-instance",
}
SUPPORTED_OPERATIONAL_RULES = {
    "ecs-platform-version-outdated",
    "ecs-service-health-degraded",
    "ecs-unsafe-task-definition",
    "rds-high-cpu",
    "rds-low-cpu-rightsizing",
    "rds-publicly-accessible",
    "rds-read-heavy-no-replica",
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
    "eks-workload-overprovisioned",
    "k8s-workload-missing-resource-requests",
    "k8s-workload-missing-memory-limit",
    "k8s-workload-missing-probes",
    "k8s-workload-disruption-unprotected",
    "k8s-workload-dangerous-privileges",
    "k8s-pod-restart-loop",
    "k8s-pod-unschedulable",
    "k8s-pod-cpu-limit-pressure",
    "k8s-pod-memory-pressure",
}
SUPPORTED_INVESTIGATION_RULES = SUPPORTED_DELETION_RULES | SUPPORTED_OPERATIONAL_RULES

_BUSINESS_TAG_KEYS = {
    "application",
    "app",
    "business-unit",
    "business_unit",
    "cost-center",
    "cost_center",
    "environment",
    "env",
    "owner",
    "project",
    "service",
    "stage",
    "team",
}
_OWNER_TAG_KEYS = {"owner", "team", "application", "app", "service", "project"}
_ENVIRONMENT_TAG_KEYS = {"environment", "env", "stage"}
_PRODUCTION_VALUES = {"prod", "production", "live"}
_CONFIG_RESOURCE_TYPES = {
    "aws.ec2.volume": "AWS::EC2::Volume",
    "aws.ec2.elastic-ip": "AWS::EC2::EIP",
    "aws.efs.file-system": "AWS::EFS::FileSystem",
    "aws.lambda.function": "AWS::Lambda::Function",
    "aws.rds.db-instance": "AWS::RDS::DBInstance",
    "aws.dynamodb.table": "AWS::DynamoDB::Table",
    "aws.ecs.task-definition": "AWS::ECS::TaskDefinition",
    "aws.elbv2.load-balancer": "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "aws.s3.bucket": "AWS::S3::Bucket",
}


class _EvidenceReader:
    def __init__(self, client: AwsProvider) -> None:
        self.client = client
        self.operations: list[str] = []
        self.errors: list[JSON] = []

    def read(self, operation: str, **parameters: Any) -> Optional[JSON]:
        self.operations.append(operation)
        try:
            return self.client.read(operation, **parameters)
        except AwsProviderError as exc:
            self.errors.append(
                {
                    "operation": operation,
                    "iam_action": iam_action_for_operation(operation),
                    "reason": (exc.detail or str(exc))[:500],
                }
            )
            return None


def investigation_kind(rule: str) -> str:
    if rule in SUPPORTED_OPERATIONAL_RULES:
        return "operational_diagnosis"
    return "deletion_readiness"


def investigate_finding(
    client: AwsProvider,
    finding: JSON,
    *,
    aws_context: JSON,
    confirmations: Optional[JSON] = None,
) -> JSON:
    """Build the rule-specific read-only investigation supported by this finding."""

    rule = str(finding.get("rule_short_id") or finding.get("rule_id") or "")
    if rule in SUPPORTED_OPERATIONAL_RULES:
        return _investigate_operational_diagnosis(client, finding, aws_context=aws_context)
    return investigate_deletion_readiness(
        client,
        finding,
        aws_context=aws_context,
        confirmations=confirmations,
    )


def investigate_deletion_readiness(
    client: AwsProvider,
    finding: JSON,
    *,
    aws_context: JSON,
    confirmations: Optional[JSON] = None,
) -> JSON:
    """Build a read-only deletion dossier without declaring a resource safe to delete."""

    reader = _EvidenceReader(client)
    resource = str(finding.get("resource") or "")
    rule = str(finding.get("rule_short_id") or finding.get("rule_id") or "")
    resource_ref = _mapping(finding.get("resource_ref"))
    resource_id = str(resource_ref.get("resource_id") or _resource_id(resource))
    evidence = _mapping(finding.get("evidence"))
    direct = _direct_evidence(reader, rule, resource_id, evidence)
    config = _config_relationships(reader, resource_ref, resource_id)

    relationships = _deduplicate_relationships(
        [*(direct.get("relationships") or []), *(config.get("relationships") or [])]
    )
    tags = _selected_business_tags(direct.get("tags") or evidence.get("tags") or {})
    business_context = _business_context(tags)
    blockers = list(direct.get("blockers") or [])
    unknowns = list(direct.get("unknowns") or [])
    if config.get("relationships"):
        blockers.append(
            {
                "code": "aws_config_relationships_observed",
                "message": "AWS Config recorded one or more relationships for this resource.",
                "relationships": config["relationships"],
            }
        )
    if config.get("status") != "available":
        unknowns.append(
            {
                "code": "cross_service_graph_incomplete",
                "message": config.get("reason"),
                "confirmation_key": "iac_references_reviewed",
            }
        )
    if not business_context["owner_known"]:
        unknowns.append(
            {
                "code": "owner_not_identified",
                "message": "No supported ownership tag was observed on the resource.",
                "confirmation_key": "owner_approved",
            }
        )
    if business_context["production_indicated"]:
        unknowns.append(
            {
                "code": "production_context_requires_approval",
                "message": "Resource tags indicate a production environment.",
                "confirmation_key": "owner_approved",
            }
        )

    supplied_confirmations = {
        str(key): value is True for key, value in _mapping(confirmations).items()
    }
    unresolved_unknowns = [
        item
        for item in unknowns
        if not supplied_confirmations.get(str(item.get("confirmation_key") or ""), False)
    ]
    readiness = _readiness_status(
        rule=rule,
        direct_supported=bool(direct.get("supported")),
        blockers=blockers,
        unresolved_unknowns=unresolved_unknowns,
    )
    checks = [*(direct.get("checks") or []), config["check"]]
    coverage = _evidence_coverage(checks, reader.errors)
    blast_radius = _blast_radius(
        resource=resource,
        relationships=relationships,
        blockers=blockers,
        production_indicated=business_context["production_indicated"],
    )
    required_confirmations = _required_confirmations(unknowns, supplied_confirmations)
    recovery = direct.get("recovery") or _unknown_recovery()
    business_impact = _business_impact(
        rule=rule,
        finding=finding,
        business_context=business_context,
        blockers=blockers,
    )
    change_plan = _planning_only_change(
        rule=rule,
        resource_id=resource_id,
        blockers=blockers,
        required_confirmations=required_confirmations,
        recovery=recovery,
    )

    return {
        "schema_version": "0.1",
        "status": "completed",
        "investigation": "deletion_readiness",
        "resource": resource,
        "resource_ref": resource_ref or None,
        "rule": rule,
        "finding_id": finding.get("finding_id"),
        "observed_at": utc_now_iso(),
        "aws_context": {
            "account_id": aws_context.get("account_id"),
            "principal_arn": aws_context.get("principal_arn"),
            "profile": aws_context.get("profile"),
            "provider": aws_context.get("provider"),
            "region": aws_context.get("region"),
        },
        "read_only": True,
        "aws_reads_performed": len(reader.operations),
        "kubernetes_reads_performed": len(evidence.get("kubernetes_read_operations") or []),
        "inside_cluster_evidence_collected": bool(evidence.get("inside_cluster_context")),
        "sensitive_fields_read": evidence.get("sensitive_fields_read") or [],
        "write_actions_applied": False,
        "current_state": direct.get("current_state") or evidence,
        "relationships": relationships,
        "dependency_summary": {
            "observed_relationships": len(relationships),
            "blocking_relationships": len(blockers),
            "cross_service_graph": config.get("status"),
            "absence_of_observed_relationships_proves_no_dependency": False,
        },
        "business_context": business_context,
        "business_impact": business_impact,
        "recovery": recovery,
        "blast_radius": blast_radius,
        "evidence_checks": checks,
        "evidence_coverage": coverage,
        "confidence": _investigation_confidence(coverage, unresolved_unknowns),
        "capability_errors": reader.errors,
        "deletion_readiness": {
            "status": readiness,
            "safe_to_delete": False,
            "automatic_deletion_supported": False,
            "blockers": blockers,
            "unknowns": unknowns,
            "unresolved_unknowns": unresolved_unknowns,
            "user_confirmations": supplied_confirmations,
            "requires_explicit_approval": True,
            "explanation": _readiness_explanation(readiness),
        },
        "required_human_confirmations": required_confirmations,
        "change_plan_preview": change_plan,
        "post_change_verification": change_plan["post_change_verification"],
        "next_steps": _next_steps(readiness, blockers, unresolved_unknowns),
        "limitations": [
            "This dossier uses AWS control-plane metadata and does not inspect application traffic, source code, external DNS, customer allowlists, or business procedures unless explicitly represented by evidence.",
            "No dependency graph can prove a destructive change is safe; the result supports review and approval rather than replacing them.",
            "Deletion and release operations remain planning-only in Steward.",
        ],
    }


def _investigate_operational_diagnosis(
    client: AwsProvider,
    finding: JSON,
    *,
    aws_context: JSON,
) -> JSON:
    reader = _EvidenceReader(client)
    resource = str(finding.get("resource") or "")
    rule = str(finding.get("rule_short_id") or finding.get("rule_id") or "")
    resource_ref = _mapping(finding.get("resource_ref"))
    resource_id = str(resource_ref.get("resource_id") or _resource_id(resource))
    evidence = _mapping(finding.get("evidence"))
    direct = _operational_evidence(reader, rule, resource_id, evidence)
    config = _config_relationships(reader, resource_ref, resource_id)
    relationships = _deduplicate_relationships(
        [*(direct.get("relationships") or []), *(config.get("relationships") or [])]
    )
    tags = _selected_business_tags(direct.get("tags") or evidence.get("tags") or {})
    business_context = _business_context(tags)
    checks = [*(direct.get("checks") or []), config["check"]]
    coverage = _evidence_coverage(checks, reader.errors)
    unknowns = list(direct.get("unknowns") or [])
    if config.get("status") != "available":
        unknowns.append(
            {
                "code": "cross_service_graph_incomplete",
                "message": config.get("reason"),
            }
        )
    status = (
        "not_supported"
        if not direct.get("supported")
        else ("partial" if reader.errors or unknowns else "evidence_collected")
    )
    change_plan = direct.get("change_plan_preview") or _operational_change_plan(
        rule,
        resource_id,
    )
    return {
        "schema_version": "0.1",
        "status": "completed",
        "investigation": "operational_diagnosis",
        "resource": resource,
        "resource_ref": resource_ref or None,
        "rule": rule,
        "finding_id": finding.get("finding_id"),
        "observed_at": utc_now_iso(),
        "aws_context": {
            "account_id": aws_context.get("account_id"),
            "principal_arn": aws_context.get("principal_arn"),
            "profile": aws_context.get("profile"),
            "provider": aws_context.get("provider"),
            "region": aws_context.get("region"),
        },
        "read_only": True,
        "aws_reads_performed": len(reader.operations),
        "kubernetes_reads_performed": len(evidence.get("kubernetes_read_operations") or []),
        "inside_cluster_evidence_collected": bool(evidence.get("inside_cluster_context")),
        "sensitive_fields_read": evidence.get("sensitive_fields_read") or [],
        "write_actions_applied": False,
        "current_state": direct.get("current_state") or evidence,
        "relationships": relationships,
        "dependency_summary": {
            "observed_relationships": len(relationships),
            "cross_service_graph": config.get("status"),
            "absence_of_observed_relationships_proves_no_dependency": False,
        },
        "business_context": business_context,
        "business_impact": direct.get("business_impact")
        or {
            "category": "service_health",
            "potential_impact": "The selected condition may affect availability, performance, cost, or security.",
            "requires_business_owner_review": True,
        },
        "evidence_checks": checks,
        "evidence_coverage": coverage,
        "confidence": {
            "score": float(coverage.get("score") or 0.0),
            "scale": "0-100",
            "label": coverage.get("label") or "low",
            "basis": "completed read-only evidence checks",
            "meaning": "Confidence in evidence completeness, not certainty that a hypothesis is the root cause.",
        },
        "capability_errors": reader.errors,
        "operational_diagnosis": {
            "status": status,
            "root_cause_confirmed": bool(direct.get("root_cause_confirmed")),
            "root_cause_scope": direct.get("root_cause_scope") or "not_confirmed",
            "hypotheses": direct.get("hypotheses") or [],
            "unresolved_questions": unknowns,
            "requires_explicit_approval_before_change": True,
        },
        "recommended_actions": direct.get("recommended_actions") or [],
        "change_plan_preview": change_plan,
        "post_change_verification": change_plan["post_change_verification"],
        "next_steps": direct.get("recommended_actions") or [],
        "limitations": [
            "A configuration and control-plane investigation cannot prove application root cause by itself.",
            "Logs, traces, code, IaC, and workload-level signals are included only when a future playbook explicitly reads them.",
            "Every proposed change remains planning-only and requires explicit review and approval.",
        ],
    }


def _operational_evidence(
    reader: _EvidenceReader,
    rule: str,
    resource_id: str,
    evidence: JSON,
) -> JSON:
    if rule.startswith("rds-"):
        return _investigate_rds_operation(reader, rule, resource_id, evidence)
    if rule.startswith("ecs-"):
        return _investigate_ecs_operation(reader, rule, resource_id, evidence)
    if rule.startswith("eks-") or rule.startswith("k8s-"):
        return _investigate_eks_operation(rule, resource_id, evidence)
    return {
        "supported": False,
        "current_state": evidence,
        "relationships": [],
        "tags": evidence.get("tags") or {},
        "checks": [
            {
                "id": "service_specific_diagnosis",
                "status": "unavailable",
                "evidence": "No service-specific operational investigator is implemented for this rule.",
            }
        ],
        "unknowns": [
            {
                "code": "service_specific_investigator_missing",
                "message": "Steward cannot yet deepen this finding beyond its live rule evidence.",
            }
        ],
    }


def _investigate_eks_operation(rule: str, resource_id: str, evidence: JSON) -> JSON:
    inside = _mapping(evidence.get("inside_cluster_context"))
    kubernetes_reads = list(evidence.get("kubernetes_read_operations") or [])
    writes = int(evidence.get("kubernetes_write_operations") or 0)
    checks: list[JSON] = [
        {
            "id": "finding_live_revalidated",
            "status": "blocked",
            "evidence": {
                "rule": rule,
                "resource_id": resource_id,
                "finding_evidence_present": True,
            },
        },
        {
            "id": "inside_cluster_evidence",
            "status": "passed" if inside else "unavailable",
            "evidence": {
                "context": evidence.get("cluster_context") or inside.get("context"),
                "kubernetes_read_operations": kubernetes_reads,
                "write_operations": writes,
                "sensitive_fields_read": evidence.get("sensitive_fields_read") or [],
            },
        },
    ]
    root_cause_confirmed = False
    root_cause_scope = "not_confirmed"
    hypotheses: list[JSON] = []

    if rule == "k8s-pod-unschedulable":
        condition = _mapping(evidence.get("condition"))
        scheduler_message = str(condition.get("message") or "")
        root_cause_confirmed = bool(
            scheduler_message and condition.get("reason") == "Unschedulable"
        )
        root_cause_scope = "scheduler_constraint" if root_cause_confirmed else "not_confirmed"
        hypotheses.append(
            {
                "id": "scheduler_constraint",
                "status": "confirmed" if root_cause_confirmed else "supported",
                "confidence": "high" if root_cause_confirmed else "medium",
                "basis": scheduler_message
                or "The scheduler marked the pod unschedulable without a usable message.",
            }
        )
    elif rule == "k8s-pod-restart-loop":
        affected = list(evidence.get("affected_containers") or [])
        termination = next(
            (
                _mapping(item.get("last_termination"))
                for item in affected
                if _mapping(item.get("last_termination")).get("reason")
            ),
            {},
        )
        root_cause_confirmed = bool(termination.get("reason"))
        root_cause_scope = (
            "immediate_container_termination" if root_cause_confirmed else "not_confirmed"
        )
        hypotheses.extend(
            [
                {
                    "id": "container_process_termination",
                    "status": "confirmed" if root_cause_confirmed else "supported",
                    "confidence": "high" if root_cause_confirmed else "medium",
                    "basis": termination or affected,
                },
                {
                    "id": "application_level_trigger",
                    "status": "not_verified",
                    "confidence": "low",
                    "basis": "Logs, exec, Secret data, and source code were not read by the Kubernetes provider.",
                },
            ]
        )
    elif rule == "k8s-pod-memory-pressure":
        oom = list(evidence.get("oom_killed_containers") or [])
        root_cause_confirmed = bool(oom)
        root_cause_scope = "oom_termination" if oom else "not_confirmed"
        hypotheses.append(
            {
                "id": "container_memory_limit_exceeded",
                "status": "confirmed" if oom else "supported",
                "confidence": "high" if oom else "medium",
                "basis": oom or evidence.get("memory_metric_evidence"),
            }
        )
    elif rule == "k8s-pod-cpu-limit-pressure":
        hypotheses.extend(
            [
                {
                    "id": "cpu_limit_pressure",
                    "status": "supported",
                    "confidence": "medium",
                    "basis": {
                        "p95_percent": evidence.get("p95_percent"),
                        "breach_count": evidence.get("breach_count"),
                    },
                },
                {
                    "id": "cpu_throttling",
                    "status": "not_verified",
                    "confidence": "low",
                    "basis": "Utilization against a CPU limit does not prove throttling.",
                },
            ]
        )
    elif rule == "eks-workload-overprovisioned":
        hypotheses.append(
            {
                "id": "resource_requests_rightsizing_candidate",
                "status": "supported",
                "confidence": evidence.get("savings_confidence") or "medium",
                "basis": {
                    "lookback_days": evidence.get("lookback_days"),
                    "completeness_percent": evidence.get("completeness_percent"),
                    "safety_margin": evidence.get("safety_margin"),
                    "hpa_saturated": evidence.get("hpa_saturated"),
                },
            }
        )
    else:
        hypotheses.append(
            {
                "id": "observed_configuration_matches_rule",
                "status": "confirmed",
                "confidence": "high",
                "basis": "The focused read-only assessment reproduced the rule predicate.",
            }
        )

    unknowns = [
        {
            "code": "application_behavior_not_inspected",
            "message": "Steward did not read container logs, execute commands, inspect Secret data, or inspect source code.",
        },
        {
            "code": "iac_ownership_not_mapped",
            "message": "The owning Terraform, CloudFormation, eksctl, Helm, Kustomize, or Kubernetes source has not yet been selected.",
        },
    ]
    if not inside:
        unknowns.append(
            {
                "code": "inside_cluster_evidence_missing",
                "message": "The Kubernetes context was unavailable or not correlated to this finding.",
            }
        )
    return {
        "supported": True,
        "current_state": evidence,
        "relationships": _eks_relationships(inside),
        "tags": evidence.get("tags") or {},
        "checks": checks,
        "hypotheses": hypotheses,
        "root_cause_confirmed": root_cause_confirmed,
        "root_cause_scope": root_cause_scope,
        "unknowns": unknowns,
        "recommended_actions": [
            "Review confirmed evidence separately from supported and unverified hypotheses.",
            "Locate the owning IaC or manifest and generate the smallest planning-only patch.",
            "Validate the patch in a disposable cluster and repeat the focused assessment before requesting approval.",
        ],
        "business_impact": {
            "category": "kubernetes_platform_or_workload",
            "potential_impact": "An incorrect EKS or Kubernetes change can remove administrative access, reduce capacity, block scheduling, or disrupt application traffic.",
            "requires_business_owner_review": True,
        },
        "change_plan_preview": _operational_change_plan(rule, resource_id),
    }


def _eks_relationships(inside: JSON) -> list[JSON]:
    relationships: list[JSON] = []
    for node in inside.get("affected_nodes") or []:
        relationships.append(
            {
                "relationship_type": "contains_node",
                "resource_type": "kubernetes.node",
                "resource_id": node,
                "source": "kubernetes_api",
            }
        )
    for workload in inside.get("affected_workloads") or []:
        relationships.append(
            {
                "relationship_type": "runs_workload",
                "resource_type": "kubernetes.workload",
                "resource_id": workload,
                "source": "kubernetes_api",
            }
        )
    for pod in inside.get("affected_pods") or []:
        relationships.append(
            {
                "relationship_type": "contains_pod",
                "resource_type": "kubernetes.pod",
                "resource_id": pod,
                "source": "kubernetes_api",
            }
        )
    return relationships


def _direct_evidence(reader: _EvidenceReader, rule: str, resource_id: str, evidence: JSON) -> JSON:
    if rule == "ec2-unattached-ebs-volume":
        return _investigate_ebs(reader, resource_id)
    if rule == "ec2-unassociated-elastic-ip":
        return _investigate_elastic_ip(reader, resource_id)
    if rule == "ecs-inactive-task-definition":
        return _investigate_ecs_task_definition(reader, resource_id, evidence)
    if rule == "efs-inactive-unmounted":
        return _investigate_efs(reader, resource_id)
    if rule == "lambda-unused-function":
        return _investigate_lambda(reader, resource_id)
    if rule == "rds-idle-instance":
        return _investigate_rds_deletion(reader, resource_id)
    return {
        "supported": False,
        "current_state": evidence,
        "relationships": [],
        "tags": evidence.get("tags") or {},
        "checks": [
            {
                "id": "service_specific_dependencies",
                "status": "unavailable",
                "evidence": "No service-specific deletion investigator is implemented for this rule.",
            }
        ],
        "blockers": [],
        "unknowns": [
            {
                "code": "service_specific_investigator_missing",
                "message": "Steward cannot yet assess deletion dependencies for this rule.",
            }
        ],
    }


def _investigate_ebs(reader: _EvidenceReader, volume_id: str) -> JSON:
    payload = reader.read("ec2.describe_volumes", VolumeIds=[volume_id])
    volumes = list((payload or {}).get("Volumes") or [])
    volume = _mapping(volumes[0]) if volumes else {}
    attachments = [
        {
            "relationship_type": "attached_to",
            "resource_type": "aws.ec2.instance",
            "resource_id": item.get("InstanceId"),
            "device": item.get("Device"),
            "state": item.get("State"),
            "source": "ec2.describe_volumes",
        }
        for item in volume.get("Attachments") or []
        if isinstance(item, Mapping)
    ]
    snapshots_payload = reader.read(
        "ec2.describe_snapshots",
        OwnerIds=["self"],
        Filters=[{"Name": "volume-id", "Values": [volume_id]}],
    )
    snapshots = list((snapshots_payload or {}).get("Snapshots") or [])
    completed_snapshots = [item for item in snapshots if item.get("State") == "completed"]
    snapshot_times = [
        value
        for item in completed_snapshots
        if (value := _iso_value(item.get("StartTime"))) is not None
    ]
    newest = max(snapshot_times, default=None)
    blockers = []
    if attachments:
        blockers.append(
            {
                "code": "live_volume_attachment",
                "message": "The volume is attached to one or more EC2 instances.",
                "relationships": attachments,
            }
        )
    if volume and volume.get("State") != "available":
        blockers.append(
            {
                "code": "volume_not_available",
                "message": f"The current EBS state is {volume.get('State')!s}, not available.",
            }
        )
    unknowns = [
        {
            "code": "iac_and_application_references_not_observed",
            "message": "CloudFormation, Terraform, launch templates, scripts, and application references were not inspected.",
            "confirmation_key": "iac_references_reviewed",
        },
        {
            "code": "workload_owner_intent_not_observed",
            "message": "AWS metadata cannot prove that the volume is no longer reserved for recovery or a future workload.",
            "confirmation_key": "owner_approved",
        },
    ]
    if not completed_snapshots:
        unknowns.append(
            {
                "code": "recovery_point_not_observed",
                "message": "No completed snapshot was observed for this volume.",
                "confirmation_key": "backup_restore_reviewed",
            }
        )
    return {
        "supported": True,
        "current_state": {
            "volume_id": volume_id,
            "exists": bool(volume),
            "state": volume.get("State"),
            "size_gib": volume.get("Size"),
            "volume_type": volume.get("VolumeType"),
            "availability_zone": volume.get("AvailabilityZone"),
            "encrypted": volume.get("Encrypted"),
            "created_at": _iso_value(volume.get("CreateTime")),
            "attachment_count": len(attachments),
        },
        "relationships": attachments,
        "tags": tags_dict(volume.get("Tags") or []),
        "checks": [
            {
                "id": "live_volume_attachments",
                "status": "blocked" if attachments else ("passed" if volume else "unavailable"),
                "evidence": {"attachment_count": len(attachments)},
            },
            {
                "id": "completed_recovery_snapshot",
                "status": "passed" if completed_snapshots else "unknown",
                "evidence": {
                    "completed_snapshot_count": len(completed_snapshots),
                    "newest_snapshot_at": _iso_value(newest),
                    "newest_snapshot_age_days": age_days(newest),
                },
            },
        ],
        "blockers": blockers,
        "unknowns": unknowns,
        "recovery": {
            "status": "partially_prepared" if completed_snapshots else "not_observed",
            "completed_snapshot_count": len(completed_snapshots),
            "newest_snapshot_at": _iso_value(newest),
            "guidance": "A snapshot can recreate data in a new volume, but it does not preserve the original volume ID, attachments, mount configuration, or application state.",
        },
    }


def _investigate_elastic_ip(reader: _EvidenceReader, allocation_id: str) -> JSON:
    payload = reader.read("ec2.describe_addresses", AllocationIds=[allocation_id])
    addresses = list((payload or {}).get("Addresses") or [])
    address = _mapping(addresses[0]) if addresses else {}
    public_ip = str(address.get("PublicIp") or "")
    relationships = []
    for field, resource_type in (
        ("InstanceId", "aws.ec2.instance"),
        ("NetworkInterfaceId", "aws.ec2.network-interface"),
        ("AssociationId", "aws.ec2.elastic-ip-association"),
    ):
        if address.get(field):
            relationships.append(
                {
                    "relationship_type": "associated_with",
                    "resource_type": resource_type,
                    "resource_id": address[field],
                    "source": "ec2.describe_addresses",
                }
            )
    dns_relationships, dns_check = _route53_references(reader, public_ip)
    relationships.extend(dns_relationships)
    blockers = []
    if relationships:
        blockers.append(
            {
                "code": "observed_elastic_ip_dependency",
                "message": "The address has an AWS association or Route 53 reference.",
                "relationships": relationships,
            }
        )
    unknowns = [
        {
            "code": "external_references_not_observed",
            "message": "External DNS, customer allowlists, partner integrations, documentation, and recovery procedures cannot be discovered from this account alone.",
            "confirmation_key": "external_dependencies_reviewed",
        },
        {
            "code": "release_is_not_reversible",
            "message": "AWS does not guarantee that a released public IPv4 address can be reacquired.",
            "confirmation_key": "change_window_confirmed",
        },
        {
            "code": "iac_references_not_observed",
            "message": "IaC and deployment references were not inspected.",
            "confirmation_key": "iac_references_reviewed",
        },
    ]
    return {
        "supported": True,
        "current_state": {
            "allocation_id": allocation_id,
            "exists": bool(address),
            "public_ip": public_ip or None,
            "domain": address.get("Domain"),
            "association_id": address.get("AssociationId"),
            "instance_id": address.get("InstanceId"),
            "network_interface_id": address.get("NetworkInterfaceId"),
        },
        "relationships": relationships,
        "tags": tags_dict(address.get("Tags") or []),
        "checks": [
            {
                "id": "live_elastic_ip_association",
                "status": "blocked"
                if any(
                    address.get(key)
                    for key in ("AssociationId", "InstanceId", "NetworkInterfaceId")
                )
                else ("passed" if address else "unavailable"),
                "evidence": {"association_count": len(relationships) - len(dns_relationships)},
            },
            dns_check,
        ],
        "blockers": blockers,
        "unknowns": unknowns,
        "recovery": {
            "status": "not_guaranteed",
            "guidance": "Preserve the allocation until every external dependency is reviewed; releasing the address may permanently lose it.",
        },
    }


def _investigate_ecs_task_definition(
    reader: _EvidenceReader,
    task_definition_id: str,
    evidence: JSON,
) -> JSON:
    target = str(evidence.get("task_definition_arn") or task_definition_id)
    detail = reader.read(
        "ecs.describe_task_definition",
        taskDefinition=target,
        include=["TAGS"],
    )
    task_definition = _mapping((detail or {}).get("taskDefinition"))
    target_arn = str(task_definition.get("taskDefinitionArn") or target)
    relationships: list[JSON] = []
    cluster_payload = reader.read("ecs.list_clusters")
    clusters = list((cluster_payload or {}).get("clusterArns") or [])
    services_scanned = 0
    for cluster_arn in clusters:
        service_payload = reader.read("ecs.list_services", cluster=cluster_arn)
        service_arns = list((service_payload or {}).get("serviceArns") or [])
        services_scanned += len(service_arns)
        for batch in _batches(service_arns, 10):
            service_details = reader.read(
                "ecs.describe_services",
                cluster=cluster_arn,
                services=batch,
            )
            for service in (service_details or {}).get("services") or []:
                referenced = {str(service.get("taskDefinition") or "")}
                referenced.update(
                    str(deployment.get("taskDefinition") or "")
                    for deployment in service.get("deployments") or []
                    if isinstance(deployment, Mapping)
                )
                if target_arn not in referenced:
                    continue
                relationships.append(
                    {
                        "relationship_type": "referenced_by_ecs_service",
                        "resource_type": "aws.ecs.service",
                        "resource_id": service.get("serviceName"),
                        "cluster_arn": cluster_arn,
                        "service_arn": service.get("serviceArn"),
                        "source": "ecs.describe_services",
                    }
                )
    blockers = []
    if relationships:
        blockers.append(
            {
                "code": "ecs_service_reference_observed",
                "message": "One or more ECS services still reference this task-definition revision.",
                "relationships": relationships,
            }
        )
    if task_definition and task_definition.get("status") != "INACTIVE":
        blockers.append(
            {
                "code": "task_definition_not_inactive",
                "message": "The task definition is not currently INACTIVE.",
            }
        )
    container_count = len(task_definition.get("containerDefinitions") or [])
    return {
        "supported": True,
        "current_state": {
            "exists": bool(task_definition),
            "task_definition_arn": target_arn or None,
            "family": task_definition.get("family"),
            "revision": task_definition.get("revision"),
            "status": task_definition.get("status"),
            "container_count": container_count,
            "environment_values_redacted": True,
        },
        "relationships": relationships,
        "tags": (detail or {}).get("tags") or [],
        "checks": [
            {
                "id": "ecs_service_references",
                "status": "blocked" if relationships else "passed",
                "evidence": {
                    "clusters_scanned": len(clusters),
                    "services_scanned": services_scanned,
                    "matching_services": len(relationships),
                },
            },
            {
                "id": "task_definition_status",
                "status": (
                    "passed"
                    if task_definition.get("status") == "INACTIVE"
                    else ("blocked" if task_definition else "unavailable")
                ),
                "evidence": {"status": task_definition.get("status")},
            },
        ],
        "blockers": blockers,
        "unknowns": [
            {
                "code": "deployment_and_rollback_references_not_observed",
                "message": "Deployment pipelines, rollback runbooks, scheduled tasks, and IaC references were not inspected.",
                "confirmation_key": "iac_references_reviewed",
            },
            {
                "code": "task_definition_owner_intent_not_observed",
                "message": "AWS metadata cannot prove that this revision is no longer retained for rollback.",
                "confirmation_key": "owner_approved",
            },
        ],
        "recovery": {
            "status": "source_definition_required",
            "guidance": (
                "Deleting an inactive revision cannot reactivate it. Preserve the reviewed task "
                "definition in IaC or a secure export so a new revision can be registered."
            ),
        },
    }


def _investigate_efs(reader: _EvidenceReader, file_system_id: str) -> JSON:
    payload = reader.read("efs.describe_file_systems", FileSystemId=file_system_id)
    file_systems = list((payload or {}).get("FileSystems") or [])
    file_system = _mapping(file_systems[0]) if file_systems else {}
    mounts_payload = reader.read("efs.describe_mount_targets", FileSystemId=file_system_id)
    mounts = list((mounts_payload or {}).get("MountTargets") or [])
    access_payload = reader.read("efs.describe_access_points", FileSystemId=file_system_id)
    access_points = list((access_payload or {}).get("AccessPoints") or [])
    recovery_payload = None
    if file_system.get("FileSystemArn"):
        recovery_payload = reader.read(
            "backup.list_recovery_points_by_resource",
            ResourceArn=file_system["FileSystemArn"],
        )
    recovery_points = list((recovery_payload or {}).get("RecoveryPoints") or [])
    relationships = [
        {
            "relationship_type": "has_mount_target",
            "resource_type": "aws.efs.mount-target",
            "resource_id": item.get("MountTargetId"),
            "subnet_id": item.get("SubnetId"),
            "vpc_id": item.get("VpcId"),
            "source": "efs.describe_mount_targets",
        }
        for item in mounts
    ]
    relationships.extend(
        {
            "relationship_type": "has_access_point",
            "resource_type": "aws.efs.access-point",
            "resource_id": item.get("AccessPointId"),
            "source": "efs.describe_access_points",
        }
        for item in access_points
    )
    blockers = []
    if relationships:
        blockers.append(
            {
                "code": "efs_consumption_path_observed",
                "message": "The file system still has mount targets or access points.",
                "relationships": relationships,
            }
        )
    unknowns = [
        {
            "code": "efs_client_and_iac_references_not_observed",
            "message": "Client fstab entries, DNS usage, container mounts, application configuration, and IaC references were not inspected.",
            "confirmation_key": "iac_references_reviewed",
        },
        {
            "code": "efs_owner_intent_not_observed",
            "message": "AWS metadata cannot prove the data is no longer needed for recovery or future workloads.",
            "confirmation_key": "owner_approved",
        },
    ]
    if not recovery_points:
        unknowns.append(
            {
                "code": "efs_recovery_point_not_observed",
                "message": "No AWS Backup recovery point was observed for this file system.",
                "confirmation_key": "backup_restore_reviewed",
            }
        )
    return {
        "supported": True,
        "current_state": {
            "exists": bool(file_system),
            "file_system_id": file_system_id,
            "life_cycle_state": file_system.get("LifeCycleState"),
            "size_bytes": _mapping(file_system.get("SizeInBytes")).get("Value"),
            "encrypted": file_system.get("Encrypted"),
            "mount_target_count": len(mounts),
            "access_point_count": len(access_points),
        },
        "relationships": relationships,
        "tags": file_system.get("Tags") or [],
        "checks": [
            {
                "id": "efs_mount_targets",
                "status": "blocked" if mounts else "passed",
                "evidence": {"mount_target_count": len(mounts)},
            },
            {
                "id": "efs_access_points",
                "status": "blocked" if access_points else "passed",
                "evidence": {"access_point_count": len(access_points)},
            },
            {
                "id": "efs_backup_recovery_points",
                "status": "passed" if recovery_points else "unknown",
                "evidence": {"recovery_point_count": len(recovery_points)},
            },
        ],
        "blockers": blockers,
        "unknowns": unknowns,
        "recovery": {
            "status": "recovery_point_observed" if recovery_points else "not_observed",
            "recovery_point_count": len(recovery_points),
            "guidance": (
                "A recovery point can restore data to a new file system but does not preserve "
                "mount targets, access points, DNS behavior, or client configuration."
            ),
        },
    }


def _investigate_lambda(reader: _EvidenceReader, function_name: str) -> JSON:
    configuration = reader.read(
        "lambda.get_function_configuration",
        FunctionName=function_name,
    )
    configuration = configuration or {}
    function_arn = str(configuration.get("FunctionArn") or "")
    mappings_payload = reader.read(
        "lambda.list_event_source_mappings",
        FunctionName=function_name,
    )
    mappings = list((mappings_payload or {}).get("EventSourceMappings") or [])
    urls_payload = reader.read("lambda.list_function_url_configs", FunctionName=function_name)
    function_urls = list((urls_payload or {}).get("FunctionUrlConfigs") or [])
    aliases_payload = reader.read("lambda.list_aliases", FunctionName=function_name)
    aliases = list((aliases_payload or {}).get("Aliases") or [])
    versions_payload = reader.read("lambda.list_versions_by_function", FunctionName=function_name)
    versions = list((versions_payload or {}).get("Versions") or [])
    event_rules_payload = (
        reader.read("events.list_rule_names_by_target", TargetArn=function_arn)
        if function_arn
        else None
    )
    event_rules = list((event_rules_payload or {}).get("RuleNames") or [])
    policy_payload = reader.read("lambda.get_policy", FunctionName=function_name)
    policy_relationships = _lambda_policy_relationships((policy_payload or {}).get("Policy"))
    tags_payload = reader.read("lambda.list_tags", Resource=function_arn) if function_arn else None

    relationships = [
        {
            "relationship_type": "invoked_by_event_source_mapping",
            "resource_type": "aws.event-source",
            "resource_id": item.get("EventSourceArn") or item.get("SelfManagedEventSource"),
            "mapping_uuid": item.get("UUID"),
            "state": item.get("State"),
            "source": "lambda.list_event_source_mappings",
        }
        for item in mappings
    ]
    relationships.extend(
        {
            "relationship_type": "invoked_by_eventbridge_rule",
            "resource_type": "aws.events.rule",
            "resource_id": name,
            "source": "events.list_rule_names_by_target",
        }
        for name in event_rules
    )
    relationships.extend(policy_relationships)
    relationships.extend(
        {
            "relationship_type": "exposed_by_function_url",
            "resource_type": "aws.lambda.function-url",
            "resource_id": item.get("FunctionUrl"),
            "auth_type": item.get("AuthType"),
            "source": "lambda.list_function_url_configs",
        }
        for item in function_urls
    )
    relationships.extend(
        {
            "relationship_type": "addressed_by_alias",
            "resource_type": "aws.lambda.alias",
            "resource_id": item.get("Name"),
            "function_version": item.get("FunctionVersion"),
            "source": "lambda.list_aliases",
        }
        for item in aliases
    )
    blockers = []
    if relationships:
        blockers.append(
            {
                "code": "lambda_invocation_or_alias_reference_observed",
                "message": "The function has one or more observed invocation paths, URLs, policies, or aliases.",
                "relationships": relationships,
            }
        )
    unknowns = [
        {
            "code": "lambda_direct_invocations_not_observed",
            "message": "SDK callers, Step Functions, API configuration, deployment scripts, and cross-account invocation paths may not be visible from these APIs.",
            "confirmation_key": "external_dependencies_reviewed",
        },
        {
            "code": "lambda_iac_references_not_observed",
            "message": "SAM, Serverless Framework, Terraform, CloudFormation, CDK, and application references were not inspected.",
            "confirmation_key": "iac_references_reviewed",
        },
        {
            "code": "lambda_owner_intent_not_observed",
            "message": "AWS metadata cannot prove that the function is no longer retained for recovery or periodic use.",
            "confirmation_key": "owner_approved",
        },
        {
            "code": "lambda_code_archive_not_verified",
            "message": "Steward did not download function code or verify a restorable source artifact.",
            "confirmation_key": "backup_restore_reviewed",
        },
    ]
    return {
        "supported": True,
        "current_state": {
            "exists": bool(configuration),
            "function_name": function_name,
            "runtime": configuration.get("Runtime"),
            "state": configuration.get("State"),
            "last_modified": configuration.get("LastModified"),
            "timeout_seconds": configuration.get("Timeout"),
            "memory_mb": configuration.get("MemorySize"),
            "environment_variable_count": len(
                _mapping(_mapping(configuration.get("Environment")).get("Variables"))
            ),
            "environment_values_redacted": True,
        },
        "relationships": relationships,
        "tags": (tags_payload or {}).get("Tags") or {},
        "checks": [
            {
                "id": "lambda_invocation_paths",
                "status": "blocked" if relationships else "passed",
                "evidence": {
                    "event_source_mappings": len(mappings),
                    "eventbridge_rules": len(event_rules),
                    "function_urls": len(function_urls),
                    "resource_policy_references": len(policy_relationships),
                    "aliases": len(aliases),
                },
            },
            {
                "id": "lambda_recovery_versions",
                "status": "passed" if len(versions) > 1 else "unknown",
                "evidence": {"published_version_count": max(0, len(versions) - 1)},
            },
        ],
        "blockers": blockers,
        "unknowns": unknowns,
        "recovery": {
            "status": "configuration_only",
            "published_version_count": max(0, len(versions) - 1),
            "guidance": (
                "Published versions do not replace a source-code and deployment-configuration "
                "archive. Preserve code, layers, environment references, permissions, and IaC."
            ),
        },
    }


def _investigate_rds_deletion(reader: _EvidenceReader, identifier: str) -> JSON:
    payload = reader.read("rds.describe_db_instances", DBInstanceIdentifier=identifier)
    instances = list((payload or {}).get("DBInstances") or [])
    instance = _mapping(instances[0]) if instances else {}
    snapshots_payload = reader.read(
        "rds.describe_db_snapshots",
        DBInstanceIdentifier=identifier,
    )
    snapshots = list((snapshots_payload or {}).get("DBSnapshots") or [])
    available_snapshots = [
        item for item in snapshots if str(item.get("Status") or "").lower() == "available"
    ]
    snapshot_times = [
        value
        for item in available_snapshots
        if (value := _iso_value(item.get("SnapshotCreateTime"))) is not None
    ]
    newest_snapshot = max(snapshot_times, default=None)
    endpoint = _mapping(instance.get("Endpoint"))
    dns_relationships, dns_check = _route53_references(
        reader,
        str(endpoint.get("Address") or ""),
    )

    relationships: list[JSON] = list(dns_relationships)
    for replica in instance.get("ReadReplicaDBInstanceIdentifiers") or []:
        relationships.append(
            {
                "relationship_type": "source_for_read_replica",
                "resource_type": "aws.rds.db-instance",
                "resource_id": replica,
                "source": "rds.describe_db_instances",
            }
        )
    if instance.get("ReadReplicaSourceDBInstanceIdentifier"):
        relationships.append(
            {
                "relationship_type": "replica_of",
                "resource_type": "aws.rds.db-instance",
                "resource_id": instance["ReadReplicaSourceDBInstanceIdentifier"],
                "source": "rds.describe_db_instances",
            }
        )
    if instance.get("DBClusterIdentifier"):
        relationships.append(
            {
                "relationship_type": "member_of_db_cluster",
                "resource_type": "aws.rds.db-cluster",
                "resource_id": instance["DBClusterIdentifier"],
                "source": "rds.describe_db_instances",
            }
        )

    blockers: list[JSON] = []
    if instance.get("DeletionProtection") is True:
        blockers.append(
            {
                "code": "rds_deletion_protection_enabled",
                "message": "RDS deletion protection is enabled for this DB instance.",
            }
        )
    database_relationships = [
        item
        for item in relationships
        if item.get("relationship_type")
        in {"source_for_read_replica", "replica_of", "member_of_db_cluster"}
    ]
    if database_relationships:
        blockers.append(
            {
                "code": "rds_database_relationship_observed",
                "message": "The DB instance participates in a replica or cluster relationship.",
                "relationships": database_relationships,
            }
        )
    if dns_relationships:
        blockers.append(
            {
                "code": "rds_dns_reference_observed",
                "message": "A Route 53 record references the current RDS endpoint.",
                "relationships": dns_relationships,
            }
        )
    status = str(instance.get("DBInstanceStatus") or "")
    if instance and status != "available":
        blockers.append(
            {
                "code": "rds_instance_not_available",
                "message": f"The current RDS state is {status!r}, not available.",
            }
        )

    unknowns = [
        {
            "code": "rds_application_connections_not_observed",
            "message": "Connection pools, secrets, jobs, analytics tools, and direct clients are not fully discoverable from RDS metadata.",
            "confirmation_key": "external_dependencies_reviewed",
        },
        {
            "code": "rds_iac_references_not_observed",
            "message": "Terraform, CloudFormation, CDK, deployment scripts, and restoration automation were not inspected.",
            "confirmation_key": "iac_references_reviewed",
        },
        {
            "code": "rds_owner_intent_not_observed",
            "message": "An idle metric window cannot prove the database is no longer needed for periodic, recovery, or future workloads.",
            "confirmation_key": "owner_approved",
        },
    ]
    if not available_snapshots:
        unknowns.append(
            {
                "code": "rds_recovery_snapshot_not_observed",
                "message": "No available DB snapshot was observed for this instance.",
                "confirmation_key": "backup_restore_reviewed",
            }
        )

    return {
        "supported": True,
        "current_state": {
            "exists": bool(instance),
            "db_instance_identifier": identifier,
            "status": status or None,
            "engine": instance.get("Engine"),
            "engine_version": instance.get("EngineVersion"),
            "instance_class": instance.get("DBInstanceClass"),
            "multi_az": instance.get("MultiAZ"),
            "publicly_accessible": instance.get("PubliclyAccessible"),
            "storage_encrypted": instance.get("StorageEncrypted"),
            "deletion_protection": instance.get("DeletionProtection"),
            "endpoint_present": bool(endpoint.get("Address")),
            "endpoint_value_redacted": True,
        },
        "relationships": relationships,
        "tags": instance.get("TagList") or [],
        "checks": [
            {
                "id": "rds_deletion_protection",
                "status": (
                    "blocked"
                    if instance.get("DeletionProtection") is True
                    else ("passed" if instance else "unavailable")
                ),
                "evidence": {"deletion_protection": instance.get("DeletionProtection")},
            },
            {
                "id": "rds_replica_and_cluster_relationships",
                "status": "blocked" if database_relationships else "passed",
                "evidence": {"relationship_count": len(database_relationships)},
            },
            dns_check,
            {
                "id": "rds_recovery_snapshots",
                "status": "passed" if available_snapshots else "unknown",
                "evidence": {
                    "available_snapshot_count": len(available_snapshots),
                    "newest_snapshot_at": _iso_value(newest_snapshot),
                    "newest_snapshot_age_days": age_days(newest_snapshot),
                },
            },
        ],
        "blockers": blockers,
        "unknowns": unknowns,
        "recovery": {
            "status": "snapshot_observed" if available_snapshots else "not_observed",
            "available_snapshot_count": len(available_snapshots),
            "newest_snapshot_at": _iso_value(newest_snapshot),
            "guidance": (
                "A snapshot can restore data into a new DB instance, but it does not preserve the "
                "original endpoint, secrets, networking, parameter groups, alarms, or application state."
            ),
        },
    }


def _investigate_rds_operation(
    reader: _EvidenceReader,
    rule: str,
    identifier: str,
    evidence: JSON,
) -> JSON:
    payload = reader.read("rds.describe_db_instances", DBInstanceIdentifier=identifier)
    instances = list((payload or {}).get("DBInstances") or [])
    instance = _mapping(instances[0]) if instances else {}
    relationships: list[JSON] = []
    if instance.get("DBClusterIdentifier"):
        relationships.append(
            {
                "relationship_type": "member_of_db_cluster",
                "resource_type": "aws.rds.db-cluster",
                "resource_id": instance["DBClusterIdentifier"],
                "source": "rds.describe_db_instances",
            }
        )
    for replica in instance.get("ReadReplicaDBInstanceIdentifiers") or []:
        relationships.append(
            {
                "relationship_type": "source_for_read_replica",
                "resource_type": "aws.rds.db-instance",
                "resource_id": replica,
                "source": "rds.describe_db_instances",
            }
        )
    if instance.get("ReadReplicaSourceDBInstanceIdentifier"):
        relationships.append(
            {
                "relationship_type": "replica_of",
                "resource_type": "aws.rds.db-instance",
                "resource_id": instance["ReadReplicaSourceDBInstanceIdentifier"],
                "source": "rds.describe_db_instances",
            }
        )
    for group in instance.get("VpcSecurityGroups") or []:
        if group.get("VpcSecurityGroupId"):
            relationships.append(
                {
                    "relationship_type": "uses_security_group",
                    "resource_type": "aws.ec2.security-group",
                    "resource_id": group["VpcSecurityGroupId"],
                    "status": group.get("Status"),
                    "source": "rds.describe_db_instances",
                }
            )
    subnet_group = _mapping(instance.get("DBSubnetGroup"))
    for subnet in subnet_group.get("Subnets") or []:
        subnet_id = _mapping(subnet).get("SubnetIdentifier")
        if subnet_id:
            relationships.append(
                {
                    "relationship_type": "placed_in_subnet",
                    "resource_type": "aws.ec2.subnet",
                    "resource_id": subnet_id,
                    "source": "rds.describe_db_instances",
                }
            )

    metric_keys = {
        "rds-high-cpu": ("cpu_breach_days", "threshold_percent"),
        "rds-low-cpu-rightsizing": (
            "observed_maximum_daily_average_cpu_percent",
            "threshold_percent",
        ),
        "rds-read-heavy-no-replica": (
            "minimum_observed_read_iops",
            "maximum_observed_write_iops",
        ),
    }
    required_metric_keys = metric_keys.get(rule, ())
    signal_present = all(key in evidence for key in required_metric_keys)
    config_reproduced = instance.get("PubliclyAccessible") is True
    checks = [
        {
            "id": "rds_live_configuration",
            "status": "passed" if instance else "unavailable",
            "evidence": {
                "exists": bool(instance),
                "status": instance.get("DBInstanceStatus"),
                "pending_modification_count": len(_mapping(instance.get("PendingModifiedValues"))),
            },
        }
    ]
    if required_metric_keys:
        checks.append(
            {
                "id": "rds_live_signal_revalidation",
                "status": "passed" if signal_present else "unavailable",
                "evidence": {
                    key: evidence.get(key) for key in required_metric_keys if key in evidence
                },
            }
        )
    if rule == "rds-publicly-accessible":
        checks.append(
            {
                "id": "rds_public_accessibility",
                "status": "blocked" if config_reproduced else "passed",
                "evidence": {"publicly_accessible": instance.get("PubliclyAccessible")},
            }
        )

    hypotheses = _rds_hypotheses(rule, instance, evidence)
    unknowns = [
        {
            "code": "rds_query_and_connection_context_missing",
            "message": "SQL plans, locks, connection-pool behavior, memory pressure, and application traces were not inspected.",
        },
        {
            "code": "rds_workload_seasonality_not_proven",
            "message": "The observed metric window may not represent business peaks, batch jobs, failover, or future demand.",
        },
        {
            "code": "rds_iac_change_not_mapped",
            "message": "The owning Terraform, CloudFormation, or CDK definition has not yet been located.",
        },
    ]
    recommendations = _rds_recommended_actions(rule)
    return {
        "supported": bool(instance),
        "current_state": {
            "exists": bool(instance),
            "db_instance_identifier": identifier,
            "status": instance.get("DBInstanceStatus"),
            "engine": instance.get("Engine"),
            "engine_version": instance.get("EngineVersion"),
            "instance_class": instance.get("DBInstanceClass"),
            "allocated_storage_gib": instance.get("AllocatedStorage"),
            "storage_type": instance.get("StorageType"),
            "multi_az": instance.get("MultiAZ"),
            "publicly_accessible": instance.get("PubliclyAccessible"),
            "read_replica_count": len(instance.get("ReadReplicaDBInstanceIdentifiers") or []),
            "performance_insights_enabled": instance.get("PerformanceInsightsEnabled"),
            "enhanced_monitoring_enabled": bool(instance.get("MonitoringInterval")),
            "pending_modification_count": len(_mapping(instance.get("PendingModifiedValues"))),
            "finding_evidence": {
                key: value
                for key, value in evidence.items()
                if key
                in {
                    "cpu_breach_days",
                    "lookback_days",
                    "maximum_observed_write_iops",
                    "minimum_observed_read_iops",
                    "observed_maximum_daily_average_cpu_percent",
                    "publicly_accessible",
                    "threshold_percent",
                }
            },
        },
        "relationships": relationships,
        "tags": instance.get("TagList") or [],
        "checks": checks,
        "hypotheses": hypotheses,
        "unknowns": unknowns,
        "recommended_actions": recommendations,
        "business_impact": {
            "category": "stateful_database",
            "potential_impact": (
                "An incorrect database change can cause connection failures, latency, data loss, "
                "failover risk, or unnecessary recurring cost."
            ),
            "requires_business_owner_review": True,
        },
        "change_plan_preview": _operational_change_plan(rule, identifier),
    }


def _rds_hypotheses(rule: str, instance: JSON, evidence: JSON) -> list[JSON]:
    if rule == "rds-high-cpu":
        return [
            {
                "id": "query_or_connection_pressure",
                "confidence": "medium",
                "basis": "Sustained CPU breaches were observed, but SQL and connection evidence is absent.",
                "confirmed": False,
            },
            {
                "id": "compute_or_memory_capacity_pressure",
                "confidence": "low",
                "basis": f"Current class is {instance.get('DBInstanceClass') or 'unknown'}; memory and wait events were not read.",
                "confirmed": False,
            },
        ]
    if rule == "rds-low-cpu-rightsizing":
        return [
            {
                "id": "compute_overprovisioning_candidate",
                "confidence": "medium",
                "basis": (
                    "Complete CPU evidence is low for the configured lookback, but memory, I/O, "
                    "connections, licensing, and peak demand still require review."
                ),
                "confirmed": False,
            }
        ]
    if rule == "rds-read-heavy-no-replica":
        return [
            {
                "id": "read_scaling_or_cache_candidate",
                "confidence": "medium",
                "basis": (
                    f"Observed read/write signals are {evidence.get('minimum_observed_read_iops')} / "
                    f"{evidence.get('maximum_observed_write_iops')} IOPS and no read replica is reported."
                ),
                "confirmed": False,
            }
        ]
    return [
        {
            "id": "network_exposure_requires_path_review",
            "confidence": "high" if instance.get("PubliclyAccessible") is True else "low",
            "basis": "The live RDS configuration reports whether a public endpoint is enabled; security-group reachability is a separate check.",
            "confirmed": False,
        }
    ]


def _rds_recommended_actions(rule: str) -> list[str]:
    if rule == "rds-high-cpu":
        return [
            "Inspect Performance Insights or database-native query statistics before selecting a fix.",
            "Correlate CPU with connections, waits, storage latency, deployments, and business traffic.",
            "Prefer query or connection fixes before scaling when evidence supports them.",
        ]
    if rule == "rds-low-cpu-rightsizing":
        return [
            "Collect memory, connections, IOPS, latency, storage, and peak-window evidence.",
            "Model a smaller class with rollback and compare actual account pricing.",
            "Test the candidate class outside production before changing the live instance.",
        ]
    if rule == "rds-read-heavy-no-replica":
        return [
            "Confirm read consistency, replication lag, cacheability, failover, and routing requirements.",
            "Compare query optimization, caching, and a read replica before selecting architecture changes.",
        ]
    return [
        "Review route tables, subnet placement, security groups, client paths, and DNS before changing accessibility.",
        "Move the instance behind private connectivity through reviewed IaC and a tested rollback plan.",
    ]


def _investigate_ecs_operation(
    reader: _EvidenceReader,
    rule: str,
    resource_id: str,
    evidence: JSON,
) -> JSON:
    if rule == "ecs-unsafe-task-definition":
        return _investigate_ecs_task_definition_operation(reader, resource_id, evidence)
    cluster_arn = str(evidence.get("cluster_arn") or "")
    service, discovered_cluster = _find_ecs_service(reader, cluster_arn, resource_id)
    cluster_arn = discovered_cluster or cluster_arn
    task_arns: list[str] = []
    for desired_status in ("RUNNING", "STOPPED"):
        payload = reader.read(
            "ecs.list_tasks",
            cluster=cluster_arn,
            serviceName=resource_id,
            desiredStatus=desired_status,
        )
        task_arns.extend(str(item) for item in (payload or {}).get("taskArns") or [])
    task_arns = list(dict.fromkeys(task_arns))
    tasks: list[JSON] = []
    for batch in _batches(task_arns, 100):
        payload = reader.read("ecs.describe_tasks", cluster=cluster_arn, tasks=batch)
        tasks.extend(_mapping(item) for item in (payload or {}).get("tasks") or [])
    task_definition_arns = {
        str(service.get("taskDefinition") or ""),
        *(
            str(item.get("taskDefinition") or "")
            for item in service.get("deployments") or []
            if isinstance(item, Mapping)
        ),
    }
    task_definition_arns.discard("")
    matching_tasks = [
        task
        for task in tasks
        if str(task.get("taskDefinitionArn") or "") in task_definition_arns
        and (not task.get("group") or str(task.get("group")) == f"service:{resource_id}")
    ]
    task_definition = {}
    if service.get("taskDefinition"):
        detail = reader.read(
            "ecs.describe_task_definition",
            taskDefinition=service["taskDefinition"],
            include=["TAGS"],
        )
        task_definition = _mapping((detail or {}).get("taskDefinition"))

    relationships = [
        {
            "relationship_type": "uses_task_definition",
            "resource_type": "aws.ecs.task-definition",
            "resource_id": arn.rsplit("/", 1)[-1],
            "source": "ecs.describe_services",
        }
        for arn in sorted(task_definition_arns)
    ]
    relationships.extend(
        {
            "relationship_type": "routes_through_target_group",
            "resource_type": "aws.elbv2.target-group",
            "resource_id": item.get("targetGroupArn"),
            "container_name": item.get("containerName"),
            "container_port": item.get("containerPort"),
            "source": "ecs.describe_services",
        }
        for item in service.get("loadBalancers") or []
        if item.get("targetGroupArn")
    )
    task_summaries = [_ecs_task_summary(task) for task in matching_tasks]
    desired = int(service.get("desiredCount") or 0)
    running = int(service.get("runningCount") or 0)
    stopped = [item for item in task_summaries if item.get("last_status") == "STOPPED"]
    deployments = [
        {
            "status": item.get("status"),
            "rollout_state": item.get("rolloutState"),
            "desired_count": item.get("desiredCount"),
            "running_count": item.get("runningCount"),
            "pending_count": item.get("pendingCount"),
        }
        for item in service.get("deployments") or []
        if isinstance(item, Mapping)
    ]
    checks = [
        {
            "id": "ecs_service_capacity",
            "status": "blocked" if desired > running else ("passed" if service else "unavailable"),
            "evidence": {
                "desired_count": desired,
                "running_count": running,
                "pending_count": service.get("pendingCount"),
            },
        },
        {
            "id": "ecs_task_failures",
            "status": "blocked" if stopped else "passed",
            "evidence": {
                "tasks_observed": len(task_summaries),
                "stopped_tasks_observed": len(stopped),
                "failure_categories": sorted(
                    {
                        str(item.get("stop_category"))
                        for item in stopped
                        if item.get("stop_category")
                    }
                ),
            },
        },
        {
            "id": "ecs_platform_version",
            "status": (
                "blocked"
                if str(service.get("platformVersion") or "").upper() not in {"", "LATEST"}
                else ("passed" if service else "unavailable")
            ),
            "evidence": {"platform_version": service.get("platformVersion")},
        },
    ]
    hypotheses = _ecs_service_hypotheses(rule, service, stopped, deployments)
    return {
        "supported": bool(service),
        "current_state": {
            "exists": bool(service),
            "cluster_arn": cluster_arn or None,
            "service_name": resource_id,
            "status": service.get("status"),
            "desired_count": desired,
            "running_count": running,
            "pending_count": service.get("pendingCount"),
            "launch_type": service.get("launchType"),
            "platform_version": service.get("platformVersion"),
            "deployments": deployments[:10],
            "tasks": task_summaries[:20],
            "task_definition": {
                "family": task_definition.get("family"),
                "revision": task_definition.get("revision"),
                "container_count": len(task_definition.get("containerDefinitions") or []),
                "environment_values_redacted": True,
            },
            "service_events_redacted": True,
        },
        "relationships": relationships,
        "tags": service.get("tags") or [],
        "checks": checks,
        "hypotheses": hypotheses,
        "unknowns": [
            {
                "code": "ecs_logs_and_traces_not_inspected",
                "message": "Application logs, traces, health-check bodies, and downstream dependencies were not inspected.",
            },
            {
                "code": "ecs_source_and_iac_not_mapped",
                "message": "The owning application repository, Dockerfile, task-definition source, and service IaC were not located.",
            },
        ],
        "recommended_actions": [
            "Inspect the redacted task failure categories, deployment state, target health, and capacity before changing desired count or platform version.",
            "Locate the owning task definition and service IaC, then prepare the smallest reviewed patch.",
            "Deploy one canary revision and verify running count, target health, logs, latency, and errors before full rollout.",
        ],
        "business_impact": {
            "category": "containerized_service",
            "potential_impact": "A wrong ECS change can reduce capacity, break deployments, or route traffic to unhealthy tasks.",
            "requires_business_owner_review": True,
        },
        "change_plan_preview": _operational_change_plan(rule, resource_id),
    }


def _find_ecs_service(
    reader: _EvidenceReader,
    cluster_arn: str,
    service_name: str,
) -> tuple[JSON, str]:
    clusters = [cluster_arn] if cluster_arn else []
    if not clusters:
        payload = reader.read("ecs.list_clusters")
        clusters = [str(item) for item in (payload or {}).get("clusterArns") or []]
    for candidate in clusters:
        payload = reader.read(
            "ecs.describe_services",
            cluster=candidate,
            services=[service_name],
            include=["TAGS"],
        )
        services = list((payload or {}).get("services") or [])
        if services:
            return _mapping(services[0]), candidate
    return {}, cluster_arn


def _ecs_task_summary(task: JSON) -> JSON:
    return {
        "task_id": str(task.get("taskArn") or "").rsplit("/", 1)[-1] or None,
        "task_definition": str(task.get("taskDefinitionArn") or "").rsplit("/", 1)[-1] or None,
        "desired_status": task.get("desiredStatus"),
        "last_status": task.get("lastStatus"),
        "stop_code": task.get("stopCode"),
        "stop_category": _reason_category(task.get("stoppedReason")),
        "containers": [
            {
                "name": item.get("name"),
                "last_status": item.get("lastStatus"),
                "exit_code": item.get("exitCode"),
                "reason_category": _reason_category(item.get("reason")),
            }
            for item in task.get("containers") or []
            if isinstance(item, Mapping)
        ],
        "reason_details_redacted": True,
    }


def _reason_category(value: Any) -> Optional[str]:
    if not value:
        return None
    prefix = str(value).split(":", 1)[0].split(" ", 1)[0]
    sanitized = "".join(
        character for character in prefix if character.isalnum() or character in "_-."
    )
    return sanitized[:80] or "redacted"


def _ecs_service_hypotheses(
    rule: str,
    service: JSON,
    stopped_tasks: list[JSON],
    deployments: list[JSON],
) -> list[JSON]:
    if rule == "ecs-platform-version-outdated":
        return [
            {
                "id": "service_pinned_to_old_fargate_platform",
                "confidence": "high",
                "basis": f"Live platformVersion is {service.get('platformVersion') or 'unknown'} rather than LATEST.",
                "confirmed": False,
            }
        ]
    categories = sorted(
        {str(item.get("stop_category")) for item in stopped_tasks if item.get("stop_category")}
    )
    hypotheses = []
    if categories:
        hypotheses.append(
            {
                "id": "stopped_task_failure",
                "confidence": "medium",
                "basis": {"redacted_failure_categories": categories},
                "confirmed": False,
            }
        )
    if any(item.get("rollout_state") == "FAILED" for item in deployments):
        hypotheses.append(
            {
                "id": "deployment_rollout_failed",
                "confidence": "high",
                "basis": "At least one ECS deployment reports rolloutState FAILED.",
                "confirmed": False,
            }
        )
    if not hypotheses:
        hypotheses.append(
            {
                "id": "capacity_healthcheck_or_startup_failure",
                "confidence": "low",
                "basis": "Desired count exceeds running count, but logs, target health, and detailed failure evidence are not yet available.",
                "confirmed": False,
            }
        )
    return hypotheses


def _investigate_ecs_task_definition_operation(
    reader: _EvidenceReader,
    resource_id: str,
    evidence: JSON,
) -> JSON:
    target = str(evidence.get("task_definition_arn") or resource_id)
    detail = reader.read("ecs.describe_task_definition", taskDefinition=target, include=["TAGS"])
    task_definition = _mapping((detail or {}).get("taskDefinition"))
    privileged: list[str] = []
    secret_like_names: list[str] = []
    secret_reference_count = 0
    for container in task_definition.get("containerDefinitions") or []:
        if not isinstance(container, Mapping):
            continue
        name = str(container.get("name") or "unnamed")
        if container.get("privileged") is True:
            privileged.append(name)
        secret_reference_count += len(container.get("secrets") or [])
        for variable in container.get("environment") or []:
            variable_name = str(_mapping(variable).get("name") or "")
            if _secret_like_variable_name(variable_name):
                secret_like_names.append(variable_name[:80])
    checks = [
        {
            "id": "ecs_privileged_containers",
            "status": "blocked" if privileged else "passed",
            "evidence": {"count": len(privileged), "container_names": privileged[:20]},
        },
        {
            "id": "ecs_literal_secret_like_variables",
            "status": "blocked" if secret_like_names else "passed",
            "evidence": {
                "count": len(secret_like_names),
                "variable_names": sorted(set(secret_like_names))[:20],
                "values_redacted": True,
                "managed_secret_reference_count": secret_reference_count,
            },
        },
    ]
    hypotheses = []
    if privileged:
        hypotheses.append(
            {
                "id": "privileged_container_escape_risk",
                "confidence": "high",
                "basis": {"container_names": privileged[:20]},
                "confirmed": False,
            }
        )
    if secret_like_names:
        hypotheses.append(
            {
                "id": "literal_secret_material_in_task_definition",
                "confidence": "medium",
                "basis": {"variable_names": sorted(set(secret_like_names))[:20]},
                "confirmed": False,
            }
        )
    return {
        "supported": bool(task_definition),
        "current_state": {
            "exists": bool(task_definition),
            "task_definition_arn": task_definition.get("taskDefinitionArn") or target,
            "family": task_definition.get("family"),
            "revision": task_definition.get("revision"),
            "status": task_definition.get("status"),
            "network_mode": task_definition.get("networkMode"),
            "task_role_arn": task_definition.get("taskRoleArn"),
            "execution_role_arn": task_definition.get("executionRoleArn"),
            "environment_values_redacted": True,
        },
        "relationships": [],
        "tags": (detail or {}).get("tags") or [],
        "checks": checks,
        "hypotheses": hypotheses,
        "unknowns": [
            {
                "code": "ecs_privilege_requirement_not_understood",
                "message": "Application and runtime requirements were not inspected to determine whether privileged mode is intentional.",
            },
            {
                "code": "ecs_source_definition_not_mapped",
                "message": "The owning Dockerfile, application repository, and task-definition IaC were not located.",
            },
        ],
        "recommended_actions": [
            "Locate the owning task-definition source and confirm why each privileged container requires host-level capabilities.",
            "Move literal secret-like values to Secrets Manager or Systems Manager references without returning current values.",
            "Register a reviewed revision and deploy it as a canary before replacing the current service revision.",
        ],
        "business_impact": {
            "category": "container_workload_security",
            "potential_impact": "An incorrect task-definition change can prevent startup or remove capabilities the workload currently depends on.",
            "requires_business_owner_review": True,
        },
        "change_plan_preview": _operational_change_plan("ecs-unsafe-task-definition", resource_id),
    }


def _secret_like_variable_name(value: str) -> bool:
    normalized = "".join(character.lower() if character.isalnum() else "_" for character in value)
    parts = {part for part in normalized.split("_") if part}
    return bool(parts & {"password", "passwd", "secret", "token", "credential", "credentials"}) or (
        "api" in parts and "key" in parts
    )


def _route53_references(reader: _EvidenceReader, target_value: str) -> tuple[list[JSON], JSON]:
    if not target_value:
        return [], {
            "id": "route53_dns_references",
            "status": "unavailable",
            "evidence": "The current DNS target value was unavailable.",
        }
    zones_payload = reader.read("route53.list_hosted_zones")
    if zones_payload is None:
        return [], {
            "id": "route53_dns_references",
            "status": "unavailable",
            "evidence": "Route 53 hosted zones could not be listed.",
        }
    matches: list[JSON] = []
    scanned_records = 0
    zones = list(zones_payload.get("HostedZones") or [])
    for zone in zones:
        zone_id = str(zone.get("Id") or "").split("/")[-1]
        if not zone_id:
            continue
        records_payload = reader.read("route53.list_resource_record_sets", HostedZoneId=zone_id)
        if records_payload is None:
            continue
        for record in records_payload.get("ResourceRecordSets") or []:
            scanned_records += 1
            values = {
                str(item.get("Value") or "").strip('"')
                for item in record.get("ResourceRecords") or []
                if isinstance(item, Mapping)
            }
            if target_value.rstrip(".") not in {value.rstrip(".") for value in values}:
                continue
            matches.append(
                {
                    "relationship_type": "referenced_by_dns_record",
                    "resource_type": "aws.route53.record",
                    "resource_id": f"{zone_id}:{record.get('Name')}:{record.get('Type')}",
                    "record_name": record.get("Name"),
                    "record_type": record.get("Type"),
                    "source": "route53.list_resource_record_sets",
                }
            )
    return matches, {
        "id": "route53_dns_references",
        "status": "blocked" if matches else "passed",
        "evidence": {
            "hosted_zones_scanned": len(zones),
            "record_sets_scanned": scanned_records,
            "matching_records": len(matches),
            "external_dns_covered": False,
        },
    }


def _lambda_policy_relationships(value: Any) -> list[JSON]:
    if not value:
        return []
    try:
        document = json.loads(value) if isinstance(value, str) else dict(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    statements = document.get("Statement") or []
    if isinstance(statements, Mapping):
        statements = [statements]
    relationships: list[JSON] = []
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        actions = _string_list(statement.get("Action"))
        if not any(
            action.lower() in {"lambda:invokefunction", "lambda:*", "*"} for action in actions
        ):
            continue
        sources = _condition_source_arns(statement.get("Condition"))
        principals = _principal_values(statement.get("Principal"))
        identifiers = sources or principals or ["unspecified-invoker"]
        for identifier in identifiers:
            relationships.append(
                {
                    "relationship_type": "allowed_by_lambda_resource_policy",
                    "resource_type": "aws.principal-or-source",
                    "resource_id": identifier,
                    "statement_id": statement.get("Sid"),
                    "source": "lambda.get_policy",
                    "policy_document_redacted": True,
                }
            )
    return relationships


def _condition_source_arns(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    sources: list[str] = []
    for operator_value in value.values():
        if not isinstance(operator_value, Mapping):
            continue
        for key, raw in operator_value.items():
            if str(key).lower() not in {"aws:sourcearn", "aws:sourceaccount"}:
                continue
            sources.extend(_string_list(raw))
    return sources


def _principal_values(value: Any) -> list[str]:
    if isinstance(value, Mapping):
        return [item for raw in value.values() for item in _string_list(raw)]
    return _string_list(value)


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return [str(item) for item in values if str(item).strip()]


def _batches(values: list[Any], size: int) -> Iterable[list[Any]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _config_relationships(
    reader: _EvidenceReader,
    resource_ref: JSON,
    resource_id: str,
) -> JSON:
    resource_type = _CONFIG_RESOURCE_TYPES.get(str(resource_ref.get("resource_type") or ""))
    check: JSON = {"id": "aws_config_relationship_graph", "status": "unavailable"}
    if not resource_type or not resource_id:
        reason = "The resource type is not mapped to an AWS Config resource type."
        check["evidence"] = reason
        return {"status": "unavailable", "reason": reason, "relationships": [], "check": check}
    recorders_payload = reader.read("config.describe_configuration_recorders")
    if recorders_payload is None:
        reason = "AWS Config recorder visibility is unavailable for this principal."
        check["evidence"] = reason
        return {"status": "unavailable", "reason": reason, "relationships": [], "check": check}
    recorders = list(recorders_payload.get("ConfigurationRecorders") or [])
    if not recorders:
        reason = "AWS Config is not configured in this Region."
        check["evidence"] = reason
        return {"status": "unavailable", "reason": reason, "relationships": [], "check": check}
    status_payload = reader.read("config.describe_configuration_recorder_status")
    statuses = list((status_payload or {}).get("ConfigurationRecordersStatus") or [])
    if status_payload is None or not any(item.get("recording") is True for item in statuses):
        reason = "AWS Config is configured but no recorder is currently recording in this Region."
        check["evidence"] = reason
        return {"status": "unavailable", "reason": reason, "relationships": [], "check": check}
    history = reader.read(
        "config.get_resource_config_history",
        resourceType=resource_type,
        resourceId=resource_id,
        chronologicalOrder="Reverse",
        limit=1,
    )
    items = list((history or {}).get("configurationItems") or [])
    if not items:
        reason = "AWS Config has no recorded configuration item for this resource."
        check["evidence"] = reason
        return {"status": "unavailable", "reason": reason, "relationships": [], "check": check}
    relationships = [
        {
            "relationship_type": item.get("relationshipName") or "related_to",
            "resource_type": item.get("resourceType"),
            "resource_id": item.get("resourceId"),
            "resource_name": item.get("resourceName"),
            "source": "config.get_resource_config_history",
        }
        for item in items[0].get("relationships") or []
        if isinstance(item, Mapping)
    ]
    check.update(
        status="passed",
        evidence={
            "resource_type": resource_type,
            "relationship_count": len(relationships),
            "captured_at": _iso_value(items[0].get("configurationItemCaptureTime")),
        },
    )
    return {"status": "available", "reason": None, "relationships": relationships, "check": check}


def _selected_business_tags(value: Any) -> JSON:
    tags = tags_dict(value if isinstance(value, (Mapping, list)) else {})
    return {
        str(key): str(raw_value)[:256]
        for key, raw_value in tags.items()
        if str(key).strip().lower() in _BUSINESS_TAG_KEYS
    }


def _business_context(tags: JSON) -> JSON:
    normalized = {str(key).lower(): str(value) for key, value in tags.items()}
    owner = {
        key: value for key, value in normalized.items() if key in _OWNER_TAG_KEYS and value.strip()
    }
    environments = {
        key: value
        for key, value in normalized.items()
        if key in _ENVIRONMENT_TAG_KEYS and value.strip()
    }
    production = any(value.strip().lower() in _PRODUCTION_VALUES for value in environments.values())
    return {
        "selected_tags": tags,
        "owner_known": bool(owner),
        "ownership": owner,
        "environment": environments,
        "production_indicated": production,
        "impact_level": (
            "production_review_required"
            if production
            else ("owner_context_available" if owner else "business_context_unknown")
        ),
        "inferred_from_resource_name": False,
    }


def _readiness_status(
    *,
    rule: str,
    direct_supported: bool,
    blockers: list[JSON],
    unresolved_unknowns: list[JSON],
) -> str:
    if blockers:
        return "blocked"
    if rule not in SUPPORTED_DELETION_RULES or not direct_supported:
        return "not_supported"
    if unresolved_unknowns:
        return "needs_context"
    return "candidate_for_approval"


def _readiness_explanation(status: str) -> str:
    return {
        "blocked": "Observed AWS relationships or resource state block deletion planning.",
        "needs_context": "No blocking AWS relationship was sufficient to decide; required business or external context is still missing.",
        "candidate_for_approval": "Required confirmations were supplied and no blocking relationship was observed. This is still not proof that deletion is safe.",
        "not_supported": "Steward does not yet implement service-specific deletion analysis for this rule.",
    }[status]


def _evidence_coverage(checks: Iterable[JSON], errors: list[JSON]) -> JSON:
    checks = list(checks)
    completed = sum(item.get("status") in {"passed", "blocked"} for item in checks)
    score = round(100.0 * completed / len(checks), 1) if checks else 0.0
    return {
        "score": score,
        "scale": "0-100",
        "label": "high" if score >= 80 else ("medium" if score >= 50 else "low"),
        "checks_total": len(checks),
        "checks_completed": completed,
        "capability_errors": len(errors),
        "meaning": "Coverage of planned evidence checks, not probability that deletion is safe.",
    }


def _blast_radius(
    *,
    resource: str,
    relationships: list[JSON],
    blockers: list[JSON],
    production_indicated: bool,
) -> JSON:
    if blockers or production_indicated:
        level = "high"
    elif resource.startswith("eip://"):
        level = "medium"
    else:
        level = "bounded_but_unproven"
    return {
        "level": level,
        "observed_related_resources": len(relationships),
        "production_indicated": production_indicated,
        "scope": "one selected resource plus observed dependents",
        "unobserved_dependencies_possible": True,
    }


def _business_impact(
    *,
    rule: str,
    finding: JSON,
    business_context: JSON,
    blockers: list[JSON],
) -> JSON:
    if rule == "ec2-unattached-ebs-volume":
        category = "persistent_data"
        impact = (
            "Deleting the volume permanently removes its data. A snapshot can recreate data, "
            "but not the original volume identity, mounts, or application state."
        )
    elif rule == "ec2-unassociated-elastic-ip":
        category = "network_identity"
        impact = (
            "Releasing the address can break DNS, allowlists, partner integrations, or recovery "
            "procedures and the same public IPv4 address may not be recoverable."
        )
    elif rule == "ecs-inactive-task-definition":
        category = "deployment_rollback"
        impact = (
            "Deleting the revision can remove a deployment or rollback target. Services, "
            "pipelines, scheduled tasks, and IaC may still reference the exact revision."
        )
    elif rule == "efs-inactive-unmounted":
        category = "shared_persistent_data"
        impact = (
            "Deleting the file system permanently removes shared data and can break clients "
            "whose mounts or recovery procedures are not visible in current AWS metadata."
        )
    elif rule == "lambda-unused-function":
        category = "event_driven_workload"
        impact = (
            "Deleting the function can break infrequent, scheduled, direct, cross-account, or "
            "emergency invocation paths that were not active during the metric window."
        )
    elif rule == "rds-idle-instance":
        category = "stateful_database"
        impact = (
            "Deleting the DB instance removes a stateful application dependency and changes its "
            "endpoint. Restoring a snapshot creates a different instance and requires reviewed "
            "networking, credentials, DNS, and application reconnection."
        )
    else:
        category = "unknown"
        impact = "A service-specific business-impact model is not implemented for this rule."
    cost_estimate = finding.get("cost_estimate") or _mapping(finding.get("evidence")).get(
        "cost_estimate"
    )
    return {
        "category": category,
        "potential_impact": impact,
        "owner_known": business_context.get("owner_known"),
        "production_indicated": business_context.get("production_indicated"),
        "observed_blockers": len(blockers),
        "estimated_monthly_savings": cost_estimate
        or {
            "status": "not_estimated",
            "estimated_monthly_savings_usd": None,
            "confidence": "none",
        },
        "requires_business_owner_review": True,
    }


def _investigation_confidence(coverage: JSON, unresolved_unknowns: list[JSON]) -> JSON:
    return {
        "score": float(coverage.get("score") or 0.0),
        "scale": "0-100",
        "label": coverage.get("label") or "low",
        "unresolved_context_items": len(unresolved_unknowns),
        "basis": "completed read-only evidence checks",
        "meaning": (
            "Confidence in evidence completeness, not probability that deletion is safe. "
            "Human confirmations do not increase the AWS evidence score."
        ),
    }


def _operational_change_plan(rule: str, resource_id: str) -> JSON:
    operations: dict[str, Optional[JSON]] = {
        "rds-high-cpu": None,
        "rds-low-cpu-rightsizing": {
            "aws_api": "rds:ModifyDBInstance",
            "sdk_method": "modify_db_instance",
            "parameters": {
                "DBInstanceIdentifier": resource_id,
                "DBInstanceClass": "<benchmark-selected-class>",
                "ApplyImmediately": False,
            },
        },
        "rds-publicly-accessible": {
            "aws_api": "rds:ModifyDBInstance",
            "sdk_method": "modify_db_instance",
            "parameters": {
                "DBInstanceIdentifier": resource_id,
                "PubliclyAccessible": False,
                "ApplyImmediately": False,
            },
        },
        "rds-read-heavy-no-replica": {
            "aws_api": "rds:CreateDBInstanceReadReplica",
            "sdk_method": "create_db_instance_read_replica",
            "parameters": {
                "SourceDBInstanceIdentifier": resource_id,
                "DBInstanceIdentifier": "<reviewed-replica-identifier>",
            },
        },
        "ecs-platform-version-outdated": {
            "aws_api": "ecs:UpdateService",
            "sdk_method": "update_service",
            "parameters": {
                "service": resource_id,
                "platformVersion": "LATEST",
                "forceNewDeployment": True,
                "cluster": "<live-cluster-arn>",
            },
        },
        "ecs-service-health-degraded": None,
        "ecs-unsafe-task-definition": {
            "aws_api": "ecs:RegisterTaskDefinition",
            "sdk_method": "register_task_definition",
            "parameters": {
                "family": resource_id.split(":", 1)[0],
                "containerDefinitions": "<reviewed-redacted-definition>",
            },
        },
    }
    verification: dict[str, list[str]] = {
        "rds-high-cpu": [
            "Re-query CPU, waits, connections, storage latency, errors, and application latency across the reviewed window.",
            "Confirm the selected query, connection, configuration, or capacity change addressed the measured cause.",
        ],
        "rds-low-cpu-rightsizing": [
            "Confirm the DB instance is available on the reviewed class.",
            "Compare CPU, memory, connections, latency, IOPS, errors, and business traffic before and after the change.",
        ],
        "rds-publicly-accessible": [
            "Confirm PubliclyAccessible is false and the endpoint resolves only through approved network paths.",
            "Run application, administration, monitoring, backup, and failover connectivity checks.",
        ],
        "rds-read-heavy-no-replica": [
            "Confirm replica status, lag, encryption, backups, monitoring, and networking are healthy.",
            "Verify read routing, consistency, failover behavior, and the measured primary-load reduction.",
        ],
        "ecs-platform-version-outdated": [
            "Confirm the service reports the reviewed platform version and reaches desired running count.",
            "Verify target health, logs, latency, errors, task stability, and rollback capacity.",
        ],
        "ecs-service-health-degraded": [
            "Confirm running count equals desired count and deployments reach a completed state.",
            "Verify target health, task stability, logs, latency, errors, and downstream dependencies.",
        ],
        "ecs-unsafe-task-definition": [
            "Describe the deployed revision and confirm privileged mode and secret-like literal values are absent.",
            "Verify task startup, target health, permissions, logs, latency, errors, and rollback capacity.",
        ],
    }
    return {
        "mode": "planning_only",
        "executable_by_steward": False,
        "target_operation": operations.get(rule),
        "root_cause_required_before_change": rule
        in {"rds-high-cpu", "ecs-service-health-degraded"},
        "incremental_steps": [
            "Collect the missing evidence and reject unsupported hypotheses.",
            "Locate and update the owning IaC or deployment source rather than drifting live AWS.",
            "Prepare one minimal canary or maintenance-window change with explicit rollback.",
            "Revalidate live state immediately before requesting approval.",
            "Apply only after the exact plan is explicitly approved, then run every verification check.",
        ],
        "post_change_verification": verification.get(
            rule,
            ["Run a fresh service-specific assessment after the reviewed change."],
        ),
    }


def _planning_only_change(
    *,
    rule: str,
    resource_id: str,
    blockers: list[JSON],
    required_confirmations: list[JSON],
    recovery: JSON,
) -> JSON:
    if rule == "ec2-unattached-ebs-volume":
        operation = {
            "aws_api": "ec2:DeleteVolume",
            "sdk_method": "delete_volume",
            "parameters": {"VolumeId": resource_id},
        }
        verification = [
            "Confirm ec2:DescribeVolumes no longer returns the selected volume.",
            "Confirm no workload, deployment, mount, alarm, backup, or restore workflow regressed.",
            "Verify the expected storage-cost change after billing data becomes available.",
        ]
    elif rule == "ec2-unassociated-elastic-ip":
        operation = {
            "aws_api": "ec2:ReleaseAddress",
            "sdk_method": "release_address",
            "parameters": {"AllocationId": resource_id},
        }
        verification = [
            "Confirm ec2:DescribeAddresses no longer returns the selected allocation.",
            "Confirm account-owned and external DNS, allowlists, integrations, and health checks still work.",
            "Verify the expected public IPv4-cost change after billing data becomes available.",
        ]
    elif rule == "ecs-inactive-task-definition":
        operation = {
            "aws_api": "ecs:DeleteTaskDefinitions",
            "sdk_method": "delete_task_definitions",
            "parameters": {"taskDefinitions": [resource_id]},
        }
        verification = [
            "Confirm ecs:DescribeTaskDefinition no longer returns the reviewed revision.",
            "Confirm ECS services, scheduled tasks, deployment pipelines, and rollback procedures remain valid.",
            "Confirm the definition can be recreated as a new revision from reviewed source if required.",
        ]
    elif rule == "efs-inactive-unmounted":
        operation = {
            "aws_api": "elasticfilesystem:DeleteFileSystem",
            "sdk_method": "delete_file_system",
            "parameters": {"FileSystemId": resource_id},
        }
        verification = [
            "Confirm elasticfilesystem:DescribeFileSystems no longer returns the reviewed file system.",
            "Confirm clients, workloads, access points, backup jobs, and restore procedures remain healthy.",
            "Verify the expected storage-cost change after billing data becomes available.",
        ]
    elif rule == "lambda-unused-function":
        operation = {
            "aws_api": "lambda:DeleteFunction",
            "sdk_method": "delete_function",
            "parameters": {"FunctionName": resource_id},
        }
        verification = [
            "Confirm lambda:GetFunctionConfiguration no longer returns the reviewed function.",
            "Confirm event sources, schedules, APIs, workflows, alarms, and direct callers remain healthy.",
            "Confirm the function can be redeployed from reviewed source and configuration if required.",
        ]
    elif rule == "rds-idle-instance":
        operation = {
            "aws_api": "rds:DeleteDBInstance",
            "sdk_method": "delete_db_instance",
            "parameters": {
                "DBInstanceIdentifier": resource_id,
                "SkipFinalSnapshot": False,
                "FinalDBSnapshotIdentifier": "<reviewed-unique-snapshot-name>",
            },
        }
        verification = [
            "Confirm rds:DescribeDBInstances no longer returns the reviewed instance only after the final snapshot is available.",
            "Confirm applications, jobs, secrets, DNS, alarms, backups, and analytics dependencies remain healthy.",
            "Perform a documented restore drill or verify the reviewed recovery procedure and recovery objectives.",
            "Verify the expected database-cost change after billing data becomes available.",
        ]
    else:
        operation = None
        verification = ["Run a fresh service-specific assessment after the reviewed change."]
    return {
        "mode": "planning_only",
        "executable_by_steward": False,
        "target_operation": operation,
        "blockers_must_be_zero": not blockers,
        "required_confirmation_keys": [
            item["key"] for item in required_confirmations if not item.get("confirmed")
        ],
        "incremental_steps": [
            "Resolve every observed blocker and evidence gap.",
            "Review and update IaC or deployment ownership before changing live AWS.",
            "Validate the documented recovery path and select a change window.",
            "Approve this one resource and operation; do not batch destructive changes.",
            "Revalidate the live state immediately before execution.",
            "Execute outside Steward only while deletion remains unsupported, then run every verification check.",
        ],
        "rollback": recovery,
        "post_change_verification": verification,
    }


def _required_confirmations(unknowns: Iterable[JSON], supplied: JSON) -> list[JSON]:
    confirmations: dict[str, JSON] = {}
    for unknown in unknowns:
        key = str(unknown.get("confirmation_key") or "").strip()
        if not key:
            continue
        confirmations.setdefault(
            key,
            {
                "key": key,
                "confirmed": supplied.get(key) is True,
                "reason": unknown.get("message"),
            },
        )
    return list(confirmations.values())


def _next_steps(readiness: str, blockers: list[JSON], unknowns: list[JSON]) -> list[str]:
    if blockers:
        return [
            "Inspect and remove or migrate every observed dependency through a separate reviewed change.",
            "Run a fresh Steward investigation after dependencies change.",
        ]
    if unknowns:
        return [
            "Resolve the listed business, IaC, recovery, and external-dependency confirmations.",
            "Re-run this investigation with only confirmations that a human reviewer has explicitly approved.",
        ]
    if readiness == "candidate_for_approval":
        return [
            "Create a planning-only change record with maintenance window, rollback limitations, and post-change verification.",
            "Require explicit approval for this one resource; Steward will not execute deletion.",
        ]
    return ["Use the rule explanation and wait for a service-specific deletion investigator."]


def _unknown_recovery() -> JSON:
    return {
        "status": "not_assessed",
        "guidance": "Define and test a service-specific recovery procedure before destructive action.",
    }


def _resource_id(resource: str) -> str:
    if resource.startswith("ebs://") or resource.startswith("eip://"):
        return resource.split("//", 1)[1].split("/", 1)[0]
    return resource.rsplit("/", 1)[-1]


def _deduplicate_relationships(items: Iterable[JSON]) -> list[JSON]:
    deduplicated: dict[tuple[str, str, str], JSON] = {}
    for item in items:
        key = (
            str(item.get("relationship_type") or "related_to"),
            str(item.get("resource_type") or "unknown"),
            str(item.get("resource_id") or "unknown"),
        )
        deduplicated.setdefault(key, item)
    return sorted(
        deduplicated.values(),
        key=lambda item: tuple(
            str(value)
            for value in (
                item.get("relationship_type"),
                item.get("resource_type"),
                item.get("resource_id"),
            )
        ),
    )


def _mapping(value: Any) -> JSON:
    return dict(value) if isinstance(value, Mapping) else {}


def _iso_value(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        parsed = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)
