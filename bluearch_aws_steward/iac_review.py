from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Sequence

from bluearch_aws_steward.catalog import load_rules
from bluearch_aws_steward.detectors.aws_common import policy_has_full_admin
from bluearch_aws_steward.models import ResourceRef, Rule, utc_now_iso

JSON = Dict[str, Any]
ControlEvaluator = Callable[[JSON], tuple[str, JSON]]


@dataclass(frozen=True)
class IacControlSpec:
    service: str
    rule: str
    resource_types: tuple[str, ...]
    evaluator: ControlEvaluator


def evaluate_iac_context(iac_context: JSON, focus: Sequence[ResourceRef]) -> JSON:
    """Evaluate deterministic, source-only controls without executing IaC or AWS calls."""

    rule_index = {rule.short_id: rule for rule in load_rules()}
    controls: List[JSON] = []
    findings: List[JSON] = []
    for resource in iac_context.get("resources") or []:
        if not any(_matches_focus(resource, target) for target in focus):
            continue
        for spec in _CONTROL_SPECS:
            if resource.get("service") != spec.service:
                continue
            if spec.resource_types and resource.get("resource_type") not in spec.resource_types:
                continue
            rule = rule_index.get(spec.rule)
            if rule is None:
                continue
            unresolved = list(resource.get("unresolved_fields") or [])
            status, evidence = spec.evaluator(resource.get("facts") or {})
            if unresolved:
                evidence = {
                    **evidence,
                    "unresolved_fields": unresolved,
                    "unresolved_fields_do_not_override_known_control_facts": True,
                }
            control = {
                "service": spec.service,
                "rule": spec.rule,
                "status": status,
                "resource": _resource_uri(resource),
                "resource_ref": _resource_ref(resource).to_dict(),
                "source_path": resource.get("source_path"),
                "address": resource.get("address"),
                "evidence": evidence,
            }
            controls.append(control)
            if status == "risk":
                findings.append(_finding_from_control(control, rule))
    return {
        "controls": controls,
        "findings": findings,
        "evaluated_rules": sorted(
            {str(item["rule"]) for item in controls if item["status"] in {"risk", "aligned"}}
        ),
        "unknown_rules": sorted(
            {str(item["rule"]) for item in controls if item["status"] == "unknown"}
        ),
        "write_operations": 0,
    }


def _finding_from_control(control: JSON, rule: Rule) -> JSON:
    identity = f"{control['rule']}|{control['resource']}|{control.get('source_path')}"
    finding_id = f"iac_{hashlib.sha256(identity.encode('utf-8')).hexdigest()[:24]}"
    remediation = dict(rule.remediation or {})
    observed_at = utc_now_iso()
    evidence = {
        "iac_control": control["evidence"],
        "source_path": control.get("source_path"),
        "address": control.get("address"),
        "observation": {
            "source": "iac_static_analysis",
            "confidence": "high",
            "observed_at": observed_at,
        },
    }
    return {
        "opportunity_id": finding_id,
        "finding_id": finding_id,
        "rule_id": rule.id,
        "rule": rule.short_id,
        "rule_short_id": rule.short_id,
        "objective": "all",
        "matched_objectives": sorted(rule.objectives),
        "resource": control["resource"],
        "resource_ref": control["resource_ref"],
        "service": rule.service,
        "severity": rule.severity,
        "value": "Improve the reviewed architecture before deployment.",
        "why": rule.scenario,
        "scenario": rule.scenario,
        "risk": rule.risk_detail,
        "risk_detail": rule.risk_detail,
        "evidence": evidence,
        "assessment": "iac_static_analysis",
        "sources": ["iac"],
        "source_count": 1,
        "validation": {
            "status": "source_confirmed",
            "observed_at": observed_at,
            "live_aws_checked": False,
        },
        "remediation": {
            "summary": remediation.get("summary"),
            "actions": remediation.get("actions") or [],
            "safety_level": remediation.get("safety_level") or "planning_only",
            "requires_approval": True,
            "verification": remediation.get("verification"),
        },
        "apply": {
            "supported": False,
            "required_approval": True,
            "reason": "Architectural review produces a source preview and never edits IaC.",
        },
    }


def _resource_ref(resource: JSON) -> ResourceRef:
    return ResourceRef(
        provider="iac",
        service=str(resource.get("service") or "unknown"),
        resource_type=str(resource.get("resource_type") or "unknown"),
        resource_id=str(resource.get("resource_id") or resource.get("address") or "unknown"),
        display_name=str(resource.get("display_name") or resource.get("address") or "unknown"),
    )


def _resource_uri(resource: JSON) -> str:
    return f"iac://{resource.get('source_kind')}/{resource.get('address')}"


def _matches_focus(resource: JSON, focus: ResourceRef) -> bool:
    candidates = {
        str(resource.get("node_id") or ""),
        str(resource.get("address") or ""),
        str(resource.get("resource_id") or ""),
        str(resource.get("display_name") or ""),
    }
    return focus.resource_id in candidates or bool(focus.arn and focus.arn in candidates)


def _normalized_items(value: Any) -> Iterable[tuple[str, Any]]:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]+", "", str(key).casefold())
            yield normalized, child
            yield from _normalized_items(child)
    elif isinstance(value, list):
        for child in value:
            yield from _normalized_items(child)


def _values(facts: JSON, *keys: str) -> List[Any]:
    wanted = {re.sub(r"[^a-z0-9]+", "", key.casefold()) for key in keys}
    return [value for key, value in _normalized_items(facts) if key in wanted]


def _first(facts: JSON, *keys: str) -> Any:
    values = _values(facts, *keys)
    return values[0] if values else None


def _boolean(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "enabled", "active", "yes", "1"}:
            return True
        if normalized in {"false", "disabled", "passthrough", "no", "0"}:
            return False
    return None


def _boolean_control(
    *keys: str,
    risk_when: bool = False,
    missing_is_risk: bool = False,
) -> ControlEvaluator:
    def evaluate(facts: JSON) -> tuple[str, JSON]:
        value = _first(facts, *keys)
        observed = _boolean(value)
        evidence = {"field_candidates": list(keys), "observed": value}
        if observed is None:
            if value is None and missing_is_risk:
                evidence["default_interpretation"] = risk_when
                return "risk", evidence
            return "unknown", {**evidence, "reason": "field_not_resolved"}
        return ("risk" if observed is risk_when else "aligned"), evidence

    return evaluate


def _present_control(*keys: str, missing_is_risk: bool = True) -> ControlEvaluator:
    def evaluate(facts: JSON) -> tuple[str, JSON]:
        value = _first(facts, *keys)
        present = value not in (None, "", [], {})
        if present:
            return "aligned", {"field_candidates": list(keys), "configured": True}
        if missing_is_risk:
            return "risk", {"field_candidates": list(keys), "configured": False}
        return "unknown", {"field_candidates": list(keys), "reason": "field_not_resolved"}

    return evaluate


def _iam_admin_policy(facts: JSON) -> tuple[str, JSON]:
    documents = _values(facts, "policy", "policy_document", "document")
    if not documents:
        return "unknown", {"reason": "policy_document_not_present"}
    parsed_documents = [_terraform_json_document(document) for document in documents]
    if any(document is None for document in parsed_documents):
        return "unknown", {
            "reason": "policy_document_not_resolved",
            "policy_values_redacted": True,
        }
    full_admin = any(policy_has_full_admin(document) for document in parsed_documents)
    return (
        "risk" if full_admin else "aligned",
        {
            "unconditioned_full_admin": full_admin,
            "policy_values_redacted": True,
        },
    )


def _terraform_json_document(value: Any) -> Any | None:
    if not isinstance(value, str):
        return value
    candidate = value.strip()
    if candidate.startswith("${jsonencode(") and candidate.endswith(")}"):
        candidate = candidate[len("${jsonencode(") : -2]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        return None


def _s3_versioning(facts: JSON) -> tuple[str, JSON]:
    value = _first(facts, "status", "versioning", "versioning_configuration")
    if isinstance(value, list) and value:
        value = value[0]
    if isinstance(value, dict):
        value = _first(value, "status", "enabled")
    enabled = _boolean(value)
    if enabled is None and isinstance(value, str):
        enabled = value.casefold() == "enabled"
    if value is None:
        return "unknown", {
            "versioning_configured_in_reviewed_resource": False,
            "reason": "versioning_may_be_declared_in_a_separate_resource_or_file",
        }
    if enabled is None:
        return "unknown", {"versioning_value": value, "reason": "field_not_resolved"}
    return ("aligned" if enabled else "risk"), {"versioning_value": value}


def _ecs_privileges(facts: JSON) -> tuple[str, JSON]:
    values = _values(facts, "privileged", "privilege_escalation", "host_network")
    risky = any(_boolean(value) is True for value in values)
    if values:
        return ("risk" if risky else "aligned"), {
            "privileged_fields_observed": len(values),
            "dangerous_privilege_enabled": risky,
            "environment_values_read": False,
        }
    definitions = _first(facts, "container_definitions")
    if isinstance(definitions, str):
        try:
            return _ecs_privileges({"container_definitions": json.loads(definitions)})
        except json.JSONDecodeError:
            pass
    return "unknown", {"reason": "container_privilege_fields_not_resolved"}


def _eks_public_endpoint(facts: JSON) -> tuple[str, JSON]:
    public = _first(facts, "endpoint_public_access")
    cidrs = _values(facts, "public_access_cidrs")
    public_enabled = True if public is None else _boolean(public)
    flattened = json.dumps(cidrs, sort_keys=True)
    unrestricted = not cidrs or "0.0.0.0/0" in flattened or "::/0" in flattened
    evidence = {
        "endpoint_public_access": public_enabled,
        "unrestricted_public_cidr": unrestricted,
    }
    if public_enabled is None:
        return "unknown", {**evidence, "reason": "endpoint_access_not_resolved"}
    return ("risk" if public_enabled and unrestricted else "aligned"), evidence


def _sqs_encryption(facts: JSON) -> tuple[str, JSON]:
    managed = _first(facts, "sqs_managed_sse_enabled")
    key = _first(facts, "kms_master_key_id", "kmsmasterkeyid")
    managed_state = _boolean(managed)
    if key not in (None, "") or managed_state is True:
        return "aligned", {"managed_sse": managed_state, "kms_key_configured": bool(key)}
    if managed_state is False:
        return "risk", {"managed_sse": False, "kms_key_configured": False}
    return "unknown", {
        "reason": "queue_encryption_default_not_explicit",
        "managed_sse": managed_state,
        "kms_key_configured": False,
    }


def _lambda_tracing(facts: JSON) -> tuple[str, JSON]:
    tracing = _first(facts, "tracing_config", "TracingConfig")
    if not isinstance(tracing, dict):
        return "risk", {
            "tracing_configured": False,
            "default_interpretation": "PassThrough",
        }
    mode = _first(tracing, "mode", "Mode")
    if not isinstance(mode, str):
        return "unknown", {"reason": "tracing_mode_not_resolved"}
    return ("aligned" if mode.casefold() == "active" else "risk"), {"tracing_mode": mode}


def _alb_access_logging(facts: JSON) -> tuple[str, JSON]:
    access_logs = _first(facts, "access_logs", "AccessLogs")
    if isinstance(access_logs, list) and access_logs:
        access_logs = access_logs[0]
    if isinstance(access_logs, dict):
        enabled = _boolean(_first(access_logs, "enabled", "Enabled"))
        if enabled is not None:
            return ("aligned" if enabled else "risk"), {"access_logs_enabled": enabled}

    attributes = _first(facts, "load_balancer_attributes", "LoadBalancerAttributes")
    if isinstance(attributes, list):
        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            key = str(attribute.get("Key") or attribute.get("key") or "")
            if key != "access_logs.s3.enabled":
                continue
            enabled = _boolean(attribute.get("Value") or attribute.get("value"))
            if enabled is not None:
                return ("aligned" if enabled else "risk"), {"access_logs_enabled": enabled}
            return "unknown", {"reason": "access_logging_value_redacted_or_unresolved"}
    return "risk", {
        "access_logs_configured": False,
        "default_interpretation": "disabled",
    }


_CONTROL_SPECS: tuple[IacControlSpec, ...] = (
    IacControlSpec("iam", "iam-policy-full-admin", ("aws.iam.policy",), _iam_admin_policy),
    IacControlSpec(
        "cloudtrail",
        "cloudtrail-multi-region-logging-disabled",
        ("aws.cloudtrail.trail",),
        _boolean_control("is_multi_region_trail", "IsMultiRegionTrail", missing_is_risk=True),
    ),
    IacControlSpec(
        "cloudwatch",
        "cloudwatch-log-retention-missing",
        ("aws.logs.log-group",),
        _present_control("retention_in_days", "RetentionInDays"),
    ),
    IacControlSpec("s3", "s3-versioning-disabled", ("aws.s3.bucket",), _s3_versioning),
    IacControlSpec(
        "efs",
        "efs-encryption-disabled",
        ("aws.efs.file-system",),
        _boolean_control("encrypted", "Encrypted", missing_is_risk=True),
    ),
    IacControlSpec(
        "ec2",
        "ec2-ebs-volume-unencrypted",
        ("aws.ec2.volume",),
        _boolean_control("encrypted", "Encrypted", missing_is_risk=True),
    ),
    IacControlSpec(
        "kms",
        "kms-key-rotation-disabled",
        ("aws.kms.key",),
        _boolean_control("enable_key_rotation", "EnableKeyRotation", missing_is_risk=True),
    ),
    IacControlSpec(
        "secrets-manager",
        "secrets-manager-rotation-disabled",
        ("aws.secretsmanager.secret",),
        _present_control(
            "rotation_lambda_arn",
            "RotationRules",
            "rotation_rules",
            missing_is_risk=False,
        ),
    ),
    IacControlSpec(
        "lambda",
        "lambda-xray-tracing-disabled",
        ("aws.lambda.function",),
        _lambda_tracing,
    ),
    IacControlSpec(
        "ecs",
        "ecs-unsafe-task-definition",
        ("aws.ecs.task-definition",),
        _ecs_privileges,
    ),
    IacControlSpec(
        "eks",
        "eks-public-endpoint-open",
        ("aws.eks.cluster",),
        _eks_public_endpoint,
    ),
    IacControlSpec(
        "rds",
        "rds-multi-az-disabled",
        ("aws.rds.db-instance",),
        _boolean_control("multi_az", "MultiAZ", missing_is_risk=True),
    ),
    IacControlSpec(
        "dynamodb",
        "dynamodb-inactive-table",
        ("aws.dynamodb.table",),
        lambda facts: (
            "unknown",
            {
                "reason": "live_utilization_metrics_required",
                "billing_mode": _first(facts, "billing_mode", "BillingMode"),
            },
        ),
    ),
    IacControlSpec(
        "alb",
        "alb-access-logging-disabled",
        ("aws.elasticloadbalancingv2.load-balancer",),
        _alb_access_logging,
    ),
    IacControlSpec(
        "api-gateway",
        "api-gateway-xray-tracing-disabled",
        ("aws.apigateway.stage",),
        _boolean_control("xray_tracing_enabled", "TracingEnabled", missing_is_risk=True),
    ),
    IacControlSpec(
        "sns",
        "sns-topic-encryption-disabled",
        ("aws.sns.topic",),
        _present_control("kms_master_key_id", "KmsMasterKeyId"),
    ),
    IacControlSpec(
        "sqs",
        "sqs-queue-encryption-disabled",
        ("aws.sqs.queue",),
        _sqs_encryption,
    ),
)
