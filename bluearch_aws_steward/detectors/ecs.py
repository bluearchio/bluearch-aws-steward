from __future__ import annotations

import re
import time
from typing import Dict, Iterable, List

from bluearch_aws_steward.detectors.aws_common import tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider

_SECRET_NAME = re.compile(
    r"(?:^|_)(?:password|passwd|secret|token|api_?key|credential|private_?key)(?:$|_)",
    re.IGNORECASE,
)


def scan_ecs(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "ecs", rule_filter)
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags
    task_definition_count = _scan_task_definitions(context, findings, region, exclusions)
    service_count = _scan_services(context, findings, region, exclusions)

    return build_scan_result(
        service="ecs",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=task_definition_count + service_count,
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _scan_task_definitions(
    context: EvaluationContext,
    findings: List[Finding],
    region: str,
    exclusions: Dict[str, str],
) -> int:
    rule = context.rule("ecs_unsafe_task_definition")
    inactive_rule = context.rule("ecs_inactive_task_definition")
    if not rule and not inactive_rule:
        return 0
    response = (
        context.read(
            "ecs_unsafe_task_definition",
            "ecs.list_task_definitions",
            status="ACTIVE",
            sort="DESC",
        )
        if rule
        else {}
    )
    arns = list((response or {}).get("taskDefinitionArns") or [])
    pending: List[Finding] = []
    for arn in arns:
        if rule is None:
            continue
        detail = context.read(
            "ecs_unsafe_task_definition",
            "ecs.describe_task_definition",
            taskDefinition=arn,
            include=["TAGS"],
        )
        task_definition = (detail or {}).get("taskDefinition") or {}
        if resource_is_exempt(tags_dict((detail or {}).get("tags") or []), exclusions):
            continue
        privileged_containers: List[str] = []
        secret_categories: set[str] = set()
        secret_literal_count = 0
        for container in task_definition.get("containerDefinitions") or []:
            if not isinstance(container, dict):
                continue
            name = str(container.get("name") or "unnamed")
            if container.get("privileged") is True:
                privileged_containers.append(name)
            for variable in container.get("environment") or []:
                if not isinstance(variable, dict) or not variable.get("value"):
                    continue
                variable_name = str(variable.get("name") or "")
                match = _SECRET_NAME.search(variable_name)
                if not match:
                    continue
                secret_literal_count += 1
                secret_categories.add(_secret_category(match.group(0)))
        if not privileged_containers and not secret_literal_count:
            continue
        resource = f"ecs://task-definition/{str(arn).rsplit('/', 1)[-1]}"
        pending.append(
            finding_from_rule(
                rule,
                resource,
                {
                    "task_definition_arn": arn,
                    "privileged_container_count": len(privileged_containers),
                    "privileged_container_names": privileged_containers[:10],
                    "literal_secret_like_value_count": secret_literal_count,
                    "literal_secret_categories": sorted(secret_categories),
                    "environment_values_redacted": True,
                },
                [
                    "Confirm whether privileged mode is required for each identified container.",
                    "Move sensitive literals to AWS Secrets Manager or Systems Manager references.",
                    "Register and deploy a reviewed task-definition revision.",
                ],
                "Describe the deployed revision and confirm privileged mode and secret-like literals are absent.",
                resource_ref=ResourceRef(
                    provider="aws",
                    service="ecs",
                    resource_type="aws.ecs.task-definition",
                    resource_id=str(arn).rsplit("/", 1)[-1],
                    region=region,
                    arn=str(arn),
                    display_name=str(arn).rsplit("/", 1)[-1],
                ),
            )
        )
    if context.rule("ecs_unsafe_task_definition"):
        findings.extend(pending)
    inactive_response = (
        context.read(
            "ecs_inactive_task_definition",
            "ecs.list_task_definitions",
            status="INACTIVE",
            sort="DESC",
        )
        if inactive_rule
        else {}
    )
    inactive_arns = list((inactive_response or {}).get("taskDefinitionArns") or [])
    if context.rule("ecs_inactive_task_definition"):
        for arn in inactive_arns:
            if inactive_rule is None:
                continue
            detail = context.read(
                "ecs_inactive_task_definition",
                "ecs.describe_task_definition",
                taskDefinition=arn,
                include=["TAGS"],
            )
            task_definition = (detail or {}).get("taskDefinition") or {}
            if resource_is_exempt(tags_dict((detail or {}).get("tags") or []), exclusions):
                continue
            family = str(task_definition.get("family") or str(arn).rsplit("/", 1)[-1])
            revision = task_definition.get("revision")
            resource_id = f"{family}:{revision}" if revision is not None else family
            findings.append(
                finding_from_rule(
                    inactive_rule,
                    f"ecs://task-definition/{resource_id}",
                    {
                        "task_definition_arn": arn,
                        "family": family,
                        "revision": revision,
                        "status": task_definition.get("status") or "INACTIVE",
                        "container_count": len(task_definition.get("containerDefinitions") or []),
                        "environment_values_redacted": True,
                    },
                    [
                        "Search services, deployment pipelines, rollback procedures, and IaC for the exact revision.",
                        "Deregister or delete only through a separately approved cleanup workflow.",
                    ],
                    "List inactive task definitions and confirm the reviewed revision is intentionally retained or removed.",
                    resource_ref=ResourceRef(
                        "aws",
                        "ecs",
                        "aws.ecs.task-definition",
                        resource_id,
                        region=region,
                        arn=str(arn),
                        display_name=resource_id,
                    ),
                )
            )
    return len(arns) + len(inactive_arns)


def _scan_services(
    context: EvaluationContext,
    findings: List[Finding],
    region: str,
    exclusions: Dict[str, str],
) -> int:
    rule = context.rule("ecs_platform_version_outdated")
    health_rule = context.rule("ecs_service_health_degraded")
    active_detectors = tuple(
        name
        for name in ("ecs_platform_version_outdated", "ecs_service_health_degraded")
        if context.rule(name)
    )
    if not active_detectors:
        return 0
    cluster_response = context.read(active_detectors, "ecs.list_clusters")
    clusters = list((cluster_response or {}).get("clusterArns") or [])
    service_count = 0
    pending: List[Finding] = []
    for cluster_arn in clusters:
        service_response = context.read(
            active_detectors,
            "ecs.list_services",
            cluster=cluster_arn,
        )
        service_arns = list((service_response or {}).get("serviceArns") or [])
        service_count += len(service_arns)
        for batch in _batches(service_arns, 10):
            details = context.read(
                active_detectors,
                "ecs.describe_services",
                cluster=cluster_arn,
                services=batch,
                include=["TAGS"],
            )
            for service in (details or {}).get("services") or []:
                if resource_is_exempt(tags_dict(service.get("tags") or []), exclusions):
                    continue
                service_arn = str(service.get("serviceArn") or "")
                service_name = str(service.get("serviceName") or service_arn.rsplit("/", 1)[-1])
                resource_ref = ResourceRef(
                    provider="aws",
                    service="ecs",
                    resource_type="aws.ecs.service",
                    resource_id=service_name,
                    region=region,
                    arn=service_arn or None,
                    display_name=service_name,
                )
                platform_version = str(service.get("platformVersion") or "").strip()
                if rule and platform_version and platform_version.upper() != "LATEST":
                    pending.append(
                        finding_from_rule(
                            rule,
                            f"ecs://service/{service_name}",
                            {
                                "cluster_arn": cluster_arn,
                                "service_arn": service_arn,
                                "launch_type": service.get("launchType") or "FARGATE",
                                "platform_version": platform_version,
                                "desired_count": service.get("desiredCount"),
                                "running_count": service.get("runningCount"),
                            },
                            [
                                "Review current tasks, runtime changes, deployment configuration, and rollback capacity.",
                                "Test the current Fargate platform in a non-production deployment.",
                                "Update the service through an approved deployment.",
                            ],
                            "Describe the service and confirm the reviewed current platform is in use.",
                            resource_ref=resource_ref,
                            confidence="medium",
                        )
                    )
                desired = int(service.get("desiredCount") or 0)
                running = int(service.get("runningCount") or 0)
                if health_rule and desired > running:
                    deployments = [
                        {
                            "status": item.get("status"),
                            "desired_count": item.get("desiredCount"),
                            "running_count": item.get("runningCount"),
                            "pending_count": item.get("pendingCount"),
                            "rollout_state": item.get("rolloutState"),
                        }
                        for item in service.get("deployments") or []
                    ]
                    pending.append(
                        finding_from_rule(
                            health_rule,
                            f"ecs://service/{service_name}",
                            {
                                "cluster_arn": cluster_arn,
                                "service_arn": service_arn,
                                "desired_count": desired,
                                "running_count": running,
                                "pending_count": service.get("pendingCount"),
                                "deployments": deployments[:5],
                                "service_events_redacted": True,
                            },
                            [
                                "Inspect deployment state, stopped-task reasons, capacity, image pulls, secrets, and health checks.",
                                "Patch the owning task definition, service IaC, or application only after the failure cause is confirmed.",
                            ],
                            "Describe the service and confirm RunningCount equals DesiredCount with healthy tasks.",
                            resource_ref=resource_ref,
                        )
                    )
    findings.extend(pending)
    return service_count


def _batches(values: List[str], size: int) -> Iterable[List[str]]:
    for index in range(0, len(values), size):
        yield values[index : index + size]


def _secret_category(value: str) -> str:
    normalized = re.sub(r"[^a-z]", "", value.lower())
    if "password" in normalized or "passwd" in normalized:
        return "password"
    if "key" in normalized:
        return "key"
    if "token" in normalized:
        return "token"
    if "credential" in normalized:
        return "credential"
    return "secret"
