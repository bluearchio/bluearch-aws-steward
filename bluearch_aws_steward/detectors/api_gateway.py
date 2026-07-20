from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Tuple

from bluearch_aws_steward.detectors.aws_common import tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider

_ACCESS_LOGGING = "api_gateway_access_logging_disabled"
_EXECUTION_LOGGING = "api_gateway_execution_logging_disabled"
_XRAY_TRACING = "api_gateway_xray_tracing_disabled"
_METHOD_AUTHORIZATION = "api_gateway_method_authorization_missing"
_ALL_DETECTORS = (_ACCESS_LOGGING, _EXECUTION_LOGGING, _XRAY_TRACING, _METHOD_AUTHORIZATION)


def scan_api_gateway(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "api-gateway", rule_filter)
    response = context.read(_ALL_DETECTORS, "apigateway.get_rest_apis")
    rest_apis = list((response or {}).get("items") or [])
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags
    resources_scanned = len(rest_apis)

    for rest_api in rest_apis:
        api_id = str(rest_api.get("id") or "").strip()
        if not api_id:
            continue
        api_arn = f"arn:aws:apigateway:{region}::/restapis/{api_id}"
        tags_response = context.read(_ALL_DETECTORS, "apigateway.get_tags", resourceArn=api_arn)
        if resource_is_exempt(tags_dict((tags_response or {}).get("tags")), exclusions):
            continue

        stages_response = context.read(_ALL_DETECTORS, "apigateway.get_stages", restApiId=api_id)
        stages = list((stages_response or {}).get("item") or [])
        resources_scanned += len(stages)
        methods = _load_methods(context, api_id)
        resources_scanned += len(methods)

        _scan_stages(
            context,
            findings,
            rest_api=rest_api,
            api_id=api_id,
            api_arn=api_arn,
            stages=stages,
            methods=methods,
            region=region,
        )
        _scan_method_authorization(
            context,
            findings,
            rest_api=rest_api,
            api_id=api_id,
            api_arn=api_arn,
            stages=stages,
            methods=methods,
            region=region,
        )

    return build_scan_result(
        service="api-gateway",
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


def _load_methods(
    context: EvaluationContext,
    api_id: str,
) -> List[Tuple[str, str, str]]:
    if not context.rule(_EXECUTION_LOGGING) and not context.rule(_METHOD_AUTHORIZATION):
        return []
    response = context.read(
        (_EXECUTION_LOGGING, _METHOD_AUTHORIZATION),
        "apigateway.get_resources",
        restApiId=api_id,
        embed=["methods"],
    )
    methods: List[Tuple[str, str, str]] = []
    for resource in (response or {}).get("items") or []:
        resource_id = str(resource.get("id") or "").strip()
        path = str(resource.get("path") or "/").strip() or "/"
        for http_method in resource.get("resourceMethods") or {}:
            verb = str(http_method).upper()
            if resource_id and verb != "OPTIONS":
                methods.append((resource_id, path, verb))
    return methods


def _scan_stages(
    context: EvaluationContext,
    findings: List[Finding],
    *,
    rest_api: Dict[str, Any],
    api_id: str,
    api_arn: str,
    stages: List[Dict[str, Any]],
    methods: List[Tuple[str, str, str]],
    region: str,
) -> None:
    for stage in stages:
        stage_name = str(stage.get("stageName") or "").strip()
        if not stage_name:
            continue
        resource = f"api-gateway://rest-api/{api_id}/stage/{stage_name}"
        resource_ref = _resource_ref(
            rest_api, api_id, api_arn, region, "aws.apigateway.stage", stage_name
        )

        access_rule = context.rule(_ACCESS_LOGGING)
        access_settings = dict(stage.get("accessLogSettings") or {})
        if access_rule and not (
            str(access_settings.get("destinationArn") or "").strip()
            and str(access_settings.get("format") or "").strip()
        ):
            findings.append(
                finding_from_rule(
                    access_rule,
                    resource,
                    {
                        "rest_api_id": api_id,
                        "stage_name": stage_name,
                        "deployment_id": stage.get("deploymentId"),
                        "access_log_destination_present": bool(
                            access_settings.get("destinationArn")
                        ),
                        "access_log_format_present": bool(access_settings.get("format")),
                    },
                    [
                        "Select an existing reviewed CloudWatch Logs group.",
                        "Define a structured format with request identifiers and no sensitive payloads.",
                        "Enable stage access logging during an approved change.",
                    ],
                    "Re-read the stage and confirm destinationArn and format are configured.",
                    resource_ref=resource_ref,
                )
            )

        tracing_rule = context.rule(_XRAY_TRACING)
        if tracing_rule and stage.get("tracingEnabled") is not True:
            findings.append(
                finding_from_rule(
                    tracing_rule,
                    resource,
                    {
                        "rest_api_id": api_id,
                        "stage_name": stage_name,
                        "deployment_id": stage.get("deploymentId"),
                        "xray_tracing_enabled": False,
                    },
                    [
                        "Review trace sampling, privacy, downstream instrumentation, and expected cost.",
                        "Enable X-Ray tracing for the stage during an approved change.",
                        "Verify traces without enabling sensitive data logging.",
                    ],
                    "Re-read the stage and confirm tracingEnabled is true.",
                    resource_ref=resource_ref,
                )
            )

        execution_rule = context.rule(_EXECUTION_LOGGING)
        if execution_rule and methods:
            method_settings = dict(stage.get("methodSettings") or {})
            missing = [
                f"{verb} {path}"
                for _, path, verb in methods
                if not _method_execution_logging_enabled(method_settings, path, verb)
            ]
            if missing:
                findings.append(
                    finding_from_rule(
                        execution_rule,
                        resource,
                        {
                            "rest_api_id": api_id,
                            "stage_name": stage_name,
                            "deployment_id": stage.get("deploymentId"),
                            "methods_without_execution_logging": len(missing),
                            "method_samples": sorted(missing)[:20],
                            "accepted_logging_levels": ["ERROR", "INFO"],
                            "data_trace_recommended": False,
                        },
                        [
                            "Configure the regional API Gateway CloudWatch role if required.",
                            "Enable ERROR or INFO execution logging for affected methods.",
                            "Keep data tracing disabled unless sensitive-data handling is reviewed.",
                        ],
                        "Re-read stage method settings and confirm ERROR or INFO logging coverage.",
                        resource_ref=resource_ref,
                    )
                )


def _scan_method_authorization(
    context: EvaluationContext,
    findings: List[Finding],
    *,
    rest_api: Dict[str, Any],
    api_id: str,
    api_arn: str,
    stages: List[Dict[str, Any]],
    methods: Iterable[Tuple[str, str, str]],
    region: str,
) -> None:
    rule = context.rule(_METHOD_AUTHORIZATION)
    if not rule or not stages:
        return
    stage_names = sorted(str(stage.get("stageName")) for stage in stages if stage.get("stageName"))
    for resource_id, path, verb in methods:
        detail = context.read(
            _METHOD_AUTHORIZATION,
            "apigateway.get_method",
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=verb,
        )
        active_rule = context.rule(_METHOD_AUTHORIZATION)
        authorization_type = str((detail or {}).get("authorizationType") or "").upper()
        if not active_rule or authorization_type != "NONE":
            continue
        resource = f"api-gateway://rest-api/{api_id}/method/{verb}{path}"
        findings.append(
            finding_from_rule(
                active_rule,
                resource,
                {
                    "rest_api_id": api_id,
                    "resource_id": resource_id,
                    "resource_path": path,
                    "http_method": verb,
                    "authorization_type": authorization_type,
                    "deployed_stages": stage_names,
                    "integration_details_read": False,
                },
                [
                    "Confirm whether this method is intentionally public.",
                    "Select IAM, Cognito, or a reviewed Lambda authorizer when authentication is required.",
                    "Test clients and authorization failures before deployment.",
                ],
                "Re-read the method and confirm the approved authorizationType is configured.",
                resource_ref=_resource_ref(
                    rest_api,
                    api_id,
                    api_arn,
                    region,
                    "aws.apigateway.method",
                    f"{verb} {path}",
                ),
            )
        )


def _method_execution_logging_enabled(
    method_settings: Dict[str, Any], path: str, verb: str
) -> bool:
    normalized_path = path.strip("/") or "~1"
    encoded_path = path.replace("/", "~1") or "~1"
    for key, raw_settings in method_settings.items():
        settings = raw_settings if isinstance(raw_settings, dict) else {}
        if str(settings.get("loggingLevel") or "").upper() not in {"ERROR", "INFO"}:
            continue
        normalized_key = str(key).strip("/")
        if "/" not in normalized_key:
            continue
        path_pattern, method_pattern = normalized_key.rsplit("/", 1)
        if method_pattern not in {"*", verb}:
            continue
        if path_pattern in {"*", normalized_path, encoded_path.strip("/")}:
            return True
        decoded_pattern = path_pattern.replace("~1", "/").strip("/") or "~1"
        if decoded_pattern == normalized_path:
            return True
    return False


def _resource_ref(
    rest_api: Dict[str, Any],
    api_id: str,
    api_arn: str,
    region: str,
    resource_type: str,
    suffix: str,
) -> ResourceRef:
    name = str(rest_api.get("name") or api_id)
    return ResourceRef(
        provider="aws",
        service="api-gateway",
        resource_type=resource_type,
        resource_id=f"{api_id}:{suffix}",
        region=region,
        arn=api_arn,
        display_name=f"{name} {suffix}",
    )
