from __future__ import annotations

import time
from typing import Any, Dict, List
from urllib.parse import quote

from bluearch_aws_steward.detectors.aws_common import age_days, cost_evidence, policy_has_full_admin
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.providers.normalize import normalize_lambda_function
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSignalQuery


def scan_lambda(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "lambda", rule_filter)
    functions = _load_functions(client, context)
    functions = _without_exemptions(context, functions, (policy or ScanPolicy()).exclude_tags)
    findings: List[Finding] = []

    _scan_tracing(context, functions, findings, region)
    _scan_admin_roles(context, functions, findings, region)
    _scan_unused_functions(client, context, functions, findings, region)
    _scan_high_error_rates(client, context, functions, findings, region)
    _scan_shared_execution_roles(context, functions, findings, region)
    _scan_operational_signals(client, context, functions, findings, region)
    _scan_provisioned_concurrency(client, context, functions, findings, region)

    return build_scan_result(
        service="lambda",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(functions),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _without_exemptions(
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    exclusions: Dict[str, str],
) -> List[Dict[str, Any]]:
    if not exclusions:
        return functions
    evaluated: List[Dict[str, Any]] = []
    detectors = tuple(context.rules)
    for function in functions:
        arn = str(function.get("arn") or "")
        if not arn:
            context.fail(
                detectors,
                "lambda.list_tags",
                "Function ARN is missing; exclusion tags cannot be evaluated.",
            )
            continue
        response = context.read(detectors, "lambda.list_tags", Resource=arn)
        if response is None or resource_is_exempt(response.get("Tags") or {}, exclusions):
            continue
        evaluated.append(function)
    return evaluated


def _load_functions(client: AwsProvider, context: EvaluationContext) -> List[Dict[str, Any]]:
    new_detectors = (
        "lambda_admin_execution_role",
        "lambda_unused_function",
        "lambda_high_error_rate",
        "lambda_timeout_rate_high",
        "lambda_memory_underutilized",
        "lambda_memory_pressure",
        "lambda_throttling_detected",
        "lambda_shared_execution_role",
        "lambda_provisioned_concurrency_underused",
        "lambda_duration_near_timeout",
    )
    if any(context.rule(detector) for detector in new_detectors):
        response = context.read(new_detectors, "lambda.list_functions")
        if response is not None:
            return [normalize_lambda_function(item) for item in response.get("Functions") or []]
    if context.rule("lambda_xray_tracing_disabled"):
        return list(client.list_lambda_functions())
    return []


def _scan_tracing(
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("lambda_xray_tracing_disabled")
    if not rule:
        return
    for function in functions:
        name = str(function.get("name") or "").strip()
        if not name or function.get("tracing_mode") == "Active":
            continue
        findings.append(
            finding_from_rule(
                rule,
                _resource(name),
                {
                    "function_name": name,
                    "runtime": function.get("runtime"),
                    "memory_mb": function.get("memory_mb"),
                    "timeout_seconds": function.get("timeout_seconds"),
                    "last_modified": function.get("last_modified"),
                    "tracing_mode": function.get("tracing_mode") or "PassThrough",
                },
                [
                    "Review expected trace volume, sampling, retention, and X-Ray cost.",
                    "Confirm the execution role can publish trace segments.",
                    "Enable Active tracing for the reviewed function.",
                ],
                "Re-read the function configuration and confirm TracingConfig.Mode is Active.",
                resource_ref=_resource_ref(function, name, region),
            )
        )


def _scan_admin_roles(
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("lambda_admin_execution_role")
    if not rule:
        return
    role_cache: Dict[str, Dict[str, Any]] = {}
    pending: List[Finding] = []
    for function in functions:
        role_arn = str(function.get("role") or "")
        name = str(function.get("name") or "").strip()
        if not role_arn or not name:
            continue
        role_name = role_arn.rsplit("/", 1)[-1]
        analysis = role_cache.get(role_name)
        if analysis is None:
            analysis = _inspect_role(context, role_name)
            role_cache[role_name] = analysis
        if not analysis.get("full_admin"):
            continue
        pending.append(
            finding_from_rule(
                rule,
                _resource(name),
                {
                    "function_name": name,
                    "execution_role_arn": role_arn,
                    "full_admin_managed_policy_names": analysis.get("managed_policy_names") or [],
                    "full_admin_inline_policy_count": analysis.get("inline_policy_count") or 0,
                    "policy_documents_redacted": True,
                },
                [
                    "Inventory the AWS actions and resources the function actually uses.",
                    "Create a least-privilege replacement policy and test it outside production.",
                    "Remove administrator access only through a reviewed deployment with rollback.",
                ],
                "Invoke representative workloads and confirm the execution role has no unrestricted administrator policy.",
                resource_ref=_resource_ref(function, name, region),
            )
        )
    if context.rule("lambda_admin_execution_role"):
        findings.extend(pending)


def _inspect_role(context: EvaluationContext, role_name: str) -> Dict[str, Any]:
    attached = context.read(
        "lambda_admin_execution_role",
        "iam.list_attached_role_policies",
        RoleName=role_name,
    )
    managed_names: List[str] = []
    for policy in (attached or {}).get("AttachedPolicies") or []:
        policy_arn = policy.get("PolicyArn")
        if not policy_arn:
            continue
        metadata = context.read(
            "lambda_admin_execution_role",
            "iam.get_policy",
            PolicyArn=policy_arn,
        )
        default_version = ((metadata or {}).get("Policy") or {}).get("DefaultVersionId")
        if not default_version:
            continue
        version = context.read(
            "lambda_admin_execution_role",
            "iam.get_policy_version",
            PolicyArn=policy_arn,
            VersionId=default_version,
        )
        document = ((version or {}).get("PolicyVersion") or {}).get("Document")
        if policy_has_full_admin(document):
            managed_names.append(str(policy.get("PolicyName") or "unnamed"))

    inline = context.read(
        "lambda_admin_execution_role",
        "iam.list_role_policies",
        RoleName=role_name,
    )
    inline_admin_count = 0
    for policy_name in (inline or {}).get("PolicyNames") or []:
        policy = context.read(
            "lambda_admin_execution_role",
            "iam.get_role_policy",
            RoleName=role_name,
            PolicyName=policy_name,
        )
        if policy_has_full_admin((policy or {}).get("PolicyDocument")):
            inline_admin_count += 1
    return {
        "full_admin": bool(managed_names or inline_admin_count),
        "managed_policy_names": sorted(managed_names),
        "inline_policy_count": inline_admin_count,
    }


def _scan_unused_functions(
    client: AwsProvider,
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("lambda_unused_function")
    if not rule:
        return
    minimum_age = int(rule.parameters.get("minimum_function_age_days", 30))
    lookback_days = int(rule.parameters.get("lookback_days", 30))
    candidates = [
        function
        for function in functions
        if age_days(function.get("last_modified")) is not None
        and int(age_days(function.get("last_modified")) or 0) >= minimum_age
        and function.get("name")
    ]
    queries = [
        MetricSignalQuery(
            key=str(function["name"]),
            namespace="AWS/Lambda",
            metric_name="Invocations",
            dimensions=(("FunctionName", str(function["name"])),),
            statistic="Sum",
            lookback_days=lookback_days,
        )
        for function in candidates
    ]
    try:
        series_by_name = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail("lambda_unused_function", "cloudwatch.get_metric_data", exc.detail or str(exc))
        return

    pending: List[Finding] = []
    for function in candidates:
        name = str(function["name"])
        series = series_by_name[name]
        if not series.complete or len(series.values) < lookback_days or any(series.values):
            continue
        pending.append(
            finding_from_rule(
                rule,
                _resource(name),
                {
                    "function_name": name,
                    "function_age_days": age_days(function.get("last_modified")),
                    "lookback_days": lookback_days,
                    "invocation_sum": 0.0,
                    "metric_datapoints": len(series.values),
                    "metric_missing_interpreted_as_zero": False,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "CloudWatch reported no invocations throughout the complete lookback window.",
                    ),
                },
                [
                    "Confirm triggers, aliases, event-source mappings, ownership, and deployment references.",
                    "Export configuration and code for rollback before any retirement decision.",
                    "Disable or delete only through a separately approved change.",
                ],
                "After the approved change, verify expected triggers and workloads remain healthy.",
                resource_ref=_resource_ref(function, name, region),
                evidence_source="aws_cloudwatch_metric",
            )
        )
    if context.rule("lambda_unused_function"):
        findings.extend(pending)


def _scan_high_error_rates(
    client: AwsProvider,
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("lambda_high_error_rate")
    if not rule:
        return
    lookback_days = int(rule.parameters.get("lookback_days", 7))
    maximum_rate = float(rule.parameters.get("maximum_error_rate_percent", 10.0))
    candidates = [function for function in functions if function.get("name")]
    invocation_queries = [
        MetricSignalQuery(
            key=str(function["name"]),
            namespace="AWS/Lambda",
            metric_name="Invocations",
            dimensions=(("FunctionName", str(function["name"])),),
            statistic="Sum",
            lookback_days=lookback_days,
        )
        for function in candidates
    ]
    error_queries = [
        MetricSignalQuery(
            key=str(function["name"]),
            namespace="AWS/Lambda",
            metric_name="Errors",
            dimensions=(("FunctionName", str(function["name"])),),
            statistic="Sum",
            lookback_days=lookback_days,
        )
        for function in candidates
    ]
    try:
        invocations_by_name = CloudWatchSignalAdapter(client).read(invocation_queries)
        errors_by_name = CloudWatchSignalAdapter(client).read(error_queries)
    except AwsProviderError as exc:
        context.fail("lambda_high_error_rate", "cloudwatch.get_metric_data", exc.detail or str(exc))
        return

    pending: List[Finding] = []
    for function in candidates:
        name = str(function["name"])
        invocations = invocations_by_name[name]
        errors = errors_by_name[name]
        if (
            not invocations.complete
            or not errors.complete
            or len(invocations.values) < lookback_days
            or len(errors.values) < lookback_days
        ):
            continue
        daily_rates = [
            (error_count / invocation_count) * 100.0
            for invocation_count, error_count in zip(invocations.values, errors.values)
            if invocation_count > 0
        ]
        if not daily_rates:
            continue
        max_rate = max(daily_rates)
        if max_rate <= maximum_rate:
            continue
        pending.append(
            finding_from_rule(
                rule,
                _resource(name),
                {
                    "function_name": name,
                    "runtime": function.get("runtime"),
                    "lookback_days": lookback_days,
                    "maximum_error_rate_percent": maximum_rate,
                    "observed_max_daily_error_rate_percent": round(max_rate, 2),
                    "invocation_sum": sum(invocations.values),
                    "error_sum": sum(errors.values),
                    "metric_datapoints": min(len(invocations.values), len(errors.values)),
                    "metric_missing_interpreted_as_zero": False,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "CloudWatch reported Lambda errors on invoked requests; exact cost impact depends on retries, duration, and upstream callers.",
                    ),
                },
                [
                    "Inspect recent deployments, CloudWatch Logs, X-Ray traces, and upstream dependency failures.",
                    "Reproduce the failing path before changing retry, timeout, or concurrency settings.",
                    "Patch application code or dependencies through the owning repository and deployment pipeline.",
                ],
                "Re-read CloudWatch Lambda Errors and Invocations and confirm daily error rate is within the approved threshold.",
                resource_ref=_resource_ref(function, name, region),
                evidence_source="aws_cloudwatch_metric",
            )
        )
    if context.rule("lambda_high_error_rate"):
        findings.extend(pending)


def _scan_shared_execution_roles(
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("lambda_shared_execution_role")
    if not rule:
        return
    by_role: Dict[str, List[Dict[str, Any]]] = {}
    for function in functions:
        role = str(function.get("role") or "")
        if role:
            by_role.setdefault(role, []).append(function)
    for role, shared in by_role.items():
        if len(shared) < 2:
            continue
        names = sorted(str(item.get("name") or "") for item in shared if item.get("name"))
        for function in shared:
            name = str(function.get("name") or "")
            if not name:
                continue
            findings.append(
                finding_from_rule(
                    rule,
                    _resource(name),
                    {
                        "function_name": name,
                        "execution_role_arn": role,
                        "shared_function_count": len(names),
                        "shared_function_names": names,
                        "policy_documents_redacted": True,
                    },
                    [
                        "Inventory each function's effective AWS actions and resources.",
                        "Create function-specific least-privilege roles through the owning IaC project.",
                    ],
                    "Re-read function configurations and confirm the reviewed execution role is not shared unexpectedly.",
                    resource_ref=_resource_ref(function, name, region),
                )
            )


def _scan_operational_signals(
    client: AwsProvider,
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    active = {
        detector
        for detector in (
            "lambda_timeout_rate_high",
            "lambda_memory_underutilized",
            "lambda_memory_pressure",
            "lambda_throttling_detected",
            "lambda_duration_near_timeout",
        )
        if context.rule(detector)
    }
    candidates = [item for item in functions if item.get("name")]
    if not active or not candidates:
        return
    days = max(int(context.rules[name].parameters.get("lookback_days") or 1) for name in active)
    queries: List[MetricSignalQuery] = []
    for function in candidates:
        name = str(function["name"])
        dimensions = (("FunctionName", name),)
        queries.extend(
            [
                MetricSignalQuery(
                    f"{name}:duration",
                    "AWS/Lambda",
                    "Duration",
                    dimensions,
                    "Maximum",
                    days,
                ),
                MetricSignalQuery(
                    f"{name}:throttles",
                    "AWS/Lambda",
                    "Throttles",
                    dimensions,
                    "Sum",
                    days,
                ),
                MetricSignalQuery(
                    f"{name}:memory",
                    "LambdaInsights",
                    "memory_utilization",
                    (("function_name", name),),
                    "Average",
                    days,
                ),
            ]
        )
    try:
        metrics = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail(active, "cloudwatch.get_metric_data", exc.detail or str(exc))
        return

    pending: List[Finding] = []
    for function in candidates:
        name = str(function["name"])
        timeout_ms = float(function.get("timeout_seconds") or 0.0) * 1000.0
        duration = metrics[f"{name}:duration"]
        throttles = metrics[f"{name}:throttles"]
        memory = metrics[f"{name}:memory"]
        timeout_rule = context.rule("lambda_timeout_rate_high")
        if timeout_rule and timeout_ms > 0:
            lookback = int(timeout_rule.parameters.get("lookback_days") or 7)
            threshold = float(
                timeout_rule.parameters.get("minimum_timeout_utilization_percent") or 95.0
            )
            minimum_percentage = float(
                timeout_rule.parameters.get("minimum_breach_percentage") or 10.0
            )
            breach_days = sum(value / timeout_ms * 100.0 >= threshold for value in duration.values)
            required_days = max(1, int(lookback * minimum_percentage / 100.0))
            if (
                duration.complete
                and len(duration.values) >= lookback
                and breach_days >= required_days
            ):
                pending.append(
                    _signal_finding(
                        timeout_rule,
                        function,
                        region,
                        {
                            "timeout_seconds": function.get("timeout_seconds"),
                            "lookback_days": lookback,
                            "duration_breach_days": breach_days,
                            "minimum_breach_days": required_days,
                            "minimum_timeout_utilization_percent": threshold,
                        },
                        "Inspect timeout paths in logs and traces and patch code or downstream dependencies before changing timeout.",
                    )
                )
        near_rule = context.rule("lambda_duration_near_timeout")
        if near_rule and timeout_ms > 0:
            lookback = int(near_rule.parameters.get("lookback_days") or 7)
            threshold = float(
                near_rule.parameters.get("minimum_timeout_utilization_percent") or 80.0
            )
            minimum_days = int(near_rule.parameters.get("minimum_breach_days") or 3)
            breach_days = sum(value / timeout_ms * 100.0 >= threshold for value in duration.values)
            if (
                duration.complete
                and len(duration.values) >= lookback
                and breach_days >= minimum_days
            ):
                pending.append(
                    _signal_finding(
                        near_rule,
                        function,
                        region,
                        {
                            "timeout_seconds": function.get("timeout_seconds"),
                            "lookback_days": lookback,
                            "duration_breach_days": breach_days,
                            "minimum_breach_days": minimum_days,
                            "minimum_timeout_utilization_percent": threshold,
                        },
                        "Profile code, initialization, downstream calls, retries, and memory before changing timeout.",
                    )
                )
        throttle_rule = context.rule("lambda_throttling_detected")
        if throttle_rule:
            lookback = int(throttle_rule.parameters.get("lookback_days") or 7)
            minimum = float(throttle_rule.parameters.get("minimum_throttles") or 1.0)
            total = sum(throttles.values)
            if throttles.complete and len(throttles.values) >= lookback and total >= minimum:
                pending.append(
                    _signal_finding(
                        throttle_rule,
                        function,
                        region,
                        {"lookback_days": lookback, "throttled_invocations": total},
                        "Inspect reserved and unreserved concurrency, event sources, retries, and downstream capacity.",
                    )
                )
        for detector, comparator, evidence_key in (
            ("lambda_memory_underutilized", "below", "maximum_memory_utilization_percent"),
            ("lambda_memory_pressure", "above", "minimum_memory_utilization_percent"),
        ):
            rule = context.rule(detector)
            if not rule:
                continue
            lookback = int(rule.parameters.get("lookback_days") or 7)
            threshold = float(
                rule.parameters.get(evidence_key) or (30.0 if comparator == "below" else 90.0)
            )
            matches = (
                memory.complete
                and len(memory.values) >= lookback
                and (
                    max(memory.values) < threshold
                    if comparator == "below"
                    else min(memory.values) > threshold
                )
            )
            if matches:
                pending.append(
                    _signal_finding(
                        rule,
                        function,
                        region,
                        {
                            "lookback_days": lookback,
                            "observed_minimum_memory_utilization_percent": round(
                                min(memory.values), 2
                            ),
                            "observed_maximum_memory_utilization_percent": round(
                                max(memory.values), 2
                            ),
                            "threshold_percent": threshold,
                            "lambda_insights_required": True,
                        },
                        "Benchmark representative workloads before changing memory or code allocation behavior.",
                    )
                )
    findings.extend(pending)


def _scan_provisioned_concurrency(
    client: AwsProvider,
    context: EvaluationContext,
    functions: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("lambda_provisioned_concurrency_underused")
    if not rule:
        return
    configured: List[tuple[Dict[str, Any], int]] = []
    for function in functions:
        name = str(function.get("name") or "")
        if not name:
            continue
        response = context.read(
            "lambda_provisioned_concurrency_underused",
            "lambda.list_provisioned_concurrency_configs",
            FunctionName=name,
        )
        allocated = sum(
            int(item.get("AllocatedProvisionedConcurrentExecutions") or 0)
            for item in (response or {}).get("ProvisionedConcurrencyConfigs") or []
        )
        if allocated > 0:
            configured.append((function, allocated))
    if not configured:
        return
    days = int(rule.parameters.get("lookback_days") or 7)
    queries = [
        MetricSignalQuery(
            key=str(function["name"]),
            namespace="AWS/Lambda",
            metric_name="Invocations",
            dimensions=(("FunctionName", str(function["name"])),),
            statistic="Sum",
            lookback_days=days,
        )
        for function, _ in configured
    ]
    try:
        metrics = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail(
            "lambda_provisioned_concurrency_underused",
            "cloudwatch.get_metric_data",
            exc.detail or str(exc),
        )
        return
    maximum = float(rule.parameters.get("maximum_daily_invocations") or 10.0)
    for function, allocated in configured:
        name = str(function["name"])
        series = metrics[name]
        if not series.complete or len(series.values) < days or max(series.values) >= maximum:
            continue
        findings.append(
            _signal_finding(
                rule,
                function,
                region,
                {
                    "lookback_days": days,
                    "allocated_provisioned_concurrency": allocated,
                    "maximum_daily_invocations": max(series.values),
                    "threshold_daily_invocations": maximum,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "Provisioned concurrency is configured while complete invocation metrics show low demand.",
                    ),
                },
                "Validate cold-start SLOs and traffic windows before reducing or scheduling provisioned concurrency.",
            )
        )


def _signal_finding(
    rule: Any,
    function: Dict[str, Any],
    region: str,
    evidence: Dict[str, Any],
    action: str,
) -> Finding:
    name = str(function.get("name") or "")
    return finding_from_rule(
        rule,
        _resource(name),
        {
            "function_name": name,
            "runtime": function.get("runtime"),
            "memory_mb": function.get("memory_mb"),
            "metric_missing_interpreted_as_zero": False,
            **evidence,
        },
        [action],
        "Re-query the same metrics and verify representative invocations after the reviewed change.",
        resource_ref=_resource_ref(function, name, region),
        evidence_source="aws_cloudwatch_metric",
    )


def _resource(name: str) -> str:
    return f"lambda://function/{quote(name, safe='._-')}"


def _resource_ref(function: Dict[str, Any], name: str, region: str) -> ResourceRef:
    arn = str(function.get("arn") or "").strip() or None
    account_id = arn.split(":", 5)[4] if arn and arn.count(":") >= 5 else None
    return ResourceRef(
        provider="aws",
        service="lambda",
        resource_type="aws.lambda.function",
        resource_id=name,
        region=region,
        account_id=account_id,
        arn=arn,
        display_name=name,
    )
