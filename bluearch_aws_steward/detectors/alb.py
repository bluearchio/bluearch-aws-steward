from __future__ import annotations

import time
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping

from bluearch_aws_steward.detectors.aws_common import cost_evidence, tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, Rule, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError
from bluearch_aws_steward.signals import CloudWatchSignalAdapter, MetricSignalQuery


def scan_alb(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "alb", rule_filter)
    detectors = tuple(context.rules)
    response = context.read(detectors, "elbv2.describe_load_balancers") if detectors else None
    load_balancers = [
        item
        for item in (response or {}).get("LoadBalancers") or []
        if str(item.get("Type") or "application") == "application"
    ]
    load_balancers = _without_exemptions(
        context,
        load_balancers,
        (policy or ScanPolicy()).exclude_tags,
    )
    findings: List[Finding] = []
    listeners_by_arn = _load_listeners(context, load_balancers)

    _scan_access_logging(context, load_balancers, findings, region)
    _scan_https(context, load_balancers, listeners_by_arn, findings, region)
    _scan_tls(context, load_balancers, listeners_by_arn, findings, region)
    _scan_certificates(context, load_balancers, listeners_by_arn, findings, region)
    target_group_count = _scan_target_health(context, load_balancers, findings, region)
    _scan_idle(client, context, load_balancers, findings, region)

    return build_scan_result(
        service="alb",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(load_balancers) + target_group_count,
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _without_exemptions(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    exclusions: Dict[str, str],
) -> List[Dict[str, Any]]:
    if not exclusions or not load_balancers:
        return load_balancers
    tags_by_arn: Dict[str, Dict[str, str]] = {}
    detectors = tuple(context.rules)
    for offset in range(0, len(load_balancers), 20):
        arns = [
            str(item.get("LoadBalancerArn"))
            for item in load_balancers[offset : offset + 20]
            if item.get("LoadBalancerArn")
        ]
        response = context.read(detectors, "elbv2.describe_tags", ResourceArns=arns)
        if response is None:
            return []
        for description in response.get("TagDescriptions") or []:
            tags_by_arn[str(description.get("ResourceArn") or "")] = tags_dict(
                description.get("Tags") or []
            )
    return [
        item
        for item in load_balancers
        if not resource_is_exempt(
            tags_by_arn.get(str(item.get("LoadBalancerArn") or ""), {}),
            exclusions,
        )
    ]


def _load_listeners(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
) -> Dict[str, List[Dict[str, Any]]]:
    listener_detectors = (
        "alb_https_listener_missing",
        "alb_weak_tls_policy",
        "alb_certificate_expiring",
    )
    if not any(context.rule(detector) for detector in listener_detectors):
        return {}
    listeners_by_arn: Dict[str, List[Dict[str, Any]]] = {}
    for load_balancer in load_balancers:
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        response = context.read(
            listener_detectors,
            "elbv2.describe_listeners",
            LoadBalancerArn=arn,
        )
        listeners_by_arn[arn] = list((response or {}).get("Listeners") or [])
    return listeners_by_arn


def _scan_access_logging(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("alb_access_logging_disabled")
    if not rule:
        return
    pending: List[Finding] = []
    for load_balancer in load_balancers:
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        response = context.read(
            "alb_access_logging_disabled",
            "elbv2.describe_load_balancer_attributes",
            LoadBalancerArn=arn,
        )
        attributes = {
            str(item.get("Key")): str(item.get("Value") or "")
            for item in (response or {}).get("Attributes") or []
        }
        if attributes.get("access_logs.s3.enabled", "false").lower() == "true":
            continue
        name = _name(load_balancer)
        pending.append(
            finding_from_rule(
                rule,
                f"alb://load-balancer/{name}",
                {
                    "load_balancer_arn": arn,
                    "scheme": load_balancer.get("Scheme"),
                    "access_logging_enabled": False,
                    "destination_present": bool(attributes.get("access_logs.s3.bucket")),
                },
                [
                    "Select an existing reviewed S3 bucket and prefix in the same Region.",
                    "Validate bucket ownership, delivery permissions, retention, and cost.",
                    "Enable access logging only after those preconditions pass.",
                ],
                "Re-read load balancer attributes and confirm access_logs.s3.enabled is true.",
                resource_ref=_resource_ref(load_balancer, region),
            )
        )
    if context.rule("alb_access_logging_disabled"):
        findings.extend(pending)


def _scan_https(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    listeners_by_arn: Dict[str, List[Dict[str, Any]]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("alb_https_listener_missing")
    if not rule:
        return
    for load_balancer in load_balancers:
        if load_balancer.get("Scheme") != "internet-facing":
            continue
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        protocols = {
            str(listener.get("Protocol") or "").upper()
            for listener in listeners_by_arn.get(arn, [])
        }
        if "HTTP" not in protocols or "HTTPS" in protocols:
            continue
        findings.append(
            finding_from_rule(
                rule,
                f"alb://load-balancer/{_name(load_balancer)}",
                {
                    "load_balancer_arn": arn,
                    "scheme": "internet-facing",
                    "listener_protocols": sorted(protocols),
                    "https_listener_present": False,
                },
                [
                    "Inventory clients, domains, certificates, listener rules, and health checks.",
                    "Create and test a reviewed HTTPS listener.",
                    "Redirect HTTP only after client compatibility and rollback are confirmed.",
                ],
                "Describe listeners and confirm HTTPS is present with the reviewed certificate and policy.",
                resource_ref=_resource_ref(load_balancer, region),
            )
        )


def _scan_tls(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    listeners_by_arn: Dict[str, List[Dict[str, Any]]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("alb_weak_tls_policy")
    if not rule:
        return
    policy_names = sorted(
        {
            str(listener.get("SslPolicy"))
            for listeners in listeners_by_arn.values()
            for listener in listeners
            if listener.get("Protocol") == "HTTPS" and listener.get("SslPolicy")
        }
    )
    response = (
        context.read(
            "alb_weak_tls_policy",
            "elbv2.describe_ssl_policies",
            Names=policy_names,
        )
        if policy_names
        else {"SslPolicies": []}
    )
    policies = {
        str(policy.get("Name")): policy for policy in (response or {}).get("SslPolicies") or []
    }
    if not context.rule("alb_weak_tls_policy"):
        return
    for load_balancer in load_balancers:
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        for listener in listeners_by_arn.get(arn, []):
            if str(listener.get("Protocol") or "").upper() != "HTTPS":
                continue
            name = str(listener.get("SslPolicy") or "")
            protocols = set(policies.get(name, {}).get("SslProtocols") or [])
            weak_protocols = sorted(protocols & {"TLSv1", "TLSv1.0", "TLSv1.1"})
            if not weak_protocols:
                continue
            findings.append(
                finding_from_rule(
                    rule,
                    f"alb://listener/{str(listener.get('ListenerArn') or '').rsplit('/', 1)[-1]}",
                    {
                        "load_balancer_arn": arn,
                        "listener_arn": listener.get("ListenerArn"),
                        "security_policy": name,
                        "weak_protocols": weak_protocols,
                    },
                    [
                        "Inventory client TLS capabilities and current handshake failures.",
                        "Test a policy requiring TLS 1.2 or newer outside production.",
                        "Update the listener only through an approved traffic change.",
                    ],
                    "Describe the listener policy and confirm no protocol older than TLS 1.2 is enabled.",
                    resource_ref=_resource_ref(load_balancer, region),
                )
            )


def _scan_certificates(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    listeners_by_arn: Dict[str, List[Dict[str, Any]]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("alb_certificate_expiring")
    if not rule:
        return
    warning_days = int(rule.parameters.get("warning_days", 30))
    critical_days = int(rule.parameters.get("critical_days", 7))
    pending: List[Finding] = []
    bindings_by_certificate: Dict[str, List[Dict[str, Any]]] = {}
    for load_balancer in load_balancers:
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        for listener in listeners_by_arn.get(arn, []):
            if str(listener.get("Protocol") or "").upper() != "HTTPS":
                continue
            listener_arn = str(listener.get("ListenerArn") or "")
            response = context.read(
                "alb_certificate_expiring",
                "elbv2.describe_listener_certificates",
                ListenerArn=listener_arn,
            )
            bindings = list((response or {}).get("Certificates") or [])
            for binding in bindings:
                certificate_arn = str(binding.get("CertificateArn") or "")
                if ":acm:" not in certificate_arn:
                    continue
                association = {
                    "listener_arn": listener_arn,
                    "load_balancer_arn": arn,
                    "load_balancer_name": _name(load_balancer),
                    "is_default": bool(binding.get("IsDefault")),
                }
                current = bindings_by_certificate.setdefault(certificate_arn, [])
                if association not in current:
                    current.append(association)

    for certificate_arn, associations in sorted(bindings_by_certificate.items()):
        response = context.read(
            "alb_certificate_expiring",
            "acm.describe_certificate",
            CertificateArn=certificate_arn,
        )
        certificate = (response or {}).get("Certificate") or {}
        days_remaining = _days_until(certificate.get("NotAfter"))
        if days_remaining is None or days_remaining > warning_days:
            continue
        severity_rule: Rule = (
            replace(rule, severity="high") if days_remaining <= critical_days else rule
        )
        certificate_id = certificate_arn.rsplit("/", 1)[-1]
        first_association = associations[0]
        pending.append(
            finding_from_rule(
                severity_rule,
                f"acm://certificate/{certificate_id}",
                {
                    "certificate_arn": certificate_arn,
                    "listener_arn": first_association["listener_arn"],
                    "load_balancer_arn": first_association["load_balancer_arn"],
                    "listener_binding_count": len(associations),
                    "listener_bindings": associations,
                    "days_until_expiration": days_remaining,
                    "not_after": _iso_timestamp(certificate.get("NotAfter")),
                    "renewal_eligibility": certificate.get("RenewalEligibility"),
                },
                [
                    "Confirm certificate ownership, validation records, domains, and renewal method.",
                    "Renew or replace the certificate before expiration.",
                    "Validate every listener binding and TLS hostname after the change.",
                ],
                "Describe the active certificate and confirm its new expiration and every listener binding.",
                resource_ref=ResourceRef(
                    provider="aws",
                    service="acm",
                    resource_type="aws.acm.certificate",
                    resource_id=certificate_id,
                    region=region,
                    account_id=_account_id(certificate_arn),
                    arn=certificate_arn,
                    display_name=certificate_id,
                ),
            )
        )
    if context.rule("alb_certificate_expiring"):
        findings.extend(pending)


def _scan_target_health(
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> int:
    rule = context.rule("alb_unhealthy_targets")
    if not rule:
        return 0
    pending: List[Finding] = []
    target_group_count = 0
    for load_balancer in load_balancers:
        load_balancer_arn = str(load_balancer.get("LoadBalancerArn") or "")
        response = context.read(
            "alb_unhealthy_targets",
            "elbv2.describe_target_groups",
            LoadBalancerArn=load_balancer_arn,
        )
        target_groups = list((response or {}).get("TargetGroups") or [])
        target_group_count += len(target_groups)
        for target_group in target_groups:
            target_group_arn = str(target_group.get("TargetGroupArn") or "")
            health = context.read(
                "alb_unhealthy_targets",
                "elbv2.describe_target_health",
                TargetGroupArn=target_group_arn,
            )
            unhealthy = [
                description
                for description in (health or {}).get("TargetHealthDescriptions") or []
                if ((description.get("TargetHealth") or {}).get("State") == "unhealthy")
            ]
            if not unhealthy:
                continue
            target_group_name = str(
                target_group.get("TargetGroupName") or target_group_arn.rsplit("/", 1)[-1]
            )
            pending.append(
                finding_from_rule(
                    rule,
                    f"alb://target-group/{target_group_name}",
                    {
                        "target_group_arn": target_group_arn,
                        "load_balancer_arn": load_balancer_arn,
                        "unhealthy_target_count": len(unhealthy),
                        "unhealthy_targets": [
                            {
                                "id": (item.get("Target") or {}).get("Id"),
                                "port": (item.get("Target") or {}).get("Port"),
                                "reason": (item.get("TargetHealth") or {}).get("Reason"),
                            }
                            for item in unhealthy[:20]
                        ],
                    },
                    [
                        "Inspect health-check configuration, application logs, networking, and target capacity.",
                        "Restore target health before changing registration or routing.",
                        "Apply traffic changes only with an approved rollback plan.",
                    ],
                    "Describe target health and confirm every expected registered target is healthy.",
                    resource_ref=ResourceRef(
                        provider="aws",
                        service="elasticloadbalancing",
                        resource_type="aws.elbv2.target-group",
                        resource_id=target_group_name,
                        region=region,
                        account_id=_account_id(target_group_arn),
                        arn=target_group_arn,
                        display_name=target_group_name,
                    ),
                )
            )
    if context.rule("alb_unhealthy_targets"):
        findings.extend(pending)
    return target_group_count


def _scan_idle(
    client: AwsProvider,
    context: EvaluationContext,
    load_balancers: List[Dict[str, Any]],
    findings: List[Finding],
    region: str,
) -> None:
    rule = context.rule("alb_idle_load_balancer")
    if not rule:
        return
    lookback_days = int(rule.parameters.get("lookback_days", 7))
    maximum = float(rule.parameters.get("maximum_daily_requests", 100))
    queries = [
        MetricSignalQuery(
            key=str(load_balancer.get("LoadBalancerArn")),
            namespace="AWS/ApplicationELB",
            metric_name="RequestCount",
            dimensions=(("LoadBalancer", _metric_dimension(load_balancer)),),
            statistic="Sum",
            lookback_days=lookback_days,
        )
        for load_balancer in load_balancers
        if load_balancer.get("LoadBalancerArn")
    ]
    try:
        metrics = CloudWatchSignalAdapter(client).read(queries)
    except AwsProviderError as exc:
        context.fail("alb_idle_load_balancer", "cloudwatch.get_metric_data", exc.detail or str(exc))
        return
    pending: List[Finding] = []
    for load_balancer in load_balancers:
        arn = str(load_balancer.get("LoadBalancerArn") or "")
        if not arn:
            continue
        series = metrics[arn]
        if (
            not series.complete
            or len(series.values) < lookback_days
            or any(value >= maximum for value in series.values)
        ):
            continue
        pending.append(
            finding_from_rule(
                rule,
                f"alb://load-balancer/{_name(load_balancer)}",
                {
                    "load_balancer_arn": arn,
                    "lookback_days": lookback_days,
                    "maximum_daily_request_count": max(series.values),
                    "threshold_daily_requests": maximum,
                    "metric_datapoints": len(series.values),
                    "metric_missing_interpreted_as_zero": False,
                    "cost_estimate": cost_evidence(
                        "usage_evidence",
                        "CloudWatch request counts stayed below the reviewed idle threshold for the complete lookback window.",
                    ),
                },
                [
                    "Confirm DNS records, listeners, target groups, clients, and resource ownership.",
                    "Estimate fixed and capacity-unit cost using account pricing.",
                    "Delete only through a separately approved change with rollback.",
                ],
                "After the approved change, verify DNS, traffic, and dependent workloads remain healthy.",
                resource_ref=_resource_ref(load_balancer, region),
                evidence_source="aws_cloudwatch_metric",
            )
        )
    if context.rule("alb_idle_load_balancer"):
        findings.extend(pending)


def _name(load_balancer: Mapping[str, Any]) -> str:
    return str(load_balancer.get("LoadBalancerName") or "unknown")


def _account_id(arn: str) -> str | None:
    return arn.split(":", 5)[4] if arn.count(":") >= 5 else None


def _resource_ref(load_balancer: Mapping[str, Any], region: str) -> ResourceRef:
    arn = str(load_balancer.get("LoadBalancerArn") or "")
    return ResourceRef(
        provider="aws",
        service="elasticloadbalancing",
        resource_type="aws.elbv2.load-balancer",
        resource_id=_name(load_balancer),
        region=region,
        account_id=_account_id(arn),
        arn=arn or None,
        display_name=_name(load_balancer),
    )


def _metric_dimension(load_balancer: Mapping[str, Any]) -> str:
    arn = str(load_balancer.get("LoadBalancerArn") or "")
    marker = "loadbalancer/"
    return arn.split(marker, 1)[1] if marker in arn else arn


def _days_until(value: Any) -> int | None:
    if value is None:
        return None
    try:
        parsed = (
            value
            if isinstance(value, datetime)
            else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        )
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return int(
        (parsed.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds() // 86400
    )


def _iso_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value)
