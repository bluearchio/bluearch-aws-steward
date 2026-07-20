from __future__ import annotations

import os
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from threading import Event
from typing import Callable, Dict, List, Tuple

from bluearch_aws_steward.catalog import filter_rules
from bluearch_aws_steward.catalog_registry import build_scan_detection_coverage
from bluearch_aws_steward.detectors.alb import scan_alb
from bluearch_aws_steward.detectors.api_gateway import scan_api_gateway
from bluearch_aws_steward.detectors.cloudtrail import scan_cloudtrail
from bluearch_aws_steward.detectors.cloudwatch import scan_cloudwatch
from bluearch_aws_steward.detectors.common import parse_rule_filter
from bluearch_aws_steward.detectors.dynamodb import scan_dynamodb
from bluearch_aws_steward.detectors.ec2 import scan_ec2
from bluearch_aws_steward.detectors.ecs import scan_ecs
from bluearch_aws_steward.detectors.efs import scan_efs
from bluearch_aws_steward.detectors.iam import scan_iam
from bluearch_aws_steward.detectors.kms import scan_kms
from bluearch_aws_steward.detectors.lambda_service import scan_lambda
from bluearch_aws_steward.detectors.rds import scan_rds
from bluearch_aws_steward.detectors.s3 import scan_s3
from bluearch_aws_steward.detectors.secrets_manager import scan_secrets_manager
from bluearch_aws_steward.detectors.sns import scan_sns
from bluearch_aws_steward.detectors.sqs import scan_sqs
from bluearch_aws_steward.models import ScanResult, utc_now_iso
from bluearch_aws_steward.policy import ScanPolicy
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError

Scanner = Callable[..., ScanResult]


@dataclass(frozen=True)
class CollectorSpec:
    service: str
    scanner: Scanner
    accepts_bucket_prefix: bool = False
    accepts_policy: bool = False
    aliases: Tuple[str, ...] = ()


COLLECTORS: Dict[str, CollectorSpec] = {
    "iam": CollectorSpec("iam", scan_iam, accepts_policy=True),
    "cloudtrail": CollectorSpec("cloudtrail", scan_cloudtrail),
    "cloudwatch": CollectorSpec("cloudwatch", scan_cloudwatch, accepts_policy=True),
    "dynamodb": CollectorSpec("dynamodb", scan_dynamodb, accepts_policy=True),
    "s3": CollectorSpec("s3", scan_s3, accepts_bucket_prefix=True, accepts_policy=True),
    "ec2": CollectorSpec("ec2", scan_ec2, accepts_policy=True, aliases=("ebs", "networking")),
    "rds": CollectorSpec("rds", scan_rds, accepts_policy=True),
    "lambda": CollectorSpec("lambda", scan_lambda, accepts_policy=True),
    "efs": CollectorSpec("efs", scan_efs, accepts_policy=True),
    "ecs": CollectorSpec("ecs", scan_ecs, accepts_policy=True),
    "alb": CollectorSpec("alb", scan_alb, accepts_policy=True),
    "kms": CollectorSpec("kms", scan_kms, accepts_policy=True),
    "secrets-manager": CollectorSpec("secrets-manager", scan_secrets_manager, accepts_policy=True),
    "sns": CollectorSpec("sns", scan_sns, accepts_policy=True),
    "sqs": CollectorSpec("sqs", scan_sqs, accepts_policy=True),
    "api-gateway": CollectorSpec("api-gateway", scan_api_gateway, accepts_policy=True),
}
SERVICE_ALIASES = {
    alias: service for service, collector in COLLECTORS.items() for alias in collector.aliases
}
AWS_SCAN_SERVICES = tuple(COLLECTORS)
AWS_SCAN_SERVICE_CHOICES = ("all",) + AWS_SCAN_SERVICES + tuple(SERVICE_ALIASES)
AWS_GLOBAL_SERVICES = ("iam", "s3")
DEFAULT_SERVICE_WORKERS = 4


def run_aws_scan(
    client: AwsProvider,
    *,
    service: str,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str,
    bucket_prefix: str | None = None,
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
    progress_callback: Callable[[Dict[str, object]], None] | None = None,
    partial_callback: Callable[[ScanResult], None] | None = None,
    cancel_event: Event | None = None,
) -> ScanResult:
    requested_service = service
    normalized_service = SERVICE_ALIASES.get(service, service)
    if service not in AWS_SCAN_SERVICE_CHOICES:
        supported = ", ".join(AWS_SCAN_SERVICE_CHOICES)
        raise ValueError(f"Unsupported service: {service}. Supported services: {supported}")

    services = _services_for_scan(normalized_service, rule_filter)
    started_at = time.monotonic()
    if len(services) == 1:
        selected_service = services[0]
        _emit_progress(
            progress_callback,
            phase="scanning",
            current_service=selected_service,
            services_total=1,
            services_completed=0,
            findings_discovered=0,
            resources_scanned=0,
        )
        _raise_if_cancelled(cancel_event)
        result = _scan_one(
            selected_service,
            client,
            profile=profile,
            endpoint_url=endpoint_url,
            region=region,
            provider=provider,
            bucket_prefix=bucket_prefix,
            rule_filter=rule_filter,
            policy=policy,
        )
        result.summary["policy_overrides"] = policy.to_dict() if policy else {}
        _add_detection_coverage(result, requested_service, services, rule_filter)
        _emit_partial(partial_callback, result)
        _emit_progress(
            progress_callback,
            phase="scanning",
            current_service=selected_service,
            services_total=1,
            services_completed=1,
            findings_discovered=len(result.findings),
            resources_scanned=int(result.summary.get("resources_scanned") or 0),
        )
        return result

    results: Dict[str, ScanResult] = {}
    service_errors: List[Dict[str, object]] = []
    worker_count = _service_worker_count(len(services))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures: Dict[Future[ScanResult], str] = {}
        for selected_service in services:
            if cancel_event and cancel_event.is_set():
                break
            _emit_progress(
                progress_callback,
                phase="scanning",
                current_service=selected_service,
                services_total=len(services),
                services_completed=0,
                findings_discovered=0,
                resources_scanned=0,
            )
            futures[
                executor.submit(
                    _scan_one,
                    selected_service,
                    client,
                    profile=profile,
                    endpoint_url=endpoint_url,
                    region=region,
                    provider=provider,
                    bucket_prefix=bucket_prefix,
                    rule_filter=rule_filter,
                    policy=policy,
                )
            ] = selected_service

        for future in as_completed(futures):
            selected_service = futures[future]
            if cancel_event and cancel_event.is_set():
                for pending in futures:
                    pending.cancel()
            try:
                results[selected_service] = future.result()
            except AwsProviderError as exc:
                service_errors.append(
                    {
                        "service": selected_service,
                        "error_type": "aws_provider",
                        "detail": exc.detail or str(exc),
                    }
                )
            except Exception as exc:  # pragma: no cover - service isolation
                service_errors.append(
                    {
                        "service": selected_service,
                        "error_type": exc.__class__.__name__,
                        "detail": str(exc),
                    }
                )

            ordered_results = [results[name] for name in services if name in results]
            partial = _aggregate_results(
                ordered_results,
                service_errors,
                requested_service=requested_service,
                services=services,
                profile=profile,
                endpoint_url=endpoint_url,
                region=region,
                provider=provider,
                bucket_prefix=bucket_prefix,
                rule_filter=rule_filter,
                policy=policy,
                started_at=started_at,
                partial=len(results) + len(service_errors) < len(services),
                cancelled=bool(cancel_event and cancel_event.is_set()),
                worker_count=worker_count,
            )
            _emit_partial(partial_callback, partial)
            _emit_progress(
                progress_callback,
                phase="scanning",
                current_service=selected_service,
                services_total=len(services),
                services_completed=len(results) + len(service_errors),
                findings_discovered=len(partial.findings),
                resources_scanned=int(partial.summary.get("resources_scanned") or 0),
                service_errors=len(service_errors),
            )

    ordered_results = [results[name] for name in services if name in results]
    return _aggregate_results(
        ordered_results,
        service_errors,
        requested_service=requested_service,
        services=services,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        provider=provider,
        bucket_prefix=bucket_prefix,
        rule_filter=rule_filter,
        policy=policy,
        started_at=started_at,
        partial=False,
        cancelled=bool(cancel_event and cancel_event.is_set()),
        worker_count=worker_count,
    )


def _aggregate_results(
    results: List[ScanResult],
    service_errors: List[Dict[str, object]],
    *,
    requested_service: str,
    services: List[str],
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str,
    bucket_prefix: str | None,
    rule_filter: str | None,
    policy: ScanPolicy | None,
    started_at: float,
    partial: bool,
    cancelled: bool,
    worker_count: int,
) -> ScanResult:
    findings = [finding for result in results for finding in result.findings]
    rules_skipped = [
        {"service": result.service, **item}
        for result in results
        for item in result.summary.get("rules_skipped") or []
    ]
    capability_errors = [
        {"service": result.service, **item}
        for result in results
        for item in result.summary.get("capability_errors") or []
    ]
    scan_errors = len(service_errors) + sum(
        int(result.summary.get("scan_errors") or 0) for result in results
    )
    payload = ScanResult(
        schema_version="0.2",
        generated_at=utc_now_iso(),
        service="all",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        findings=findings,
        summary={
            "resources_scanned": sum(
                int(result.summary.get("resources_scanned") or 0) for result in results
            ),
            "resources_matched": len({finding.resource for finding in findings}),
            "findings": len(findings),
            "rules_evaluated": sum(
                int(result.summary.get("rules_evaluated") or 0) for result in results
            ),
            "bucket_prefix": bucket_prefix,
            "rule_filter": rule_filter,
            "scan_errors": scan_errors,
            "scan_error_samples": _scan_error_samples(results, service_errors),
            "rules_skipped": rules_skipped,
            "capability_errors": capability_errors,
            "duration_seconds": round(time.monotonic() - started_at, 2),
            "services_requested": services,
            "services_scanned": [result.service for result in results],
            "services_pending": [
                item
                for item in services
                if item not in {result.service for result in results}
                and item not in {error.get("service") for error in service_errors}
            ],
            "service_errors": list(service_errors),
            "service_summaries": {result.service: result.summary for result in results},
            "policy_overrides": policy.to_dict() if policy else {},
            "partial": partial,
            "cancelled": cancelled,
            "worker_count": worker_count,
        },
    )
    _add_detection_coverage(payload, requested_service, services, rule_filter)
    return payload


def _scan_error_samples(
    results: List[ScanResult],
    service_errors: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    samples: List[Dict[str, object]] = [dict(item) for item in service_errors]
    for result in results:
        for item in result.summary.get("scan_error_samples") or []:
            samples.append({"service": result.service, **item})
    return samples[:10]


def _add_detection_coverage(
    result: ScanResult,
    requested_service: str,
    services: List[str],
    rule_filter: str | None,
) -> None:
    result.summary["detection_coverage"] = build_scan_detection_coverage(
        requested_service=requested_service,
        services_requested=services,
        rule_filter=rule_filter,
        automated_rules_evaluated=int(result.summary.get("rules_evaluated") or 0),
        scan_errors=int(result.summary.get("scan_errors") or 0),
    )


def _emit_progress(
    callback: Callable[[Dict[str, object]], None] | None,
    **update: object,
) -> None:
    if callback is None:
        return
    try:
        callback(dict(update))
    except Exception:
        return


def _emit_partial(callback: Callable[[ScanResult], None] | None, result: ScanResult) -> None:
    if callback is None:
        return
    try:
        callback(result)
    except Exception:
        return


def _raise_if_cancelled(cancel_event: Event | None) -> None:
    if cancel_event and cancel_event.is_set():
        raise RuntimeError("Assessment cancelled before scanning started.")


def _service_worker_count(service_count: int) -> int:
    raw = os.environ.get("BLUEARCH_STEWARD_SERVICE_WORKERS")
    try:
        configured = int(raw) if raw else DEFAULT_SERVICE_WORKERS
    except ValueError:
        configured = DEFAULT_SERVICE_WORKERS
    return max(1, min(configured, service_count))


def _scan_one(service: str, client: AwsProvider, **kwargs: object) -> ScanResult:
    collector = COLLECTORS[service]
    if not collector.accepts_bucket_prefix:
        kwargs.pop("bucket_prefix", None)
    if not collector.accepts_policy:
        kwargs.pop("policy", None)
    return collector.scanner(client, **kwargs)


def _services_for_scan(service: str, rule_filter: str | None) -> List[str]:
    if service != "all":
        return [SERVICE_ALIASES.get(service, service)]
    filters = parse_rule_filter(rule_filter)
    if not filters:
        return list(AWS_SCAN_SERVICES)

    matching_services = []
    for candidate in AWS_SCAN_SERVICES:
        rules = filter_rules(service=candidate)
        if any(filters & {rule.short_id, rule.id, rule.detector} for rule in rules):
            matching_services.append(candidate)
    if matching_services:
        return matching_services

    allowed = ", ".join(sorted(rule.short_id for rule in filter_rules()))
    raise ValueError(
        f"No executable rules matched rule_filter={rule_filter!r}. Supported rules: {allowed}"
    )
