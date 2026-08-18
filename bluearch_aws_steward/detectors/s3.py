from __future__ import annotations

import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from fnmatch import fnmatchcase
from typing import Any, Dict, Iterator, List

from bluearch_aws_steward.catalog import filter_rules
from bluearch_aws_steward.detectors.aws_common import tags_dict
from bluearch_aws_steward.detectors.common import supported_rules_by_detector
from bluearch_aws_steward.models import (
    Finding,
    RemediationPlan,
    ResourceRef,
    Rule,
    ScanEvent,
    ScanResult,
    utc_now_iso,
)
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider, AwsProviderError

DEFAULT_S3_WORKERS = 24


def scan_s3(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    bucket_prefix: str | None = None,
    max_workers: int | None = None,
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    final_result: ScanResult | None = None
    for event in iter_s3_scan_events(
        client,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        provider=provider,
        bucket_prefix=bucket_prefix,
        max_workers=max_workers,
        rule_filter=rule_filter,
        policy=policy,
    ):
        if event.type == "scan_completed":
            final_result = event.result
    if final_result is None:
        raise RuntimeError("S3 scan did not produce a final result.")
    return final_result


def iter_s3_scan_events(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    bucket_prefix: str | None = None,
    max_workers: int | None = None,
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> Iterator[ScanEvent]:
    rules, rules_skipped = supported_rules_by_detector(client, "s3", rule_filter)
    buckets = client.list_buckets()
    if bucket_prefix:
        buckets = [bucket for bucket in buckets if bucket.startswith(bucket_prefix)]
    findings: List[Finding] = []
    scan_errors: List[Dict[str, Any]] = []
    capability_errors: List[Dict[str, Any]] = []
    failed_rule_ids: set[str] = set()
    started_at = time.monotonic()
    worker_count = _worker_count(len(buckets), max_workers)
    exclusions = (policy or ScanPolicy()).exclude_tags

    yield ScanEvent(
        type="scan_started",
        timestamp=utc_now_iso(),
        service="s3",
        message="S3 scan started.",
        data={
            "resources_total": len(buckets),
            "rules_evaluated": len(rules),
            "profile": profile,
            "endpoint_url": endpoint_url,
            "region": region,
            "provider": provider,
            "bucket_prefix": bucket_prefix,
            "worker_count": worker_count,
            "rule_filter": rule_filter,
        },
    )

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_by_bucket = {}
        for bucket in buckets:
            resource = f"s3://{bucket}"
            yield ScanEvent(
                type="resource_started",
                timestamp=utc_now_iso(),
                service="s3",
                resource=resource,
                message=f"Scanning {resource}",
            )
            future_by_bucket[
                executor.submit(_scan_bucket_safe, client, bucket, rules, region, exclusions)
            ] = bucket

        for future in as_completed(future_by_bucket):
            bucket = future_by_bucket[future]
            resource = f"s3://{bucket}"
            resource_findings, scan_error, rule_errors = future.result()
            capability_errors.extend(rule_errors)
            failed_rule_ids.update(
                str(item.get("rule_id")) for item in rule_errors if item.get("rule_id")
            )
            if scan_error:
                scan_errors.append(scan_error)
                yield ScanEvent(
                    type="resource_error",
                    timestamp=utc_now_iso(),
                    service="s3",
                    resource=resource,
                    message=f"Could not inspect {resource}",
                    data=scan_error,
                )
            else:
                findings.extend(resource_findings)
                for finding in resource_findings:
                    yield ScanEvent(
                        type="finding",
                        timestamp=utc_now_iso(),
                        service="s3",
                        resource=resource,
                        finding=finding,
                        message=f"{finding.severity} finding on {resource}",
                    )
            yield ScanEvent(
                type="resource_completed",
                timestamp=utc_now_iso(),
                service="s3",
                resource=resource,
                message=f"Completed {resource}",
                data={
                    "findings": len(resource_findings),
                    "status": "error" if scan_error else "fail" if resource_findings else "pass",
                },
            )

    if failed_rule_ids:
        findings = [finding for finding in findings if finding.rule_id not in failed_rule_ids]
    failed_rules = [rule for rule in rules.values() if rule.id in failed_rule_ids]
    runtime_skips = [
        {
            "rule": rule.short_id,
            "reason": "aws_read_failed",
        }
        for rule in failed_rules
    ]
    result = ScanResult(
        schema_version="0.2",
        generated_at=utc_now_iso(),
        service="s3",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        findings=findings,
        summary={
            "resources_scanned": len(buckets),
            "resources_matched": len({finding.resource for finding in findings}),
            "findings": len(findings),
            "rules_evaluated": len(rules) - len(failed_rules),
            "bucket_prefix": bucket_prefix,
            "rule_filter": rule_filter,
            "scan_errors": len(scan_errors),
            "scan_error_samples": scan_errors[:10],
            "rules_skipped": [*rules_skipped, *runtime_skips],
            "capability_errors": capability_errors[:20],
            "duration_seconds": round(time.monotonic() - started_at, 2),
            "worker_count": worker_count,
        },
    )
    yield ScanEvent(
        type="scan_completed",
        timestamp=utc_now_iso(),
        service="s3",
        result=result,
        message="S3 scan completed.",
        data=result.summary,
    )


def _worker_count(bucket_count: int, max_workers: int | None) -> int:
    if bucket_count <= 0:
        return 1
    if max_workers is None:
        raw_value = os.environ.get("BLUEARCH_STEWARD_S3_WORKERS")
        if raw_value:
            try:
                max_workers = int(raw_value)
            except ValueError:
                max_workers = DEFAULT_S3_WORKERS
        else:
            max_workers = DEFAULT_S3_WORKERS
    return max(1, min(max_workers, bucket_count))


def _rules_by_detector(rule_filter: str | None) -> Dict[str, Rule]:
    selected_rules = filter_rules(service="s3")
    filters = _parse_rule_filter(rule_filter)
    if filters:
        selected_rules = [
            rule
            for rule in selected_rules
            if rule.short_id in filters or rule.id in filters or rule.detector in filters
        ]
        if not selected_rules:
            allowed = ", ".join(sorted(rule.short_id for rule in filter_rules(service="s3")))
            raise ValueError(
                f"No S3 rules matched rule_filter={rule_filter!r}. Supported rules: {allowed}"
            )
    return {rule.detector: rule for rule in selected_rules}


def _parse_rule_filter(rule_filter: str | None) -> set[str]:
    if not rule_filter:
        return set()
    return {part.strip() for part in rule_filter.split(",") if part.strip()}


def _scan_bucket_safe(
    client: AwsProvider,
    bucket: str,
    rules: Dict[str, Rule],
    region: str,
    exclusions: Dict[str, str],
) -> tuple[List[Finding], Dict[str, Any] | None, List[Dict[str, Any]]]:
    try:
        findings, capability_errors = _scan_bucket(client, bucket, rules, region, exclusions)
        return findings, None, capability_errors
    except AwsProviderError as exc:
        return (
            [],
            {
                "resource": f"s3://{bucket}",
                "error_type": "aws_provider",
                "detail": exc.detail or str(exc),
            },
            [],
        )
    except Exception as exc:  # pragma: no cover - defensive scan isolation
        return (
            [],
            {
                "resource": f"s3://{bucket}",
                "error_type": exc.__class__.__name__,
                "detail": str(exc),
            },
            [],
        )


def _scan_bucket(
    client: AwsProvider,
    bucket: str,
    rules: Dict[str, Rule],
    region: str,
    exclusions: Dict[str, str],
) -> tuple[List[Finding], List[Dict[str, Any]]]:
    findings: List[Finding] = []
    capability_errors: List[Dict[str, Any]] = []
    tag_detector_names = {
        "s3_object_lock_required",
        "s3_replication_required",
        "s3_kms_encryption_required",
    }
    bucket_tags: Dict[str, str] = {}
    if exclusions or tag_detector_names & set(rules):
        try:
            tagging = client.read("s3.get_bucket_tagging", Bucket=bucket)
        except AwsProviderError as exc:
            return [], [
                _capability_error(rules[name], bucket, "s3.get_bucket_tagging", exc)
                for name in tag_detector_names & set(rules)
            ]
        bucket_tags = tags_dict(tagging.get("TagSet") or [])
        if resource_is_exempt(bucket_tags, exclusions):
            return [], []
    policy_detector_names = {
        "s3_policy_all_actions_public",
        "s3_policy_public_delete",
        "s3_policy_public_read",
        "s3_tls_enforcement_missing",
        "s3_cloudtrail_access_logging_disabled",
    }

    if "s3_public_bucket" in rules or "s3_policy_public_read" in rules:
        public_access_block = client.get_public_access_block(bucket)
        public_access_block_complete = _public_access_block_complete(public_access_block)
    else:
        public_access_block = {}
        public_access_block_complete = None

    needs_bucket_policy = bool(policy_detector_names & set(rules)) or (
        "s3_public_bucket" in rules and not public_access_block_complete
    )
    bucket_policy = client.get_bucket_policy(bucket) if needs_bucket_policy else None
    public_policy = _policy_allows_public(bucket_policy)

    if "s3_public_bucket" in rules and public_policy and not public_access_block_complete:
        findings.append(
            _finding(
                rules["s3_public_bucket"],
                bucket,
                {
                    "public_policy_allows_public": public_policy,
                    "public_access_block": public_access_block,
                },
                [
                    "Set BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, and RestrictPublicBuckets to true.",
                    "Review bucket policy separately before removing statements.",
                ],
                "Re-read public access block and confirm all four controls are true.",
            )
        )

    all_actions_rule = rules.get("s3_policy_all_actions_public")
    if all_actions_rule:
        matches = _public_action_matches(bucket_policy, ("*", "s3:*"))
        if matches:
            findings.append(
                _finding(
                    all_actions_rule,
                    bucket,
                    {
                        "public_wildcard_actions": matches,
                        "public_access_block_complete": public_access_block_complete,
                    },
                    [
                        "Identify every principal and workload that depends on the public statement.",
                        "Replace wildcard actions and principals with the minimum required permissions.",
                        "Validate access before and after updating the bucket policy.",
                    ],
                    "Re-read the bucket policy and confirm no public Allow statement grants * or s3:* actions.",
                )
            )

    public_delete_rule = rules.get("s3_policy_public_delete")
    if public_delete_rule:
        matches = _public_action_matches(
            bucket_policy,
            ("s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket"),
        )
        if matches:
            findings.append(
                _finding(
                    public_delete_rule,
                    bucket,
                    {
                        "public_delete_actions": matches,
                        "public_access_block_complete": public_access_block_complete,
                    },
                    [
                        "Identify whether any external workflow intentionally depends on delete access.",
                        "Remove public delete actions and grant deletion only to reviewed identities.",
                        "Validate object retention, lifecycle, and recovery behavior before the change.",
                    ],
                    "Re-read the bucket policy and confirm no public Allow statement grants delete actions.",
                )
            )

    public_read_rule = rules.get("s3_policy_public_read")
    if public_read_rule:
        matches = [
            match
            for match in _public_action_matches(
                bucket_policy,
                ("s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"),
            )
            if any(action not in ("*", "s3:*") for action in match["actions"])
        ]
        if matches:
            findings.append(
                _finding(
                    public_read_rule,
                    bucket,
                    {
                        "public_read_actions": matches,
                        "public_access_block_complete": public_access_block_complete,
                    },
                    [
                        "Identify whether any consumer legitimately depends on anonymous reads.",
                        "Remove or narrowly scope the public read statements in the bucket policy.",
                        "Keep the public access block enabled; a public statement remains a latent exposure even while blocked.",
                    ],
                    "Re-read the bucket policy and confirm no public Allow statement grants read access.",
                )
            )

    tls_rule = rules.get("s3_tls_enforcement_missing")
    if tls_rule and not _policy_denies_insecure_transport(bucket_policy, bucket):
        findings.append(
            _finding(
                tls_rule,
                bucket,
                {
                    "bucket_policy_present": bool(bucket_policy),
                    "insecure_transport_deny_present": False,
                },
                [
                    "Review clients and integrations for TLS support.",
                    "Add a Deny statement for s3:* when aws:SecureTransport is false.",
                    "Apply the statement to both the bucket ARN and its object ARN pattern.",
                ],
                "Re-read the bucket policy and confirm it denies non-TLS requests for the bucket and objects.",
            )
        )

    if "s3_missing_default_encryption" in rules:
        encryption_rules = client.get_bucket_encryption_rules(bucket)
    else:
        encryption_rules = []

    if "s3_missing_default_encryption" in rules and not encryption_rules:
        findings.append(
            _finding(
                rules["s3_missing_default_encryption"],
                bucket,
                {"server_side_encryption_rules": encryption_rules},
                ["Enable default SSE-S3 or SSE-KMS encryption for the bucket."],
                "Re-read bucket encryption and confirm at least one encryption rule exists.",
            )
        )

    lifecycle_rule_names = {"s3_missing_lifecycle", "s3_storage_tiering_missing"}
    if lifecycle_rule_names & set(rules):
        lifecycle_rules = client.get_bucket_lifecycle_rules(bucket)
    else:
        lifecycle_rules = []

    if "s3_missing_lifecycle" in rules and not lifecycle_rules:
        lifecycle_rule = rules["s3_missing_lifecycle"]
        cost_evidence_required = bool(
            lifecycle_rule.parameters.get("cost_evidence_required", False)
        )
        advisory_without_cost_evidence = bool(
            lifecycle_rule.parameters.get("advisory_without_cost_evidence", True)
        )
        is_advisory = cost_evidence_required and advisory_without_cost_evidence
        findings.append(
            _finding(
                lifecycle_rule,
                bucket,
                {
                    "lifecycle_rules": lifecycle_rules,
                    "assessment": "advisory" if is_advisory else "finding",
                    "cost_estimate": {
                        "status": "insufficient" if cost_evidence_required else "not_required",
                        "estimated_monthly_cost_usd": None,
                        "estimated_monthly_savings_usd": None,
                        "confidence": "none",
                        "basis": (
                            "Lifecycle configuration alone does not prove meaningful storage savings."
                            if cost_evidence_required
                            else "Cost evidence is not required by this rule."
                        ),
                        "assumptions": [],
                    },
                },
                ["Add a lifecycle rule for older objects or configure Intelligent-Tiering."],
                "Re-read bucket lifecycle configuration and confirm at least one enabled rule exists.",
            )
        )

    tiering_rule = rules.get("s3_storage_tiering_missing")
    if (
        tiering_rule
        and lifecycle_rules
        and not _lifecycle_has_storage_optimization(
            lifecycle_rules,
            tuple(
                str(item)
                for item in tiering_rule.parameters.get(
                    "accepted_transition_storage_classes",
                    (),
                )
            ),
        )
    ):
        findings.append(
            _finding(
                tiering_rule,
                bucket,
                {
                    "lifecycle_rules": _summarize_lifecycle_rules(lifecycle_rules),
                    "storage_tiering_present": False,
                    "accepted_transition_storage_classes": list(
                        tiering_rule.parameters.get("accepted_transition_storage_classes", ())
                    ),
                    "assessment": "advisory",
                    "cost_estimate": {
                        "status": "insufficient",
                        "estimated_monthly_cost_usd": None,
                        "estimated_monthly_savings_usd": None,
                        "confidence": "none",
                        "basis": (
                            "Lifecycle structure shows no storage tiering action, but object age, "
                            "access frequency, and storage class evidence are not available."
                        ),
                        "assumptions": [],
                    },
                },
                [
                    "Review object age, access patterns, retention requirements, and retrieval cost.",
                    "Add a lifecycle transition, expiration, or Intelligent-Tiering policy for eligible objects.",
                    "Prefer an IaC patch when the bucket lifecycle is source controlled.",
                ],
                (
                    "Re-read bucket lifecycle configuration and confirm at least one enabled rule "
                    "transitions eligible objects to a lower-cost or Intelligent-Tiering storage class."
                ),
            )
        )

    mfa_rule = rules.get("s3_mfa_delete_disabled")
    if mfa_rule:
        try:
            versioning = client.read("s3.get_bucket_versioning", Bucket=bucket) or {}
            versioning_status = versioning.get("Status")
        except AwsProviderError as exc:
            capability_errors.append(
                _capability_error(mfa_rule, bucket, "s3.get_bucket_versioning", exc)
            )
            versioning = {}
            versioning_status = (
                client.get_bucket_versioning_status(bucket)
                if "s3_versioning_disabled" in rules
                else None
            )
    elif "s3_versioning_disabled" in rules:
        versioning = {}
        versioning_status = client.get_bucket_versioning_status(bucket)
    else:
        versioning = {}
        versioning_status = None

    if "s3_versioning_disabled" in rules and versioning_status != "Enabled":
        findings.append(
            _finding(
                rules["s3_versioning_disabled"],
                bucket,
                {"versioning_status": versioning_status},
                ["Enable bucket versioning."],
                "Re-read bucket versioning and confirm Status is Enabled.",
                region=region,
            )
        )

    logging_rule = rules.get("s3_server_access_logging_disabled")
    if logging_rule:
        try:
            logging = client.read("s3.get_bucket_logging", Bucket=bucket)
        except AwsProviderError as exc:
            capability_errors.append(
                _capability_error(logging_rule, bucket, "s3.get_bucket_logging", exc)
            )
            logging = None
        logging_enabled = logging.get("LoggingEnabled") if logging is not None else None
        if logging is not None and not logging_enabled:
            findings.append(
                _finding(
                    logging_rule,
                    bucket,
                    {"server_access_logging_enabled": False},
                    [
                        "Select an existing reviewed destination bucket and prefix.",
                        "Validate destination ownership, permissions, retention, and cost.",
                        "Enable server access logging only after those preconditions pass.",
                    ],
                    "Re-read bucket logging and confirm LoggingEnabled targets the reviewed destination.",
                    region=region,
                )
            )

    if mfa_rule:
        if versioning.get("Status") == "Enabled" and versioning.get("MFADelete") != "Enabled":
            findings.append(
                _finding(
                    mfa_rule,
                    bucket,
                    {
                        "versioning_status": "Enabled",
                        "mfa_delete_status": versioning.get("MFADelete") or "Disabled",
                    },
                    [
                        "Confirm the bucket owner root credentials and MFA device are available through an approved process.",
                        "Review automation and operational recovery procedures before enabling MFA Delete.",
                        "Enable MFA Delete manually with an authenticated root-account request.",
                    ],
                    "Re-read bucket versioning with an authorized principal and confirm MFADelete is Enabled.",
                    region=region,
                )
            )

    object_lock_rule = rules.get("s3_object_lock_required")
    if object_lock_rule and _required_tags_match(object_lock_rule, bucket_tags):
        object_lock = client.read("s3.get_object_lock_configuration", Bucket=bucket) or {}
        status = (object_lock.get("ObjectLockConfiguration") or {}).get("ObjectLockEnabled")
        if status != "Enabled":
            findings.append(
                _finding(
                    object_lock_rule,
                    bucket,
                    {
                        "object_lock_enabled": False,
                        "requirement_tags_matched": object_lock_rule.parameters.get(
                            "requirement_tags"
                        ),
                    },
                    [
                        "Confirm retention mode, default duration, legal-hold workflow, and governance ownership.",
                        "Create a replacement Object-Lock-enabled bucket when the existing bucket cannot be upgraded safely.",
                    ],
                    "Re-read Object Lock configuration and confirm ObjectLockEnabled is Enabled.",
                    region=region,
                )
            )

    replication_rule = rules.get("s3_replication_required")
    if replication_rule and _required_tags_match(replication_rule, bucket_tags):
        replication = client.read("s3.get_bucket_replication", Bucket=bucket) or {}
        enabled_rules = [
            item
            for item in (replication.get("ReplicationConfiguration") or {}).get("Rules") or []
            if str(item.get("Status") or "").lower() == "enabled"
        ]
        if not enabled_rules:
            findings.append(
                _finding(
                    replication_rule,
                    bucket,
                    {
                        "enabled_replication_rules": 0,
                        "requirement_tags_matched": replication_rule.parameters.get(
                            "requirement_tags"
                        ),
                    },
                    [
                        "Validate destination account, Region, versioning, KMS grants, ownership, and recovery objectives.",
                        "Add replication through the owning IaC project after destination preconditions pass.",
                    ],
                    "Re-read replication configuration and confirm at least one reviewed rule is Enabled.",
                    region=region,
                )
            )

    kms_rule = rules.get("s3_kms_encryption_required")
    if kms_rule and _required_tags_match(kms_rule, bucket_tags):
        encryption = client.get_bucket_encryption_rules(bucket)
        algorithms = sorted(
            {
                str(
                    (item.get("ApplyServerSideEncryptionByDefault") or {}).get("SSEAlgorithm") or ""
                )
                for item in encryption
            }
            - {""}
        )
        if "aws:kms" not in algorithms and "aws:kms:dsse" not in algorithms:
            findings.append(
                _finding(
                    kms_rule,
                    bucket,
                    {
                        "default_encryption_algorithms": algorithms,
                        "kms_default_encryption_present": False,
                        "requirement_tags_matched": kms_rule.parameters.get("requirement_tags"),
                    },
                    [
                        "Select a reviewed KMS key and validate key policy access for every writer and reader.",
                        "Update bucket encryption through IaC and test cross-account and service integrations.",
                    ],
                    "Re-read bucket encryption and confirm an aws:kms default encryption rule is present.",
                    region=region,
                )
            )

    cloudtrail_logging_rule = rules.get("s3_cloudtrail_access_logging_disabled")
    if cloudtrail_logging_rule and _policy_accepts_cloudtrail_writes(bucket_policy):
        logging = client.read("s3.get_bucket_logging", Bucket=bucket) or {}
        if not logging.get("LoggingEnabled"):
            findings.append(
                _finding(
                    cloudtrail_logging_rule,
                    bucket,
                    {
                        "cloudtrail_delivery_policy_present": True,
                        "server_access_logging_enabled": False,
                    },
                    [
                        "Choose a separate reviewed logging destination with retention and access controls.",
                        "Enable logging only after destination permissions and recursive logging risks are validated.",
                    ],
                    "Re-read bucket logging and confirm LoggingEnabled targets the reviewed destination.",
                    region=region,
                )
            )

    return findings, capability_errors


def _required_tags_match(rule: Rule, tags: Dict[str, str]) -> bool:
    actual = {str(key).lower(): str(value).lower() for key, value in tags.items()}
    required = {
        str(key).lower(): str(value).lower()
        for key, value in dict(rule.parameters.get("requirement_tags") or {}).items()
    }
    return bool(required) and all(actual.get(key) == value for key, value in required.items())


def _policy_accepts_cloudtrail_writes(policy: Dict[str, Any] | None) -> bool:
    for statement in _policy_statements(policy):
        if str(statement.get("Effect") or "").lower() != "allow":
            continue
        principal = statement.get("Principal")
        services: List[str] = []
        if isinstance(principal, dict):
            value = principal.get("Service")
            services = [str(item) for item in value] if isinstance(value, list) else [str(value)]
        actions = statement.get("Action")
        actions = actions if isinstance(actions, list) else [actions]
        accepts_cloudtrail = any(
            service.strip().lower() == "cloudtrail.amazonaws.com" for service in services
        )
        if accepts_cloudtrail and any(
            str(action).lower() in {"s3:putobject", "s3:*", "*"} for action in actions
        ):
            return True
    return False


def _capability_error(
    rule: Rule,
    bucket: str,
    operation: str,
    error: AwsProviderError,
) -> Dict[str, Any]:
    return {
        "rule_id": rule.id,
        "rule": rule.short_id,
        "resource": f"s3://{bucket}",
        "operation": operation,
        "detail": error.detail or str(error),
    }


def _finding(
    rule: Rule,
    bucket: str,
    evidence: Dict[str, Any],
    actions: List[str],
    verification: str,
    *,
    region: str | None = None,
) -> Finding:
    resource = f"s3://{bucket}"
    finding_key = f"{rule.id}:{resource}"
    finding_hash = hashlib.sha256(finding_key.encode("utf-8")).hexdigest()[:12]
    remediation = RemediationPlan(
        summary=rule.remediation["summary"],
        safety_level=rule.remediation["safety_level"],
        requires_approval=bool(rule.remediation["requires_approval"]),
        actions=actions,
        verification=verification,
    )
    return Finding(
        finding_id=f"steward-{finding_hash}",
        rule_id=rule.id,
        rule_short_id=rule.short_id,
        service=rule.service,
        resource=resource,
        severity=rule.severity,
        risk_detail=rule.risk_detail,
        scenario=rule.scenario,
        evidence={
            **evidence,
            "observation": {
                "observed_at": utc_now_iso(),
                "confidence": "high",
                "source": "aws_control_plane",
            },
        },
        remediation=remediation,
        resource_ref=ResourceRef(
            provider="aws",
            service="s3",
            resource_type="aws.s3.bucket",
            resource_id=bucket,
            region=region,
            arn=f"arn:aws:s3:::{bucket}",
            display_name=bucket,
        ),
    )


def _public_access_block_complete(public_access_block: Dict[str, Any]) -> bool:
    required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
    return all(public_access_block.get(field) is True for field in required)


def _policy_allows_public(policy: Dict[str, Any] | None) -> bool:
    return any(
        statement.get("Effect") == "Allow" and _is_public_principal(statement.get("Principal"))
        for statement in _policy_statements(policy)
    )


def _public_action_matches(
    policy: Dict[str, Any] | None,
    target_actions: tuple[str, ...],
) -> List[Dict[str, Any]]:
    matches: List[Dict[str, Any]] = []
    for statement in _policy_statements(policy):
        if statement.get("Effect") != "Allow" or not _is_public_principal(
            statement.get("Principal")
        ):
            continue
        actions = _string_values(statement.get("Action"))
        matched_actions = sorted(
            {
                action
                for action in actions
                if any(_action_pattern_covers(action, target) for target in target_actions)
            }
        )
        if matched_actions:
            matches.append(
                {
                    "statement_id": statement.get("Sid"),
                    "actions": matched_actions,
                    "conditional": bool(statement.get("Condition")),
                }
            )
    return matches


def _lifecycle_has_storage_optimization(
    rules: List[Dict[str, Any]],
    accepted_transition_storage_classes: tuple[str, ...],
) -> bool:
    accepted = {item.upper() for item in accepted_transition_storage_classes}
    for rule in rules:
        if str(rule.get("Status") or "").casefold() != "enabled":
            continue
        transitions = _list_values(rule.get("Transitions"))
        noncurrent_transitions = _list_values(rule.get("NoncurrentVersionTransitions"))
        if any(_transition_is_accepted(item, accepted) for item in transitions):
            return True
        if any(_transition_is_accepted(item, accepted) for item in noncurrent_transitions):
            return True
    return False


def _transition_is_accepted(transition: Any, accepted_storage_classes: set[str]) -> bool:
    if not isinstance(transition, dict):
        return False
    storage_class = str(transition.get("StorageClass") or "").upper()
    return storage_class in accepted_storage_classes


def _summarize_lifecycle_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    summary: List[Dict[str, Any]] = []
    for rule in rules:
        summary.append(
            {
                "id": rule.get("ID"),
                "status": rule.get("Status"),
                "has_transition": bool(_list_values(rule.get("Transitions"))),
                "has_noncurrent_transition": bool(
                    _list_values(rule.get("NoncurrentVersionTransitions"))
                ),
                "has_expiration": "Expiration" in rule,
                "has_noncurrent_expiration": "NoncurrentVersionExpiration" in rule,
                "has_abort_incomplete_multipart_upload": isinstance(
                    rule.get("AbortIncompleteMultipartUpload"),
                    dict,
                ),
            }
        )
    return summary


def _list_values(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _policy_denies_insecure_transport(
    policy: Dict[str, Any] | None,
    bucket: str,
) -> bool:
    bucket_arn = f"arn:aws:s3:::{bucket}"
    object_arn = f"{bucket_arn}/*"
    for statement in _policy_statements(policy):
        if statement.get("Effect") != "Deny" or not _is_public_principal(
            statement.get("Principal")
        ):
            continue
        actions = _string_values(statement.get("Action"))
        if not any(_action_pattern_covers(action, "s3:GetObject") for action in actions):
            continue
        resources = _string_values(statement.get("Resource"))
        if not _resources_cover(resources, bucket_arn, object_arn):
            continue
        if _condition_sets_secure_transport_false(statement.get("Condition")):
            return True
    return False


def _policy_statements(policy: Dict[str, Any] | None) -> List[Dict[str, Any]]:
    if not isinstance(policy, dict):
        return []
    statements = policy.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return []
    return [statement for statement in statements if isinstance(statement, dict)]


def _is_public_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if not isinstance(principal, dict):
        return False
    return any("*" in _string_values(value) for value in principal.values())


def _string_values(value: Any) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _action_pattern_covers(pattern: str, target: str) -> bool:
    return fnmatchcase(target.lower(), pattern.lower())


def _resources_cover(resources: List[str], bucket_arn: str, object_arn: str) -> bool:
    if "*" in resources:
        return True
    return all(
        any(fnmatchcase(target, pattern) for pattern in resources)
        for target in (bucket_arn, object_arn)
    )


def _condition_sets_secure_transport_false(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    for operator, values in condition.items():
        if str(operator).lower() not in {"bool", "boolifexists"} or not isinstance(values, dict):
            continue
        for key, value in values.items():
            if str(key).lower() != "aws:securetransport":
                continue
            normalized = value if isinstance(value, list) else [value]
            if any(item is False or str(item).lower() == "false" for item in normalized):
                return True
    return False
