from __future__ import annotations

import time
from typing import Any, Dict, List

from bluearch_aws_steward.detectors.aws_common import public_allow_statements, tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider

_SQS_SENSITIVE_ACTIONS = {
    "sqs:addpermission",
    "sqs:changemessagevisibility",
    "sqs:deletemessage",
    "sqs:receivemessage",
    "sqs:removepermission",
    "sqs:sendmessage",
    "sqs:setqueueattributes",
}


def scan_sqs(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    detectors = ("sqs_queue_encryption_disabled", "sqs_queue_public_access")
    context = EvaluationContext(client, "sqs", rule_filter)
    response = context.read(detectors, "sqs.list_queues")
    queue_urls = [str(url) for url in (response or {}).get("QueueUrls") or [] if url]
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags

    for queue_url in queue_urls:
        tags_response = context.read(detectors, "sqs.list_queue_tags", QueueUrl=queue_url)
        if resource_is_exempt(tags_dict((tags_response or {}).get("Tags")), exclusions):
            continue
        attributes_response = context.read(
            detectors,
            "sqs.get_queue_attributes",
            QueueUrl=queue_url,
            AttributeNames=["QueueArn", "KmsMasterKeyId", "SqsManagedSseEnabled", "Policy"],
        )
        attributes: Dict[str, Any] = dict((attributes_response or {}).get("Attributes") or {})
        arn = str(attributes.get("QueueArn") or "").strip()
        queue_name = arn.rsplit(":", 1)[-1] if arn else queue_url.rstrip("/").rsplit("/", 1)[-1]
        resource = f"sqs://queue/{queue_name}"
        resource_ref = ResourceRef(
            provider="aws",
            service="sqs",
            resource_type="aws.sqs.queue",
            resource_id=queue_name,
            region=region,
            account_id=_account_id(arn),
            arn=arn or None,
            display_name=queue_name,
        )

        encryption_rule = context.rule("sqs_queue_encryption_disabled")
        encrypted = (
            bool(str(attributes.get("KmsMasterKeyId") or "").strip())
            or str(attributes.get("SqsManagedSseEnabled") or "").lower() == "true"
        )
        if encryption_rule and not encrypted:
            findings.append(
                finding_from_rule(
                    encryption_rule,
                    resource,
                    {
                        "queue_arn": arn or None,
                        "kms_encryption_enabled": False,
                        "sqs_managed_encryption_enabled": False,
                        "message_bodies_read": False,
                    },
                    [
                        "Inventory producers, consumers, dead-letter queues, and service integrations.",
                        "Choose SSE-SQS or a reviewed KMS key and validate required permissions.",
                        "Enable encryption and test message flow during an approved change.",
                    ],
                    "Re-read queue attributes and confirm an encryption attribute is enabled.",
                    resource_ref=resource_ref,
                )
            )

        public_rule = context.rule("sqs_queue_public_access")
        public_statements = public_allow_statements(
            attributes.get("Policy"), sensitive_actions=_SQS_SENSITIVE_ACTIONS
        )
        if public_rule and public_statements:
            findings.append(
                finding_from_rule(
                    public_rule,
                    resource,
                    {
                        "queue_arn": arn or None,
                        "public_statement_count": len(public_statements),
                        "public_statements": public_statements,
                        "policy_document_redacted": True,
                        "message_bodies_read": False,
                    },
                    [
                        "Confirm intended producers, consumers, and service integrations.",
                        "Replace wildcard access with reviewed principals and source restrictions.",
                        "Test every message path before applying the policy change.",
                    ],
                    "Re-read the queue policy and confirm no unconditioned public allow remains.",
                    resource_ref=resource_ref,
                )
            )

    return build_scan_result(
        service="sqs",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(queue_urls),
        findings=context.completed_findings(findings),
        rules_evaluated=context.rules_evaluated,
        rule_filter=rule_filter,
        started_at=started_at,
        rules_skipped=context.rules_skipped,
        capability_errors=context.capability_errors,
    )


def _account_id(arn: str) -> str | None:
    parts = arn.split(":", 5)
    return parts[4] if len(parts) == 6 and parts[4] else None
