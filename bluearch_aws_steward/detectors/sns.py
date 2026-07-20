from __future__ import annotations

import time
from typing import Any, Dict, List

from bluearch_aws_steward.detectors.aws_common import public_allow_statements, tags_dict
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider

_SNS_SENSITIVE_ACTIONS = {
    "sns:addpermission",
    "sns:publish",
    "sns:removepermission",
    "sns:settopicattributes",
    "sns:subscribe",
}


def scan_sns(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    detectors = ("sns_topic_encryption_disabled", "sns_topic_public_access")
    context = EvaluationContext(client, "sns", rule_filter)
    response = context.read(detectors, "sns.list_topics")
    topics = list((response or {}).get("Topics") or [])
    findings: List[Finding] = []
    exclusions = (policy or ScanPolicy()).exclude_tags

    for topic in topics:
        arn = str(topic.get("TopicArn") or "").strip()
        if not arn:
            continue
        tags_response = context.read(detectors, "sns.list_tags_for_resource", ResourceArn=arn)
        if resource_is_exempt(tags_dict((tags_response or {}).get("Tags")), exclusions):
            continue
        attributes_response = context.read(detectors, "sns.get_topic_attributes", TopicArn=arn)
        attributes: Dict[str, Any] = dict((attributes_response or {}).get("Attributes") or {})
        topic_name = arn.rsplit(":", 1)[-1]
        resource = f"sns://topic/{topic_name}"
        resource_ref = ResourceRef(
            provider="aws",
            service="sns",
            resource_type="aws.sns.topic",
            resource_id=topic_name,
            region=region,
            account_id=_account_id(arn),
            arn=arn,
            display_name=topic_name,
        )

        encryption_rule = context.rule("sns_topic_encryption_disabled")
        if encryption_rule and not str(attributes.get("KmsMasterKeyId") or "").strip():
            findings.append(
                finding_from_rule(
                    encryption_rule,
                    resource,
                    {"topic_arn": arn, "server_side_encryption_enabled": False},
                    [
                        "Inventory publishers, subscribers, and AWS service integrations.",
                        "Choose the AWS-managed SNS key or a reviewed customer-managed key.",
                        "Enable encryption and validate message delivery in an approved change.",
                    ],
                    "Re-read topic attributes and confirm KmsMasterKeyId is configured.",
                    resource_ref=resource_ref,
                )
            )

        public_rule = context.rule("sns_topic_public_access")
        public_statements = public_allow_statements(
            attributes.get("Policy"), sensitive_actions=_SNS_SENSITIVE_ACTIONS
        )
        if public_rule and public_statements:
            findings.append(
                finding_from_rule(
                    public_rule,
                    resource,
                    {
                        "topic_arn": arn,
                        "public_statement_count": len(public_statements),
                        "public_statements": public_statements,
                        "policy_document_redacted": True,
                    },
                    [
                        "Confirm intended publishers, subscribers, and service integrations.",
                        "Replace wildcard access with reviewed principals and source restrictions.",
                        "Test every delivery path before applying the policy change.",
                    ],
                    "Re-read the topic policy and confirm no unconditioned public allow remains.",
                    resource_ref=resource_ref,
                )
            )

    return build_scan_result(
        service="sns",
        provider=provider,
        profile=profile,
        endpoint_url=endpoint_url,
        region=region,
        resources_scanned=len(topics),
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
