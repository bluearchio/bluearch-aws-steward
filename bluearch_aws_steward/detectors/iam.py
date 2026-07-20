from __future__ import annotations

import hashlib
import time
from typing import Any, Dict, Iterable, List, Mapping

from bluearch_aws_steward.detectors.aws_common import (
    age_days,
    policy_document,
    policy_has_full_admin,
    tags_dict,
)
from bluearch_aws_steward.detectors.common import build_scan_result, finding_from_rule
from bluearch_aws_steward.detectors.runtime import EvaluationContext
from bluearch_aws_steward.models import Finding, ResourceRef, ScanResult
from bluearch_aws_steward.policy import ScanPolicy, resource_is_exempt
from bluearch_aws_steward.providers.base import AwsProvider


def scan_iam(
    client: AwsProvider,
    profile: str | None,
    endpoint_url: str | None,
    region: str,
    provider: str = "aws-cli",
    rule_filter: str | None = None,
    policy: ScanPolicy | None = None,
) -> ScanResult:
    started_at = time.monotonic()
    context = EvaluationContext(client, "iam", rule_filter)
    findings: List[Finding] = []
    root_detectors = {
        "iam_root_mfa_disabled",
        "iam_root_access_key_present",
        "iam_root_hardware_mfa_missing",
    }
    summary = (
        client.get_iam_account_summary()
        if any(context.rule(detector) for detector in root_detectors)
        else {}
    )

    _evaluate_root_rules(context, summary, findings)

    new_detectors = {
        "iam_password_policy_missing",
        "iam_console_user_mfa_disabled",
        "iam_access_key_older_than_90_days",
        "iam_policy_full_admin",
        "iam_policy_attached_directly_to_user",
        "iam_password_policy_number_missing",
        "iam_support_role_missing",
        "iam_role_wildcard_trust",
    }
    authorization = context.read(new_detectors, "iam.get_account_authorization_details") or {}
    exclusions = (policy or ScanPolicy()).exclude_tags
    users = _without_exemptions(authorization.get("UserDetailList") or [], exclusions)
    groups = _without_exemptions(authorization.get("GroupDetailList") or [], exclusions)
    roles = _without_exemptions(authorization.get("RoleDetailList") or [], exclusions)
    managed_policies = _without_exemptions(authorization.get("Policies") or [], exclusions)

    console_users = _console_users(context, users)
    _evaluate_password_policy(context, console_users, findings)
    _evaluate_console_mfa(context, console_users, findings)
    _evaluate_access_keys(context, users, findings)
    _evaluate_direct_user_policies(context, users, findings)
    _evaluate_full_admin(context, users, groups, roles, managed_policies, findings)
    _evaluate_support_role(context, roles, findings)
    _evaluate_wildcard_trust(context, roles, findings)

    resources_scanned = 1 + len(users) + len(groups) + len(roles) + len(managed_policies)
    return build_scan_result(
        service="iam",
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


def _without_exemptions(
    values: Iterable[Mapping[str, Any]],
    exclusions: Mapping[str, str],
) -> List[Mapping[str, Any]]:
    if not exclusions:
        return list(values)
    return [
        value
        for value in values
        if not resource_is_exempt(tags_dict(value.get("Tags")), exclusions)
    ]


def _evaluate_root_rules(
    context: EvaluationContext, summary: Mapping[str, Any], findings: List[Finding]
) -> None:
    resource = "iam://account/root"
    resource_ref = ResourceRef("aws", "iam", "root-user", "root", display_name="root")
    mfa_rule = context.rule("iam_root_mfa_disabled")
    if mfa_rule and int(summary.get("AccountMFAEnabled") or 0) <= 0:
        findings.append(
            finding_from_rule(
                mfa_rule,
                resource,
                {"root_mfa_enabled": False},
                [
                    "Use the root user only for this protected account-level change.",
                    "Register a phishing-resistant MFA device and store recovery procedures.",
                ],
                "Confirm AccountMFAEnabled is 1.",
                resource_ref=resource_ref,
            )
        )
    key_rule = context.rule("iam_root_access_key_present")
    root_access_keys = int(summary.get("AccountAccessKeysPresent") or 0)
    if key_rule and root_access_keys > 0:
        findings.append(
            finding_from_rule(
                key_rule,
                resource,
                {"root_access_keys_present": root_access_keys},
                [
                    "Replace every root-key dependency with role credentials.",
                    "Disable and then delete the root access key after validation.",
                ],
                "Confirm AccountAccessKeysPresent is 0.",
                resource_ref=resource_ref,
            )
        )
    hardware_rule = context.rule("iam_root_hardware_mfa_missing")
    if hardware_rule and int(summary.get("AccountMFAEnabled") or 0) <= 0:
        findings.append(
            finding_from_rule(
                hardware_rule,
                resource,
                {
                    "root_mfa_enabled": False,
                    "hardware_mfa_present": False,
                    "mfa_device_type_inferred": True,
                },
                [
                    "Use the root user only for this protected account-level change.",
                    "Register a phishing-resistant hardware MFA device and document recovery ownership.",
                ],
                "Confirm AccountMFAEnabled is 1 and verify the registered root MFA device through the approved account process.",
                resource_ref=resource_ref,
            )
        )


def _console_users(
    context: EvaluationContext, users: List[Mapping[str, Any]]
) -> List[Mapping[str, Any]]:
    relevant = {
        "iam_password_policy_missing",
        "iam_password_policy_number_missing",
        "iam_console_user_mfa_disabled",
    }
    if not any(context.rule(detector) for detector in relevant):
        return []
    console_users: List[Mapping[str, Any]] = []
    for user in users:
        name = str(user.get("UserName") or "")
        if not name:
            continue
        response = context.read(relevant, "iam.get_login_profile", UserName=name)
        if response and response.get("LoginProfile"):
            console_users.append(user)
    return console_users


def _evaluate_password_policy(
    context: EvaluationContext,
    console_users: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    missing_rule = context.rule("iam_password_policy_missing")
    number_rule = context.rule("iam_password_policy_number_missing")
    if (not missing_rule and not number_rule) or not console_users:
        return
    response = context.read(
        ("iam_password_policy_missing", "iam_password_policy_number_missing"),
        "iam.get_account_password_policy",
    )
    policy_present = bool(response and response.get("PasswordPolicy"))
    if missing_rule and response is not None and not policy_present:
        findings.append(
            finding_from_rule(
                missing_rule,
                "iam://account/password-policy",
                {
                    "password_policy_present": policy_present,
                    "console_users_count": len(console_users),
                },
                [
                    "Define a reviewed account password policy before changing user authentication behavior."
                ],
                "Re-read get-account-password-policy and confirm a policy is returned.",
                resource_ref=ResourceRef(
                    "aws", "iam", "account-password-policy", "password-policy"
                ),
            )
        )
    policy = (response or {}).get("PasswordPolicy") or {}
    if (
        number_rule
        and response is not None
        and (not policy_present or not policy.get("RequireNumbers"))
    ):
        findings.append(
            finding_from_rule(
                number_rule,
                "iam://account/password-policy",
                {
                    "password_policy_present": policy_present,
                    "require_numbers": False,
                    "console_users_count": len(console_users),
                },
                [
                    "Review service-account and human-user authentication dependencies.",
                    "Update the account password policy to require at least one number.",
                ],
                "Re-read get-account-password-policy and confirm RequireNumbers is true.",
                resource_ref=ResourceRef(
                    "aws", "iam", "account-password-policy", "password-policy"
                ),
            )
        )


def _evaluate_console_mfa(
    context: EvaluationContext,
    console_users: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    rule = context.rule("iam_console_user_mfa_disabled")
    if not rule:
        return
    for user in console_users:
        name = str(user.get("UserName") or "")
        response = context.read(
            "iam_console_user_mfa_disabled", "iam.list_mfa_devices", UserName=name
        )
        if response is not None and not response.get("MFADevices"):
            findings.append(
                finding_from_rule(
                    rule,
                    f"iam://user/{name}",
                    {"user_name": name, "console_access": True, "mfa_devices": 0},
                    [
                        "Register MFA for the user or remove console access if it is no longer required."
                    ],
                    "List MFA devices and confirm at least one device is registered.",
                    resource_ref=ResourceRef(
                        "aws", "iam", "user", name, arn=user.get("Arn"), display_name=name
                    ),
                )
            )


def _evaluate_access_keys(
    context: EvaluationContext,
    users: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    rule = context.rule("iam_access_key_older_than_90_days")
    if not rule:
        return
    maximum_age = int(rule.parameters.get("maximum_access_key_age_days") or 90)
    for user in users:
        name = str(user.get("UserName") or "")
        response = context.read(
            "iam_access_key_older_than_90_days", "iam.list_access_keys", UserName=name
        )
        for key in (response or {}).get("AccessKeyMetadata") or []:
            key_age = age_days(key.get("CreateDate"))
            if key.get("Status") != "Active" or key_age is None or key_age <= maximum_age:
                continue
            key_id = str(key.get("AccessKeyId") or "")
            redacted_id = "key-" + hashlib.sha256(key_id.encode("utf-8")).hexdigest()[:12]
            findings.append(
                finding_from_rule(
                    rule,
                    f"iam://user/{name}/access-key/{redacted_id}",
                    {
                        "user_name": name,
                        "access_key_id_suffix": key_id[-4:],
                        "age_days": key_age,
                        "maximum_age_days": maximum_age,
                    },
                    [
                        "Create a replacement key, update dependencies, validate usage, then disable the old key."
                    ],
                    "List access keys and confirm no active key exceeds the approved age.",
                    resource_ref=ResourceRef(
                        "aws",
                        "iam",
                        "access-key",
                        redacted_id,
                        display_name=f"{name}:...{key_id[-4:]}",
                    ),
                )
            )


def _evaluate_direct_user_policies(
    context: EvaluationContext,
    users: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    rule = context.rule("iam_policy_attached_directly_to_user")
    if not rule:
        return
    for user in users:
        inline = [str(item.get("PolicyName") or "") for item in user.get("UserPolicyList") or []]
        attached = [
            str(item.get("PolicyArn") or "") for item in user.get("AttachedManagedPolicies") or []
        ]
        if not inline and not attached:
            continue
        name = str(user.get("UserName") or "")
        findings.append(
            finding_from_rule(
                rule,
                f"iam://user/{name}",
                {
                    "user_name": name,
                    "inline_policy_names": sorted(filter(None, inline)),
                    "attached_policy_arns": sorted(filter(None, attached)),
                },
                [
                    "Move equivalent permissions to a reviewed group or role before detaching user policies."
                ],
                "Re-read authorization details and confirm the user has no direct policies.",
                resource_ref=ResourceRef(
                    "aws", "iam", "user", name, arn=user.get("Arn"), display_name=name
                ),
            )
        )


def _evaluate_full_admin(
    context: EvaluationContext,
    users: List[Mapping[str, Any]],
    groups: List[Mapping[str, Any]],
    roles: List[Mapping[str, Any]],
    managed_policies: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    rule = context.rule("iam_policy_full_admin")
    if not rule:
        return
    policy_documents: Dict[str, Any] = {}
    for policy in managed_policies:
        arn = str(policy.get("Arn") or "")
        versions = policy.get("PolicyVersionList") or []
        default = next((version for version in versions if version.get("IsDefaultVersion")), None)
        if arn and default:
            policy_documents[arn] = default.get("Document")

    attached_arns = {
        str(item.get("PolicyArn") or "")
        for principal in [*users, *groups, *roles]
        for item in principal.get("AttachedManagedPolicies") or []
        if item.get("PolicyArn")
    }
    for arn in sorted(attached_arns - set(policy_documents)):
        metadata = context.read("iam_policy_full_admin", "iam.get_policy", PolicyArn=arn) or {}
        policy = metadata.get("Policy") or {}
        version_id = policy.get("DefaultVersionId")
        if not version_id:
            continue
        version = (
            context.read(
                "iam_policy_full_admin",
                "iam.get_policy_version",
                PolicyArn=arn,
                VersionId=version_id,
            )
            or {}
        )
        policy_documents[arn] = (version.get("PolicyVersion") or {}).get("Document")

    for principal_type, principals, inline_key, name_key in (
        ("user", users, "UserPolicyList", "UserName"),
        ("group", groups, "GroupPolicyList", "GroupName"),
        ("role", roles, "RolePolicyList", "RoleName"),
    ):
        for principal in principals:
            name = str(principal.get(name_key) or "")
            matches = [
                str(item.get("PolicyName") or "inline")
                for item in principal.get(inline_key) or []
                if policy_has_full_admin(item.get("PolicyDocument"))
            ]
            matches.extend(
                str(item.get("PolicyArn") or "")
                for item in principal.get("AttachedManagedPolicies") or []
                if policy_has_full_admin(policy_documents.get(str(item.get("PolicyArn") or "")))
            )
            if not matches:
                continue
            findings.append(
                finding_from_rule(
                    rule,
                    f"iam://{principal_type}/{name}",
                    {
                        "principal_type": principal_type,
                        "principal_name": name,
                        "unrestricted_policy_identifiers": sorted(set(matches)),
                    },
                    [
                        "Design and test least-privilege replacement policies before removing administrator access."
                    ],
                    "Re-read every effective policy and confirm no unconditional Allow * on Resource * remains.",
                    resource_ref=ResourceRef(
                        "aws",
                        "iam",
                        principal_type,
                        name,
                        arn=principal.get("Arn"),
                        display_name=name,
                    ),
                )
            )


def _evaluate_support_role(
    context: EvaluationContext,
    roles: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    rule = context.rule("iam_support_role_missing")
    if not rule:
        return
    support_roles = [
        str(role.get("RoleName") or "")
        for role in roles
        if any(
            str(policy.get("PolicyArn") or "").endswith("/AWSSupportAccess")
            for policy in role.get("AttachedManagedPolicies") or []
        )
    ]
    if support_roles:
        return
    findings.append(
        finding_from_rule(
            rule,
            "iam://account/support-role",
            {"support_access_role_present": False, "roles_evaluated": len(roles)},
            [
                "Define a controlled incident-support trust policy and break-glass access process.",
                "Create the support role through the account baseline IaC project.",
            ],
            "Re-read authorization details and confirm a reviewed role has AWSSupportAccess attached.",
            resource_ref=ResourceRef("aws", "iam", "account-control", "support-role"),
        )
    )


def _evaluate_wildcard_trust(
    context: EvaluationContext,
    roles: List[Mapping[str, Any]],
    findings: List[Finding],
) -> None:
    rule = context.rule("iam_role_wildcard_trust")
    if not rule:
        return
    for role in roles:
        document = policy_document(role.get("AssumeRolePolicyDocument"))
        statements = document.get("Statement") or []
        statements = statements if isinstance(statements, list) else [statements]
        matching_sids: List[str] = []
        for index, statement in enumerate(statements):
            if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
                continue
            principal = statement.get("Principal")
            aws_principal = principal.get("AWS") if isinstance(principal, Mapping) else principal
            values = aws_principal if isinstance(aws_principal, list) else [aws_principal]
            if "*" in values and not statement.get("Condition"):
                matching_sids.append(str(statement.get("Sid") or f"statement-{index + 1}"))
        if not matching_sids:
            continue
        name = str(role.get("RoleName") or "")
        findings.append(
            finding_from_rule(
                rule,
                f"iam://role/{name}",
                {
                    "role_name": name,
                    "wildcard_trust_statement_ids": matching_sids,
                    "trust_policy_redacted": True,
                },
                [
                    "Identify every trusted account, service, and workload.",
                    "Replace wildcard trust with reviewed principals and organization or external-ID conditions.",
                ],
                "Re-read the trust policy and confirm no unconditional wildcard AWS principal remains.",
                resource_ref=ResourceRef(
                    "aws", "iam", "role", name, arn=role.get("Arn"), display_name=name
                ),
            )
        )
