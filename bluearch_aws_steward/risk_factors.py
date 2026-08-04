"""Contextual risk factors that raise the priority of genuinely dangerous findings.

The catalog owns severity. This layer owns context, and contributes additive
points to the priority score without ever modifying severity, so a catalog sync
has nothing to overwrite.

Every factor carries a rationale. A priority number is a claim, and the product
does not ship claims without evidence.
"""

from __future__ import annotations

from typing import Any, Dict, List

JSON = Dict[str, Any]

_ROOT_CREDENTIAL_RULES = {
    "iam-root-access-key-present",
    "iam-root-mfa-disabled",
    "iam-root-hardware-mfa-missing",
}

_PUBLICLY_READABLE_RULES = {
    "s3-public-bucket",
    "s3-policy-all-actions-public",
    "s3-policy-public-delete",
    "rds-publicly-accessible",
    "sns-topic-public-access",
    "sqs-queue-public-access",
}

_INTERNET_EXPOSED_RULES = {
    "ec2-security-group-ssh-open",
    "ec2-security-group-rdp-open",
}

_ADMIN_PRIVILEGE_RULES = {
    "iam-policy-full-admin",
    "lambda-admin-execution-role",
    "iam-role-wildcard-trust",
}

_AGED_CREDENTIAL_RULES = {
    "iam-access-key-older-than-90-days",
}

_FACTOR_DEFINITIONS = (
    (
        "root_credential",
        40.0,
        "Root account credential; a compromise bypasses every IAM control in the account.",
        _ROOT_CREDENTIAL_RULES,
    ),
    (
        "publicly_readable",
        30.0,
        "Resource is reachable by anonymous principals, so exposure needs no prior access.",
        _PUBLICLY_READABLE_RULES,
    ),
    (
        "internet_exposed",
        25.0,
        "Administrative port is open to the internet, giving attackers a direct entry path.",
        _INTERNET_EXPOSED_RULES,
    ),
    (
        "admin_privilege",
        20.0,
        "Grants unrestricted administrative permissions, removing blast-radius containment.",
        _ADMIN_PRIVILEGE_RULES,
    ),
    (
        "aged_credential",
        10.0,
        "Long-lived credential increases the window in which a leak stays usable.",
        _AGED_CREDENTIAL_RULES,
    ),
)


def risk_factors(finding: JSON) -> JSON:
    """Return additive contextual risk for a finding.

    Accepts either an opportunity (``rule``) or a raw scan finding
    (``rule_short_id`` / ``rule_id``). The merge path in ``recommendation_queue``
    scores findings before they are translated into opportunities, so reading only
    ``rule`` there would silently score every contextual factor as zero and let one
    issue carry two contradictory priorities in the same result.

    Never raises. A malformed finding yields no factors, so the caller degrades to
    the base score rather than failing an entire scan.
    """
    try:
        rule = finding.get("rule") or finding.get("rule_short_id") or finding.get("rule_id")
    except AttributeError:
        return {"factors": [], "total": 0.0}
    if not isinstance(rule, str):
        return {"factors": [], "total": 0.0}

    factors: List[JSON] = []
    for factor_id, points, rationale, rules in _FACTOR_DEFINITIONS:
        if rule in rules:
            factors.append({"id": factor_id, "points": points, "rationale": rationale})

    factors.sort(key=lambda factor: -float(factor["points"]))
    return {"factors": factors, "total": float(sum(factor["points"] for factor in factors))}
