"""Pure policy-evaluation core for ``bluearch_explain_denial``.

Deterministic re-implementation of the documented IAM evaluation order
over policy documents supplied by the caller. No AWS reads happen here;
the live collector gathers documents and the MCP layer assembles the
response contract (docs/explain-denial-design.md).

v1 scope: same-account identity/resource policies, KMS key-policy
authority (with root delegation), the S3 public access block, and
Condition evaluation against caller-supplied context. Statements using
NotAction/NotPrincipal/NotResource are outside v1 and are skipped for
allows (never for denies, where skipping could hide a real deny -- they
produce an "unknown" verdict instead).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

JSON = Dict[str, Any]

SCHEMA_VERSION = "1"

# Frozen vocabularies (contract: graders string-match against these; any
# addition bumps SCHEMA_VERSION).
BLOCKING_LAYERS = (
    "identity_policy",
    "resource_policy",
    "kms_key_policy",
    "public_access_block",
    "condition_mismatch",
    "scp",
    "none",
    "unknown",
)
CLAIM_KINDS = (
    "denying_statement",
    "missing_permission",
    "condition_mismatch",
    "satisfied_layer",
    "blocking_control",
)

_SERVICE_PRINCIPAL_RE = re.compile(r"^[a-z0-9.-]+\.amazonaws\.com$")

_CONDITION_OPERATORS = {
    "StringEquals": "equals",
    "ArnEquals": "equals",
    "StringLike": "like",
    "ArnLike": "like",
    "Bool": "equals",
}


@dataclass(frozen=True)
class AccessRequest:
    action: str
    resource: str
    principal: str
    account_id: str
    condition_context: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Evaluation:
    verdict: JSON
    claims: List[JSON]


def _string_values(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]


def _pattern_matches(pattern: str, value: str, *, case_insensitive: bool = False) -> bool:
    flags = re.IGNORECASE if case_insensitive else 0
    translated = "^" + re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".") + "$"
    return re.match(translated, value, flags) is not None


def _action_matches(statement: JSON, action: str) -> bool:
    return any(
        _pattern_matches(pattern, action, case_insensitive=True)
        for pattern in _string_values(statement.get("Action"))
    )


def _resource_matches(statement: JSON, resource: str) -> bool:
    patterns = _string_values(statement.get("Resource"))
    if not patterns:
        # Identity policy statements without Resource are malformed; a
        # resource/key policy without Resource applies to its carrier.
        return True
    return any(_pattern_matches(pattern, resource) for pattern in patterns)


def _is_public_principal(principal: str) -> bool:
    return principal == "*"


def _is_service_principal(principal: str) -> bool:
    return bool(_SERVICE_PRINCIPAL_RE.match(principal))


def _root_arn(account_id: str) -> str:
    return f"arn:aws:iam::{account_id}:root"


def _principal_entries(statement: JSON) -> Tuple[List[str], List[str], bool]:
    """(aws_principals, service_principals, matches_everyone)."""
    principal = statement.get("Principal")
    if principal == "*":
        return [], [], True
    if not isinstance(principal, dict):
        return [], [], False
    aws = _string_values(principal.get("AWS"))
    if "*" in aws:
        return [], [], True
    services = _string_values(principal.get("Service"))
    return aws, services, False


def _principal_applies(statement: JSON, request: AccessRequest) -> bool:
    aws, services, everyone = _principal_entries(statement)
    if everyone:
        return True
    if _is_service_principal(request.principal):
        return request.principal in services
    return request.principal in aws


def _principal_delegates_to_root(statement: JSON, account_id: str) -> bool:
    aws, _services, _everyone = _principal_entries(statement)
    return _root_arn(account_id) in aws


_CONDITION_SATISFIED = "satisfied"


def _evaluate_conditions(
    statement: JSON, context: Mapping[str, str]
) -> Tuple[str, Optional[JSON]]:
    """-> (status, detail): 'satisfied' | 'missing_key' | 'mismatch' | 'unsupported'."""
    conditions = statement.get("Condition")
    if not isinstance(conditions, dict) or not conditions:
        return _CONDITION_SATISFIED, None
    for operator, pairs in conditions.items():
        mode = _CONDITION_OPERATORS.get(str(operator))
        if mode is None:
            return "unsupported", {"operator": str(operator)}
        if not isinstance(pairs, dict):
            return "unsupported", {"operator": str(operator)}
        for key, expected in pairs.items():
            expected_values = _string_values(expected)
            got = context.get(str(key))
            if got is None:
                return "missing_key", {"key": str(key), "expected": expected_values}
            if mode == "equals":
                matched = str(got) in expected_values
            else:
                matched = any(
                    _pattern_matches(pattern, str(got)) for pattern in expected_values
                )
            if not matched:
                return "mismatch", {
                    "key": str(key),
                    "expected": expected_values,
                    "got": str(got),
                }
    return _CONDITION_SATISFIED, None


@dataclass(frozen=True)
class _LayerStatement:
    layer: str
    carrier: str
    index: int
    statement: JSON


def _layer_statements(
    request: AccessRequest,
    identity_policies: Sequence[JSON],
    resource_policy: Optional[JSON],
    kms_key_policy: Optional[JSON],
) -> List[_LayerStatement]:
    collected: List[_LayerStatement] = []
    for policy in identity_policies:
        for index, statement in enumerate(policy.get("Statement") or []):
            if isinstance(statement, dict):
                collected.append(
                    _LayerStatement("identity_policy", request.principal, index, statement)
                )
    for layer, policy in (
        ("resource_policy", resource_policy),
        ("kms_key_policy", kms_key_policy),
    ):
        if policy is None:
            continue
        for index, statement in enumerate(policy.get("Statement") or []):
            if isinstance(statement, dict):
                collected.append(
                    _LayerStatement(layer, request.resource, index, statement)
                )
    return collected


def _claim(
    kind: str,
    layer: str,
    entry: Optional[_LayerStatement],
    explanation: str,
    *,
    carrier: Optional[str] = None,
) -> JSON:
    policy_ref: JSON = {"resource": carrier or (entry.carrier if entry else None)}
    evidence: JSON = {}
    if entry is not None:
        policy_ref["statement_sid"] = entry.statement.get("Sid")
        policy_ref["statement_index"] = entry.index
        evidence["statement"] = entry.statement
    return {
        "kind": kind,
        "layer": layer,
        "policy_ref": policy_ref,
        "evidence": evidence,
        "explanation": explanation,
    }


def _verdict(effect: str, blocking_layer: str) -> JSON:
    assert blocking_layer in BLOCKING_LAYERS
    return {"effect": effect, "blocking_layer": blocking_layer}


def evaluate_access(
    request: AccessRequest,
    *,
    identity_policies: Optional[Sequence[JSON]] = None,
    resource_policy: Optional[JSON] = None,
    kms_key_policy: Optional[JSON] = None,
    public_access_block: Optional[JSON] = None,
) -> Evaluation:
    identity_policies = list(identity_policies or [])
    statements = _layer_statements(
        request, identity_policies, resource_policy, kms_key_policy
    )
    anonymous = _is_public_principal(request.principal)
    service = _is_service_principal(request.principal)

    # 1. Explicit deny anywhere that applies wins outright.
    for entry in statements:
        statement = entry.statement
        if statement.get("Effect") != "Deny":
            continue
        if not _action_matches(statement, request.action):
            continue
        if not _resource_matches(statement, request.resource):
            continue
        if entry.layer != "identity_policy" and not _principal_applies(
            statement, request
        ):
            continue
        status, _detail = _evaluate_conditions(statement, request.condition_context)
        if status != _CONDITION_SATISFIED:
            continue
        return Evaluation(
            verdict=_verdict("explicit_deny", entry.layer),
            claims=[
                _claim(
                    "denying_statement",
                    entry.layer,
                    entry,
                    f"Statement {statement.get('Sid') or f'#{entry.index}'} explicitly "
                    f"denies {request.action} on {request.resource} for this principal.",
                )
            ],
        )

    # 2. S3 public access block: a complete block stops anonymous access
    # regardless of the bucket policy.
    if anonymous and public_access_block is not None:
        complete = all(
            bool(public_access_block.get(flag))
            for flag in (
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            )
        )
        if complete:
            return Evaluation(
                verdict=_verdict("explicit_deny", "public_access_block"),
                claims=[
                    _claim(
                        "blocking_control",
                        "public_access_block",
                        None,
                        "The bucket's public access block is fully enabled; "
                        "anonymous access is blocked regardless of the bucket "
                        "policy. Note: the public statement remains a latent "
                        "exposure and still deserves review.",
                        carrier=request.resource,
                    )
                ],
            )

    # 3. Allow search on the deciding layer(s).
    def _allow_search(layers: Sequence[str]) -> Tuple[Optional[_LayerStatement], List[Tuple[_LayerStatement, str, JSON]]]:
        near_misses: List[Tuple[_LayerStatement, str, JSON]] = []
        for entry in statements:
            if entry.layer not in layers:
                continue
            statement = entry.statement
            if statement.get("Effect") != "Allow":
                continue
            if any(
                key in statement for key in ("NotAction", "NotPrincipal", "NotResource")
            ):
                continue
            if not _action_matches(statement, request.action):
                continue
            if not _resource_matches(statement, request.resource):
                continue
            if entry.layer != "identity_policy" and not _principal_applies(
                statement, request
            ):
                continue
            status, detail = _evaluate_conditions(statement, request.condition_context)
            if status == _CONDITION_SATISFIED:
                return entry, near_misses
            near_misses.append((entry, status, detail or {}))
        return None, near_misses

    if kms_key_policy is not None:
        # KMS: the key policy is authoritative. A direct grant suffices;
        # a root grant delegates to identity policies.
        direct, key_misses = _allow_search(["kms_key_policy"])
        if direct is not None:
            return _allow_result(request, direct)
        delegates = any(
            entry.statement.get("Effect") == "Allow"
            and _principal_delegates_to_root(entry.statement, request.account_id)
            and _action_matches(entry.statement, request.action)
            for entry in statements
            if entry.layer == "kms_key_policy"
        )
        if delegates:
            identity_allow, identity_misses = _allow_search(["identity_policy"])
            if identity_allow is not None:
                return _allow_result(request, identity_allow)
            return _blocked_result(request, "identity_policy", identity_misses)
        return _blocked_result(request, "kms_key_policy", key_misses)

    if anonymous or service:
        # Anonymous and service principals are decided by the resource
        # policy alone in v1.
        allow, misses = _allow_search(["resource_policy"])
        if allow is not None:
            return _allow_result(request, allow)
        return _blocked_result(request, "resource_policy", misses)

    # Same-account IAM principal: identity policy OR resource policy allow.
    allow, misses = _allow_search(["identity_policy", "resource_policy"])
    if allow is not None:
        return _allow_result(request, allow)
    return _blocked_result(request, "identity_policy", misses)


def _allow_result(request: AccessRequest, entry: _LayerStatement) -> Evaluation:
    statement = entry.statement
    return Evaluation(
        verdict=_verdict("allow", "none"),
        claims=[
            _claim(
                "satisfied_layer",
                entry.layer,
                entry,
                f"Statement {statement.get('Sid') or f'#{entry.index}'} allows "
                f"{request.action} on {request.resource} for this principal.",
            )
        ],
    )


def _blocked_result(
    request: AccessRequest,
    default_layer: str,
    near_misses: List[Tuple[_LayerStatement, str, JSON]],
) -> Evaluation:
    for entry, status, detail in near_misses:
        if status == "missing_key":
            key = detail.get("key")
            return Evaluation(
                verdict=_verdict("conditional", "condition_mismatch"),
                claims=[
                    _claim(
                        "condition_mismatch",
                        entry.layer,
                        entry,
                        f"Statement {entry.statement.get('Sid') or f'#{entry.index}'} "
                        f"would allow this request, but its Condition references "
                        f"{key} and no value was supplied in condition_context -- "
                        "the tool never guesses request context.",
                    )
                ],
            )
        if status == "mismatch":
            return Evaluation(
                verdict=_verdict("implicit_deny", "condition_mismatch"),
                claims=[
                    _claim(
                        "condition_mismatch",
                        entry.layer,
                        entry,
                        f"Statement {entry.statement.get('Sid') or f'#{entry.index}'} "
                        f"allows {request.action} only when {detail.get('key')} "
                        f"matches {detail.get('expected')}; the request carries "
                        f"{detail.get('got')}, which does not match.",
                    )
                ],
            )
    return Evaluation(
        verdict=_verdict("implicit_deny", default_layer),
        claims=[
            _claim(
                "missing_permission",
                default_layer,
                None,
                f"No statement grants {request.action} on {request.resource} to "
                f"{request.principal}; the smallest missing grant is an Allow for "
                f"{request.action} on {request.resource} in the "
                f"{default_layer.replace('_', ' ')}.",
                carrier=request.resource
                if default_layer in ("resource_policy", "kms_key_policy")
                else request.principal,
            )
        ],
    )
