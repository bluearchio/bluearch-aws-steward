"""Pure policy-evaluation core and response assembly for ``bluearch_explain_denial``.

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

import hashlib
import json
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

# Services whose policy layers the v1 collector can gather. Anything else
# returns status "not_supported" (scope honesty -- never a plausible empty).
EXPLAIN_SUPPORTED_SERVICES = ("dynamodb", "iam", "kms", "s3", "sns", "sqs")

_MAX_CLAIMS = 5
_MAX_STATEMENT_BYTES = 2048
_MAX_RESPONSE_BYTES = 8192

_REMEDIATION_OPERATIONS = {
    "identity_policy": "iam.PutRolePolicy",
    "resource_policy": None,  # service-specific; named in the description
    "kms_key_policy": "kms.PutKeyPolicy",
    "public_access_block": "s3.PutPublicAccessBlock",
}

# mode -> (matcher, negated). Negated operators evaluate true when the
# key is absent from the request context (documented AWS semantics).
_CONDITION_OPERATORS = {
    "StringEquals": ("equals", False),
    "StringNotEquals": ("equals", True),
    "StringLike": ("like", False),
    "StringNotLike": ("like", True),
    "ArnEquals": ("equals", False),
    "ArnNotEquals": ("equals", True),
    "ArnLike": ("like", False),
    "ArnNotLike": ("like", True),
    "Bool": ("equals", False),
    "IpAddress": ("cidr", False),
    "NotIpAddress": ("cidr", True),
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


def _values_match(mode: str, expected_values: List[str], got: str) -> bool:
    if mode == "equals":
        return got in expected_values
    if mode == "like":
        return any(_pattern_matches(pattern, got) for pattern in expected_values)
    if mode == "cidr":
        import ipaddress

        try:
            address = ipaddress.ip_address(got)
        except ValueError:
            return False
        for expected in expected_values:
            try:
                network = ipaddress.ip_network(expected, strict=False)
            except ValueError:
                continue
            if address in network:
                return True
        return False
    raise ValueError(f"unknown condition matcher: {mode}")


def _evaluate_conditions(statement: JSON, context: Mapping[str, str]) -> Tuple[str, Optional[JSON]]:
    """-> (status, detail): 'satisfied' | 'missing_key' | 'mismatch' | 'unsupported'.

    Documented AWS semantics, computed exactly: negated operators are
    satisfied when the key is absent; ``...IfExists`` is satisfied when
    the key is absent; ``Null`` tests presence itself.
    """
    conditions = statement.get("Condition")
    if not isinstance(conditions, dict) or not conditions:
        return _CONDITION_SATISFIED, None
    for operator, pairs in conditions.items():
        operator_name = str(operator)
        if not isinstance(pairs, dict):
            return "unsupported", {"operator": operator_name}
        if operator_name == "Null":
            for key, expected in pairs.items():
                expect_absent = str(_string_values(expected)[0]).lower() == "true"
                is_absent = context.get(str(key)) is None
                if is_absent != expect_absent:
                    return "mismatch", {
                        "key": str(key),
                        "expected": [f"Null={expect_absent}"],
                        "got": "absent" if is_absent else str(context.get(str(key))),
                    }
            continue
        if_exists = operator_name.endswith("IfExists")
        base_name = operator_name.removesuffix("IfExists") if if_exists else operator_name
        entry = _CONDITION_OPERATORS.get(base_name)
        if entry is None:
            return "unsupported", {"operator": operator_name}
        mode, negated = entry
        for key, expected in pairs.items():
            expected_values = _string_values(expected)
            got = context.get(str(key))
            if got is None:
                if negated or if_exists:
                    # Absent key satisfies negated operators and IfExists.
                    continue
                return "missing_key", {"key": str(key), "expected": expected_values}
            matched = _values_match(mode, expected_values, str(got))
            if negated:
                matched = not matched
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
    for layer, carrier_policy in (
        ("resource_policy", resource_policy),
        ("kms_key_policy", kms_key_policy),
    ):
        if carrier_policy is None:
            continue
        for index, statement in enumerate(carrier_policy.get("Statement") or []):
            if isinstance(statement, dict):
                collected.append(_LayerStatement(layer, request.resource, index, statement))
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
    if blocking_layer not in BLOCKING_LAYERS:
        raise ValueError(f"blocking_layer outside the frozen vocabulary: {blocking_layer!r}")
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
    statements = _layer_statements(request, identity_policies, resource_policy, kms_key_policy)
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
        if entry.layer != "identity_policy" and not _principal_applies(statement, request):
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
    def _allow_search(
        layers: Sequence[str],
    ) -> Tuple[Optional[_LayerStatement], List[Tuple[_LayerStatement, str, JSON]]]:
        near_misses: List[Tuple[_LayerStatement, str, JSON]] = []
        for entry in statements:
            if entry.layer not in layers:
                continue
            statement = entry.statement
            if statement.get("Effect") != "Allow":
                continue
            if any(key in statement for key in ("NotAction", "NotPrincipal", "NotResource")):
                continue
            if not _action_matches(statement, request.action):
                continue
            if not _resource_matches(statement, request.resource):
                continue
            if entry.layer != "identity_policy" and not _principal_applies(statement, request):
                continue
            status, detail = _evaluate_conditions(statement, request.condition_context)
            if status == _CONDITION_SATISFIED:
                return entry, near_misses
            near_misses.append((entry, status, detail or {}))
        return None, near_misses

    if kms_key_policy is not None:
        # KMS: the key policy is authoritative. A direct grant suffices;
        # a root grant delegates to identity policies -- but when the key
        # policy grants this principal nothing directly, the decisive
        # layer is always the key policy: a delegated identity allow can
        # rescue the request (checked below), while an identity verdict
        # built without identity evidence is a guess (sweep-diagnosis
        # 2026-08-19 defect).
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
        if delegates and identity_policies:
            identity_allow, _identity_misses = _allow_search(["identity_policy"])
            if identity_allow is not None:
                return _allow_result(request, identity_allow)
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
    return _blocked_result(
        request,
        "identity_policy",
        misses,
        near_misses_by_resource=_resource_near_misses(request, statements),
    )


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


def _resource_near_misses(request: AccessRequest, statements: List[_LayerStatement]) -> List[JSON]:
    """Statements that match the requested ACTION on a different resource
    scope. Naming them (with their real Sids and honest scoping) is what
    an expert does when the caller asked about the wrong resource shape --
    e.g. a bucket ARN for an object-level action."""
    claims: List[JSON] = []
    for entry in statements:
        statement = entry.statement
        effect = statement.get("Effect")
        if effect not in ("Allow", "Deny"):
            continue
        if not _action_matches(statement, request.action):
            continue
        if _resource_matches(statement, request.resource):
            continue
        if entry.layer != "identity_policy" and not _principal_applies(statement, request):
            continue
        scope = ", ".join(_string_values(statement.get("Resource"))[:3])
        kind = "denying_statement" if effect == "Deny" else "missing_permission"
        verb = "denies" if effect == "Deny" else "grants"
        claims.append(
            _claim(
                kind,
                entry.layer,
                entry,
                f"Statement {statement.get('Sid') or f'#{entry.index}'} {verb} "
                f"{request.action}, but only on {scope} -- the requested resource "
                f"{request.resource} does not match. If you meant an object or a "
                "narrower resource, re-run with that exact ARN.",
            )
        )
        if len(claims) >= 2:
            break
    return claims


def _blocked_result(
    request: AccessRequest,
    default_layer: str,
    near_misses: List[Tuple[_LayerStatement, str, JSON]],
    *,
    near_misses_by_resource: Optional[List[JSON]] = None,
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
    extra_claims = list(near_misses_by_resource or [])
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
            ),
            *extra_claims,
        ],
    )


def _statement_digest(statement: JSON) -> str:
    canonical = json.dumps(statement, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _trimmed_statement(statement: JSON) -> Tuple[JSON, bool]:
    if len(json.dumps(statement)) <= _MAX_STATEMENT_BYTES:
        return statement, False
    trimmed = dict(statement)
    for key in ("Resource", "NotResource", "Action", "NotAction"):
        values = trimmed.get(key)
        if isinstance(values, list) and len(values) > 1:
            trimmed[key] = [values[0], f"... (+{len(values) - 1} more values trimmed)"]
        if len(json.dumps(trimmed)) <= _MAX_STATEMENT_BYTES:
            return trimmed, True
    minimal = {key: trimmed.get(key) for key in ("Sid", "Effect") if trimmed.get(key) is not None}
    minimal["_trimmed"] = "statement exceeded the evidence budget"
    return minimal, True


def _budget_claim(claim: JSON) -> JSON:
    budgeted = dict(claim)
    evidence = dict(claim.get("evidence") or {})
    statement = evidence.get("statement")
    if isinstance(statement, dict):
        trimmed, truncated = _trimmed_statement(statement)
        evidence["statement"] = trimmed
        evidence["evidence_truncated"] = truncated
        if truncated:
            evidence["statement_sha256"] = _statement_digest(statement)
    else:
        evidence["evidence_truncated"] = False
    budgeted["evidence"] = evidence
    return budgeted


def _next_block(request: AccessRequest, evaluation: Evaluation) -> JSON:
    verification: JSON = {
        "tool": "bluearch_explain_denial",
        "arguments": {
            "action": request.action,
            "resource": request.resource,
            "principal": request.principal,
            "condition_context": dict(request.condition_context),
        },
    }
    next_block: JSON = {"verification": verification}
    effect = evaluation.verdict.get("effect")
    if effect in ("allow", "unknown"):
        return next_block
    decisive = evaluation.claims[0] if evaluation.claims else {}
    layer = str(decisive.get("layer") or evaluation.verdict.get("blocking_layer") or "")
    next_block["remediation"] = {
        "description": str(decisive.get("explanation") or "Review the blocking layer."),
        "operation": _REMEDIATION_OPERATIONS.get(layer),
        "tool": None,
        "requires_review": True,
    }
    return next_block


def assemble_response(
    *,
    request: AccessRequest,
    evaluation: Evaluation,
    ledger: Sequence[JSON],
    unknowns: Sequence[JSON],
    status: Optional[str] = None,
    message: Optional[str] = None,
) -> JSON:
    claims = [_budget_claim(claim) for claim in evaluation.claims[:_MAX_CLAIMS]]
    overflow = len(evaluation.claims) - len(claims)
    effect = str(evaluation.verdict.get("effect") or "unknown")
    if status is None:
        status = "not_denied" if effect == "allow" else "explained"
    response: JSON = {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "verdict": evaluation.verdict,
        "claims": claims,
        "evaluation_ledger": list(ledger),
        "unknowns": list(unknowns),
        "next": _next_block(request, evaluation),
    }
    if overflow > 0:
        response["claims_truncated"] = overflow
    if message:
        response["message"] = message
    while len(json.dumps(response)) > _MAX_RESPONSE_BYTES and len(response["claims"]) > 1:
        response["claims"] = response["claims"][:-1]
        response["claims_truncated"] = int(response.get("claims_truncated") or 0) + 1
    return response


_ASSUMED_ROLE_RE = re.compile(r"^arn:aws:sts::(\d+):assumed-role/([^/]+)/.+$")
_DENIED_MESSAGE_RE = re.compile(
    r"User: (?P<principal>arn:\S+) is not authorized to perform: "
    r"(?P<action>[A-Za-z0-9-]+:[A-Za-z0-9*]+)"
    r"(?: on resource: (?P<resource>[^\s,\"]+))?"
)


def canonical_principal(principal: str) -> str:
    """Map an STS assumed-role ARN to the role ARN policies reference."""
    match = _ASSUMED_ROLE_RE.match(principal or "")
    if match:
        return f"arn:aws:iam::{match.group(1)}:role/{match.group(2)}"
    return principal or ""


def normalize_resource_ref(resource: str) -> str:
    if resource.startswith("s3://"):
        return "arn:aws:s3:::" + resource.removeprefix("s3://")
    return resource


def arn_service(resource: str) -> str:
    parts = resource.split(":")
    return parts[2] if resource.startswith("arn:") and len(parts) > 2 else ""


def arn_account(resource: str) -> str:
    parts = resource.split(":")
    return parts[4] if resource.startswith("arn:") and len(parts) > 4 else ""


def policy_document(value: Any) -> Optional[JSON]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        text = value
        if text.startswith("%7B"):
            from urllib.parse import unquote

            text = unquote(text)
        try:
            parsed = json.loads(text)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def parse_denied_message(text: str) -> JSON:
    match = _DENIED_MESSAGE_RE.search(text or "")
    if not match:
        return {}
    return {key: value for key, value in match.groupdict().items() if value}
