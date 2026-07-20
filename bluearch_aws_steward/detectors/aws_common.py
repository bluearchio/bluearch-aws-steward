from __future__ import annotations

import fnmatch
import json
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional
from urllib.parse import unquote


def age_days(value: Any, *, now: datetime | None = None) -> Optional[int]:
    if value is None:
        return None
    current = now or datetime.now(timezone.utc)
    try:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)):
            timestamp = float(value)
            if timestamp > 10_000_000_000:
                timestamp /= 1000
            parsed = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        else:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    except (OverflowError, TypeError, ValueError):
        return None
    return max(0, int((current - parsed.astimezone(timezone.utc)).total_seconds() // 86400))


def tags_dict(tags: Iterable[Mapping[str, Any]] | Mapping[str, Any] | None) -> Dict[str, str]:
    if isinstance(tags, Mapping):
        return {str(key): str(value or "") for key, value in tags.items()}
    return {
        str(tag.get("Key") if tag.get("Key") is not None else tag.get("key")): str(
            tag.get("Value") if tag.get("Value") is not None else tag.get("value") or ""
        )
        for tag in tags or []
        if tag.get("Key") is not None or tag.get("key") is not None
    }


def policy_document(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if not isinstance(value, str) or not value:
        return {}
    decoded = unquote(value)
    try:
        payload = json.loads(decoded)
    except (json.JSONDecodeError, TypeError):
        return {}
    return dict(payload) if isinstance(payload, Mapping) else {}


def policy_has_full_admin(value: Any) -> bool:
    document = policy_document(value)
    statements = document.get("Statement") or []
    if isinstance(statements, Mapping):
        statements = [statements]
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("Effect") != "Allow":
            continue
        actions = _values(statement.get("Action"))
        resources = _values(statement.get("Resource"))
        if "*" in actions and "*" in resources and not statement.get("Condition"):
            return True
    return False


def public_allow_statements(
    value: Any, *, sensitive_actions: Iterable[str]
) -> List[Dict[str, Any]]:
    """Return redacted evidence for unconditioned wildcard-principal allows."""

    document = policy_document(value)
    statements = document.get("Statement") or []
    if isinstance(statements, Mapping):
        statements = [statements]
    action_patterns = {str(action).lower() for action in sensitive_actions}
    matches: List[Dict[str, Any]] = []
    for index, statement in enumerate(statements):
        if not isinstance(statement, Mapping):
            continue
        if str(statement.get("Effect") or "").lower() != "allow":
            continue
        if not _principal_is_public(statement.get("Principal")):
            continue
        if _has_restricting_condition(statement.get("Condition")):
            continue
        actions = sorted(
            {
                action
                for action in _values(statement.get("Action"))
                if _action_matches(action, action_patterns)
            }
        )
        if not actions:
            continue
        matches.append(
            {
                "statement_id": str(statement.get("Sid") or f"statement-{index + 1}"),
                "matched_actions": actions,
                "principal": "public",
                "restricting_condition_present": False,
            }
        )
    return matches


def flattened_instances(payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
    return [
        dict(instance)
        for reservation in payload.get("Reservations") or []
        for instance in reservation.get("Instances") or []
        if isinstance(instance, Mapping)
    ]


def cost_evidence(status: str, basis: str, *, confidence: str = "medium") -> Dict[str, Any]:
    """Describe cost evidence without inventing an account-specific dollar estimate."""

    return {
        "status": status,
        "estimated_monthly_cost_usd": None,
        "estimated_monthly_savings_usd": None,
        "confidence": confidence,
        "basis": basis,
        "assumptions": [],
    }


def _values(value: Any) -> List[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def _principal_is_public(value: Any) -> bool:
    if value == "*":
        return True
    if not isinstance(value, Mapping):
        return False
    aws_principals = value.get("AWS")
    return "*" in _values(aws_principals)


def _has_restricting_condition(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    restricting_keys = {
        "aws:principalaccount",
        "aws:principalarn",
        "aws:principalorgid",
        "aws:sourceaccount",
        "aws:sourcearn",
        "aws:sourceowner",
        "aws:sourcevpc",
        "aws:sourcevpce",
        "aws:userid",
    }
    for operator_values in value.values():
        if not isinstance(operator_values, Mapping):
            continue
        if restricting_keys & {str(key).lower() for key in operator_values}:
            return True
    return False


def _action_matches(action: str, sensitive_actions: set[str]) -> bool:
    normalized = action.lower()
    if normalized == "*":
        return True
    return any(fnmatch.fnmatchcase(sensitive, normalized) for sensitive in sensitive_actions)
