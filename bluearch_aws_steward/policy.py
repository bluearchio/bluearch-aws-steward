from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional


@dataclass(frozen=True)
class ScanPolicy:
    ebs_min_unattached_days: Optional[int] = None
    cloudwatch_retention_days: Optional[int] = None
    cloudwatch_min_stored_bytes: Optional[int] = None
    exclude_tags: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            key: value
            for key, value in {
                "ebs_min_unattached_days": self.ebs_min_unattached_days,
                "cloudwatch_retention_days": self.cloudwatch_retention_days,
                "cloudwatch_min_stored_bytes": self.cloudwatch_min_stored_bytes,
                "exclude_tags": self.exclude_tags,
            }.items()
            if value is not None and value != {}
        }


def build_scan_policy(
    *,
    ebs_min_unattached_days: Any = None,
    cloudwatch_retention_days: Any = None,
    cloudwatch_min_stored_bytes: Any = None,
    exclude_tags: Any = None,
) -> ScanPolicy:
    return ScanPolicy(
        ebs_min_unattached_days=_optional_int(
            "ebs_min_unattached_days",
            ebs_min_unattached_days,
            minimum=0,
            maximum=3650,
        ),
        cloudwatch_retention_days=_optional_int(
            "cloudwatch_retention_days",
            cloudwatch_retention_days,
            minimum=1,
            maximum=3653,
        ),
        cloudwatch_min_stored_bytes=_optional_int(
            "cloudwatch_min_stored_bytes",
            cloudwatch_min_stored_bytes,
            minimum=0,
        ),
        exclude_tags=_parse_exclude_tags(exclude_tags),
    )


def effective_int(parameters: Mapping[str, Any], name: str, override: Optional[int]) -> int:
    value = override if override is not None else parameters.get(name)
    if value is None:
        raise ValueError(f"Missing executable rule parameter: {name}")
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Executable rule parameter {name} must be an integer, got {value!r}"
        ) from exc


def effective_float(parameters: Mapping[str, Any], name: str) -> float:
    value = parameters.get(name)
    if value is None:
        raise ValueError(f"Missing executable rule parameter: {name}")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"Executable rule parameter {name} must be numeric, got {value!r}"
        ) from exc


def effective_exempt_tags(parameters: Mapping[str, Any], policy: ScanPolicy) -> Dict[str, str]:
    configured = parameters.get("exempt_tags") or {}
    defaults = (
        {str(key): str(value) for key, value in configured.items()}
        if isinstance(configured, dict)
        else {}
    )
    return {**defaults, **policy.exclude_tags}


def resource_is_exempt(tags: Mapping[str, Any], exemptions: Mapping[str, str]) -> bool:
    normalized = {str(key): str(value).lower() for key, value in tags.items()}
    return any(normalized.get(str(key)) == str(value).lower() for key, value in exemptions.items())


def _optional_int(
    name: str, value: Any, *, minimum: int, maximum: Optional[int] = None
) -> Optional[int]:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if parsed < minimum or (maximum is not None and parsed > maximum):
        upper = f" and at most {maximum}" if maximum is not None else ""
        raise ValueError(f"{name} must be at least {minimum}{upper}")
    return parsed


def _parse_exclude_tags(value: Any) -> Dict[str, str]:
    if value is None:
        return {}
    if isinstance(value, Mapping):
        return {str(key): str(tag_value) for key, tag_value in value.items()}
    if isinstance(value, str):
        values: Iterable[Any] = [value]
    elif isinstance(value, Iterable):
        values = value
    else:
        raise ValueError("exclude_tags must be an object or a list of KEY=VALUE strings")

    parsed: Dict[str, str] = {}
    for item in values:
        text = str(item)
        if "=" not in text:
            raise ValueError(f"exclude tag must use KEY=VALUE syntax: {text}")
        key, tag_value = text.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("exclude tag key cannot be empty")
        parsed[key] = tag_value.strip()
    return parsed
