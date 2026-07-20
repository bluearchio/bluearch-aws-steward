from __future__ import annotations

import os
from importlib import import_module
from typing import Any, Dict, Mapping, Optional

JSON = Dict[str, Any]


def discover_aws_context(
    *,
    environ: Optional[Mapping[str, str]] = None,
    full_config: Optional[JSON] = None,
) -> JSON:
    """Return non-secret local AWS profile metadata for interactive selection."""

    environment = dict(os.environ if environ is None else environ)
    discovery_errors = []
    if full_config is None:
        try:
            botocore_session = import_module("botocore.session")
            full_config = botocore_session.Session().full_config
        except Exception as exc:  # noqa: BLE001 - discovery must remain usable without config
            full_config = {}
            discovery_errors.append(f"Could not read AWS profile configuration: {exc}")

    configured_profiles = full_config.get("profiles") if isinstance(full_config, dict) else {}
    configured_profiles = configured_profiles if isinstance(configured_profiles, dict) else {}
    active_profile = _first_value(environment, "AWS_PROFILE", "AWS_DEFAULT_PROFILE")
    environment_region = _first_value(environment, "AWS_REGION", "AWS_DEFAULT_REGION")

    profiles = []
    for name in sorted(str(profile_name) for profile_name in configured_profiles):
        settings = configured_profiles.get(name)
        settings = settings if isinstance(settings, dict) else {}
        profiles.append(
            {
                "name": name,
                "kind": _profile_kind(settings),
                "region": _clean(settings.get("region")),
                "active": name == active_profile,
            }
        )

    credential_sources = []
    if environment.get("AWS_ACCESS_KEY_ID") or environment.get("AWS_SECRET_ACCESS_KEY"):
        credential_sources.append("environment")
    if environment.get("AWS_WEB_IDENTITY_TOKEN_FILE"):
        credential_sources.append("web_identity")
    if environment.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI") or environment.get(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI"
    ):
        credential_sources.append("container")

    return {
        "profiles": profiles,
        "profile_count": len(profiles),
        "active_profile": active_profile,
        "environment_region": environment_region,
        "credential_sources": credential_sources,
        "non_profile_credentials_configured": bool(credential_sources),
        "discovery_errors": discovery_errors,
        "secrets_included": False,
    }


def _profile_kind(settings: Mapping[str, Any]) -> str:
    if settings.get("sso_session") or settings.get("sso_start_url"):
        return "sso"
    if settings.get("web_identity_token_file"):
        return "web_identity"
    if settings.get("role_arn"):
        return "assume_role"
    if settings.get("credential_process"):
        return "credential_process"
    if settings.get("aws_access_key_id"):
        return "static_credentials"
    return "configured"


def _first_value(values: Mapping[str, str], *keys: str) -> Optional[str]:
    for key in keys:
        value = _clean(values.get(key))
        if value:
            return value
    return None


def _clean(value: Any) -> Optional[str]:
    cleaned = str(value or "").strip()
    return cleaned or None
