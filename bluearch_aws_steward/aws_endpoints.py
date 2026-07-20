from __future__ import annotations

from ipaddress import ip_address
from typing import Optional
from urllib.parse import urlparse

LOCAL_AWS_CREDENTIAL_VALUE = "test"


def is_loopback_aws_endpoint(endpoint_url: Optional[str]) -> bool:
    """Return whether an explicit AWS endpoint is confined to this machine."""

    if not endpoint_url:
        return False

    hostname = (urlparse(endpoint_url).hostname or "").rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        return True
    if hostname == "localhost.localstack.cloud":
        return True

    try:
        return ip_address(hostname).is_loopback
    except ValueError:
        return False


def validate_explicit_aws_endpoint(endpoint_url: Optional[str]) -> None:
    """Reject explicit AWS endpoints that could receive signed AWS requests remotely."""

    if not endpoint_url:
        return

    parsed = urlparse(endpoint_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("AWS endpoint_url must be an HTTP(S) loopback URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("AWS endpoint_url cannot contain credentials, a query, or a fragment.")
    if not is_loopback_aws_endpoint(endpoint_url):
        raise ValueError(
            "Explicit AWS endpoint_url values are restricted to loopback emulators. "
            "Use normal AWS endpoint resolution for live AWS."
        )
