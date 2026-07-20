from __future__ import annotations

import shutil
from importlib.util import find_spec
from typing import Any, Dict, Optional

from bluearch_aws_steward.providers.aws_cli import AwsCliProvider, AwsCliProviderConfig
from bluearch_aws_steward.providers.aws_sdk import AwsSdkProvider, AwsSdkProviderConfig
from bluearch_aws_steward.providers.base import AwsProvider

DEFAULT_AWS_PROVIDER = "aws-sdk"
SUPPORTED_AWS_PROVIDERS = ("aws-sdk", "aws-cli")


def create_aws_provider(
    provider: str = DEFAULT_AWS_PROVIDER,
    profile: Optional[str] = None,
    endpoint_url: Optional[str] = None,
    region: str = "us-east-1",
) -> AwsProvider:
    if provider == "aws-cli":
        return AwsCliProvider(
            AwsCliProviderConfig(profile=profile, endpoint_url=endpoint_url, region=region)
        )
    if provider == "aws-sdk":
        return AwsSdkProvider(
            AwsSdkProviderConfig(profile=profile, endpoint_url=endpoint_url, region=region)
        )
    supported = ", ".join(SUPPORTED_AWS_PROVIDERS)
    raise ValueError(f"Unsupported AWS provider: {provider}. Supported providers: {supported}")


def provider_dependency_status(provider: str) -> Dict[str, Any]:
    if provider == "aws-cli":
        aws_path = shutil.which("aws")
        return {"name": "aws-cli", "ok": bool(aws_path), "detail": aws_path or "not found"}
    if provider == "aws-sdk":
        available = find_spec("boto3") is not None
        return {
            "name": "boto3",
            "ok": available,
            "detail": "installed" if available else "not found; reinstall BlueArch AWS Steward",
        }
    supported = ", ".join(SUPPORTED_AWS_PROVIDERS)
    raise ValueError(f"Unsupported AWS provider: {provider}. Supported providers: {supported}")
