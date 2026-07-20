from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from bluearch_aws_steward.aws_cli import AwsCli, AwsCliConfig
from bluearch_aws_steward.providers.normalize import (
    normalize_cloudtrail_trail,
    normalize_ebs_volume,
    normalize_elastic_ip,
    normalize_lambda_function,
    normalize_log_group,
    normalize_rds_instance,
)
from bluearch_aws_steward.providers.operations import READ_OPERATIONS, read_operation


@dataclass(frozen=True)
class AwsCliProviderConfig:
    profile: Optional[str] = None
    endpoint_url: Optional[str] = None
    region: str = "us-east-1"
    command_timeout_sec: int = 20


class AwsCliProvider(AwsCli):
    """AWS provider backed by the local AWS CLI.

    The current implementation subclasses the existing narrow CLI wrapper so
    the provider refactor changes the detector boundary without changing AWS
    behavior. A future SDK or AWS MCP provider can implement the same protocol
    without inheriting from this class.
    """

    def __init__(self, config: AwsCliProviderConfig) -> None:
        super().__init__(
            AwsCliConfig(
                profile=config.profile,
                endpoint_url=config.endpoint_url,
                region=config.region,
                command_timeout_sec=config.command_timeout_sec,
            )
        )

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        spec = read_operation(operation)
        arguments = list(spec.cli_command)
        for key, value in parameters.items():
            if value is None:
                continue
            flag = "--" + _camel_to_kebab(key)
            if isinstance(value, bool):
                arguments.append(flag if value else "--no-" + _camel_to_kebab(key))
            elif isinstance(value, list) and all(
                not isinstance(item, (dict, list)) for item in value
            ):
                arguments.append(flag)
                arguments.extend(_cli_scalar(item) for item in value)
            elif isinstance(value, (dict, list)):
                arguments.extend([flag, json.dumps(value, separators=(",", ":"), default=str)])
            else:
                arguments.extend([flag, _cli_scalar(value)])

        payload = self.run_json(arguments, allow_error=bool(spec.expected_missing_codes))
        if "__error__" in payload:
            detail = str(payload.get("__error__") or "")
            if any(code in detail for code in spec.expected_missing_codes):
                return {}
            self._raise_unexpected_error(payload, [])
        return payload

    def caller_identity(self) -> Dict[str, Any]:
        return self.read("sts.get_caller_identity")

    def list_buckets(self) -> List[str]:
        payload = self.read("s3.list_buckets")
        return sorted(bucket["Name"] for bucket in payload.get("Buckets") or [])

    def list_log_groups(self) -> List[Dict[str, Any]]:
        groups = [
            normalize_log_group(group)
            for group in self.read("logs.describe_log_groups").get("logGroups") or []
        ]
        return sorted(groups, key=lambda group: str(group.get("name") or ""))

    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        volumes = [
            normalize_ebs_volume(volume)
            for volume in self.read("ec2.describe_volumes").get("Volumes") or []
        ]
        return sorted(volumes, key=lambda volume: str(volume.get("volume_id") or ""))

    def list_elastic_ips(self) -> List[Dict[str, Any]]:
        addresses = [
            normalize_elastic_ip(address)
            for address in self.read("ec2.describe_addresses").get("Addresses") or []
        ]
        return sorted(addresses, key=lambda address: str(address.get("allocation_id") or ""))

    def get_iam_account_summary(self) -> Dict[str, Any]:
        return dict(self.read("iam.get_account_summary").get("SummaryMap") or {})

    def list_cloudtrail_trails(self) -> List[Dict[str, Any]]:
        payload = self.read("cloudtrail.describe_trails", includeShadowTrails=False)
        trails = []
        for trail in payload.get("trailList") or []:
            name = trail.get("TrailARN") or trail.get("Name")
            status = self.read("cloudtrail.get_trail_status", Name=name) if name else {}
            trails.append(normalize_cloudtrail_trail(trail, status))
        return sorted(trails, key=lambda trail: str(trail.get("name") or ""))

    def list_rds_instances(self) -> List[Dict[str, Any]]:
        instances = [
            normalize_rds_instance(item)
            for item in self.read("rds.describe_db_instances").get("DBInstances") or []
        ]
        return sorted(instances, key=lambda instance: str(instance.get("identifier") or ""))

    def list_lambda_functions(self) -> List[Dict[str, Any]]:
        functions = [
            normalize_lambda_function(item)
            for item in self.read("lambda.list_functions").get("Functions") or []
        ]
        return sorted(functions, key=lambda function: str(function.get("name") or ""))

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        payload = self.read("s3.get_public_access_block", Bucket=bucket)
        return payload.get("PublicAccessBlockConfiguration", {})

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        payload = self.read("s3.get_bucket_policy", Bucket=bucket)
        policy = payload.get("Policy")
        if not policy:
            return None
        if isinstance(policy, dict):
            return policy
        return json.loads(policy)

    def get_bucket_encryption_rules(self, bucket: str) -> List[Dict[str, Any]]:
        payload = self.read("s3.get_bucket_encryption", Bucket=bucket)
        configuration = payload.get("ServerSideEncryptionConfiguration") or {}
        return configuration.get("Rules") or []

    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        payload = self.read("s3.get_bucket_lifecycle_configuration", Bucket=bucket)
        return payload.get("Rules") or []

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        return self.read("s3.get_bucket_versioning", Bucket=bucket).get("Status")


def _camel_to_kebab(value: str) -> str:
    chars: List[str] = []
    for char in value:
        if char.isupper() and chars:
            chars.append("-")
        chars.append(char.lower())
    return "".join(chars).replace("_", "-")


def _cli_scalar(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
