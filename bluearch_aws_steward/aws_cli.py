from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from bluearch_aws_steward.aws_endpoints import (
    LOCAL_AWS_CREDENTIAL_VALUE,
    is_loopback_aws_endpoint,
    validate_explicit_aws_endpoint,
)
from bluearch_aws_steward.providers.base import AwsProviderError
from bluearch_aws_steward.providers.normalize import (
    normalize_cloudtrail_trail,
    normalize_ebs_volume,
    normalize_elastic_ip,
    normalize_lambda_function,
    normalize_log_group,
    normalize_rds_instance,
)


class AwsCliError(AwsProviderError):
    def __init__(self, message: str, returncode: int, stderr: str = "") -> None:
        super().__init__(message, returncode=returncode, detail=stderr)
        self.stderr = stderr


@dataclass(frozen=True)
class AwsCliConfig:
    profile: Optional[str] = None
    endpoint_url: Optional[str] = None
    region: str = "us-east-1"
    command_timeout_sec: int = 20


class AwsCli:
    """Narrow AWS CLI wrapper.

    This is intentionally explicit: the product should never execute arbitrary
    agent/model-provided shell commands.
    """

    def __init__(self, config: AwsCliConfig) -> None:
        validate_explicit_aws_endpoint(config.endpoint_url)
        self.config = config

    def _base_command(self) -> List[str]:
        command = ["aws", "--region", self.config.region, "--no-cli-pager"]
        if self.config.profile:
            command.extend(["--profile", self.config.profile])
        if self.config.endpoint_url:
            command.extend(["--endpoint-url", self.config.endpoint_url])
        return command

    def run_json(self, args: List[str], allow_error: bool = False) -> Dict[str, Any]:
        command = self._base_command() + args + ["--output", "json"]
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                env=self._environment(),
                timeout=self.config.command_timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = f"Timed out after {self.config.command_timeout_sec}s: {' '.join(args)}"
            if allow_error:
                return {"__error__": stderr, "__returncode__": 124}
            raise AwsCliError(
                f"AWS CLI command timed out: {' '.join(args)}",
                returncode=124,
                stderr=stderr,
            ) from exc
        if result.returncode != 0:
            if allow_error:
                return {"__error__": result.stderr.strip(), "__returncode__": result.returncode}
            raise AwsCliError(
                f"AWS CLI command failed: {' '.join(args)}",
                returncode=result.returncode,
                stderr=result.stderr.strip(),
            )
        if not result.stdout.strip():
            return {}
        return json.loads(result.stdout)

    def run_text(self, args: List[str], allow_error: bool = False) -> str:
        command = self._base_command() + args + ["--output", "text"]
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                env=self._environment(),
                timeout=self.config.command_timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            if allow_error:
                return ""
            raise AwsCliError(
                f"AWS CLI command timed out: {' '.join(args)}",
                returncode=124,
                stderr=f"Timed out after {self.config.command_timeout_sec}s: {' '.join(args)}",
            ) from exc
        if result.returncode != 0:
            if allow_error:
                return ""
            raise AwsCliError(
                f"AWS CLI command failed: {' '.join(args)}",
                returncode=result.returncode,
                stderr=result.stderr.strip(),
            )
        return result.stdout.strip()

    def run_no_output(self, args: List[str]) -> None:
        command = self._base_command() + args
        try:
            result = subprocess.run(
                command,
                check=False,
                text=True,
                capture_output=True,
                env=self._environment(),
                timeout=self.config.command_timeout_sec,
            )
        except subprocess.TimeoutExpired as exc:
            raise AwsCliError(
                f"AWS CLI command timed out: {' '.join(args)}",
                returncode=124,
                stderr=f"Timed out after {self.config.command_timeout_sec}s: {' '.join(args)}",
            ) from exc
        if result.returncode != 0:
            raise AwsCliError(
                f"AWS CLI command failed: {' '.join(args)}",
                returncode=result.returncode,
                stderr=result.stderr.strip(),
            )

    def _environment(self) -> Dict[str, str]:
        env = dict(os.environ)
        env.setdefault("AWS_PAGER", "")
        if is_loopback_aws_endpoint(self.config.endpoint_url) and not self.config.profile:
            env["AWS_ACCESS_KEY_ID"] = LOCAL_AWS_CREDENTIAL_VALUE
            env["AWS_SECRET_ACCESS_KEY"] = LOCAL_AWS_CREDENTIAL_VALUE
            env["AWS_SESSION_TOKEN"] = LOCAL_AWS_CREDENTIAL_VALUE
        return env

    def caller_identity(self) -> Dict[str, Any]:
        return self.run_json(["sts", "get-caller-identity"])

    def list_buckets(self) -> List[str]:
        payload = self.run_json(["s3api", "list-buckets"])
        return sorted(bucket["Name"] for bucket in payload.get("Buckets", []))

    def list_log_groups(self) -> List[Dict[str, Any]]:
        payload = self.run_json(["logs", "describe-log-groups"])
        groups = [normalize_log_group(group) for group in payload.get("logGroups", [])]
        return sorted(groups, key=lambda group: str(group.get("name") or ""))

    def list_ebs_volumes(self) -> List[Dict[str, Any]]:
        payload = self.run_json(["ec2", "describe-volumes"])
        volumes = [normalize_ebs_volume(volume) for volume in payload.get("Volumes", [])]
        return sorted(volumes, key=lambda volume: str(volume.get("volume_id") or ""))

    def list_elastic_ips(self) -> List[Dict[str, Any]]:
        payload = self.run_json(["ec2", "describe-addresses"])
        addresses = [normalize_elastic_ip(address) for address in payload.get("Addresses") or []]
        return sorted(addresses, key=lambda address: str(address.get("allocation_id") or ""))

    def get_iam_account_summary(self) -> Dict[str, Any]:
        payload = self.run_json(["iam", "get-account-summary"])
        return dict(payload.get("SummaryMap") or {})

    def list_cloudtrail_trails(self) -> List[Dict[str, Any]]:
        payload = self.run_json(["cloudtrail", "describe-trails", "--no-include-shadow-trails"])
        trails = []
        for trail in payload.get("trailList") or []:
            name = trail.get("TrailARN") or trail.get("Name")
            status = (
                self.run_json(["cloudtrail", "get-trail-status", "--name", str(name)])
                if name
                else {}
            )
            trails.append(normalize_cloudtrail_trail(trail, status))
        return sorted(trails, key=lambda trail: str(trail.get("name") or ""))

    def list_rds_instances(self) -> List[Dict[str, Any]]:
        payload = self.run_json(["rds", "describe-db-instances"])
        instances = [normalize_rds_instance(item) for item in payload.get("DBInstances") or []]
        return sorted(instances, key=lambda instance: str(instance.get("identifier") or ""))

    def list_lambda_functions(self) -> List[Dict[str, Any]]:
        payload = self.run_json(["lambda", "list-functions"])
        functions = [normalize_lambda_function(item) for item in payload.get("Functions") or []]
        return sorted(functions, key=lambda function: str(function.get("name") or ""))

    def get_public_access_block(self, bucket: str) -> Dict[str, Any]:
        payload = self.run_json(
            ["s3api", "get-public-access-block", "--bucket", bucket], allow_error=True
        )
        self._raise_unexpected_error(payload, ["NoSuchPublicAccessBlockConfiguration"])
        return payload.get("PublicAccessBlockConfiguration", {})

    def get_bucket_policy(self, bucket: str) -> Optional[Dict[str, Any]]:
        payload = self.run_json(
            ["s3api", "get-bucket-policy", "--bucket", bucket], allow_error=True
        )
        self._raise_unexpected_error(payload, ["NoSuchBucketPolicy"])
        policy = payload.get("Policy")
        if not policy:
            return None
        return json.loads(policy)

    def get_bucket_encryption_rules(self, bucket: str) -> List[Dict[str, Any]]:
        payload = self.run_json(
            ["s3api", "get-bucket-encryption", "--bucket", bucket], allow_error=True
        )
        self._raise_unexpected_error(payload, ["ServerSideEncryptionConfigurationNotFoundError"])
        config = payload.get("ServerSideEncryptionConfiguration") or {}
        return config.get("Rules") or []

    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        payload = self.run_json(
            ["s3api", "get-bucket-lifecycle-configuration", "--bucket", bucket], allow_error=True
        )
        self._raise_unexpected_error(payload, ["NoSuchLifecycleConfiguration"])
        return payload.get("Rules") or []

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        payload = self.run_json(
            ["s3api", "get-bucket-versioning", "--bucket", bucket], allow_error=True
        )
        self._raise_unexpected_error(payload, [])
        return payload.get("Status")

    def _raise_unexpected_error(
        self, payload: Dict[str, Any], expected_error_codes: List[str]
    ) -> None:
        error = str(payload.get("__error__") or "")
        if not error:
            return
        if any(code in error for code in expected_error_codes):
            return
        raise AwsCliError(
            "AWS CLI inspection failed",
            returncode=int(payload.get("__returncode__") or 1),
            stderr=error,
        )

    def put_public_access_block(self, bucket: str) -> None:
        self.run_no_output(
            [
                "s3api",
                "put-public-access-block",
                "--bucket",
                bucket,
                "--public-access-block-configuration",
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ]
        )

    def put_default_encryption(self, bucket: str) -> None:
        self.run_no_output(
            [
                "s3api",
                "put-bucket-encryption",
                "--bucket",
                bucket,
                "--server-side-encryption-configuration",
                '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}',
            ]
        )

    def put_lifecycle(
        self,
        bucket: str,
        *,
        transition_days: int = 30,
        storage_class: str = "STANDARD_IA",
    ) -> None:
        configuration = json.dumps(
            {
                "Rules": [
                    {
                        "ID": "bluearch-steward-transition-old-objects",
                        "Status": "Enabled",
                        "Filter": {"Prefix": ""},
                        "Transitions": [{"Days": transition_days, "StorageClass": storage_class}],
                    }
                ]
            },
            separators=(",", ":"),
        )
        self.run_no_output(
            [
                "s3api",
                "put-bucket-lifecycle-configuration",
                "--bucket",
                bucket,
                "--lifecycle-configuration",
                configuration,
            ]
        )

    def put_versioning(self, bucket: str) -> None:
        self.run_no_output(
            [
                "s3api",
                "put-bucket-versioning",
                "--bucket",
                bucket,
                "--versioning-configuration",
                "Status=Enabled",
            ]
        )

    def put_bucket_logging(
        self,
        bucket: str,
        *,
        target_bucket: str,
        target_prefix: str,
    ) -> None:
        configuration = json.dumps(
            {
                "LoggingEnabled": {
                    "TargetBucket": target_bucket,
                    "TargetPrefix": target_prefix,
                }
            },
            separators=(",", ":"),
        )
        self.run_no_output(
            [
                "s3api",
                "put-bucket-logging",
                "--bucket",
                bucket,
                "--bucket-logging-status",
                configuration,
            ]
        )

    def enable_alb_access_logging(
        self,
        load_balancer_arn: str,
        *,
        target_bucket: str,
        target_prefix: str,
    ) -> None:
        attributes = json.dumps(
            [
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": target_bucket},
                {"Key": "access_logs.s3.prefix", "Value": target_prefix},
            ],
            separators=(",", ":"),
        )
        self.run_no_output(
            [
                "elbv2",
                "modify-load-balancer-attributes",
                "--load-balancer-arn",
                load_balancer_arn,
                "--attributes",
                attributes,
            ]
        )

    def put_log_retention(self, log_group_name: str, retention_days: int) -> None:
        self.run_no_output(
            [
                "logs",
                "put-retention-policy",
                "--log-group-name",
                log_group_name,
                "--retention-in-days",
                str(retention_days),
            ]
        )

    def update_cloudtrail_log_file_validation(self, trail_name: str, *, enabled: bool) -> None:
        self.run_no_output(
            [
                "cloudtrail",
                "update-trail",
                "--name",
                trail_name,
                "--enable-log-file-validation" if enabled else "--no-enable-log-file-validation",
            ]
        )
