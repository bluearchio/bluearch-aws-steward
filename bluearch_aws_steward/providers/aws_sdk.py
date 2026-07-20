from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import import_module
from threading import Lock
from typing import Any, Dict, List, Optional, Set

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
from bluearch_aws_steward.providers.operations import READ_OPERATIONS, read_operation


class AwsSdkError(AwsProviderError):
    def __init__(self, message: str, code: str = "", detail: str = "", returncode: int = 1) -> None:
        super().__init__(message, returncode=returncode, detail=detail)
        self.code = code


@dataclass(frozen=True)
class AwsSdkProviderConfig:
    profile: Optional[str] = None
    endpoint_url: Optional[str] = None
    region: str = "us-east-1"


class AwsSdkProvider:
    """AWS provider backed by boto3.

    boto3 is loaded lazily so importing Steward remains fast and provider
    dependency failures are returned through the normal provider error model.
    """

    def __init__(self, config: AwsSdkProviderConfig, session: Any = None) -> None:
        validate_explicit_aws_endpoint(config.endpoint_url)
        self.config = config
        self._session = session or self._create_session()
        self._clients: Dict[str, Any] = {}
        self._clients_lock = Lock()

    def _create_session(self) -> Any:
        try:
            boto3 = import_module("boto3")
        except ModuleNotFoundError as exc:
            raise AwsSdkError(
                "AWS SDK provider requires boto3.",
                code="MissingDependency",
                detail="Reinstall BlueArch AWS Steward to restore its bundled boto3 dependency.",
            ) from exc

        session_options: Dict[str, Any] = {
            "profile_name": self.config.profile,
            "region_name": self.config.region,
        }
        if is_loopback_aws_endpoint(self.config.endpoint_url) and not self.config.profile:
            session_options.update(
                aws_access_key_id=LOCAL_AWS_CREDENTIAL_VALUE,
                aws_secret_access_key=LOCAL_AWS_CREDENTIAL_VALUE,
                aws_session_token=LOCAL_AWS_CREDENTIAL_VALUE,
            )

        try:
            return boto3.Session(**session_options)
        except Exception as exc:
            raise self._translate_error("create AWS SDK session", exc) from exc

    def capabilities(self) -> Set[str]:
        return set(READ_OPERATIONS)

    def read(self, operation: str, **parameters: Any) -> Dict[str, Any]:
        spec = read_operation(operation)
        if spec.expected_missing_codes:
            response = self._call_optional(
                spec.service,
                spec.sdk_operation,
                list(spec.expected_missing_codes),
                **parameters,
            )
            return response or {}
        if not spec.paginated:
            return self._call(spec.service, spec.sdk_operation, **parameters)

        client = self._client(spec.service)
        can_paginate = getattr(client, "can_paginate", None)
        if not callable(can_paginate) or not can_paginate(spec.sdk_operation):
            return self._call(spec.service, spec.sdk_operation, **parameters)

        merged: Dict[str, Any] = {key: [] for key in spec.result_keys}
        try:
            paginator = client.get_paginator(spec.sdk_operation)
            for page in paginator.paginate(**parameters):
                for key in spec.result_keys:
                    merged[key].extend(page.get(key) or [])
        except Exception as exc:
            raise self._translate_error(f"{spec.service}.{spec.sdk_operation}", exc) from exc
        return merged

    def _client(self, service: str) -> Any:
        client = self._clients.get(service)
        if client is not None:
            return client

        with self._clients_lock:
            client = self._clients.get(service)
            if client is None:
                try:
                    client = self._session.client(
                        service,
                        region_name=self.config.region,
                        endpoint_url=self.config.endpoint_url,
                    )
                except Exception as exc:
                    raise self._translate_error(f"create {service} client", exc) from exc
                self._clients[service] = client
        return client

    def _call(self, service: str, operation: str, **kwargs: Any) -> Dict[str, Any]:
        try:
            response = getattr(self._client(service), operation)(**kwargs)
        except Exception as exc:
            raise self._translate_error(f"{service}.{operation}", exc) from exc
        return response or {}

    def _call_optional(
        self,
        service: str,
        operation: str,
        expected_error_codes: List[str],
        **kwargs: Any,
    ) -> Optional[Dict[str, Any]]:
        try:
            return self._call(service, operation, **kwargs)
        except AwsSdkError as exc:
            if exc.code in expected_error_codes:
                return None
            raise

    @staticmethod
    def _translate_error(operation: str, exc: Exception) -> AwsSdkError:
        response = getattr(exc, "response", None)
        response = response if isinstance(response, dict) else {}
        raw_error = response.get("Error")
        error: Dict[str, Any] = raw_error if isinstance(raw_error, dict) else {}
        raw_metadata = response.get("ResponseMetadata")
        metadata: Dict[str, Any] = raw_metadata if isinstance(raw_metadata, dict) else {}
        code = str(error.get("Code") or exc.__class__.__name__)
        message = str(error.get("Message") or exc)
        status = metadata.get("HTTPStatusCode")
        returncode = int(status) if isinstance(status, int) else 1
        detail = f"{code}: {message}" if message else code
        return AwsSdkError(
            f"AWS SDK operation failed: {operation}",
            code=code,
            detail=detail,
            returncode=returncode,
        )

    def caller_identity(self) -> Dict[str, Any]:
        return self.read("sts.get_caller_identity")

    def list_buckets(self) -> List[str]:
        payload = self.read("s3.list_buckets")
        return sorted(bucket["Name"] for bucket in payload.get("Buckets", []))

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
            normalize_rds_instance(instance)
            for instance in self.read("rds.describe_db_instances").get("DBInstances") or []
        ]
        return sorted(instances, key=lambda instance: str(instance.get("identifier") or ""))

    def list_lambda_functions(self) -> List[Dict[str, Any]]:
        functions = [
            normalize_lambda_function(function)
            for function in self.read("lambda.list_functions").get("Functions") or []
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
        config = payload.get("ServerSideEncryptionConfiguration") or {}
        return config.get("Rules") or []

    def get_bucket_lifecycle_rules(self, bucket: str) -> List[Dict[str, Any]]:
        payload = self.read("s3.get_bucket_lifecycle_configuration", Bucket=bucket)
        return payload.get("Rules") or []

    def get_bucket_versioning_status(self, bucket: str) -> Optional[str]:
        payload = self.read("s3.get_bucket_versioning", Bucket=bucket)
        return payload.get("Status")

    def put_public_access_block(self, bucket: str) -> None:
        self._call(
            "s3",
            "put_public_access_block",
            Bucket=bucket,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

    def put_default_encryption(self, bucket: str) -> None:
        self._call(
            "s3",
            "put_bucket_encryption",
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            },
        )

    def put_lifecycle(
        self,
        bucket: str,
        *,
        transition_days: int = 30,
        storage_class: str = "STANDARD_IA",
    ) -> None:
        self._call(
            "s3",
            "put_bucket_lifecycle_configuration",
            Bucket=bucket,
            LifecycleConfiguration={
                "Rules": [
                    {
                        "ID": "bluearch-steward-transition-old-objects",
                        "Status": "Enabled",
                        "Filter": {"Prefix": ""},
                        "Transitions": [{"Days": transition_days, "StorageClass": storage_class}],
                    }
                ]
            },
        )

    def put_versioning(self, bucket: str) -> None:
        self._call(
            "s3",
            "put_bucket_versioning",
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )

    def put_bucket_logging(
        self,
        bucket: str,
        *,
        target_bucket: str,
        target_prefix: str,
    ) -> None:
        self._call(
            "s3",
            "put_bucket_logging",
            Bucket=bucket,
            BucketLoggingStatus={
                "LoggingEnabled": {
                    "TargetBucket": target_bucket,
                    "TargetPrefix": target_prefix,
                }
            },
        )

    def enable_alb_access_logging(
        self,
        load_balancer_arn: str,
        *,
        target_bucket: str,
        target_prefix: str,
    ) -> None:
        self._call(
            "elbv2",
            "modify_load_balancer_attributes",
            LoadBalancerArn=load_balancer_arn,
            Attributes=[
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": target_bucket},
                {"Key": "access_logs.s3.prefix", "Value": target_prefix},
            ],
        )

    def put_log_retention(self, log_group_name: str, retention_days: int) -> None:
        self._call(
            "logs",
            "put_retention_policy",
            logGroupName=log_group_name,
            retentionInDays=retention_days,
        )

    def update_cloudtrail_log_file_validation(self, trail_name: str, *, enabled: bool) -> None:
        self._call(
            "cloudtrail",
            "update_trail",
            Name=trail_name,
            EnableLogFileValidation=enabled,
        )
