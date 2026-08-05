from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import yaml

from bluearch_aws_steward.models import ResourceRef, utc_now_iso

JSON = Dict[str, Any]
MAX_IAC_FILES = 20
MAX_IAC_FILE_BYTES = 5 * 1024 * 1024
SUPPORTED_IAC_FORMATS = ("auto", "terraform", "cloudformation")
_ALLOWED_SUFFIXES = {".tf", ".json", ".yaml", ".yml"}
_REJECTED_SUFFIXES = {".tfstate", ".tfvars", ".env"}
_REJECTED_NAMES = {
    ".env",
    "credentials",
    "credentials.json",
    "secrets.json",
    "terraform.tfstate",
}
_SENSITIVE_KEYS = {
    "access_key",
    "access_key_id",
    "authorization",
    "credential",
    "credentials",
    "environment",
    "password",
    "secret",
    "secret_access_key",
    "secret_string",
    "token",
    "user_data",
    "value",
    "variables",
}

TERRAFORM_TYPES: Dict[str, Tuple[str, str]] = {
    "aws_iam_user": ("iam", "aws.iam.user"),
    "aws_iam_role": ("iam", "aws.iam.role"),
    "aws_iam_policy": ("iam", "aws.iam.policy"),
    "aws_iam_role_policy": ("iam", "aws.iam.policy"),
    "aws_iam_role_policy_attachment": ("iam", "aws.iam.policy-attachment"),
    "aws_iam_user_policy": ("iam", "aws.iam.policy"),
    "aws_iam_user_policy_attachment": ("iam", "aws.iam.policy-attachment"),
    "aws_cloudtrail": ("cloudtrail", "aws.cloudtrail.trail"),
    "aws_cloudwatch_log_group": ("cloudwatch", "aws.logs.log-group"),
    "aws_cloudwatch_metric_alarm": ("cloudwatch", "aws.cloudwatch.alarm"),
    "aws_s3_bucket": ("s3", "aws.s3.bucket"),
    "aws_s3_bucket_policy": ("s3", "aws.s3.bucket"),
    "aws_s3_bucket_public_access_block": ("s3", "aws.s3.bucket"),
    "aws_s3_bucket_server_side_encryption_configuration": ("s3", "aws.s3.bucket"),
    "aws_s3_bucket_lifecycle_configuration": ("s3", "aws.s3.bucket"),
    "aws_s3_bucket_logging": ("s3", "aws.s3.bucket"),
    "aws_s3_bucket_versioning": ("s3", "aws.s3.bucket"),
    "aws_efs_file_system": ("efs", "aws.efs.file-system"),
    "aws_efs_mount_target": ("efs", "aws.efs.mount-target"),
    "aws_efs_access_point": ("efs", "aws.efs.access-point"),
    "aws_instance": ("ec2", "aws.ec2.instance"),
    "aws_ebs_volume": ("ec2", "aws.ec2.volume"),
    "aws_volume_attachment": ("ec2", "aws.ec2.volume-attachment"),
    "aws_security_group": ("ec2", "aws.ec2.security-group"),
    "aws_vpc_security_group_ingress_rule": ("ec2", "aws.ec2.security-group-rule"),
    "aws_vpc_security_group_egress_rule": ("ec2", "aws.ec2.security-group-rule"),
    "aws_vpc": ("ec2", "aws.ec2.vpc"),
    "aws_subnet": ("ec2", "aws.ec2.subnet"),
    "aws_kms_key": ("kms", "aws.kms.key"),
    "aws_kms_alias": ("kms", "aws.kms.alias"),
    "aws_secretsmanager_secret": ("secrets-manager", "aws.secretsmanager.secret"),
    "aws_secretsmanager_secret_rotation": ("secrets-manager", "aws.secretsmanager.secret"),
    "aws_lambda_function": ("lambda", "aws.lambda.function"),
    "aws_lambda_permission": ("lambda", "aws.lambda.permission"),
    "aws_lambda_event_source_mapping": ("lambda", "aws.lambda.event-source-mapping"),
    "aws_ecs_cluster": ("ecs", "aws.ecs.cluster"),
    "aws_ecs_service": ("ecs", "aws.ecs.service"),
    "aws_ecs_task_definition": ("ecs", "aws.ecs.task-definition"),
    "aws_eks_cluster": ("eks", "aws.eks.cluster"),
    "aws_eks_node_group": ("eks", "aws.eks.nodegroup"),
    "aws_eks_addon": ("eks", "aws.eks.addon"),
    "aws_eks_access_entry": ("eks", "aws.eks.access-entry"),
    "kubernetes_deployment": ("eks", "kubernetes.workload"),
    "kubernetes_stateful_set": ("eks", "kubernetes.workload"),
    "aws_db_instance": ("rds", "aws.rds.db-instance"),
    "aws_dynamodb_table": ("dynamodb", "aws.dynamodb.table"),
    "aws_lb": ("alb", "aws.elasticloadbalancingv2.load-balancer"),
    "aws_lb_listener": ("alb", "aws.elasticloadbalancingv2.listener"),
    "aws_lb_target_group": ("alb", "aws.elasticloadbalancingv2.target-group"),
    "aws_lb_target_group_attachment": ("alb", "aws.elasticloadbalancingv2.target-attachment"),
    "aws_api_gateway_rest_api": ("api-gateway", "aws.apigateway.rest-api"),
    "aws_api_gateway_stage": ("api-gateway", "aws.apigateway.stage"),
    "aws_api_gateway_method": ("api-gateway", "aws.apigateway.method"),
    "aws_api_gateway_integration": ("api-gateway", "aws.apigateway.integration"),
    "aws_sns_topic": ("sns", "aws.sns.topic"),
    "aws_sns_topic_subscription": ("sns", "aws.sns.subscription"),
    "aws_sqs_queue": ("sqs", "aws.sqs.queue"),
    "aws_sqs_queue_policy": ("sqs", "aws.sqs.queue"),
}

CLOUDFORMATION_TYPES: Dict[str, Tuple[str, str]] = {
    "AWS::IAM::User": ("iam", "aws.iam.user"),
    "AWS::IAM::Role": ("iam", "aws.iam.role"),
    "AWS::IAM::ManagedPolicy": ("iam", "aws.iam.policy"),
    "AWS::CloudTrail::Trail": ("cloudtrail", "aws.cloudtrail.trail"),
    "AWS::Logs::LogGroup": ("cloudwatch", "aws.logs.log-group"),
    "AWS::S3::Bucket": ("s3", "aws.s3.bucket"),
    "AWS::S3::BucketPolicy": ("s3", "aws.s3.bucket"),
    "AWS::EFS::FileSystem": ("efs", "aws.efs.file-system"),
    "AWS::EC2::Instance": ("ec2", "aws.ec2.instance"),
    "AWS::EC2::Volume": ("ec2", "aws.ec2.volume"),
    "AWS::EC2::SecurityGroup": ("ec2", "aws.ec2.security-group"),
    "AWS::EC2::VPC": ("ec2", "aws.ec2.vpc"),
    "AWS::KMS::Key": ("kms", "aws.kms.key"),
    "AWS::SecretsManager::Secret": ("secrets-manager", "aws.secretsmanager.secret"),
    "AWS::Lambda::Function": ("lambda", "aws.lambda.function"),
    "AWS::ECS::Cluster": ("ecs", "aws.ecs.cluster"),
    "AWS::ECS::Service": ("ecs", "aws.ecs.service"),
    "AWS::ECS::TaskDefinition": ("ecs", "aws.ecs.task-definition"),
    "AWS::EKS::Cluster": ("eks", "aws.eks.cluster"),
    "AWS::EKS::Nodegroup": ("eks", "aws.eks.nodegroup"),
    "AWS::RDS::DBInstance": ("rds", "aws.rds.db-instance"),
    "AWS::DynamoDB::Table": ("dynamodb", "aws.dynamodb.table"),
    "AWS::ElasticLoadBalancingV2::LoadBalancer": (
        "alb",
        "aws.elasticloadbalancingv2.load-balancer",
    ),
    "AWS::ApiGateway::RestApi": ("api-gateway", "aws.apigateway.rest-api"),
    "AWS::ApiGateway::Stage": ("api-gateway", "aws.apigateway.stage"),
    "AWS::SNS::Topic": ("sns", "aws.sns.topic"),
    "AWS::SQS::Queue": ("sqs", "aws.sqs.queue"),
}


class IacContextError(ValueError):
    """Raised when a requested IaC source is unsafe or cannot be interpreted."""


def parse_iac_context(config: JSON | None) -> JSON:
    config = dict(config or {})
    if not config:
        return _empty_context()
    root_value = str(config.get("workspace_root") or "").strip()
    if not root_value:
        raise IacContextError("review_context.iac.workspace_root is required when IaC is supplied.")
    root = Path(root_value).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise IacContextError("review_context.iac.workspace_root must be a directory.")

    requested_format = str(config.get("format") or "auto").strip().lower()
    if requested_format not in SUPPORTED_IAC_FORMATS:
        raise IacContextError(
            f"Unsupported IaC format: {requested_format}. Supported: {', '.join(SUPPORTED_IAC_FORMATS)}"
        )
    paths = config.get("paths") or []
    if not isinstance(paths, list):
        raise IacContextError("review_context.iac.paths must be an array.")
    if len(paths) > MAX_IAC_FILES:
        raise IacContextError(f"At most {MAX_IAC_FILES} explicit IaC files may be reviewed.")

    plan_path = str(config.get("terraform_plan_json_path") or "").strip()
    resolved_files = [_confined_file(root, value) for value in paths]
    resolved_plan = _confined_file(root, plan_path) if plan_path else None
    if not resolved_files and resolved_plan is None:
        return _empty_context(workspace_root=str(root))

    resources: List[JSON] = []
    warnings: List[JSON] = []
    source_files: List[str] = []
    for path in resolved_files:
        source_files.append(str(path.relative_to(root)))
        source_format = _detect_format(path, requested_format)
        if source_format == "terraform":
            parsed, file_warnings = _parse_terraform(path, root)
        else:
            parsed, file_warnings = _parse_cloudformation(path, root)
        resources.extend(parsed)
        warnings.extend(file_warnings)

    if resolved_plan is not None:
        source_files.append(str(resolved_plan.relative_to(root)))
        parsed, plan_warnings = _parse_terraform_plan(resolved_plan, root)
        resources.extend(parsed)
        warnings.extend(plan_warnings)

    resources = _deduplicate_resources(resources)
    relationships = _iac_relationships(resources)
    return {
        "workspace_root": str(root),
        "source_files": source_files,
        "resources": resources,
        "relationships": relationships,
        "warnings": warnings,
        "resource_count": len(resources),
        "relationship_count": len(relationships),
        "read_only": True,
        "files_modified": False,
        "transforms_executed": False,
        "terraform_plan_executed": False,
    }


def resource_ref_from_iac(resource: JSON) -> ResourceRef:
    return ResourceRef(
        provider="iac",
        service=str(resource["service"]),
        resource_type=str(resource["resource_type"]),
        resource_id=str(resource["resource_id"]),
        arn=str(resource.get("arn") or "") or None,
        display_name=str(resource.get("display_name") or resource["resource_id"]),
    )


def _confined_file(root: Path, value: Any) -> Path:
    raw = str(value or "").strip()
    if not raw:
        raise IacContextError("IaC paths must be non-empty strings.")
    requested = Path(raw).expanduser()
    candidate = requested if requested.is_absolute() else root / requested
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise IacContextError(f"IaC file does not exist or cannot be read: {raw}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise IacContextError(f"IaC path escapes workspace_root: {raw}") from exc
    if not resolved.is_file():
        raise IacContextError(f"IaC path is not a regular file: {raw}")
    if (
        resolved.name.casefold() in _REJECTED_NAMES
        or resolved.suffix.casefold() in _REJECTED_SUFFIXES
    ):
        raise IacContextError(f"Sensitive or state-bearing IaC file is not allowed: {raw}")
    if resolved.suffix.casefold() not in _ALLOWED_SUFFIXES:
        raise IacContextError(f"Unsupported IaC file extension: {resolved.suffix or '<none>'}")
    if resolved.stat().st_size > MAX_IAC_FILE_BYTES:
        raise IacContextError(f"IaC file exceeds the {MAX_IAC_FILE_BYTES} byte limit: {raw}")
    return resolved


def _detect_format(path: Path, requested_format: str) -> str:
    if requested_format != "auto":
        return requested_format
    if path.suffix.casefold() == ".tf":
        return "terraform"
    try:
        payload = _load_json_or_yaml(path)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise IacContextError(f"Unable to parse IaC file {path.name}: {exc}") from exc
    if isinstance(payload, dict) and "resource_changes" in payload:
        return "terraform"
    if isinstance(payload, dict) and "Resources" in payload:
        return "cloudformation"
    raise IacContextError(
        f"Unable to infer IaC format for {path.name}; set review_context.iac.format explicitly."
    )


def _parse_terraform(path: Path, root: Path) -> Tuple[List[JSON], List[JSON]]:
    # The python-hcl2 <8 ceiling in pyproject.toml is load-bearing. Version 8
    # keeps quotes on string literals and tags blocks with __is_block__, so
    # every resource type arrives as '"aws_s3_bucket"' and matches nothing.
    # Its strip_string_quotes option looks like the fix but is worse: it also
    # strips quotes inside interpolation expressions, turning
    # jsonencode({Action = "*"}) into Action = *, which silently stops the
    # wildcard-admin IAM rule from firing. Adopting 8 needs a normalization
    # layer that separates literals from expressions, not a version bump.
    try:
        import hcl2
    except ModuleNotFoundError as exc:
        raise IacContextError(
            "Terraform source review requires the bundled python-hcl2 dependency. Reinstall Steward."
        ) from exc
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = hcl2.load(handle)
    except Exception as exc:
        raise IacContextError(f"Unable to parse Terraform file {path.name}: {exc}") from exc

    result: List[JSON] = []
    warnings: List[JSON] = []
    for resource_group in payload.get("resource") or []:
        if not isinstance(resource_group, dict):
            continue
        for terraform_type, instances in resource_group.items():
            mapping = TERRAFORM_TYPES.get(str(terraform_type))
            if mapping is None:
                warnings.append(
                    {
                        "source_path": str(path.relative_to(root)),
                        "reason": "unsupported_resource_type",
                        "resource_type": str(terraform_type),
                    }
                )
                continue
            for name, attributes in (instances or {}).items():
                address = f"{terraform_type}.{name}"
                result.append(
                    _iac_resource(
                        source_kind="terraform",
                        source_path=str(path.relative_to(root)),
                        address=address,
                        service=mapping[0],
                        resource_type=mapping[1],
                        attributes=attributes if isinstance(attributes, dict) else {},
                        changed=True,
                    )
                )
    return result, warnings


def _parse_terraform_plan(path: Path, root: Path) -> Tuple[List[JSON], List[JSON]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise IacContextError(f"Unable to parse Terraform plan JSON {path.name}: {exc}") from exc
    changes = payload.get("resource_changes") if isinstance(payload, dict) else None
    if not isinstance(changes, list):
        raise IacContextError("terraform_plan_json_path is not Terraform plan JSON.")
    resources: List[JSON] = []
    warnings: List[JSON] = []
    for change in changes:
        if not isinstance(change, dict) or str(change.get("mode") or "managed") != "managed":
            continue
        terraform_type = str(change.get("type") or "")
        mapping = TERRAFORM_TYPES.get(terraform_type)
        if mapping is None:
            continue
        actions = list(((change.get("change") or {}).get("actions") or []))
        if actions in ([], ["no-op"], ["read"]):
            continue
        after = (change.get("change") or {}).get("after")
        if not isinstance(after, dict):
            after = {}
        resources.append(
            _iac_resource(
                source_kind="terraform_plan",
                source_path=str(path.relative_to(root)),
                address=str(change.get("address") or terraform_type),
                service=mapping[0],
                resource_type=mapping[1],
                attributes=after,
                changed=True,
                actions=actions,
            )
        )
    return resources, warnings


def _parse_cloudformation(path: Path, root: Path) -> Tuple[List[JSON], List[JSON]]:
    try:
        payload = _load_json_or_yaml(path)
    except (OSError, json.JSONDecodeError, yaml.YAMLError) as exc:
        raise IacContextError(f"Unable to parse CloudFormation file {path.name}: {exc}") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("Resources"), dict):
        raise IacContextError(f"CloudFormation template {path.name} has no Resources object.")
    warnings: List[JSON] = []
    if payload.get("Transform"):
        warnings.append(
            {
                "source_path": str(path.relative_to(root)),
                "reason": "transform_not_executed",
                "detail": "CloudFormation transforms and macros are treated as unresolved input.",
            }
        )
    result: List[JSON] = []
    for logical_id, resource in payload["Resources"].items():
        if not isinstance(resource, dict):
            continue
        cloudformation_type = str(resource.get("Type") or "")
        mapping = CLOUDFORMATION_TYPES.get(cloudformation_type)
        if mapping is None:
            warnings.append(
                {
                    "source_path": str(path.relative_to(root)),
                    "reason": "unsupported_resource_type",
                    "resource_type": cloudformation_type,
                }
            )
            continue
        result.append(
            _iac_resource(
                source_kind="cloudformation",
                source_path=str(path.relative_to(root)),
                address=str(logical_id),
                service=mapping[0],
                resource_type=mapping[1],
                attributes=resource.get("Properties") or {},
                changed=True,
            )
        )
    return result, warnings


class _CloudFormationLoader(yaml.SafeLoader):
    pass


def _construct_intrinsic(loader: yaml.SafeLoader, suffix: str, node: yaml.Node) -> JSON:
    if isinstance(node, yaml.ScalarNode):
        value: Any = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node)
    else:
        # YAML defines exactly these three node kinds, so this is unreachable.
        # It is spelled out because the previous `else` handed an unnarrowed
        # Node to construct_mapping, which accepts only a MappingNode.
        value = None
    return {f"Fn::{suffix}": value}


_CloudFormationLoader.add_multi_constructor("!", _construct_intrinsic)


def _load_json_or_yaml(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.casefold() == ".json":
        return json.loads(text)
    # _CloudFormationLoader subclasses SafeLoader and only adds an intrinsic-tag
    # constructor returning plain dicts, so no arbitrary objects are instantiated.
    return yaml.load(text, Loader=_CloudFormationLoader)  # noqa: S506  # nosec B506


def _iac_resource(
    *,
    source_kind: str,
    source_path: str,
    address: str,
    service: str,
    resource_type: str,
    attributes: JSON,
    changed: bool,
    actions: List[str] | None = None,
) -> JSON:
    safe_attributes = _redact(attributes)
    unresolved = sorted(set(_unresolved_paths(attributes)))
    references = sorted(set(_reference_candidates(attributes)))
    physical_name = _physical_name(attributes)
    return {
        "node_id": f"iac:{source_kind}:{address}",
        "source_kind": source_kind,
        "source_path": source_path,
        "address": address,
        "service": service,
        "resource_type": resource_type,
        "resource_id": physical_name or address,
        "display_name": physical_name or address,
        "facts": safe_attributes,
        "references": references,
        "unresolved_fields": unresolved,
        "changed": changed,
        "actions": actions or ["review"],
        "observed_at": utc_now_iso(),
        "confidence": "medium" if unresolved else "high",
    }


def _physical_name(attributes: JSON) -> str | None:
    candidates = (
        "name",
        "bucket",
        "function_name",
        "cluster_name",
        "service_name",
        "family",
        "identifier",
        "db_instance_identifier",
        "table_name",
        "queue_name",
        "topic_name",
        "FileSystemId",
        "BucketName",
        "FunctionName",
        "ClusterName",
        "DBInstanceIdentifier",
        "TableName",
        "QueueName",
        "TopicName",
        "Name",
    )
    for key in candidates:
        value = attributes.get(key)
        if isinstance(value, str) and value and not _is_unresolved(value):
            return value
    return None


def _redact(value: Any, *, key: str = "") -> Any:
    normalized_key = re.sub(r"[^a-z0-9]+", "_", key.casefold()).strip("_")
    if normalized_key in _SENSITIVE_KEYS or any(
        token in normalized_key for token in ("password", "secret", "credential", "token")
    ):
        if isinstance(value, dict):
            return {"redacted_keys": sorted(str(item) for item in value)}
        return "<redacted>"
    if isinstance(value, dict):
        return {str(item): _redact(child, key=str(item)) for item, child in value.items()}
    if isinstance(value, list):
        return [_redact(child, key=key) for child in value]
    return value


def _unresolved_paths(value: Any, path: str = "") -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            if str(key).startswith("Fn::") or key in {"Ref", "Condition"}:
                yield child_path
            yield from _unresolved_paths(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _unresolved_paths(child, f"{path}[{index}]")
    elif isinstance(value, str) and _is_unresolved(value):
        yield path or "value"


def _is_unresolved(value: str) -> bool:
    return "${" in value or "{{resolve:" in value


def _iac_relationships(resources: List[JSON]) -> List[JSON]:
    by_address = {str(resource["address"]): resource for resource in resources}
    relationships: List[JSON] = []
    for resource in resources:
        references = set(resource.get("references") or [])
        for address, target in by_address.items():
            if address == resource["address"] or address not in references:
                continue
            relationships.append(
                {
                    "source_node_id": resource["node_id"],
                    "target_node_id": target["node_id"],
                    "relationship_type": _relationship_type(
                        json.dumps(resource.get("facts") or {}, sort_keys=True, default=str),
                        target,
                    ),
                    "source": "iac_reference",
                    "confidence": "high",
                    "observed_at": resource["observed_at"],
                    "evidence_provenance": {
                        "source_path": resource["source_path"],
                        "reference": address,
                    },
                }
            )
    return relationships


def _reference_candidates(value: Any) -> Iterable[str]:
    """Return resource addresses only; never retain referenced values or expressions."""

    if isinstance(value, dict):
        for key, child in value.items():
            if key == "Ref" and isinstance(child, str):
                yield child
            elif key == "Fn::GetAtt":
                if isinstance(child, list) and child and isinstance(child[0], str):
                    yield child[0]
                elif isinstance(child, str):
                    yield child.split(".", 1)[0]
            yield from _reference_candidates(child)
        return
    if isinstance(value, list):
        for child in value:
            yield from _reference_candidates(child)
        return
    if not isinstance(value, str):
        return
    for match in re.finditer(
        r"(?<![A-Za-z0-9_])((?:data\.)?(?:aws|kubernetes)_[A-Za-z0-9_]+\.[A-Za-z][A-Za-z0-9_-]*)\.",
        value,
    ):
        yield match.group(1)


def _relationship_type(serialized_source: str, target: JSON) -> str:
    resource_type = str(target.get("resource_type") or "")
    if "kms" in resource_type:
        return "encrypted_by"
    if ".iam.role" in resource_type:
        return "assumes_role"
    if "log-group" in resource_type:
        return "logs_to"
    if resource_type.endswith((".vpc", ".subnet")):
        return "deployed_in"
    if resource_type.endswith((".topic", ".queue")):
        return "publishes_to"
    if "load-balancer" in resource_type or "target" in serialized_source.casefold():
        return "routes_to"
    return "references"


def _deduplicate_resources(resources: List[JSON]) -> List[JSON]:
    deduplicated: Dict[str, JSON] = {}
    for resource in resources:
        existing = deduplicated.get(str(resource["node_id"]))
        if existing is None or resource.get("source_kind") == "terraform_plan":
            deduplicated[str(resource["node_id"])] = resource
    return list(deduplicated.values())


def _empty_context(*, workspace_root: str | None = None) -> JSON:
    return {
        "workspace_root": workspace_root,
        "source_files": [],
        "resources": [],
        "relationships": [],
        "warnings": [],
        "resource_count": 0,
        "relationship_count": 0,
        "read_only": True,
        "files_modified": False,
        "transforms_executed": False,
        "terraform_plan_executed": False,
    }
