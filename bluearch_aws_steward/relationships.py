from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional

from bluearch_aws_steward.models import ResourceRef

JSON = Dict[str, Any]
Reader = Callable[..., JSON]


def _first_mapping(items: Any) -> JSON:
    for item in items or []:
        if isinstance(item, dict):
            return item
    return {}


def relationship_collector_services() -> tuple[str, ...]:
    return tuple(sorted(_COLLECTORS))


def collect_live_relationships(provider: Any, resource: ResourceRef) -> JSON:
    """Collect a bounded, redacted one-hop neighborhood for an exact AWS resource."""

    collector = _COLLECTORS.get(resource.service)
    if collector is None:
        return {"relationships": [], "errors": []}

    relationships: List[JSON] = []
    errors: List[JSON] = []

    def read(operation: str, **parameters: Any) -> JSON:
        try:
            return provider.read(operation, **parameters)
        except Exception as exc:  # Partial permissions must not erase other evidence.
            errors.append(
                {
                    "resource": resource.resource_id,
                    "source": "aws_direct_relationship_collector",
                    "operation": operation,
                    "detail": str(exc),
                }
            )
            return {}

    def add(
        relationship_type: str,
        service: str,
        resource_type: str,
        resource_id: Any,
        *,
        operation: str,
        field: str,
        arn: Optional[str] = None,
        confidence: str = "high",
    ) -> None:
        identifier = str(resource_id or "").strip()
        if not identifier:
            return
        target_arn = arn or (identifier if identifier.startswith("arn:") else None)
        normalized_id = _identifier_from_arn(identifier) if target_arn else identifier
        relationships.append(
            {
                "relationship_type": relationship_type,
                "target": ResourceRef(
                    provider="aws",
                    service=service,
                    resource_type=resource_type,
                    resource_id=normalized_id,
                    region=resource.region,
                    account_id=resource.account_id,
                    arn=target_arn,
                    display_name=normalized_id,
                ).to_dict(),
                "source": "aws_direct_relationship_collector",
                "confidence": confidence,
                "evidence_provenance": {
                    "operation": operation,
                    "field": field,
                    "sensitive_values_included": False,
                },
            }
        )

    collector(resource, read, add, errors)
    return {
        "relationships": _deduplicate_relationships(relationships),
        "errors": errors,
    }


def _collect_iam(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    if resource.resource_type not in {"aws.iam.user", "aws.iam.role"}:
        return
    response = read("iam.get_account_authorization_details")
    collection = (
        response.get("RoleDetailList")
        if resource.resource_type == "aws.iam.role"
        else response.get("UserDetailList")
    ) or []
    name_key = "RoleName" if resource.resource_type == "aws.iam.role" else "UserName"
    selected = next(
        (item for item in collection if str(item.get(name_key) or "") == resource.resource_id),
        None,
    )
    if not selected:
        return
    for policy in selected.get("AttachedManagedPolicies") or []:
        add(
            "governed_by",
            "iam",
            "aws.iam.policy",
            policy.get("PolicyArn"),
            operation="iam.get_account_authorization_details",
            field="AttachedManagedPolicies.PolicyArn",
        )
    for group in selected.get("GroupList") or []:
        add(
            "attached_to",
            "iam",
            "aws.iam.group",
            group,
            operation="iam.get_account_authorization_details",
            field="GroupList",
            confidence="high",
        )


def _collect_cloudtrail(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read(
        "cloudtrail.describe_trails",
        trailNameList=[resource.arn or resource.resource_id],
        includeShadowTrails=False,
    )
    trail = _first_mapping(response.get("trailList"))
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        trail.get("KmsKeyId"),
        operation="cloudtrail.describe_trails",
        field="trailList.KmsKeyId",
    )
    add(
        "logs_to",
        "cloudwatch",
        "aws.logs.log-group",
        trail.get("CloudWatchLogsLogGroupArn"),
        operation="cloudtrail.describe_trails",
        field="trailList.CloudWatchLogsLogGroupArn",
    )
    add(
        "logs_to",
        "s3",
        "aws.s3.bucket",
        trail.get("S3BucketName"),
        operation="cloudtrail.describe_trails",
        field="trailList.S3BucketName",
    )
    add(
        "publishes_to",
        "sns",
        "aws.sns.topic",
        trail.get("SnsTopicARN") or trail.get("SnsTopicName"),
        operation="cloudtrail.describe_trails",
        field="trailList.SnsTopicARN",
    )


def _collect_cloudwatch(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read("logs.describe_log_groups", logGroupNamePrefix=resource.resource_id)
    groups = response.get("logGroups") or []
    selected = next(
        (item for item in groups if item.get("logGroupName") == resource.resource_id),
        _first_mapping(groups),
    )
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        selected.get("kmsKeyId"),
        operation="logs.describe_log_groups",
        field="logGroups.kmsKeyId",
    )


def _collect_s3(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    bucket = resource.resource_id
    encryption = read("s3.get_bucket_encryption", Bucket=bucket)
    for rule in (encryption.get("ServerSideEncryptionConfiguration") or {}).get("Rules") or []:
        default = rule.get("ApplyServerSideEncryptionByDefault") or {}
        add(
            "encrypted_by",
            "kms",
            "aws.kms.key",
            default.get("KMSMasterKeyID"),
            operation="s3.get_bucket_encryption",
            field="Rules.ApplyServerSideEncryptionByDefault.KMSMasterKeyID",
        )
    logging = read("s3.get_bucket_logging", Bucket=bucket).get("LoggingEnabled") or {}
    add(
        "logs_to",
        "s3",
        "aws.s3.bucket",
        logging.get("TargetBucket"),
        operation="s3.get_bucket_logging",
        field="LoggingEnabled.TargetBucket",
    )
    replication = (
        read("s3.get_bucket_replication", Bucket=bucket).get("ReplicationConfiguration") or {}
    )
    add(
        "assumes_role",
        "iam",
        "aws.iam.role",
        replication.get("Role"),
        operation="s3.get_bucket_replication",
        field="ReplicationConfiguration.Role",
    )
    for rule in replication.get("Rules") or []:
        destination = rule.get("Destination") or {}
        add(
            "replicates_to",
            "s3",
            "aws.s3.bucket",
            destination.get("Bucket"),
            operation="s3.get_bucket_replication",
            field="ReplicationConfiguration.Rules.Destination.Bucket",
        )


def _collect_efs(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read("efs.describe_file_systems", FileSystemId=resource.resource_id)
    file_system = _first_mapping(response.get("FileSystems"))
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        file_system.get("KmsKeyId"),
        operation="efs.describe_file_systems",
        field="FileSystems.KmsKeyId",
    )
    mounts = read("efs.describe_mount_targets", FileSystemId=resource.resource_id)
    for mount in mounts.get("MountTargets") or []:
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            mount.get("SubnetId"),
            operation="efs.describe_mount_targets",
            field="MountTargets.SubnetId",
        )
        add(
            "mounted_by",
            "ec2",
            "aws.ec2.network-interface",
            mount.get("NetworkInterfaceId"),
            operation="efs.describe_mount_targets",
            field="MountTargets.NetworkInterfaceId",
        )


def _collect_ec2(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    identifier = resource.resource_id
    if identifier.startswith("i-"):
        response = read("ec2.describe_instances", InstanceIds=[identifier])
        instances = [
            instance
            for reservation in response.get("Reservations") or []
            for instance in reservation.get("Instances") or []
        ]
        selected = _first_mapping(instances)
        add(
            "uses_image",
            "ec2",
            "aws.ec2.image",
            selected.get("ImageId"),
            operation="ec2.describe_instances",
            field="Instances.ImageId",
        )
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            selected.get("SubnetId"),
            operation="ec2.describe_instances",
            field="Instances.SubnetId",
        )
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.vpc",
            selected.get("VpcId"),
            operation="ec2.describe_instances",
            field="Instances.VpcId",
        )
        for group in selected.get("SecurityGroups") or []:
            add(
                "protected_by",
                "ec2",
                "aws.ec2.security-group",
                group.get("GroupId"),
                operation="ec2.describe_instances",
                field="Instances.SecurityGroups.GroupId",
            )
        for mapping in selected.get("BlockDeviceMappings") or []:
            add(
                "attached_to",
                "ec2",
                "aws.ec2.volume",
                (mapping.get("Ebs") or {}).get("VolumeId"),
                operation="ec2.describe_instances",
                field="Instances.BlockDeviceMappings.Ebs.VolumeId",
            )
        return
    if identifier.startswith("vol-"):
        response = read("ec2.describe_volumes", VolumeIds=[identifier])
        selected = _first_mapping(response.get("Volumes"))
        add(
            "encrypted_by",
            "kms",
            "aws.kms.key",
            selected.get("KmsKeyId"),
            operation="ec2.describe_volumes",
            field="Volumes.KmsKeyId",
        )
        add(
            "backed_up_by",
            "ec2",
            "aws.ec2.snapshot",
            selected.get("SnapshotId"),
            operation="ec2.describe_volumes",
            field="Volumes.SnapshotId",
        )
        for attachment in selected.get("Attachments") or []:
            add(
                "attached_to",
                "ec2",
                "aws.ec2.instance",
                attachment.get("InstanceId"),
                operation="ec2.describe_volumes",
                field="Volumes.Attachments.InstanceId",
            )
        return
    if identifier.startswith("sg-"):
        response = read("ec2.describe_security_groups", GroupIds=[identifier])
        selected = _first_mapping(response.get("SecurityGroups"))
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.vpc",
            selected.get("VpcId"),
            operation="ec2.describe_security_groups",
            field="SecurityGroups.VpcId",
        )
        return
    if identifier.startswith("snap-"):
        response = read("ec2.describe_snapshots", SnapshotIds=[identifier])
        selected = _first_mapping(response.get("Snapshots"))
        add(
            "backed_up_by",
            "ec2",
            "aws.ec2.volume",
            selected.get("VolumeId"),
            operation="ec2.describe_snapshots",
            field="Snapshots.VolumeId",
        )
        add(
            "encrypted_by",
            "kms",
            "aws.kms.key",
            selected.get("KmsKeyId"),
            operation="ec2.describe_snapshots",
            field="Snapshots.KmsKeyId",
        )


def _collect_kms(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    # KMS does not expose a complete reverse consumer index. Config relationships
    # and service-side encryption fields remain the evidence-backed sources.
    read("kms.describe_key", KeyId=resource.arn or resource.resource_id)


def _collect_secret(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read("secretsmanager.describe_secret", SecretId=resource.arn or resource.resource_id)
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        response.get("KmsKeyId"),
        operation="secretsmanager.describe_secret",
        field="KmsKeyId",
    )
    add(
        "rotated_by",
        "lambda",
        "aws.lambda.function",
        response.get("RotationLambdaARN"),
        operation="secretsmanager.describe_secret",
        field="RotationLambdaARN",
    )


def _collect_lambda(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    name = resource.arn or resource.resource_id
    response = read("lambda.get_function_configuration", FunctionName=name)
    add(
        "assumes_role",
        "iam",
        "aws.iam.role",
        response.get("Role"),
        operation="lambda.get_function_configuration",
        field="Role",
    )
    vpc = response.get("VpcConfig") or {}
    for group in vpc.get("SecurityGroupIds") or []:
        add(
            "protected_by",
            "ec2",
            "aws.ec2.security-group",
            group,
            operation="lambda.get_function_configuration",
            field="VpcConfig.SecurityGroupIds",
        )
    for subnet in vpc.get("SubnetIds") or []:
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            subnet,
            operation="lambda.get_function_configuration",
            field="VpcConfig.SubnetIds",
        )
    event_sources = read("lambda.list_event_source_mappings", FunctionName=name)
    for mapping in event_sources.get("EventSourceMappings") or []:
        arn = mapping.get("EventSourceArn")
        service, resource_type = _target_type_from_arn(arn)
        add(
            "invoked_by",
            service,
            resource_type,
            arn,
            operation="lambda.list_event_source_mappings",
            field="EventSourceMappings.EventSourceArn",
        )


def _collect_ecs(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    if "task-definition" in resource.resource_type or "task-definition/" in (resource.arn or ""):
        response = read(
            "ecs.describe_task_definition", taskDefinition=resource.arn or resource.resource_id
        )
        _ecs_task_relationships(response.get("taskDefinition") or {}, add)
        return
    cluster, service = _ecs_service_identity(resource)
    if not cluster:
        errors.append(
            {
                "resource": resource.resource_id,
                "source": "aws_direct_relationship_collector",
                "operation": "ecs.describe_services",
                "detail": "An exact ECS service ARN is required to identify its cluster without inventorying unrelated services.",
            }
        )
        return
    response = read("ecs.describe_services", cluster=cluster, services=[service])
    selected = _first_mapping(response.get("services"))
    task_definition = selected.get("taskDefinition")
    add(
        "runs_task",
        "ecs",
        "aws.ecs.task-definition",
        task_definition,
        operation="ecs.describe_services",
        field="services.taskDefinition",
    )
    for load_balancer in selected.get("loadBalancers") or []:
        add(
            "routes_to",
            "alb",
            "aws.elasticloadbalancingv2.target-group",
            load_balancer.get("targetGroupArn"),
            operation="ecs.describe_services",
            field="services.loadBalancers.targetGroupArn",
        )
    network = (selected.get("networkConfiguration") or {}).get("awsvpcConfiguration") or {}
    for subnet in network.get("subnets") or []:
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            subnet,
            operation="ecs.describe_services",
            field="services.networkConfiguration.awsvpcConfiguration.subnets",
        )
    for group in network.get("securityGroups") or []:
        add(
            "protected_by",
            "ec2",
            "aws.ec2.security-group",
            group,
            operation="ecs.describe_services",
            field="services.networkConfiguration.awsvpcConfiguration.securityGroups",
        )
    if task_definition:
        definition = read("ecs.describe_task_definition", taskDefinition=task_definition)
        _ecs_task_relationships(definition.get("taskDefinition") or {}, add)


def _ecs_task_relationships(task: JSON, add: Callable[..., None]) -> None:
    add(
        "assumes_role",
        "iam",
        "aws.iam.role",
        task.get("taskRoleArn"),
        operation="ecs.describe_task_definition",
        field="taskDefinition.taskRoleArn",
    )
    add(
        "assumes_role",
        "iam",
        "aws.iam.role",
        task.get("executionRoleArn"),
        operation="ecs.describe_task_definition",
        field="taskDefinition.executionRoleArn",
    )
    for container in task.get("containerDefinitions") or []:
        log_configuration = container.get("logConfiguration") or {}
        options = log_configuration.get("options") or {}
        add(
            "logs_to",
            "cloudwatch",
            "aws.logs.log-group",
            options.get("awslogs-group"),
            operation="ecs.describe_task_definition",
            field="taskDefinition.containerDefinitions.logConfiguration.options.awslogs-group",
        )


def _collect_eks(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    name = resource.resource_id
    response = read("eks.describe_cluster", name=name)
    cluster = response.get("cluster") or {}
    add(
        "assumes_role",
        "iam",
        "aws.iam.role",
        cluster.get("roleArn"),
        operation="eks.describe_cluster",
        field="cluster.roleArn",
    )
    resources = cluster.get("resourcesVpcConfig") or {}
    for subnet in resources.get("subnetIds") or []:
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            subnet,
            operation="eks.describe_cluster",
            field="cluster.resourcesVpcConfig.subnetIds",
        )
    for group in resources.get("securityGroupIds") or []:
        add(
            "protected_by",
            "ec2",
            "aws.ec2.security-group",
            group,
            operation="eks.describe_cluster",
            field="cluster.resourcesVpcConfig.securityGroupIds",
        )
    add(
        "protected_by",
        "ec2",
        "aws.ec2.security-group",
        resources.get("clusterSecurityGroupId"),
        operation="eks.describe_cluster",
        field="cluster.resourcesVpcConfig.clusterSecurityGroupId",
    )
    for encryption in cluster.get("encryptionConfig") or []:
        add(
            "encrypted_by",
            "kms",
            "aws.kms.key",
            (encryption.get("provider") or {}).get("keyArn"),
            operation="eks.describe_cluster",
            field="cluster.encryptionConfig.provider.keyArn",
        )
    nodegroups = read("eks.list_nodegroups", clusterName=name)
    for nodegroup in nodegroups.get("nodegroups") or []:
        add(
            "runs_on",
            "eks",
            "aws.eks.nodegroup",
            nodegroup,
            operation="eks.list_nodegroups",
            field="nodegroups",
        )


def _collect_rds(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read("rds.describe_db_instances", DBInstanceIdentifier=resource.resource_id)
    instance = _first_mapping(response.get("DBInstances"))
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        instance.get("KmsKeyId"),
        operation="rds.describe_db_instances",
        field="DBInstances.KmsKeyId",
    )
    for group in instance.get("VpcSecurityGroups") or []:
        add(
            "protected_by",
            "ec2",
            "aws.ec2.security-group",
            group.get("VpcSecurityGroupId"),
            operation="rds.describe_db_instances",
            field="DBInstances.VpcSecurityGroups.VpcSecurityGroupId",
        )
    subnet_group = instance.get("DBSubnetGroup") or {}
    add(
        "deployed_in",
        "ec2",
        "aws.ec2.vpc",
        subnet_group.get("VpcId"),
        operation="rds.describe_db_instances",
        field="DBInstances.DBSubnetGroup.VpcId",
    )
    for subnet in subnet_group.get("Subnets") or []:
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            (subnet.get("SubnetIdentifier")),
            operation="rds.describe_db_instances",
            field="DBInstances.DBSubnetGroup.Subnets.SubnetIdentifier",
        )
    for replica in instance.get("ReadReplicaDBInstanceIdentifiers") or []:
        add(
            "replicates_to",
            "rds",
            "aws.rds.db-instance",
            replica,
            operation="rds.describe_db_instances",
            field="DBInstances.ReadReplicaDBInstanceIdentifiers",
        )


def _collect_dynamodb(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read("dynamodb.describe_table", TableName=resource.resource_id)
    table = response.get("Table") or {}
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        (table.get("SSEDescription") or {}).get("KMSMasterKeyArn"),
        operation="dynamodb.describe_table",
        field="Table.SSEDescription.KMSMasterKeyArn",
    )
    add(
        "streams_to",
        "dynamodb",
        "aws.dynamodb.stream",
        table.get("LatestStreamArn"),
        operation="dynamodb.describe_table",
        field="Table.LatestStreamArn",
    )
    for replica in table.get("Replicas") or []:
        region = replica.get("RegionName")
        if region:
            add(
                "replicates_to",
                "dynamodb",
                "aws.dynamodb.replica",
                f"{resource.resource_id}@{region}",
                operation="dynamodb.describe_table",
                field="Table.Replicas.RegionName",
            )


def _collect_alb(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    parameters = (
        {"LoadBalancerArns": [resource.arn]} if resource.arn else {"Names": [resource.resource_id]}
    )
    response = read("elbv2.describe_load_balancers", **parameters)
    load_balancer = _first_mapping(response.get("LoadBalancers"))
    load_balancer_arn = load_balancer.get("LoadBalancerArn")
    for group in load_balancer.get("SecurityGroups") or []:
        add(
            "protected_by",
            "ec2",
            "aws.ec2.security-group",
            group,
            operation="elbv2.describe_load_balancers",
            field="LoadBalancers.SecurityGroups",
        )
    for zone in load_balancer.get("AvailabilityZones") or []:
        add(
            "deployed_in",
            "ec2",
            "aws.ec2.subnet",
            zone.get("SubnetId"),
            operation="elbv2.describe_load_balancers",
            field="LoadBalancers.AvailabilityZones.SubnetId",
        )
    if not load_balancer_arn:
        return
    listeners = read("elbv2.describe_listeners", LoadBalancerArn=load_balancer_arn)
    for listener in listeners.get("Listeners") or []:
        for certificate in listener.get("Certificates") or []:
            add(
                "uses_certificate",
                "acm",
                "aws.acm.certificate",
                certificate.get("CertificateArn"),
                operation="elbv2.describe_listeners",
                field="Listeners.Certificates.CertificateArn",
            )
        for action in listener.get("DefaultActions") or []:
            add(
                "routes_to",
                "alb",
                "aws.elasticloadbalancingv2.target-group",
                action.get("TargetGroupArn"),
                operation="elbv2.describe_listeners",
                field="Listeners.DefaultActions.TargetGroupArn",
            )
    target_groups = read("elbv2.describe_target_groups", LoadBalancerArn=load_balancer_arn)
    for target_group in target_groups.get("TargetGroups") or []:
        add(
            "routes_to",
            "alb",
            "aws.elasticloadbalancingv2.target-group",
            target_group.get("TargetGroupArn"),
            operation="elbv2.describe_target_groups",
            field="TargetGroups.TargetGroupArn",
        )


def _collect_api_gateway(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    response = read("apigateway.get_stages", restApiId=resource.resource_id)
    for stage in response.get("item") or response.get("items") or []:
        access_log = stage.get("accessLogSettings") or {}
        add(
            "logs_to",
            "cloudwatch",
            "aws.logs.log-group",
            access_log.get("destinationArn"),
            operation="apigateway.get_stages",
            field="item.accessLogSettings.destinationArn",
        )
        add(
            "protected_by",
            "wafv2",
            "aws.wafv2.web-acl",
            stage.get("webAclArn"),
            operation="apigateway.get_stages",
            field="item.webAclArn",
        )


def _collect_sns(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    arn = resource.arn or _regional_arn("sns", resource)
    if not arn:
        errors.append(_missing_arn_error(resource, "sns.get_topic_attributes"))
        return
    attributes = read("sns.get_topic_attributes", TopicArn=arn).get("Attributes") or {}
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        attributes.get("KmsMasterKeyId"),
        operation="sns.get_topic_attributes",
        field="Attributes.KmsMasterKeyId",
    )


def _collect_sqs(
    resource: ResourceRef,
    read: Reader,
    add: Callable[..., None],
    errors: List[JSON],
) -> None:
    queue_url = resource.arn if resource.arn and resource.arn.startswith("http") else None
    if not queue_url:
        listed = read("sqs.list_queues", QueueNamePrefix=resource.resource_id)
        queue_url = next(
            (
                url
                for url in listed.get("QueueUrls") or []
                if url.rstrip("/").endswith(f"/{resource.resource_id}")
            ),
            next(iter(listed.get("QueueUrls") or []), None),
        )
    if not queue_url:
        return
    attributes = (
        read("sqs.get_queue_attributes", QueueUrl=queue_url, AttributeNames=["All"]).get(
            "Attributes"
        )
        or {}
    )
    add(
        "encrypted_by",
        "kms",
        "aws.kms.key",
        attributes.get("KmsMasterKeyId"),
        operation="sqs.get_queue_attributes",
        field="Attributes.KmsMasterKeyId",
    )
    try:
        redrive = json.loads(attributes.get("RedrivePolicy") or "{}")
    except json.JSONDecodeError:
        redrive = {}
    add(
        "redrives_to",
        "sqs",
        "aws.sqs.queue",
        redrive.get("deadLetterTargetArn"),
        operation="sqs.get_queue_attributes",
        field="Attributes.RedrivePolicy.deadLetterTargetArn",
    )


def _ecs_service_identity(resource: ResourceRef) -> tuple[Optional[str], str]:
    arn = resource.arn or ""
    marker = ":service/"
    if marker not in arn:
        return None, resource.resource_id
    path = arn.split(marker, 1)[1]
    parts = path.split("/", 1)
    if len(parts) != 2:
        return None, resource.resource_id
    return parts[0], parts[1]


def _regional_arn(service: str, resource: ResourceRef) -> Optional[str]:
    if not resource.region or not resource.account_id:
        return None
    return f"arn:aws:{service}:{resource.region}:{resource.account_id}:{resource.resource_id}"


def _target_type_from_arn(value: Any) -> tuple[str, str]:
    arn = str(value or "")
    if not arn.startswith("arn:"):
        return "unknown", "aws.unknown.resource"
    parts = arn.split(":", 5)
    service = parts[2] if len(parts) > 2 else "unknown"
    aliases = {"dynamodb": "dynamodb", "kinesis": "kinesis", "sqs": "sqs", "sns": "sns"}
    normalized = aliases.get(service, service)
    return normalized, f"aws.{normalized}.resource"


def _identifier_from_arn(value: str) -> str:
    suffix = value.split(":", 5)[-1]
    return suffix.split("/")[-1]


def _missing_arn_error(resource: ResourceRef, operation: str) -> JSON:
    return {
        "resource": resource.resource_id,
        "source": "aws_direct_relationship_collector",
        "operation": operation,
        "detail": "Region and account context are required to derive the exact resource ARN.",
    }


def _deduplicate_relationships(relationships: List[JSON]) -> List[JSON]:
    result: List[JSON] = []
    seen = set()
    for relationship in relationships:
        target = relationship.get("target") or {}
        key = (
            relationship.get("relationship_type"),
            target.get("service"),
            target.get("arn") or target.get("resource_id"),
        )
        if key not in seen:
            result.append(relationship)
            seen.add(key)
    return result


_COLLECTORS = {
    "iam": _collect_iam,
    "cloudtrail": _collect_cloudtrail,
    "cloudwatch": _collect_cloudwatch,
    "s3": _collect_s3,
    "efs": _collect_efs,
    "ec2": _collect_ec2,
    "kms": _collect_kms,
    "secrets-manager": _collect_secret,
    "lambda": _collect_lambda,
    "ecs": _collect_ecs,
    "eks": _collect_eks,
    "rds": _collect_rds,
    "dynamodb": _collect_dynamodb,
    "alb": _collect_alb,
    "api-gateway": _collect_api_gateway,
    "sns": _collect_sns,
    "sqs": _collect_sqs,
}
