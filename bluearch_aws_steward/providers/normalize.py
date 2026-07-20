from __future__ import annotations

from typing import Any, Dict


def normalize_log_group(group: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": group.get("logGroupName"),
        "arn": group.get("logGroupArn") or group.get("arn"),
        "retention_days": group.get("retentionInDays"),
        "stored_bytes": int(group.get("storedBytes") or 0),
        "created_at": _timestamp(group.get("creationTime")),
    }


def normalize_ebs_volume(volume: Dict[str, Any]) -> Dict[str, Any]:
    attachments = [
        {
            "instance_id": attachment.get("InstanceId"),
            "device": attachment.get("Device"),
            "state": attachment.get("State"),
            "delete_on_termination": attachment.get("DeleteOnTermination"),
        }
        for attachment in volume.get("Attachments") or []
    ]
    tags = {
        str(tag.get("Key")): str(tag.get("Value") or "")
        for tag in volume.get("Tags") or []
        if tag.get("Key") is not None
    }
    return {
        "volume_id": volume.get("VolumeId"),
        "state": volume.get("State"),
        "size_gib": volume.get("Size"),
        "volume_type": volume.get("VolumeType"),
        "availability_zone": volume.get("AvailabilityZone"),
        "encrypted": volume.get("Encrypted"),
        "created_at": _timestamp(volume.get("CreateTime")),
        "iops": volume.get("Iops"),
        "throughput": volume.get("Throughput"),
        "attachments": attachments,
        "tags": tags,
    }


def normalize_elastic_ip(address: Dict[str, Any]) -> Dict[str, Any]:
    tags = {
        str(tag.get("Key")): str(tag.get("Value") or "")
        for tag in address.get("Tags") or []
        if tag.get("Key") is not None
    }
    return {
        "allocation_id": address.get("AllocationId"),
        "association_id": address.get("AssociationId"),
        "public_ip": address.get("PublicIp"),
        "instance_id": address.get("InstanceId"),
        "network_interface_id": address.get("NetworkInterfaceId"),
        "domain": address.get("Domain"),
        "tags": tags,
    }


def normalize_cloudtrail_trail(trail: Dict[str, Any], status: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": trail.get("Name"),
        "arn": trail.get("TrailARN"),
        "home_region": trail.get("HomeRegion"),
        "is_multi_region": bool(trail.get("IsMultiRegionTrail")),
        "is_organization_trail": bool(trail.get("IsOrganizationTrail")),
        "log_file_validation_enabled": bool(trail.get("LogFileValidationEnabled")),
        "kms_key_id": trail.get("KmsKeyId"),
        "cloudwatch_logs_log_group_arn": trail.get("CloudWatchLogsLogGroupArn"),
        "is_logging": bool(status.get("IsLogging")),
        "latest_delivery_time": _timestamp(status.get("LatestDeliveryTime")),
        "latest_delivery_error": status.get("LatestDeliveryError"),
    }


def normalize_rds_instance(instance: Dict[str, Any]) -> Dict[str, Any]:
    tags = {
        str(tag.get("Key")): str(tag.get("Value") or "")
        for tag in instance.get("TagList") or []
        if tag.get("Key") is not None
    }
    return {
        "identifier": instance.get("DBInstanceIdentifier"),
        "arn": instance.get("DBInstanceArn"),
        "engine": instance.get("Engine"),
        "engine_version": instance.get("EngineVersion"),
        "instance_class": instance.get("DBInstanceClass"),
        "status": instance.get("DBInstanceStatus"),
        "publicly_accessible": bool(instance.get("PubliclyAccessible")),
        "storage_encrypted": bool(instance.get("StorageEncrypted")),
        "multi_az": bool(instance.get("MultiAZ")),
        "storage_type": instance.get("StorageType"),
        "allocated_storage_gib": instance.get("AllocatedStorage"),
        "max_allocated_storage_gib": instance.get("MaxAllocatedStorage"),
        "read_replica_source_identifier": instance.get("ReadReplicaSourceDBInstanceIdentifier"),
        "read_replica_identifiers": list(instance.get("ReadReplicaDBInstanceIdentifiers") or []),
        "availability_zone": instance.get("AvailabilityZone"),
        "tags": tags,
    }


def normalize_lambda_function(function: Dict[str, Any]) -> Dict[str, Any]:
    tracing = function.get("TracingConfig") or {}
    return {
        "name": function.get("FunctionName"),
        "arn": function.get("FunctionArn"),
        "runtime": function.get("Runtime"),
        "role": function.get("Role"),
        "memory_mb": function.get("MemorySize"),
        "timeout_seconds": function.get("Timeout"),
        "last_modified": function.get("LastModified"),
        "tracing_mode": tracing.get("Mode"),
    }


def _timestamp(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float)):
        return value
    isoformat = getattr(value, "isoformat", None)
    return isoformat() if callable(isoformat) else str(value)
