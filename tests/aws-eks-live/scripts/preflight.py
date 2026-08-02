#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Mapping

import boto3
from aws_lifecycle import BROKEN_NODEGROUP_AMI_TYPE
from botocore.exceptions import BotoCoreError, ClientError

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACT_DIR = ROOT / "tests/aws-eks-live/.artifacts"
ACKNOWLEDGEMENT = "I_UNDERSTAND_THIS_IS_DESTRUCTIVE"
JSON = Dict[str, Any]


class PreflightError(RuntimeError):
    pass


def run(artifact_dir: Path) -> JSON:
    profile = os.environ.get("AWS_PROFILE", "").strip() or None
    if profile is None and os.environ.get("EKS_LAB_USE_ENV_CREDENTIALS") != "true":
        raise PreflightError(
            "AWS_PROFILE is required for local runs. OIDC workflows must set "
            "EKS_LAB_USE_ENV_CREDENTIALS=true explicitly."
        )
    allowed_account = _required_env("EKS_LAB_ALLOWED_ACCOUNT_ID")
    acknowledgement = _required_env("BLUEARCH_EKS_LAB_ACK")
    if acknowledgement != ACKNOWLEDGEMENT:
        raise PreflightError(
            f"BLUEARCH_EKS_LAB_ACK must equal {ACKNOWLEDGEMENT!r}; no AWS resources were created."
        )
    if not re.fullmatch(r"\d{12}", allowed_account):
        raise PreflightError("EKS_LAB_ALLOWED_ACCOUNT_ID must be one explicit 12-digit account ID.")

    region = os.environ.get("AWS_REGION", "us-east-1").strip()
    admin_cidr = _validated_admin_cidr(_required_env("EKS_LAB_ADMIN_CIDR"))
    fixture_images = {
        "nginx": _pinned_image("EKS_LAB_NGINX_IMAGE"),
        "busybox": _pinned_image("EKS_LAB_BUSYBOX_IMAGE"),
        "python": _pinned_image("EKS_LAB_PYTHON_IMAGE"),
    }
    ttl_hours = _bounded_float(os.environ.get("EKS_LAB_TTL_HOURS", "8"), 1, 8)
    budget_limit = _bounded_float(os.environ.get("EKS_LAB_BUDGET_USD", "30"), 1, 30)
    nodegroup_degrade_timeout_minutes = _bounded_int(
        os.environ.get("EKS_LAB_NODEGROUP_DEGRADE_TIMEOUT_MINUTES", "45"), 25, 60
    )
    tools = _required_tools()

    session = boto3.Session(profile_name=profile, region_name=region)
    sts = session.client("sts")
    try:
        identity = sts.get_caller_identity()
    except (BotoCoreError, ClientError) as exc:
        raise PreflightError(f"Unable to validate the sandbox identity: {exc}") from exc
    account_id = str(identity.get("Account") or "")
    if account_id != allowed_account:
        raise PreflightError(
            "The active AWS account does not match EKS_LAB_ALLOWED_ACCOUNT_ID; "
            "preflight stopped before Terraform."
        )
    principal_arn = _operator_principal_arn(session, str(identity.get("Arn") or ""))

    network_selection = _select_network(session.client("ec2"))
    eks = session.client("eks")
    _validate_create_nodegroup_ami_type(eks)
    version_selection = _select_versions(eks)
    addon_selection = _select_coredns_versions(
        eks,
        healthy_version=version_selection["healthy_cluster_version"],
        vulnerable_version=version_selection["vulnerable_cluster_version"],
    )
    ssm = session.client("ssm")
    healthy_ami_release_version = _recommended_al2023_release(
        ssm,
        version_selection["healthy_cluster_version"],
    )
    ami_selection = _select_old_al2023_release(
        ssm,
        session.client("ec2"),
        version_selection["vulnerable_cluster_version"],
    )
    guardduty_baseline = _guardduty_baseline(session.client("guardduty"))

    started_at = datetime.now(timezone.utc)
    expires_at = started_at + timedelta(hours=ttl_hours)
    run_id = os.environ.get("EKS_LAB_RUN_ID", "").strip() or (
        started_at.strftime("%Y%m%d%H%M") + "-" + uuid.uuid4().hex[:6]
    )
    if not re.fullmatch(r"[a-zA-Z0-9-]{6,32}", run_id):
        raise PreflightError("EKS_LAB_RUN_ID must contain 6-32 letters, digits, or hyphens.")

    extended_cluster = bool(version_selection["vulnerable_extended_support"])
    hourly_control_plane = 0.10 + (0.60 if extended_cluster else 0.10)
    # Four managed baseline nodes plus the intentionally failing node-group attempt.
    hourly_nodes_estimate = 5 * 0.05
    estimated_cost = round((hourly_control_plane + hourly_nodes_estimate) * ttl_hours + 3, 2)
    if estimated_cost > budget_limit:
        raise PreflightError(
            f"Estimated lab cost ${estimated_cost:.2f} exceeds the configured "
            f"${budget_limit:.2f} budget."
        )

    artifact_dir.mkdir(parents=True, exist_ok=True)
    terraform_values: JSON = {
        "aws_profile": profile,
        "region": region,
        "run_id": run_id,
        "owner": os.environ.get("EKS_LAB_OWNER", "bluearch-steward-validation"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "admin_cidr": admin_cidr,
        "operator_principal_arn": principal_arn,
        "budget_limit_usd": budget_limit,
        **network_selection["terraform"],
        **{key: value for key, value in version_selection.items() if key.endswith("_version")},
        "healthy_coredns_version": addon_selection["healthy_coredns_version"],
        "vulnerable_coredns_version": addon_selection["vulnerable_coredns_version"],
        "healthy_ami_release_version": healthy_ami_release_version,
        "old_ami_release_version": ami_selection["old_release_version"],
    }
    preflight: JSON = {
        "status": "ready",
        "read_only": True,
        "aws_writes": 0,
        "account_id": account_id,
        "account_fingerprint": hashlib.sha256(account_id.encode("utf-8")).hexdigest()[:12],
        "principal_arn": principal_arn,
        "profile": profile or "environment_credential_chain",
        "region": region,
        "run_id": run_id,
        "started_at": started_at.isoformat().replace("+00:00", "Z"),
        "expires_at": terraform_values["expires_at"],
        "ttl_hours": ttl_hours,
        "budget_limit_usd": budget_limit,
        "estimated_max_cost_usd": estimated_cost,
        "admin_cidr": admin_cidr,
        "fixture_images": fixture_images,
        "network": network_selection["receipt"],
        "tools": tools,
        "versions": version_selection,
        "addons": addon_selection,
        "ami": ami_selection,
        "external_fixture_ami_type": BROKEN_NODEGROUP_AMI_TYPE,
        "nodegroup_degrade_timeout_minutes": nodegroup_degrade_timeout_minutes,
        "guardduty_baseline": guardduty_baseline,
    }
    _write_json(artifact_dir / "terraform.tfvars.json", terraform_values)
    _write_json(artifact_dir / "preflight.json", preflight)
    _write_json(artifact_dir / "fixture-images.json", fixture_images)
    print(
        json.dumps(
            {
                "status": "ready",
                "account_fingerprint": preflight["account_fingerprint"],
                "region": region,
                "run_id": run_id,
                "expires_at": preflight["expires_at"],
                "estimated_max_cost_usd": estimated_cost,
                "terraform": tools["terraform"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return preflight


def _select_versions(client: Any) -> JSON:
    records: list[JSON] = []
    token: str | None = None
    while True:
        parameters = {"maxResults": 100}
        if token:
            parameters["nextToken"] = token
        response = client.describe_cluster_versions(**parameters)
        records.extend(item for item in response.get("clusterVersions") or [] if item)
        token = str(response.get("nextToken") or "") or None
        if not token:
            break
    if not records:
        raise PreflightError("DescribeClusterVersions returned no EKS versions.")

    by_version = {str(item.get("clusterVersion") or ""): item for item in records}
    available = set(by_version)
    standard = [
        item
        for item in records
        if "STANDARD" in str(item.get("versionStatus") or item.get("status") or "").upper()
    ]
    healthy = max(standard, key=lambda item: _version_key(item["clusterVersion"]), default=None)
    if healthy is None:
        raise PreflightError("AWS returned no EKS version in standard support.")

    now = datetime.now(timezone.utc)
    candidates = []
    for item in records:
        version = str(item.get("clusterVersion") or "")
        previous = _previous_minor(version)
        status = str(item.get("versionStatus") or item.get("status") or "").upper()
        end = _as_datetime(item.get("endOfStandardSupportDate"))
        days = (end - now).days if end else None
        risk = "EXTENDED" in status or (days is not None and 0 <= days <= 90)
        if risk and previous in available:
            candidates.append((item, previous, days))
    if not candidates:
        raise PreflightError(
            "AWS currently offers no real version-risk cluster with an available previous minor for "
            "nodegroup skew. No resources were created and no AWS response will be mocked."
        )
    vulnerable, previous, days = max(
        candidates,
        key=lambda value: _version_key(str(value[0].get("clusterVersion") or "0.0")),
    )
    vulnerable_status = str(
        vulnerable.get("versionStatus") or vulnerable.get("status") or ""
    ).upper()
    return {
        "healthy_cluster_version": str(healthy["clusterVersion"]),
        "vulnerable_cluster_version": str(vulnerable["clusterVersion"]),
        "skew_nodegroup_version": previous,
        "vulnerable_version_status": vulnerable_status,
        "vulnerable_extended_support": "EXTENDED" in vulnerable_status,
        "days_until_standard_support_end": days,
    }


def _validate_create_nodegroup_ami_type(client: Any) -> None:
    operation = client.meta.service_model.operation_model("CreateNodegroup")
    ami_shape = operation.input_shape.members["amiType"]
    supported = set(ami_shape.enum or [])
    if BROKEN_NODEGROUP_AMI_TYPE not in supported:
        raise PreflightError(
            "The installed botocore does not support the AL2023 AMI type required by the "
            "degraded node-group fixture. Upgrade the project dependencies before provisioning."
        )


def _select_coredns_versions(
    client: Any,
    *,
    healthy_version: str,
    vulnerable_version: str,
) -> JSON:
    healthy_versions = _addon_versions(client, "coredns", healthy_version)
    vulnerable_versions = _addon_versions(client, "coredns", vulnerable_version)
    healthy_default = next((item["version"] for item in healthy_versions if item["default"]), None)
    vulnerable_default = next(
        (item["version"] for item in vulnerable_versions if item["default"]), None
    )
    compatible = [item["version"] for item in vulnerable_versions]
    vulnerable_previous = next(
        (version for version in compatible if version != vulnerable_default),
        None,
    )
    if not healthy_default or not vulnerable_default or not vulnerable_previous:
        raise PreflightError(
            "Unable to choose current and previous compatible CoreDNS add-on versions."
        )
    return {
        "healthy_coredns_version": healthy_default,
        "vulnerable_coredns_version": vulnerable_previous,
        "vulnerable_coredns_default_version": vulnerable_default,
    }


def _addon_versions(client: Any, addon_name: str, kubernetes_version: str) -> list[JSON]:
    response = client.describe_addon_versions(
        addonName=addon_name,
        kubernetesVersion=kubernetes_version,
        maxResults=100,
    )
    values = []
    for addon in response.get("addons") or []:
        for item in addon.get("addonVersions") or []:
            compatibility = item.get("compatibilities") or []
            values.append(
                {
                    "version": str(item.get("addonVersion") or ""),
                    "default": any(entry.get("defaultVersion") is True for entry in compatibility),
                }
            )
    return values


def _select_old_al2023_release(ssm: Any, ec2: Any, cluster_version: str) -> JSON:
    current = _recommended_al2023_release(ssm, cluster_version)
    name = _al2023_release_parameter_name(cluster_version)

    try:
        images = (
            ec2.describe_images(
                Owners=["amazon"],
                Filters=[
                    {
                        "Name": "name",
                        "Values": [f"amazon-eks-node-al2023-x86_64-standard-{cluster_version}-v*"],
                    },
                    {"Name": "architecture", "Values": ["x86_64"]},
                    {"Name": "state", "Values": ["available"]},
                ],
            ).get("Images")
            or []
        )
    except (BotoCoreError, ClientError) as exc:
        raise PreflightError(
            f"Unable to list official AL2023 EKS images for Kubernetes {cluster_version}: {exc}"
        ) from exc

    previous: str | None = None
    image_id: str | None = None
    for image in sorted(images, key=lambda item: str(item.get("CreationDate") or ""), reverse=True):
        description = str(image.get("Description") or "")
        image_name = str(image.get("Name") or "")
        patch_match = re.search(r"\(k8s:\s*(\d+\.\d+\.\d+),", description)
        date_match = re.search(r"-v(\d{8})$", image_name)
        if not patch_match or not date_match:
            continue
        candidate = f"{patch_match.group(1)}-{date_match.group(1)}"
        if candidate == current:
            continue
        previous = candidate
        image_id = str(image.get("ImageId") or "") or None
        if image_id:
            break

    if not previous or not image_id:
        raise PreflightError(
            "EC2 returned no available previous AL2023 EKS image whose release version could be "
            "verified from the AWS-published AMI metadata. No resources were created."
        )
    return {
        "parameter_name": name,
        "recommended_release_version": current,
        "old_release_version": previous,
        "old_image_id": image_id,
        "old_image_source": "ec2_describe_images_amazon_owner",
    }


def _recommended_al2023_release(ssm: Any, cluster_version: str) -> str:
    name = _al2023_release_parameter_name(cluster_version)
    try:
        return str(ssm.get_parameter(Name=name)["Parameter"]["Value"])
    except (BotoCoreError, ClientError, KeyError) as exc:
        raise PreflightError(
            f"Unable to read the recommended AL2023 EKS release for {cluster_version}: {exc}"
        ) from exc


def _al2023_release_parameter_name(cluster_version: str) -> str:
    name = (
        f"/aws/service/eks/optimized-ami/{cluster_version}/"
        "amazon-linux-2023/x86_64/standard/recommended/release_version"
    )
    return name


def _guardduty_baseline(client: Any) -> JSON:
    detector_ids = list(client.list_detectors().get("DetectorIds") or [])
    detectors = []
    for detector_id in detector_ids:
        detail = client.get_detector(DetectorId=detector_id)
        detectors.append(
            {
                "detector_id": detector_id,
                "status": detail.get("Status"),
                "features": [
                    {
                        "name": item.get("Name"),
                        "status": item.get("Status"),
                        "additional_configuration": item.get("AdditionalConfiguration") or [],
                    }
                    for item in detail.get("Features") or []
                ],
            }
        )
    return {"detectors": detectors, "created_by_lab": False}


def _operator_principal_arn(session: boto3.Session, caller_arn: str) -> str:
    marker = ":assumed-role/"
    if marker not in caller_arn:
        if any(value in caller_arn for value in (":user/", ":role/")):
            return caller_arn
        raise PreflightError(
            "The sandbox caller must be an IAM user or assumed role so Terraform can create an exact trust policy."
        )
    account_prefix, remainder = caller_arn.split(marker, 1)
    role_name = remainder.split("/", 1)[0]
    account_id = account_prefix.rsplit(":", 1)[-1]
    try:
        return str(session.client("iam").get_role(RoleName=role_name)["Role"]["Arn"])
    except (BotoCoreError, ClientError) as exc:
        raise PreflightError(
            f"Unable to resolve the IAM role behind the sandbox session {account_id}: {exc}"
        ) from exc


def _select_network(ec2: Any) -> JSON:
    existing_vpc_id = os.environ.get("EKS_LAB_EXISTING_VPC_ID", "").strip()
    if not existing_vpc_id:
        return {
            "terraform": {},
            "receipt": {"mode": "dedicated_vpc", "existing_resources_managed": False},
        }

    subnet_ids = [
        value.strip()
        for value in os.environ.get("EKS_LAB_EXISTING_PUBLIC_SUBNET_IDS", "").split(",")
        if value.strip()
    ]
    if len(set(subnet_ids)) < 2:
        raise PreflightError(
            "EKS_LAB_EXISTING_PUBLIC_SUBNET_IDS must contain at least two unique subnet IDs."
        )
    broken_cidr_text = _required_env("EKS_LAB_BROKEN_SUBNET_CIDR")
    try:
        broken_cidr = ipaddress.ip_network(broken_cidr_text, strict=True)
    except ValueError as exc:
        raise PreflightError("EKS_LAB_BROKEN_SUBNET_CIDR must be a valid IPv4 CIDR.") from exc
    if broken_cidr.version != 4 or broken_cidr.prefixlen < 24:
        raise PreflightError("EKS_LAB_BROKEN_SUBNET_CIDR must be an IPv4 /24 or narrower network.")

    try:
        vpcs = ec2.describe_vpcs(VpcIds=[existing_vpc_id]).get("Vpcs") or []
        selected_subnets = ec2.describe_subnets(SubnetIds=subnet_ids).get("Subnets") or []
        all_subnets = (
            ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [existing_vpc_id]}]).get(
                "Subnets"
            )
            or []
        )
        route_tables = (
            ec2.describe_route_tables(
                Filters=[{"Name": "vpc-id", "Values": [existing_vpc_id]}]
            ).get("RouteTables")
            or []
        )
    except (BotoCoreError, ClientError) as exc:
        raise PreflightError(f"Unable to validate the existing sandbox VPC: {exc}") from exc
    if len(vpcs) != 1 or str(vpcs[0].get("State") or "") != "available":
        raise PreflightError("EKS_LAB_EXISTING_VPC_ID must identify one available VPC.")
    vpc_networks = [
        ipaddress.ip_network(str(association.get("CidrBlock")), strict=False)
        for association in vpcs[0].get("CidrBlockAssociationSet") or []
        if association.get("CidrBlock")
    ] or [ipaddress.ip_network(str(vpcs[0]["CidrBlock"]), strict=False)]
    if not any(broken_cidr.subnet_of(network) for network in vpc_networks):
        raise PreflightError("The broken subnet CIDR is not contained by the selected VPC.")

    if len(selected_subnets) != len(set(subnet_ids)):
        raise PreflightError("One or more selected public subnets do not exist.")
    if any(str(item.get("VpcId") or "") != existing_vpc_id for item in selected_subnets):
        raise PreflightError("Every selected public subnet must belong to the existing VPC.")
    availability_zones = {str(item.get("AvailabilityZone") or "") for item in selected_subnets}
    if len(availability_zones) < 2:
        raise PreflightError("Selected public subnets must span at least two Availability Zones.")
    if any(item.get("MapPublicIpOnLaunch") is not True for item in selected_subnets):
        raise PreflightError("Every selected subnet must assign public IPv4 addresses on launch.")
    if any(not _subnet_has_public_route(item, route_tables) for item in selected_subnets):
        raise PreflightError("Every selected subnet must have an active default route to an IGW.")

    for item in all_subnets:
        existing_network = ipaddress.ip_network(str(item["CidrBlock"]), strict=False)
        if broken_cidr.overlaps(existing_network):
            raise PreflightError(
                f"The broken subnet CIDR overlaps existing subnet {item['SubnetId']}."
            )
    broken_az = (
        os.environ.get("EKS_LAB_BROKEN_SUBNET_AZ", "").strip() or sorted(availability_zones)[0]
    )
    if broken_az not in availability_zones:
        raise PreflightError(
            "EKS_LAB_BROKEN_SUBNET_AZ must match an Availability Zone used by a selected subnet."
        )
    return {
        "terraform": {
            "existing_vpc_id": existing_vpc_id,
            "existing_public_subnet_ids": sorted(set(subnet_ids)),
            "broken_subnet_cidr": str(broken_cidr),
            "broken_subnet_az": broken_az,
        },
        "receipt": {
            "mode": "existing_vpc",
            "vpc_id": existing_vpc_id,
            "public_subnet_ids": sorted(set(subnet_ids)),
            "broken_subnet_cidr": str(broken_cidr),
            "broken_subnet_az": broken_az,
            "existing_resources_managed": False,
        },
    }


def _subnet_has_public_route(subnet: Mapping[str, Any], route_tables: list[JSON]) -> bool:
    subnet_id = str(subnet.get("SubnetId") or "")
    selected = next(
        (
            table
            for table in route_tables
            if any(
                str(association.get("SubnetId") or "") == subnet_id
                for association in table.get("Associations") or []
            )
        ),
        None,
    )
    if selected is None:
        selected = next(
            (
                table
                for table in route_tables
                if any(
                    association.get("Main") is True
                    for association in table.get("Associations") or []
                )
            ),
            None,
        )
    return bool(
        selected
        and any(
            route.get("DestinationCidrBlock") == "0.0.0.0/0"
            and str(route.get("GatewayId") or "").startswith("igw-")
            and str(route.get("State") or "active") == "active"
            for route in selected.get("Routes") or []
        )
    )


def _required_tools() -> JSON:
    terraform = os.environ.get("TERRAFORM", "").strip()
    if terraform:
        terraform_path = shutil.which(terraform)
    else:
        terraform_path = shutil.which("terraform") or shutil.which("tofu")
    tools = {
        "terraform": terraform_path,
        "aws": shutil.which("aws"),
        "jq": shutil.which("jq"),
        "kubectl": shutil.which("kubectl"),
        "uv": shutil.which("uv"),
    }
    missing = sorted(name for name, path in tools.items() if not path)
    if missing:
        raise PreflightError(f"Missing required local tools: {', '.join(missing)}")
    return tools


def _validated_admin_cidr(value: str) -> str:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise PreflightError("EKS_LAB_ADMIN_CIDR must be a valid IPv4 CIDR.") from exc
    if network.version != 4 or network.prefixlen < 24:
        raise PreflightError(
            "EKS_LAB_ADMIN_CIDR must be an explicit IPv4 /24 or narrower network; 0.0.0.0/0 is forbidden."
        )
    return str(network)


def _pinned_image(name: str) -> str:
    value = _required_env(name)
    if not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", value):
        raise PreflightError(f"{name} must be an immutable image reference pinned with @sha256:...")
    return value


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise PreflightError(f"{name} is required; no AWS resources were created.")
    return value


def _bounded_float(raw: str, minimum: float, maximum: float) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise PreflightError(f"Expected a number between {minimum} and {maximum}: {raw}") from exc
    if not minimum <= value <= maximum:
        raise PreflightError(f"Expected a number between {minimum} and {maximum}: {raw}")
    return value


def _bounded_int(raw: str, minimum: int, maximum: int) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise PreflightError(f"Expected an integer between {minimum} and {maximum}: {raw}") from exc
    if not minimum <= value <= maximum:
        raise PreflightError(f"Expected an integer between {minimum} and {maximum}: {raw}")
    return value


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in str(value).split("."))


def _previous_minor(value: str) -> str:
    major, minor = _version_key(value)[:2]
    return f"{major}.{minor - 1}"


def _as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    if isinstance(value, str) and value:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    return None


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, default=DEFAULT_ARTIFACT_DIR)
    args = parser.parse_args()
    try:
        run(args.artifact_dir)
    except PreflightError as exc:
        print(f"preflight blocked: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
