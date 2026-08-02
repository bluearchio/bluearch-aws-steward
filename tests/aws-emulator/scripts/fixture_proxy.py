#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, Tuple
from urllib.parse import parse_qs, unquote, urlsplit

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bluearch_aws_steward.aws_endpoints import is_loopback_aws_endpoint  # noqa: E402

ENDPOINT_TOKEN = "__FIXTURE_ENDPOINT__"
OLD_TIMESTAMP = "2020-01-01T00:00:00Z"
_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
_FORWARDED_RESPONSE_HEADERS = {
    "accept-ranges": "Accept-Ranges",
    "cache-control": "Cache-Control",
    "content-disposition": "Content-Disposition",
    "content-language": "Content-Language",
    "content-type": "Content-Type",
    "date": "Date",
    "etag": "ETag",
    "expires": "Expires",
    "last-modified": "Last-Modified",
    "location": "Location",
    "retry-after": "Retry-After",
    "x-amz-bucket-region": "x-amz-bucket-region",
    "x-amz-checksum-crc32": "x-amz-checksum-crc32",
    "x-amz-checksum-crc32c": "x-amz-checksum-crc32c",
    "x-amz-checksum-crc64nvme": "x-amz-checksum-crc64nvme",
    "x-amz-checksum-sha1": "x-amz-checksum-sha1",
    "x-amz-checksum-sha256": "x-amz-checksum-sha256",
    "x-amz-checksum-type": "x-amz-checksum-type",
    "x-amz-delete-marker": "x-amz-delete-marker",
    "x-amz-expiration": "x-amz-expiration",
    "x-amz-id-2": "x-amz-id-2",
    "x-amz-missing-meta": "x-amz-missing-meta",
    "x-amz-mp-parts-count": "x-amz-mp-parts-count",
    "x-amz-object-lock-legal-hold": "x-amz-object-lock-legal-hold",
    "x-amz-object-lock-mode": "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date": "x-amz-object-lock-retain-until-date",
    "x-amz-replication-status": "x-amz-replication-status",
    "x-amz-request-id": "x-amz-request-id",
    "x-amz-restore": "x-amz-restore",
    "x-amz-server-side-encryption": "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id": ("x-amz-server-side-encryption-aws-kms-key-id"),
    "x-amz-server-side-encryption-bucket-key-enabled": (
        "x-amz-server-side-encryption-bucket-key-enabled"
    ),
    "x-amz-storage-class": "x-amz-storage-class",
    "x-amz-tagging-count": "x-amz-tagging-count",
    "x-amz-version-id": "x-amz-version-id",
    "x-amz-website-redirect-location": "x-amz-website-redirect-location",
    "x-amzn-requestid": "x-amzn-requestid",
}


def _response_header_for_forwarding(name: str, value: str) -> tuple[str, str] | None:
    safe_name = _FORWARDED_RESPONSE_HEADERS.get(name.lower())
    safe_value = value.replace("\n", "").replace("\r", "").replace("\0", "")
    if safe_name is None or safe_value != value:
        return None
    return safe_name, safe_value


class FixtureProxy:
    """Loopback-only proxy for AWS states that public create APIs cannot seed."""

    def __init__(self, upstream_url: str, host: str = "127.0.0.1", port: int = 0) -> None:
        if not is_loopback_aws_endpoint(upstream_url):
            raise ValueError("Fixture proxy upstream must be an explicit loopback endpoint")
        self.upstream_url = upstream_url.rstrip("/")
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def endpoint_url(self) -> str:
        if self._server is None:
            raise RuntimeError("Fixture proxy has not been started")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self) -> "FixtureProxy":
        upstream_url = self.upstream_url

        class Handler(_FixtureProxyHandler):
            upstream = upstream_url

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="bluearch-fixture-proxy",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._server = None
        self._thread = None

    def __enter__(self) -> "FixtureProxy":
        return self.start()

    def __exit__(self, *_: object) -> None:
        self.close()


class _FixtureProxyHandler(BaseHTTPRequestHandler):
    upstream = ""
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802
        self._forward()

    def do_HEAD(self) -> None:  # noqa: N802
        self._forward()

    def do_POST(self) -> None:  # noqa: N802
        self._forward()

    def do_PUT(self) -> None:  # noqa: N802
        self._forward()

    def do_DELETE(self) -> None:  # noqa: N802
        self._forward()

    def do_PATCH(self) -> None:  # noqa: N802
        self._forward()

    def log_message(self, _: str, *__: object) -> None:
        return

    def _forward(self) -> None:
        content_length = int(self.headers.get("Content-Length") or 0)
        request_body = self.rfile.read(content_length) if content_length else b""
        target = self.headers.get("X-Amz-Target") or ""
        signed_service = _signed_aws_service(self.headers.get("Authorization") or "")
        signal_fixture = fixture_signal_response(
            target,
            service=signed_service,
            request_path=self.path,
            request_body=request_body,
        )
        if signal_fixture is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/x-amz-json-1.1")
            self.send_header("Content-Length", str(len(signal_fixture)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(signal_fixture)
            return
        upstream = urlsplit(self.upstream)
        connection = http.client.HTTPConnection(
            upstream.hostname,
            upstream.port or 80,
            timeout=60,
        )
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.lower() not in _HOP_BY_HOP_HEADERS and name.lower() != "host"
        }
        headers["Host"] = upstream.netloc
        path = self.path
        if upstream.path and upstream.path != "/":
            path = upstream.path.rstrip("/") + "/" + self.path.lstrip("/")
        try:
            connection.request(self.command, path, body=request_body, headers=headers)
            response = connection.getresponse()
            response_body = response.read()
            response_headers = list(response.getheaders())
        except OSError as exc:
            self.send_error(502, f"LocalEmu upstream failed: {exc}")
            return
        finally:
            connection.close()

        patched_body = patch_fixture_response(
            request_body,
            target,
            response_body,
            request_path=self.path,
        )
        body_changed = patched_body != response_body
        self.send_response(response.status)
        for name, value in response_headers:
            lower = name.lower()
            if lower in _HOP_BY_HOP_HEADERS or lower in {"content-length", "content-encoding"}:
                continue
            if body_changed and (
                lower == "x-amz-crc32"
                or lower == "content-md5"
                or lower.startswith("x-amz-checksum-")
            ):
                continue
            safe_header = _response_header_for_forwarding(name, value)
            if safe_header is None:
                continue
            safe_name, safe_value = safe_header
            self.send_header(safe_name, safe_value)
        self.send_header("Content-Length", str(len(patched_body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(patched_body)


def fixture_signal_response(
    target: str,
    *,
    service: str = "",
    request_path: str = "",
    request_body: bytes = b"",
) -> bytes | None:
    normalized_target = re.sub(r"[^a-z0-9]", "", target.lower())
    normalized_path = urlsplit(request_path).path.lower()
    if service == "eks":
        return _eks_fixture_response(request_path)
    if service == "guardduty":
        return _guardduty_fixture_response(normalized_target, request_body)
    if service == "ssm" and "getparameter" in normalized_target:
        return _ssm_fixture_response(request_body)
    if "getfindings" in normalized_target or (
        service == "securityhub" and "finding" in normalized_path
    ):
        return _json_bytes(
            {
                "Findings": [
                    {
                        "SchemaVersion": "2018-10-08",
                        "Id": "localemu-security-hub-versioning",
                        "ProductArn": "arn:aws:securityhub:us-east-1::product/aws/securityhub",
                        "GeneratorId": "s3_bucket_versioning_enabled",
                        "AwsAccountId": "000000000000",
                        "Types": ["Software and Configuration Checks/AWS Security Best Practices"],
                        "FirstObservedAt": "2026-07-16T12:00:00Z",
                        "LastObservedAt": "2026-07-16T12:00:00Z",
                        "CreatedAt": "2026-07-16T12:00:00Z",
                        "UpdatedAt": "2026-07-16T12:00:00Z",
                        "Severity": {"Label": "MEDIUM"},
                        "Title": "Fixture S3 versioning signal",
                        "Description": "Fixture recommendation used only for local MCP validation.",
                        "Resources": [
                            {
                                "Type": "AwsS3Bucket",
                                "Id": "arn:aws:s3:::bluearch-steward-versioning-disabled",
                                "Region": "us-east-1",
                            }
                        ],
                        "Compliance": {"Status": "FAILED"},
                        "RecordState": "ACTIVE",
                        "Workflow": {"Status": "NEW"},
                    }
                ]
            }
        )
    if "getec2instancerecommendations" in normalized_target:
        return _json_bytes(
            {
                "instanceRecommendations": [
                    {
                        "instanceArn": "arn:aws:ec2:us-east-1:000000000000:instance/i-signal-demo",
                        "finding": "Overprovisioned",
                        "currentPerformanceRisk": "Low",
                        "lastRefreshTimestamp": "2026-07-16T12:00:00Z",
                        "recommendationOptions": [
                            {
                                "rank": 1,
                                "instanceType": "t3.small",
                                "savingsOpportunity": {
                                    "savingsOpportunityPercentage": 40.0,
                                    "estimatedMonthlySavings": {
                                        "currency": "USD",
                                        "value": 18.5,
                                    },
                                },
                            }
                        ],
                    }
                ]
            }
        )
    if "getebsvolumerecommendations" in normalized_target:
        return _json_bytes({"volumeRecommendations": []})
    if "getlambdafunctionrecommendations" in normalized_target:
        return _json_bytes({"lambdaFunctionRecommendations": []})
    if "listrecommendations" in normalized_target or (
        service == "cost-optimization-hub" and "recommendation" in normalized_path
    ):
        return _json_bytes(
            {
                "items": [
                    {
                        "recommendationId": "localemu-coh-rightsize",
                        "accountId": "000000000000",
                        "region": "us-east-1",
                        "resourceArn": "arn:aws:ec2:us-east-1:000000000000:instance/i-signal-demo",
                        "currentResourceType": "Ec2Instance",
                        "actionType": "Rightsize",
                        "estimatedMonthlySavings": 20.0,
                        "implementationEffort": "Low",
                        "restartNeeded": True,
                        "rollbackPossible": True,
                        "lastRefreshTimestamp": "2026-07-16T12:00:00Z",
                    }
                ]
            }
        )
    return None


def _eks_fixture_response(request_path: str) -> bytes | None:
    parsed = urlsplit(request_path)
    path = unquote(parsed.path).strip("/")
    parts = path.split("/") if path else []
    query = parse_qs(parsed.query)
    vulnerable = "bluearch-eks-vulnerable"
    healthy = "bluearch-eks-healthy"

    if path in {"clusters", "clusters/"}:
        return _json_bytes({"clusters": [vulnerable, healthy]})
    if path in {"cluster-versions", "clusters/versions"}:
        return _json_bytes(
            {
                "clusterVersions": [
                    {
                        "clusterVersion": "1.30",
                        "versionStatus": "EXTENDED_SUPPORT",
                        "endOfStandardSupportDate": "2025-06-23T00:00:00Z",
                        "endOfExtendedSupportDate": "2026-06-23T00:00:00Z",
                    },
                    {
                        "clusterVersion": "1.31",
                        "versionStatus": "STANDARD_SUPPORT",
                        "endOfStandardSupportDate": "2028-01-01T00:00:00Z",
                        "endOfExtendedSupportDate": "2029-01-01T00:00:00Z",
                    },
                ]
            }
        )
    if path == "addons/supported-versions":
        addon_name = str((query.get("addonName") or [""])[0])
        version = "v1.99.0-eksbuild.1" if addon_name == "coredns" else "v1.0.0-eksbuild.1"
        return _json_bytes(
            {
                "addons": [
                    {
                        "addonName": addon_name,
                        "addonVersions": [
                            {
                                "addonVersion": version,
                                "compatibilities": [{"defaultVersion": True}],
                            }
                        ],
                    }
                ]
            }
        )
    if len(parts) == 2 and parts[0] == "clusters":
        cluster_name = parts[1]
        healthy_cluster = cluster_name == healthy
        return _json_bytes(
            {
                "cluster": {
                    "name": cluster_name,
                    "arn": f"arn:aws:eks:us-east-1:000000000000:cluster/{cluster_name}",
                    "status": "ACTIVE",
                    "version": "1.31" if healthy_cluster else "1.30",
                    "endpoint": "https://127.0.0.1.invalid",
                    "roleArn": "arn:aws:iam::000000000000:role/bluearch-eks-lab",
                    "resourcesVpcConfig": {
                        "endpointPublicAccess": True,
                        "endpointPrivateAccess": healthy_cluster,
                        "publicAccessCidrs": ["10.0.0.0/8"]
                        if healthy_cluster
                        else ["0.0.0.0/0", "::/0"],
                        "subnetIds": ["subnet-fixture-a", "subnet-fixture-b"],
                        "securityGroupIds": ["sg-fixture"],
                    },
                    "logging": {
                        "clusterLogging": [
                            {
                                "types": [
                                    "api",
                                    "audit",
                                    "authenticator",
                                    "controllerManager",
                                    "scheduler",
                                ]
                                if healthy_cluster
                                else ["api", "scheduler"],
                                "enabled": True,
                            }
                        ]
                    },
                }
            }
        )
    if len(parts) == 3 and parts[:1] == ["clusters"] and parts[2] == "node-groups":
        cluster_name = parts[1]
        return _json_bytes(
            {
                "nodegroups": (
                    ["healthy-ng"]
                    if cluster_name == healthy
                    else ["skew-ng", "old-ami-ng", "degraded-ng", "custom-ng"]
                )
            }
        )
    if len(parts) == 4 and parts[:1] == ["clusters"] and parts[2] == "node-groups":
        cluster_name, nodegroup_name = parts[1], parts[3]
        values = {
            "healthy-ng": {
                "version": "1.31",
                "releaseVersion": "1.31.9-20260701",
                "latestReleaseVersion": "1.31.9-20260701",
                "amiType": "AL2_X86_64",
                "status": "ACTIVE",
                "health": {"issues": []},
            },
            "skew-ng": {
                "version": "1.28",
                "releaseVersion": "1.28.15-20260701",
                "latestReleaseVersion": "1.28.15-20260701",
                "amiType": "AL2_X86_64",
                "status": "ACTIVE",
                "health": {"issues": []},
            },
            "old-ami-ng": {
                "version": "1.30",
                "releaseVersion": "1.30.2-20250101",
                "latestReleaseVersion": "1.30.14-20260701",
                "amiType": "AL2_X86_64",
                "status": "ACTIVE",
                "health": {"issues": []},
            },
            "degraded-ng": {
                "version": "1.30",
                "releaseVersion": "1.30.14-20260701",
                "latestReleaseVersion": "1.30.14-20260701",
                "amiType": "AL2_X86_64",
                "status": "DEGRADED",
                "health": {
                    "issues": [
                        {
                            "code": "NodeCreationFailure",
                            "message": "Fixture nodes failed health checks.",
                            "resourceIds": ["bluearch-eks-lab-worker2"],
                        }
                    ]
                },
            },
            "custom-ng": {
                "version": "1.30",
                "releaseVersion": "custom-fixture-1",
                "amiType": "CUSTOM",
                "status": "ACTIVE",
                "health": {"issues": []},
            },
        }.get(nodegroup_name)
        if values is None:
            return None
        return _json_bytes(
            {
                "nodegroup": {
                    "clusterName": cluster_name,
                    "nodegroupName": nodegroup_name,
                    "nodegroupArn": f"arn:aws:eks:us-east-1:000000000000:nodegroup/{cluster_name}/{nodegroup_name}/fixture",
                    "scalingConfig": {"minSize": 1, "maxSize": 3, "desiredSize": 1},
                    **values,
                }
            }
        )
    if len(parts) == 3 and parts[:1] == ["clusters"] and parts[2] == "addons":
        cluster_name = parts[1]
        return _json_bytes(
            {"addons": ["kube-proxy"] if cluster_name == healthy else ["vpc-cni", "coredns"]}
        )
    if len(parts) == 4 and parts[:1] == ["clusters"] and parts[2] == "addons":
        cluster_name, addon_name = parts[1], parts[3]
        healthy_addon = cluster_name == healthy
        unhealthy = addon_name == "vpc-cni"
        return _json_bytes(
            {
                "addon": {
                    "clusterName": cluster_name,
                    "addonName": addon_name,
                    "addonArn": f"arn:aws:eks:us-east-1:000000000000:addon/{cluster_name}/{addon_name}/fixture",
                    "addonVersion": (
                        "v1.0.0-eksbuild.1" if healthy_addon or unhealthy else "v1.80.0-eksbuild.1"
                    ),
                    "status": "DEGRADED" if unhealthy else "ACTIVE",
                    "health": {
                        "issues": [
                            {
                                "code": "ConfigurationConflict",
                                "message": "Fixture add-on pod is not Ready.",
                                "resourceIds": ["aws-node-fixture"],
                            }
                        ]
                        if unhealthy
                        else []
                    },
                }
            }
        )
    return None


def _guardduty_fixture_response(normalized_target: str, request_body: bytes) -> bytes | None:
    del request_body
    if "listdetectors" in normalized_target:
        return _json_bytes({"DetectorIds": ["fixture-detector"]})
    if "getdetector" in normalized_target:
        return _json_bytes(
            {
                "Status": "ENABLED",
                "Features": [{"Name": "EKS_RUNTIME_MONITORING", "Status": "DISABLED"}],
            }
        )
    return None


def _ssm_fixture_response(request_body: bytes) -> bytes:
    try:
        request = json.loads(request_body or b"{}")
    except json.JSONDecodeError:
        request = {}
    parameter_name = str(request.get("Name") or "")
    releases = {
        "/1.28/": "1.28.15-20260701",
        "/1.30/": "1.30.14-20260701",
        "/1.31/": "1.31.9-20260701",
    }
    release = next(
        (value for marker, value in releases.items() if marker in parameter_name),
        "1.30.14-20260701",
    )
    return _json_bytes(
        {
            "Parameter": {
                "Name": parameter_name,
                "Type": "String",
                "Value": release,
                "Version": 1,
                "ARN": f"arn:aws:ssm:us-east-1::parameter{parameter_name}",
                "DataType": "text",
            }
        }
    )


def _json_bytes(document: object) -> bytes:
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def _signed_aws_service(authorization: str) -> str:
    match = re.search(
        r"Credential=[^, ]+/\d{8}/[^/]+/([^/]+)/aws4_request",
        authorization,
    )
    return match.group(1) if match else ""


def patch_fixture_response(
    request_body: bytes,
    target: str,
    response_body: bytes,
    request_path: str = "",
) -> bytes:
    parameters = parse_qs(request_body.decode("utf-8", errors="ignore"))
    action = (parameters.get("Action") or [""])[0]
    if action == "GetMetricData" or target.endswith(".GetMetricData"):
        return _patch_fixture_metric_series(response_body)
    if action == "GetAccountSummary":
        return _patch_account_summary(response_body)
    if action == "ListAccessKeys" and (parameters.get("UserName") or [""])[0].endswith(
        "-iam-console-admin"
    ):
        return _patch_xml_values(response_body, "CreateDate", OLD_TIMESTAMP)
    if action == "DescribeSnapshots":
        return _patch_snapshot_dates(response_body)
    if target.endswith(".ListFunctions") or _is_lambda_list_functions_path(request_path):
        return _patch_lambda_dates(response_body)
    if target.endswith(".DescribeTable"):
        return _patch_dynamodb_table_size(request_body, response_body)
    return response_body


def _is_lambda_list_functions_path(request_path: str) -> bool:
    return urlsplit(request_path).path.rstrip("/") == "/2015-03-31/functions"


def _patch_account_summary(payload: bytes) -> bytes:
    root = _parse_xml(payload)
    if root is None:
        return payload
    summary_map = next(
        (element for element in root.iter() if _local_name(element.tag).lower() == "summarymap"),
        None,
    )
    if summary_map is None:
        return payload
    for member in list(summary_map):
        if _child_text(member, "key") == "AccountAccessKeysPresent":
            value = _child(member, "value")
            if value is not None:
                value.text = "1"
                return _serialize_xml(root, payload)
    member = ET.SubElement(summary_map, _qualified(summary_map, "entry"))
    ET.SubElement(member, _qualified(summary_map, "key")).text = "AccountAccessKeysPresent"
    ET.SubElement(member, _qualified(summary_map, "value")).text = "1"
    return _serialize_xml(root, payload)


def _patch_snapshot_dates(payload: bytes) -> bytes:
    root = _parse_xml(payload)
    if root is None:
        return payload
    changed = False
    for item in _elements(root, "item"):
        description = _child_text(item, "description")
        if not description.endswith("-fixture-orphaned-snapshot"):
            continue
        start_time = _child(item, "startTime")
        if start_time is not None:
            start_time.text = OLD_TIMESTAMP
            changed = True
    return _serialize_xml(root, payload) if changed else payload


def _patch_lambda_dates(payload: bytes) -> bytes:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload
    changed = False
    for function in document.get("Functions") or []:
        if str(function.get("FunctionName") or "").endswith("-unused"):
            function["LastModified"] = OLD_TIMESTAMP
            changed = True
    if not changed:
        return payload
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def _patch_dynamodb_table_size(request: bytes, payload: bytes) -> bytes:
    try:
        request_document = json.loads(request)
        response_document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload
    if not str(request_document.get("TableName") or "").endswith("-ddb-infrequent"):
        return payload
    table = response_document.get("Table")
    if not isinstance(table, dict):
        return payload
    table["TableSizeBytes"] = 2 * 1024 * 1024 * 1024
    return json.dumps(response_document, separators=(",", ":")).encode("utf-8")


def _patch_fixture_metric_series(payload: bytes) -> bytes:
    root = _parse_xml(payload)
    if root is not None:
        changed = False
        for result in _elements(root, "member"):
            label = _child_text(result, "Label")
            replacement = _fixture_metric_values(label)
            if replacement is None:
                continue
            values = _child(result, "Values")
            if values is None:
                values = ET.SubElement(result, _qualified(result, "Values"))
            for child in list(values):
                values.remove(child)
            for value in replacement:
                ET.SubElement(values, _qualified(values, "member")).text = str(value)
            changed = True
        return _serialize_xml(root, payload) if changed else payload

    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return payload
    changed = False
    for result in document.get("MetricDataResults") or []:
        replacement = _fixture_metric_values(str(result.get("Label") or ""))
        if replacement is None:
            continue
        result["Values"] = list(replacement)
        changed = True
    if not changed:
        return payload
    return json.dumps(document, separators=(",", ":")).encode("utf-8")


def _fixture_metric_values(label: str) -> Tuple[float, ...] | None:
    for statistic in (" Average", " Maximum", " Sum"):
        if label.endswith(statistic):
            label = label[: -len(statistic)]
            break
    if not label.startswith("bluearch-steward-"):
        return None
    rds_values = {
        "rds:CPUUtilization:average": 2.0,
        "rds:CPUUtilization:maximum": 2.0,
        "rds:ReadIOPS:average": 200.0,
        "rds:WriteIOPS:average": 10.0,
        "rds-high-cpu:CPUUtilization:average": 98.0,
        "rds-high-cpu:CPUUtilization:maximum": 98.0,
        "rds-high-cpu:ReadIOPS:average": 20.0,
        "rds-high-cpu:WriteIOPS:average": 20.0,
    }
    for suffix, value in rds_values.items():
        if label.endswith(suffix):
            return (value,) * 7
    dynamodb_values = {
        "ddb-inactive:ConsumedReadCapacityUnits": 0.0,
        "ddb-inactive:ConsumedWriteCapacityUnits": 0.0,
        "ddb-infrequent:ConsumedReadCapacityUnits": 25.0,
        "ddb-infrequent:ConsumedWriteCapacityUnits": 25.0,
        "ddb-provisioned-low:ConsumedReadCapacityUnits": 1000.0,
        "ddb-provisioned-low:ConsumedWriteCapacityUnits": 1000.0,
    }
    for suffix, value in dynamodb_values.items():
        if label.endswith(suffix):
            return (value,) * 30
    return None


def _patch_xml_values(payload: bytes, local_name: str, value: str) -> bytes:
    root = _parse_xml(payload)
    if root is None:
        return payload
    changed = False
    for element in _elements(root, local_name):
        element.text = value
        changed = True
    return _serialize_xml(root, payload) if changed else payload


def _parse_xml(payload: bytes) -> ET.Element | None:
    try:
        return DefusedET.fromstring(payload)
    except (ET.ParseError, DefusedXmlException):
        return None


def _serialize_xml(root: ET.Element, original: bytes) -> bytes:
    return ET.tostring(
        root,
        encoding="utf-8",
        xml_declaration=original.lstrip().startswith(b"<?xml"),
    )


def _elements(root: ET.Element, local_name: str) -> Iterable[ET.Element]:
    return (element for element in root.iter() if _local_name(element.tag) == local_name)


def _child(root: ET.Element, local_name: str) -> ET.Element | None:
    return next(
        (element for element in list(root) if _local_name(element.tag) == local_name),
        None,
    )


def _child_text(root: ET.Element, local_name: str) -> str:
    element = _child(root, local_name)
    return str(element.text or "") if element is not None else ""


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _qualified(reference: ET.Element, local_name: str) -> str:
    if reference.tag.startswith("{"):
        namespace = reference.tag.split("}", 1)[0][1:]
        return f"{{{namespace}}}{local_name}"
    return local_name


def _parse_command(argv: list[str]) -> Tuple[argparse.Namespace, list[str]]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", default="http://localhost:4566")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required after --")
    return args, command


def main(argv: list[str] | None = None) -> int:
    args, command = _parse_command(argv or os.sys.argv[1:])
    with FixtureProxy(args.upstream) as proxy:
        resolved = [value.replace(ENDPOINT_TOKEN, proxy.endpoint_url) for value in command]
        environment: Dict[str, str] = {
            **os.environ,
            "BLUEARCH_STEWARD_FIXTURE_PROXY": "1",
        }
        return subprocess.run(resolved, env=environment, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
