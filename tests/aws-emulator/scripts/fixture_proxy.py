#!/usr/bin/env python3
from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Iterable, Tuple
from urllib.parse import parse_qs, urlsplit

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from bluearch_aws_steward.aws_endpoints import is_loopback_aws_endpoint

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
_SAFE_RESPONSE_HEADER_VALUE = re.compile(r"[\t\x20-\x7e\x80-\xff]*")


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
            safe_name = _FORWARDED_RESPONSE_HEADERS.get(lower)
            safe_value = _SAFE_RESPONSE_HEADER_VALUE.fullmatch(value)
            if safe_name is None or safe_value is None:
                continue
            self.send_header(safe_name, safe_value.group(0))
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
) -> bytes | None:
    normalized_target = re.sub(r"[^a-z0-9]", "", target.lower())
    normalized_path = urlsplit(request_path).path.lower()
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
