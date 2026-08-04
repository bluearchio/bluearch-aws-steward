"""Shared fixture for triage tests.

Reproduces the ordering pathology seen on a live account: iam-root-access-key-present
carries severity medium in the catalog while six other findings carry high, and all
six sort ahead of it alphabetically. Under the old severity-then-alphabetical sort,
that pushes the root access key to 7th place, outside any reasonable "top N" window
that an operator would actually read.
"""

from __future__ import annotations

import json
import time
from typing import Any, Dict

JSON = Dict[str, Any]

_RULES = (
    ("api-gateway-access-logging-disabled", "high", "api-gateway", "apigw://stage/prod"),
    ("api-gateway-execution-logging-disabled", "high", "api-gateway", "apigw://stage/staging"),
    ("api-gateway-method-authorization-missing", "high", "api-gateway", "apigw://method/get-users"),
    ("ecs-unsafe-task-definition", "high", "ecs", "ecs://task-definition/worker"),
    ("iam-access-key-older-than-90-days", "high", "iam", "iam://user/ci/access-key/key-1"),
    ("kms-key-rotation-disabled", "high", "kms", "kms://key/abc-123"),
    ("iam-root-access-key-present", "medium", "iam", "iam://account/root"),
    ("s3-no-lifecycle", "low", "s3", "s3://archive-bucket"),
)


def triage_scan_result() -> JSON:
    findings = []
    for index, (rule, severity, service, resource) in enumerate(_RULES):
        findings.append(
            {
                "finding_id": f"triage-{index}",
                "rule_id": f"00000000-0000-0000-0000-00000000000{index}",
                "rule_short_id": rule,
                "service": service,
                "resource": resource,
                "resource_ref": {
                    "provider": "aws",
                    "service": service,
                    "resource_type": f"aws.{service}.resource",
                    "resource_id": resource.rsplit("/", 1)[-1],
                    "region": "us-east-1",
                },
                "severity": severity,
                "risk_detail": "security",
                "scenario": f"Fixture finding for {rule}.",
                "evidence": {"observation": {"source": "aws_control_plane", "confidence": "high"}},
                "remediation": {},
            }
        )
    return {
        "schema_version": "0.2",
        "generated_at": "2026-08-04T00:00:00Z",
        "service": "all",
        "provider": "aws-sdk",
        "profile": None,
        "region": "us-east-1",
        "findings": findings,
        "summary": {
            "resources_scanned": len(findings),
            "rules_evaluated": len(findings),
            "scan_errors": 0,
        },
    }


def call_tool(server: Any, request_id: int, tool: str, arguments: JSON) -> JSON:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
    )
    if "error" in response:
        raise AssertionError(f"{tool} failed: {response['error']}")
    return json.loads(response["result"]["content"][0]["text"])


def completed_result(server: Any, assessment_id: str) -> JSON:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status = call_tool(
            server, 900, "bluearch_get_scan_status", {"assessment_id": assessment_id}
        )
        if status["status"] == "completed":
            break
        time.sleep(0.01)
    else:
        raise AssertionError("assessment did not complete")
    return call_tool(
        server,
        901,
        "bluearch_get_scan_results",
        {"assessment_id": assessment_id, "generate_pdf_report": False},
    )["result"]
