#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional


class McpProcess:
    def __init__(self, profile: str, region: str) -> None:
        environment = {
            **os.environ,
            "AWS_PROFILE": profile,
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
            "BLUEARCH_STEWARD_SERVICE_WORKERS": "4",
            "PYTHONUNBUFFERED": "1",
        }
        self.process = subprocess.Popen(
            [sys.executable, "-m", "bluearch_aws_steward.mcp"],
            cwd=Path(__file__).resolve().parents[3],
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request_id = 0

    def initialize(self) -> Dict[str, Any]:
        self.request_id += 1
        return self._request(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "bluearch-aws-live-e2e", "version": "0.7.0b2"},
                },
            }
        )["result"]

    def call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        self.request_id += 1
        response = self._request(
            {
                "jsonrpc": "2.0",
                "id": self.request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        result = response["result"]
        if result.get("isError"):
            raise AssertionError(result["content"][0]["text"])
        return result.get("structuredContent") or json.loads(result["content"][0]["text"])

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            self.process.wait(timeout=3)
        if self.process.returncode not in {0, None}:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP process exited with {self.process.returncode}: {stderr}")

    def _request(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not self.process.stdin or not self.process.stdout:
            raise RuntimeError("MCP process pipes are unavailable")
        self.process.stdin.write(json.dumps(payload) + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read() if self.process.stderr else ""
            raise RuntimeError(f"MCP process closed unexpectedly: {stderr}")
        return json.loads(line)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run a summarized, read-only Steward MCP assessment against real AWS."
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--service",
        default="all",
        help="Native Steward service scope. Managed recommendation sources remain account-wide.",
    )
    parser.add_argument(
        "--signal-sources",
        default="native,security-hub,compute-optimizer,cost-optimization-hub",
        help="Comma-separated recommendation sources requested through bluearch_assess.",
    )
    parser.add_argument(
        "--prowler-json-file",
        help="Optional local Prowler JSON-OCSF export to correlate with live AWS reads.",
    )
    parser.add_argument("--timeout-seconds", type=int, default=900)
    parser.add_argument("--max-returned-resources", type=int, default=5)
    parser.add_argument("--max-returned-findings", type=int, default=5)
    arguments = parser.parse_args()
    signal_sources = [item.strip() for item in arguments.signal_sources.split(",") if item.strip()]
    if not signal_sources:
        parser.error("--signal-sources must include at least one source")
    external_findings = []
    if arguments.prowler_json_file:
        prowler_path = Path(arguments.prowler_json_file).expanduser().resolve()
        external_findings.append(
            {
                "source": "prowler-json",
                "payload": json.loads(prowler_path.read_text(encoding="utf-8")),
            }
        )

    mcp = McpProcess(arguments.profile, arguments.region)
    try:
        initialized = mcp.initialize()
        _expect(initialized["serverInfo"]["name"] == "bluearch-aws-steward", initialized)

        started = mcp.call(
            "bluearch_assess",
            {
                "provider": "aws-sdk",
                "profile": arguments.profile,
                "region": arguments.region,
                "service": arguments.service,
                "objective": "all",
                "signal_sources": signal_sources,
                "external_findings": external_findings,
                "max_returned_resources": arguments.max_returned_resources,
                "max_returned_findings": arguments.max_returned_findings,
                "prompt": (
                    "Build one prioritized, read-only remediation queue from all requested "
                    "recommendation sources. Show only resources caught by rules or source "
                    "recommendations and do not apply changes."
                ),
            },
        )
        if started.get("status") not in {"queued", "running"}:
            print(
                json.dumps(
                    {
                        "status": started.get("status") or "blocked",
                        "reason": started.get("reason") or "assessment_not_started",
                        "message": started.get("message") or "The assessment did not start.",
                        "actions": started.get("actions") or [],
                        "write_actions_applied": False,
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
            )
            return 2
        context = started.get("aws_context") or {}
        _expect(context.get("validated") is True, context)
        _expect(context.get("profile") == arguments.profile, context)
        assessment_id = str(started["assessment_id"])

        partial: Optional[Dict[str, Any]] = None
        status: Dict[str, Any] = {}
        deadline = time.monotonic() + max(1, arguments.timeout_seconds)
        while time.monotonic() < deadline:
            response = mcp.call(
                "bluearch_get_scan_results",
                {
                    "assessment_id": assessment_id,
                    "include_partial": True,
                    "generate_pdf_report": False,
                },
            )
            partial = response.get("partial_result") or partial
            status = mcp.call("bluearch_get_scan_status", {"assessment_id": assessment_id})
            if status.get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.5)
        _expect(status.get("status") == "completed", status)

        response = mcp.call(
            "bluearch_get_scan_results",
            {
                "assessment_id": assessment_id,
                "include_partial": True,
                "generate_pdf_report": False,
            },
        )
        final = response["result"]
        summary = final["summary"]
        _expect(final["mcp"]["write_actions_applied"] is False, final["mcp"])

        print(
            json.dumps(
                {
                    "profile": arguments.profile,
                    "region": arguments.region,
                    "service": arguments.service,
                    "prowler_file_imported": bool(arguments.prowler_json_file),
                    "sources_requested": summary.get("sources_requested") or signal_sources,
                    "status": "completed",
                    "partial_results_observed": partial is not None,
                    "resources_scanned": summary.get("resources_scanned", 0),
                    "findings": summary.get("total_findings_considered", 0),
                    "rules_evaluated": summary.get("rules_evaluated", 0),
                    "scan_errors": summary.get("scan_errors", 0),
                    "service_errors": len(summary.get("service_errors") or []),
                    "rules_skipped": len(summary.get("rules_skipped") or []),
                    "capability_errors": len(summary.get("capability_errors") or []),
                    "incomplete_sources": summary.get("incomplete_sources") or [],
                    "source_findings": summary.get("sources") or {},
                    "signal_snapshots": summary.get("signal_snapshots", 0),
                    "signals_received": summary.get("signals_received", 0),
                    "deduplicated_signals": summary.get("deduplicated_signals", 0),
                    "resolved_or_stale_recommendations": summary.get(
                        "resolved_or_stale_recommendations", 0
                    ),
                    "validation_statuses": summary.get("validation_statuses") or {},
                    "unified_recommendation_queue": bool(
                        summary.get("unified_recommendation_queue")
                    ),
                    "capability_error_details": [
                        {
                            "source": item.get("source"),
                            "reason": item.get("reason") or item.get("code"),
                            "message": item.get("message"),
                        }
                        for item in (final.get("capability_errors") or [])
                    ],
                    "write_actions_applied": False,
                    "account_identifiers_printed": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    finally:
        mcp.close()


def _expect(condition: bool, evidence: Any) -> None:
    if not condition:
        raise AssertionError(json.dumps(evidence, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
