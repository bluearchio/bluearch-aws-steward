#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from fixture_proxy import FixtureProxy  # noqa: E402

CATALOG = json.loads(
    (REPOSITORY_ROOT / "bluearch_aws_steward/catalog/rules.json").read_text(encoding="utf-8")
)
ACTIVE_RULES = {str(rule["short_id"]) for rule in CATALOG["rules"]}
RULE_FILTER = ",".join(sorted(ACTIVE_RULES))


class McpProcess:
    def __init__(self, endpoint_url: str, region: str) -> None:
        environment = {
            **os.environ,
            "AWS_ACCESS_KEY_ID": "test",
            "AWS_SECRET_ACCESS_KEY": "test",  # pragma: allowlist secret
            "AWS_SESSION_TOKEN": "test",
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
            "BLUEARCH_STEWARD_SERVICE_WORKERS": "1",
            "PYTHONUNBUFFERED": "1",
        }
        self.endpoint_url = endpoint_url
        self.region = region
        self.process = subprocess.Popen(
            [sys.executable, "-m", "bluearch_aws_steward.mcp"],
            cwd=REPOSITORY_ROOT,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.request_id = 0

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
                    "clientInfo": {"name": "bluearch-emulator-e2e", "version": "0.7.0b1"},
                },
            }
        )["result"]

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
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--region", default="us-east-1")
    arguments = parser.parse_args()

    fixture_proxy = FixtureProxy(arguments.endpoint_url).start()
    mcp = McpProcess(fixture_proxy.endpoint_url, arguments.region)
    try:
        initialized = mcp.initialize()
        _expect(initialized["serverInfo"]["name"] == "bluearch-aws-steward", initialized)

        started = mcp.call(
            "bluearch_assess",
            {
                "provider": "aws-sdk",
                "endpoint_url": fixture_proxy.endpoint_url,
                "region": arguments.region,
                "assessment_mode": "full_report",
                "services": ["all"],
                "objectives": ["all"],
                "bucket_prefix": "bluearch-steward-",
                "ebs_min_unattached_days": 0,
                "max_returned_resources": 30,
                "max_returned_findings": 30,
                "rule_filter": RULE_FILTER,
                "signal_sources": [
                    "native",
                    "security-hub",
                    "compute-optimizer",
                    "cost-optimization-hub",
                ],
                "external_findings": [
                    {
                        "source": "prowler-json",
                        "payload": [
                            {
                                "FINDING_UID": "localemu-prowler-versioning",
                                "CHECK_ID": "s3_bucket_versioning_enabled",
                                "STATUS": "FAIL",
                                "SERVICE_NAME": "s3",
                                "ACCOUNT_UID": "000000000000",
                                "RESOURCE_ARN": "arn:aws:s3:::bluearch-steward-versioning-disabled",
                                "REGION": "us-east-1",
                            }
                        ],
                    }
                ],
                "prompt": (
                    "Run a comprehensive read-only assessment using all recommendation sources for the "
                    "AWS emulator fixture account. "
                    "Show only resources caught by rules and do not apply changes."
                ),
            },
        )
        _expect(started.get("status") in {"queued", "running"}, started)
        assessment_id = str(started["assessment_id"])

        status: Dict[str, Any] = {}
        partial: Optional[Dict[str, Any]] = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            partial_response = mcp.call(
                "bluearch_get_scan_results",
                {
                    "assessment_id": assessment_id,
                    "include_partial": True,
                    "generate_pdf_report": False,
                },
            )
            partial = partial_response.get("partial_result") or partial
            status = mcp.call("bluearch_get_scan_status", {"assessment_id": assessment_id})
            if status.get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.1)
        _expect(status.get("status") == "completed", status)

        results = mcp.call(
            "bluearch_get_scan_results",
            {
                "assessment_id": assessment_id,
                "include_partial": True,
                "generate_pdf_report": False,
            },
        )
        partial = results.get("partial_result") or partial
        _expect(partial is not None, results)
        partial_summary = (partial or {}).get("summary") or {}
        _expect(int(partial_summary.get("resources_scanned") or 0) > 0, partial_summary)

        final = results["result"]
        summary = final["summary"]
        coverage = summary["detection_coverage"]
        _expect(summary["scan_errors"] == 0, summary)
        _expect(summary["unified_recommendation_queue"] is True, summary)
        source_evidence = {
            "summary": summary,
            "capability_errors": final.get("capability_errors") or [],
        }
        _expect(summary["deduplicated_signals"] >= 3, source_evidence)
        _expect(summary["incomplete_sources"] == [], source_evidence)
        _expect(summary["rules_evaluated"] == len(ACTIVE_RULES), summary)
        _expect(summary["total_findings_considered"] >= len(ACTIVE_RULES), summary)
        _expect(coverage["complete_catalog_evaluation"] is True, coverage)
        _expect(final["mcp"]["write_actions_applied"] is False, final["mcp"])
        _expect(summary["complete_findings"] == summary["total_findings_considered"], summary)
        _expect(len(final["opportunities"]) == 30, final["summary"])

        queried_findings = []
        cursor: Optional[str] = None
        while True:
            query_arguments: Dict[str, Any] = {
                "assessment_id": assessment_id,
                "sort": "priority",
                "page_size": 37,
            }
            if cursor:
                query_arguments["cursor"] = cursor
            page = mcp.call("bluearch_query_results", query_arguments)
            queried_findings.extend(page["findings"])
            cursor = page.get("next_cursor")
            if not cursor:
                break
        _expect(len(queried_findings) == summary["complete_findings"], summary)
        _expect(
            len({item["opportunity_id"] for item in queried_findings}) == len(queried_findings),
            {"queried_findings": len(queried_findings)},
        )
        returned_rules = {item["rule"] for item in queried_findings}
        _expect(
            returned_rules == ACTIVE_RULES,
            {
                "missing_rules": sorted(ACTIVE_RULES - returned_rules),
                "unexpected_rules": sorted(returned_rules - ACTIVE_RULES),
                "returned_rule_count": len(returned_rules),
                "unexpected_findings": [
                    item for item in queried_findings if item["rule"] not in ACTIVE_RULES
                ],
                "signal_findings": [
                    item
                    for item in queried_findings
                    if item.get("resource") == "ec2://instance/i-signal-demo"
                ],
            },
        )

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "complete-localemu.pdf"
            exported = mcp.call(
                "bluearch_export_report",
                {
                    "assessment_id": assessment_id,
                    "format": "pdf",
                    "report_profile": "complete",
                    "include_all_findings": True,
                    "output_path": str(report_path),
                },
            )
            _expect(exported["report_summary"]["findings"] == len(queried_findings), exported)
            _expect(report_path.read_bytes().startswith(b"%PDF-"), exported)

        versioning = next(
            item
            for item in queried_findings
            if item["rule"] == "s3-versioning-disabled"
            and item["resource"] == "s3://bluearch-steward-versioning-disabled"
        )
        _expect(
            versioning["sources"] == ["bluearch-steward", "prowler-json", "security-hub"],
            versioning,
        )
        _expect(versioning["validation"]["status"] == "confirmed", versioning)
        cost_signal = next(
            item for item in queried_findings if item["resource"] == "ec2://instance/i-signal-demo"
        )
        _expect(
            cost_signal["sources"] == ["compute-optimizer", "cost-optimization-hub"],
            cost_signal,
        )
        _expect(cost_signal["validation"]["status"] == "source_current", cost_signal)
        plan = mcp.call(
            "bluearch_plan_remediation",
            {"assessment_id": assessment_id, "finding_id": versioning["opportunity_id"]},
        )
        _expect(plan["status"] == "awaiting_approval", plan)
        _expect(plan["plan"]["approval"]["required"] is True, plan)

        verification = mcp.call(
            "bluearch_verify_remediation",
            {"assessment_id": assessment_id, "finding_ids": [versioning["opportunity_id"]]},
        )
        _expect(verification["verified"] is False, verification)
        _expect(
            versioning["opportunity_id"] in verification["remaining_requested_finding_ids"],
            verification,
        )

        print(
            json.dumps(
                {
                    "assessment_id": assessment_id,
                    "resources_scanned": summary["resources_scanned"],
                    "findings": summary["total_findings_considered"],
                    "service_summaries": {
                        service: {
                            "resources_scanned": int(receipt.get("resources_scanned") or 0),
                            "findings": int(receipt.get("findings") or 0),
                            "rules_evaluated": int(receipt.get("rules_evaluated") or 0),
                        }
                        for service, receipt in (summary.get("service_summaries") or {}).items()
                    },
                    "rules_evaluated": summary["rules_evaluated"],
                    "partial_results_verified": True,
                    "complete_results_queried": len(queried_findings),
                    "complete_pdf_verified": True,
                    "unified_sources_verified": True,
                    "deduplicated_signals": summary["deduplicated_signals"],
                    "plan_created": True,
                    "verification_read_only": True,
                    "write_actions_applied": False,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    finally:
        try:
            mcp.close()
        finally:
            fixture_proxy.close()


def _expect(condition: bool, evidence: Any) -> None:
    if not condition:
        raise AssertionError(json.dumps(evidence, indent=2, sort_keys=True, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
