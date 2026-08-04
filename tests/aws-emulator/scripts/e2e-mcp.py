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
ACTIVE_RULES = {
    str(rule["short_id"]) for rule in CATALOG["rules"] if str(rule.get("service") or "") != "eks"
}
if len(ACTIVE_RULES) != 100:
    raise RuntimeError(f"Expected 100 AWS-only rules, found {len(ACTIVE_RULES)}")
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
                    "clientInfo": {"name": "bluearch-emulator-e2e", "version": "0.9.0b1"},
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

        vague_review = mcp.call(
            "bluearch_assess",
            {
                "prompt": "Review the S3 bucket I am deploying.",
                "assessment_mode": "architectural_review",
                "review_context": {"operation": "create"},
            },
        )
        _expect(vague_review["status"] == "input_required", vague_review)
        _expect(vague_review["reason"] == "architectural_review_focus_required", vague_review)
        _expect(vague_review["security"]["aws_calls"] is False, vague_review)

        context_request = mcp.call(
            "bluearch_assess",
            {
                "prompt": "Review s3://bluearch-steward-versioning-disabled before deletion.",
                "assessment_mode": "architectural_review",
                "review_context": {
                    "operation": "delete",
                    "resource_refs": [
                        {
                            "resource": "s3://bluearch-steward-versioning-disabled",
                            "service": "s3",
                        }
                    ],
                },
            },
        )
        _expect(context_request["status"] == "input_required", context_request)
        _expect(
            context_request["reason"] == "architectural_review_context_required",
            context_request,
        )
        _expect(len(context_request["questions"]) <= 5, context_request)

        contextual_started_at = time.monotonic()
        contextual_started = mcp.call(
            "bluearch_assess",
            {
                "provider": "aws-sdk",
                "endpoint_url": fixture_proxy.endpoint_url,
                "region": arguments.region,
                "prompt": "Review s3://bluearch-steward-versioning-disabled before deletion.",
                "assessment_mode": "architectural_review",
                "review_context": {
                    "operation": "delete",
                    "resource_refs": [
                        {
                            "resource": "s3://bluearch-steward-versioning-disabled",
                            "service": "s3",
                        }
                    ],
                    "answers": {
                        "environment": "production",
                        "data_classification": "confidential",
                        "access_pattern": "private_application",
                        "retention": "multi_year",
                        "consumers": "multiple_workloads",
                    },
                    "max_relationship_hops": 1,
                },
                "max_returned_resources": 25,
                "max_returned_findings": 25,
            },
        )
        contextual_submit_ms = round((time.monotonic() - contextual_started_at) * 1000, 2)
        _expect(contextual_submit_ms < 1000, contextual_started)
        contextual_id = str(contextual_started["assessment_id"])
        contextual_partial: Optional[Dict[str, Any]] = None
        contextual_status: Dict[str, Any] = {}
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            contextual_results = mcp.call(
                "bluearch_get_scan_results",
                {
                    "assessment_id": contextual_id,
                    "include_partial": True,
                    "generate_pdf_report": False,
                },
            )
            contextual_partial = contextual_results.get("partial_result") or contextual_partial
            contextual_status = mcp.call(
                "bluearch_get_scan_status",
                {"assessment_id": contextual_id},
            )
            if contextual_status.get("status") in {"completed", "failed", "cancelled"}:
                break
            time.sleep(0.05)
        _expect(contextual_status.get("status") == "completed", contextual_status)
        contextual_duration_ms = round((time.monotonic() - contextual_started_at) * 1000, 2)
        _expect(contextual_duration_ms < 10_000, contextual_status)
        _expect(contextual_partial is not None, contextual_status)

        contextual_response = mcp.call(
            "bluearch_get_scan_results",
            {
                "assessment_id": contextual_id,
                "include_partial": True,
                "generate_pdf_report": False,
            },
        )
        contextual = contextual_response["result"]
        contextual_summary = contextual["summary"]
        _expect(contextual["assessment_mode"] == "architectural_review", contextual)
        _expect(contextual_summary["full_account_scan"] is False, contextual_summary)
        _expect(contextual_summary["services_requested"] == ["s3"], contextual_summary)
        _expect(contextual_summary["services_scanned"] == ["s3"], contextual_summary)
        _expect(contextual["evidence_ledger"]["operation_count"] <= 50, contextual)
        _expect(contextual["evidence_ledger"]["write_operations"] == 0, contextual)
        _expect(contextual["mcp"]["write_actions_applied"] is False, contextual["mcp"])
        _expect("ec2" in contextual["excluded_scope"]["services"], contextual)
        _expect("rds" in contextual["excluded_scope"]["services"], contextual)
        _expect(
            all(
                "bluearch-steward-versioning-disabled" in str(item.get("resource") or "")
                for item in contextual["recommendations"]
            ),
            contextual["recommendations"],
        )
        contextual_operations = contextual["evidence_ledger"]["operations"]
        _expect(
            not any(
                str(item.get("operation") or "").startswith(("ec2.", "rds."))
                for item in contextual_operations
            ),
            contextual_operations,
        )
        _expect(
            all(
                item.get("operation") and item.get("status") and item.get("observed_at")
                for item in contextual_operations
            ),
            contextual_operations,
        )
        contextual_practices = [
            practice
            for pillar in contextual["well_architected_review"]["pillars"]
            for practice in pillar["practices"]
        ]
        _expect(contextual_practices, contextual["well_architected_review"])
        _expect(
            all(
                practice.get("source_url")
                and practice.get("catalog_revision")
                and practice.get("reviewed_at")
                for practice in contextual_practices
            ),
            contextual_practices,
        )
        contextual_versioning = next(
            item
            for item in contextual["recommendations"]
            if item["rule"] == "s3-versioning-disabled"
        )
        resource_details = mcp.call(
            "bluearch_get_resource_details",
            {
                "assessment_id": contextual_id,
                "resource": contextual_versioning["resource"],
                "rule": "s3-versioning-disabled",
            },
        )
        _expect(resource_details.get("architecture_neighborhood"), resource_details)
        _expect(resource_details.get("well_architected_context"), resource_details)

        contextual_investigation = mcp.call(
            "bluearch_investigate_resource",
            {
                "assessment_id": contextual_id,
                "finding_id": contextual_versioning["opportunity_id"],
            },
        )
        _expect(contextual_investigation["read_only"] is True, contextual_investigation)
        _expect(
            contextual_investigation["write_actions_applied"] is False,
            contextual_investigation,
        )

        with tempfile.TemporaryDirectory() as directory:
            contextual_report_path = Path(directory) / "contextual-review.html"
            contextual_export = mcp.call(
                "bluearch_export_report",
                {
                    "assessment_id": contextual_id,
                    "format": "html",
                    "report_profile": "complete",
                    "include_all_findings": True,
                    "output_path": str(contextual_report_path),
                },
            )
            _expect(contextual_report_path.exists(), contextual_export)
            contextual_html = contextual_report_path.read_text(encoding="utf-8")
            _expect("architectural_review" in contextual_html, contextual_html[:1000])

        contextual_receipt = {
            "assessment_id": contextual_id,
            "focus": contextual["focus"],
            "questions_verified": True,
            "partial_results_verified": True,
            "submit_ms": contextual_submit_ms,
            "duration_ms": contextual_duration_ms,
            "services_scanned": contextual_summary["services_scanned"],
            "read_operations": contextual["evidence_ledger"]["operation_count"],
            "write_operations": contextual["evidence_ledger"]["write_operations"],
            "unrelated_collectors": [],
            "resource_details_verified": True,
            "investigation_verified": True,
            "html_report_verified": True,
        }

        investigation_targets = {
            "ec2-unattached-ebs-volume": "ec2:DeleteVolume",
            "ec2-unassociated-elastic-ip": "ec2:ReleaseAddress",
            "ecs-inactive-task-definition": "ecs:DeleteTaskDefinitions",
            "efs-inactive-unmounted": "elasticfilesystem:DeleteFileSystem",
            "lambda-unused-function": "lambda:DeleteFunction",
            "rds-idle-instance": "rds:DeleteDBInstance",
        }
        investigation_receipts: Dict[str, Any] = {}
        for rule, planned_api in investigation_targets.items():
            selected = next(item for item in queried_findings if item["rule"] == rule)
            dossier = mcp.call(
                "bluearch_investigate_resource",
                {
                    "assessment_id": assessment_id,
                    "finding_id": selected["opportunity_id"],
                },
            )
            _expect(dossier["read_only"] is True, dossier)
            _expect(dossier["write_actions_applied"] is False, dossier)
            _expect(dossier["deletion_readiness"]["safe_to_delete"] is False, dossier)
            _expect(dossier["change_plan_preview"]["executable_by_steward"] is False, dossier)
            _expect(
                dossier["change_plan_preview"]["target_operation"]["aws_api"] == planned_api,
                dossier,
            )
            investigation_receipts[rule] = {
                "status": dossier["deletion_readiness"]["status"],
                "aws_reads_performed": dossier["aws_reads_performed"],
                "evidence_coverage": dossier["evidence_coverage"]["score"],
                "planned_api": planned_api,
                "write_actions_applied": False,
            }

        operational_targets = {
            "ecs-platform-version-outdated": "ecs:UpdateService",
            "ecs-service-health-degraded": None,
            "ecs-unsafe-task-definition": "ecs:RegisterTaskDefinition",
            "rds-high-cpu": None,
            "rds-low-cpu-rightsizing": "rds:ModifyDBInstance",
            "rds-publicly-accessible": "rds:ModifyDBInstance",
            "rds-read-heavy-no-replica": "rds:CreateDBInstanceReadReplica",
        }
        operational_receipts: Dict[str, Any] = {}
        for rule, planned_api in operational_targets.items():
            selected = next(item for item in queried_findings if item["rule"] == rule)
            dossier = mcp.call(
                "bluearch_investigate_resource",
                {
                    "assessment_id": assessment_id,
                    "finding_id": selected["opportunity_id"],
                },
            )
            _expect(dossier["investigation"] == "operational_diagnosis", dossier)
            _expect(dossier["read_only"] is True, dossier)
            _expect(dossier["write_actions_applied"] is False, dossier)
            _expect(dossier["operational_diagnosis"]["root_cause_confirmed"] is False, dossier)
            _expect(dossier["change_plan_preview"]["executable_by_steward"] is False, dossier)
            target_operation = dossier["change_plan_preview"]["target_operation"]
            if planned_api is None:
                _expect(target_operation is None, dossier)
            else:
                _expect(target_operation["aws_api"] == planned_api, dossier)
            operational_receipts[rule] = {
                "status": dossier["operational_diagnosis"]["status"],
                "aws_reads_performed": dossier["aws_reads_performed"],
                "evidence_coverage": dossier["evidence_coverage"]["score"],
                "hypotheses": len(dossier["operational_diagnosis"]["hypotheses"]),
                "planned_api": planned_api,
                "write_actions_applied": False,
            }

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
                    "contextual_review": contextual_receipt,
                    "deletion_investigations": investigation_receipts,
                    "operational_investigations": operational_receipts,
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
