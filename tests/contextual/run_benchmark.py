#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import tempfile
import time
from pathlib import Path
from typing import Any, Dict

from bluearch_aws_steward.mcp_server import StewardMcpServer

JSON = Dict[str, Any]
ROOT = Path(__file__).resolve().parents[2]


def _call(server: StewardMcpServer, request_id: int, name: str, arguments: JSON) -> JSON:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    if response is None or response["result"].get("isError"):
        raise AssertionError(response)
    return response["result"].get("structuredContent") or json.loads(
        response["result"]["content"][0]["text"]
    )


def _completed(server: StewardMcpServer, assessment_id: str, request_id: int) -> JSON:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        status = _call(
            server,
            request_id,
            "bluearch_get_scan_status",
            {"assessment_id": assessment_id},
        )
        request_id += 1
        if status["status"] == "completed":
            return _call(
                server,
                request_id,
                "bluearch_get_scan_results",
                {"assessment_id": assessment_id, "generate_pdf_report": False},
            )["result"]
        if status["status"] == "failed":
            raise AssertionError(status.get("error"))
        time.sleep(0.01)
    raise AssertionError("contextual benchmark assessment timed out")


def run_benchmark() -> JSON:
    scenarios = json.loads(
        (ROOT / "tests/contextual/golden-scenarios.json").read_text(encoding="utf-8")
    )["scenarios"]
    baseline = json.loads(
        (ROOT / "tests/contextual/generic-agent-baseline.json").read_text(encoding="utf-8")
    )
    baseline_by_id = {item["id"]: item for item in baseline["scenarios"]}
    receipts = []
    durations = []
    expected_practices = 0
    observed_practices = 0
    irrelevant_recommendations = 0
    recommendation_count = 0
    unsupported_claims = 0
    request_id = 1
    server = StewardMcpServer(
        aws_provider_factory=lambda _: (_ for _ in ()).throw(
            AssertionError("IaC benchmark must not create an AWS provider")
        )
    )
    for scenario in scenarios:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "main.tf").write_text(scenario["terraform"], encoding="utf-8")
            started_at = time.monotonic()
            submitted = _call(
                server,
                request_id,
                "bluearch_assess",
                {
                    "prompt": scenario["prompt"],
                    "assessment_mode": "architectural_review",
                    "review_context": {
                        "operation": scenario["operation"],
                        "iac": {
                            "workspace_root": str(root),
                            "paths": ["main.tf"],
                            "format": "terraform",
                        },
                        "answers": {"_continue_with_unknowns": True},
                    },
                },
            )
            request_id += 1
            result = _completed(server, submitted["assessment_id"], request_id)
            request_id += 20
            duration_ms = round((time.monotonic() - started_at) * 1000, 2)
            durations.append(duration_ms)

        rules = set(result.get("rules") or [])
        practices = {
            str(practice["practice_id"])
            for pillar in result["well_architected_review"]["pillars"]
            for practice in pillar["practices"]
        }
        services = {str(item.get("service")) for item in result.get("recommendations") or []}
        recommendation_count += len(result.get("recommendations") or [])
        irrelevant_recommendations += sum(service != scenario["service"] for service in services)
        unsupported = [
            item
            for item in result.get("recommendations") or []
            if not item.get("evidence") or not item.get("confidence")
        ]
        unsupported_claims += len(unsupported)
        expected_practices += 1
        observed_practices += int(scenario["expected_practice"] in practices)
        passed = (
            scenario["expected_rule"] in rules
            and scenario["expected_practice"] in practices
            and services.issubset({scenario["service"]})
            and not unsupported
            and result["summary"]["full_account_scan"] is False
            and result["evidence_ledger"]["operation_count"] == 0
            and result["evidence_ledger"]["write_operations"] == 0
        )
        receipts.append(
            {
                "scenario_id": scenario["id"],
                "family": scenario["family"],
                "passed": passed,
                "expected_rule_observed": scenario["expected_rule"] in rules,
                "expected_practice_observed": scenario["expected_practice"] in practices,
                "recommendation_services": sorted(services),
                "aws_reads": result["evidence_ledger"]["operation_count"],
                "writes": result["evidence_ledger"]["write_operations"],
                "duration_ms": duration_ms,
            }
        )

    sorted_durations = sorted(durations)
    p95_index = max(0, min(len(sorted_durations) - 1, int(len(sorted_durations) * 0.95) - 1))
    generic_irrelevant = sum(
        sum(
            service != next(item["service"] for item in scenarios if item["id"] == row["id"])
            for service in row["recommendation_services"]
        )
        for row in baseline_by_id.values()
    )
    generic_total = sum(len(row["recommendation_services"]) for row in baseline_by_id.values())
    report = {
        "schema_version": "contextual-benchmark-result-0.1",
        "passed": all(item["passed"] for item in receipts),
        "steward": {
            "applicable_practice_recall": observed_practices / expected_practices,
            "irrelevant_recommendation_rate": (
                irrelevant_recommendations / recommendation_count if recommendation_count else 0.0
            ),
            "unsupported_claims": unsupported_claims,
            "focused_review_p95_ms": sorted_durations[p95_index],
        },
        "generic_reference_fixture": {
            "model_measurement": baseline["model_measurement"],
            "irrelevant_recommendation_rate": generic_irrelevant / generic_total,
            "unsupported_claims": sum(
                int(row["unsupported_claims"]) for row in baseline_by_id.values()
            ),
        },
        "receipts": receipts,
    }
    if not report["passed"]:
        raise AssertionError(json.dumps(report, indent=2, sort_keys=True))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output")
    arguments = parser.parse_args()
    report = run_benchmark()
    rendered = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        Path(arguments.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
