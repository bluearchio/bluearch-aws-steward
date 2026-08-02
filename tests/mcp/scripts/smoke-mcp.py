from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List


def main() -> int:
    finding = {
        "finding_id": "steward-test",
        "rule_id": "rule",
        "rule_short_id": "s3-versioning-disabled",
        "service": "s3",
        "resource": "s3://example",
        "severity": "medium",
        "risk_detail": "operations",
        "scenario": "S3 versioning should support object recovery",
        "evidence": {"versioning_status": None},
        "remediation": {
            "summary": "Enable bucket versioning.",
            "safety_level": "low_risk",
            "requires_approval": True,
            "actions": ["Enable bucket versioning."],
            "verification": "Re-read bucket versioning.",
        },
    }
    cost_finding = {
        **finding,
        "finding_id": "steward-cost",
        "rule_short_id": "s3-no-lifecycle",
        "resource": "s3://cost-example",
        "risk_detail": "cost, operations",
        "scenario": "S3 lifecycle manager is turned off",
        "evidence": {
            "lifecycle_rules": [],
            "assessment": "advisory",
            "cost_estimate": {
                "status": "insufficient",
                "estimated_monthly_savings_usd": None,
                "confidence": "none",
            },
        },
        "remediation": {
            "summary": "Add a lifecycle rule for older objects.",
            "safety_level": "low_risk",
            "requires_approval": True,
            "actions": ["Add a lifecycle rule for older objects or configure Intelligent-Tiering."],
            "verification": "Re-read bucket lifecycle configuration and confirm at least one enabled rule exists.",
        },
    }
    cloudwatch_finding = {
        **cost_finding,
        "finding_id": "steward-cloudwatch-cost",
        "rule_short_id": "cloudwatch-log-retention-missing",
        "service": "cloudwatch",
        "resource": "cloudwatch-logs://log-group/example",
        "evidence": {
            "cost_estimate": {
                "status": "estimated",
                "estimated_monthly_savings_usd": 0.06,
                "confidence": "low",
            }
        },
    }
    ebs_finding = {
        **cost_finding,
        "finding_id": "steward-ebs-cost",
        "rule_short_id": "ec2-unattached-ebs-volume",
        "service": "ec2",
        "resource": "ebs://vol-example",
        "evidence": {
            "cost_estimate": {
                "status": "estimated",
                "estimated_monthly_savings_usd": 8.0,
                "confidence": "medium",
            }
        },
    }
    responses = _run_mcp(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "bluearch-smoke", "version": "0.0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_rules_search",
                    "arguments": {"service": "s3", "query": "versioning"},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_explain_finding",
                    "arguments": {"finding": finding},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_apply_remediation",
                    "arguments": {"finding": finding, "allow_write": False},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_find_opportunities",
                    "arguments": {
                        "objective": "cost_optimization",
                        "scan_result": {
                            "service": "all",
                            "findings": [finding, cost_finding, cloudwatch_finding, ebs_finding],
                        },
                    },
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "bluearch_advise",
                    "arguments": {
                        "prompt": "Find top 5 AWS cost savings in us-east-1.",
                        "scan_result": {
                            "service": "all",
                            "findings": [finding, cost_finding, cloudwatch_finding, ebs_finding],
                        },
                    },
                },
            },
            {"jsonrpc": "2.0", "id": 8, "method": "prompts/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "prompts/get",
                "params": {
                    "name": "security_review",
                    "arguments": {
                        "profile": "example-sso",
                        "region": "us-east-1",
                        "service": "all",
                        "max_results": "10",
                    },
                },
            },
        ]
    )

    assert [response.get("id") for response in responses] == [1, 2, 3, 4, 5, 6, 7, 8, 9], responses
    assert responses[0]["result"]["serverInfo"]["name"] == "bluearch-aws-steward"
    assert responses[0]["result"]["capabilities"]["prompts"] == {"listChanged": False}

    tool_names = {tool["name"] for tool in responses[1]["result"]["tools"]}
    expected_tools = {
        "bluearch_assess",
        "bluearch_import_findings",
        "bluearch_list_aws_profiles",
        "bluearch_get_scan_status",
        "bluearch_get_scan_results",
        "bluearch_cancel_assessment",
        "bluearch_get_resource_details",
        "bluearch_investigate_resource",
        "bluearch_generate_iac_patch",
        "bluearch_validate_iac_patch",
        "bluearch_get_coverage",
        "bluearch_status",
        "bluearch_advise",
        "bluearch_rules_search",
        "bluearch_scan_aws",
        "bluearch_find_opportunities",
        "bluearch_explain_finding",
        "bluearch_plan_remediation",
        "bluearch_verify_remediation",
        "bluearch_apply_remediation",
        "bluearch_doctor",
    }
    assert expected_tools <= tool_names, tool_names
    scan_tool = next(
        tool for tool in responses[1]["result"]["tools"] if tool["name"] == "bluearch_scan_aws"
    )
    scan_properties = scan_tool["inputSchema"]["properties"]
    for expected_property in [
        "rule_filter",
        "max_returned_resources",
        "max_returned_findings",
        "include_raw_findings",
        "ebs_min_unattached_days",
        "cloudwatch_retention_days",
        "cloudwatch_min_stored_bytes",
        "exclude_tags",
    ]:
        assert expected_property in scan_properties, scan_properties

    rules_payload = _tool_payload(responses[2])
    assert any(
        (rule.get("evaluation") or {}).get("short_id") == "s3-versioning-disabled"
        for rule in rules_payload["rules"]
    ), rules_payload

    explain_payload = _tool_payload(responses[3])
    assert explain_payload["approval_required"] is True, explain_payload

    write_guard = responses[4]["result"]
    assert write_guard["isError"] is True, write_guard
    assert "allow_write=true" in write_guard["content"][0]["text"], write_guard

    opportunities_payload = _tool_payload(responses[5])
    assert opportunities_payload["objective"] == "cost_optimization", opportunities_payload
    assert opportunities_payload["summary"]["opportunities"] == 2, opportunities_payload
    assert opportunities_payload["summary"]["returned_rules"] == 2, opportunities_payload
    assert opportunities_payload["opportunities"][0]["resource"] == "ebs://vol-example", (
        opportunities_payload
    )
    assert opportunities_payload["opportunities"][0]["apply"]["supported"] is False

    advise_payload = _tool_payload(responses[6])
    assert advise_payload["objective"] == "cost_optimization", advise_payload
    assert advise_payload["service"] == "all", advise_payload
    assert advise_payload["service_errors"] == [], advise_payload
    assert advise_payload["routing"]["objective"] == "cost_optimization", advise_payload
    assert advise_payload["routing"]["region"] == "us-east-1", advise_payload
    assert len(advise_payload["solution_cards"]) == 2, advise_payload
    assert len(advise_payload["grouped_solutions"]) == 2, advise_payload
    assert "s3-no-lifecycle" not in advise_payload["rules"], advise_payload
    assert advise_payload["mcp"]["read_only"] is True, advise_payload

    prompt_names = {prompt["name"] for prompt in responses[7]["result"]["prompts"]}
    assert "comprehensive_assessment" in prompt_names, prompt_names
    assert "remediation_plan" in prompt_names, prompt_names
    security_prompt = responses[8]["result"]["messages"][0]["content"]["text"]
    assert 'AWS profile "example-sso"' in security_prompt, security_prompt
    assert "read-only" in security_prompt, security_prompt

    print("MCP smoke test passed")
    return 0


def _run_mcp(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    wire = "\n".join(json.dumps(message) for message in messages) + "\n"
    proc = subprocess.run(
        [sys.executable, "-m", "bluearch_aws_steward.mcp"],
        input=wire,
        text=True,
        capture_output=True,
        cwd=Path.cwd(),
        timeout=10,
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr or proc.stdout)
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def _tool_payload(response: Dict[str, Any]) -> Dict[str, Any]:
    return json.loads(response["result"]["content"][0]["text"])


if __name__ == "__main__":
    raise SystemExit(main())
