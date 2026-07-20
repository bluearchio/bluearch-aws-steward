from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

from bluearch_aws_steward.mcp_server import StewardMcpServer

JSON = Dict[str, Any]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply approved temporary S3 fixture findings through Steward's guarded MCP workflow."
    )
    parser.add_argument("--scan-file", required=True)
    parser.add_argument("--profile")
    parser.add_argument("--region", required=True)
    parser.add_argument("--endpoint-url")
    parser.add_argument("--bucket-prefix", required=True)
    parser.add_argument("--output-file", required=True)
    args = parser.parse_args()

    scan = json.loads(Path(args.scan_file).read_text(encoding="utf-8"))
    findings = scan.get("findings") or []
    if not isinstance(findings, list):
        raise ValueError("scan file findings must be an array")

    server = StewardMcpServer()
    results = []
    for finding in findings:
        if not isinstance(finding, dict) or finding.get("service") != "s3":
            raise ValueError("live fixture harness accepts only S3 findings")
        resource = str(finding.get("resource") or "")
        if not resource.startswith(f"s3://{args.bucket_prefix}"):
            raise ValueError(f"refusing finding outside fixture prefix: {resource}")

        plan_arguments: JSON = {
            "finding": finding,
            "provider": scan.get("provider") or "aws-sdk",
            "region": args.region,
        }
        if args.profile:
            plan_arguments["profile"] = args.profile
        if args.endpoint_url:
            plan_arguments["endpoint_url"] = args.endpoint_url
        if finding.get("rule_short_id") == "s3-no-lifecycle":
            plan_arguments.update(
                {
                    "s3_lifecycle_transition_days": 30,
                    "s3_lifecycle_storage_class": "STANDARD_IA",
                }
            )

        plan = _call(server, "bluearch_plan_remediation", plan_arguments)
        if plan.get("status") == "no_change_required":
            results.append(
                {
                    "finding_id": finding.get("finding_id"),
                    "resource": resource,
                    "status": "no_change_required",
                    "verified": True,
                }
            )
            continue
        if plan.get("status") != "awaiting_approval":
            raise RuntimeError(f"could not create fixture plan for {resource}: {plan}")

        applied = _call(
            server,
            "bluearch_apply_remediation",
            {
                "plan_id": plan["plan_id"],
                "plan_digest": plan["plan_digest"],
                "allow_write": True,
            },
        )
        results.append(
            {
                "finding_id": finding.get("finding_id"),
                "resource": resource,
                "rule": finding.get("rule_short_id"),
                **applied,
            }
        )

    payload = {
        "remediated": results,
        "verified": all(bool(result.get("verified")) for result in results),
        "guard": "mcp_plan_digest_preconditions",
    }
    Path(args.output_file).write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["verified"] else 1


def _call(server: StewardMcpServer, tool: str, arguments: JSON) -> JSON:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
    )
    if response is None:
        raise RuntimeError(f"{tool} returned no response")
    result = response.get("result") or {}
    if result.get("isError"):
        content = result.get("content") or []
        message = (
            content[0].get("text") if content and isinstance(content[0], dict) else str(result)
        )
        raise RuntimeError(f"{tool} failed: {message}")
    structured = result.get("structuredContent")
    if not isinstance(structured, dict):
        raise RuntimeError(f"{tool} returned invalid structured content")
    return structured


if __name__ == "__main__":
    raise SystemExit(main())
