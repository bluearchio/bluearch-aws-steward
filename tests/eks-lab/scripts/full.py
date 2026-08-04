#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[3]
SCRIPT_DIR = Path(__file__).resolve().parent
USE_INSTALLED_PACKAGE = os.environ.get("BLUEARCH_STEWARD_USE_INSTALLED_PACKAGE") == "1"
if not USE_INSTALLED_PACKAGE and str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from phase import (  # noqa: E402
    EXPECTED_EVIDENCE,
    EXPECTED_RESOURCE,
    HEALTHY_MARKERS,
    PHASE_RULES,
    FixtureProxy,
    McpProcess,
    _query_all,
    _unsupported_claims,
    _wait_for_runtime_fixtures,
)
from remediation import (  # noqa: E402
    AMBIGUOUS_RULE,
    CONTROL_PLANE_RULE,
    FORMATS,
    WORKLOAD_RULE,
    _apply_disposable_kind_patch,
    _assess,
    _finding,
    _generate_and_validate,
)

JSON = Dict[str, Any]
EKS_RULES = tuple(rule for phase in ("1", "2", "3", "4") for rule in PHASE_RULES[phase])


def run(endpoint_url: str, region: str, artifact_dir: Path) -> JSON:
    _wait_for_runtime_fixtures()
    proxy = FixtureProxy(endpoint_url).start()
    mcp = McpProcess(proxy.endpoint_url, region)
    receipt: JSON = {"rules": {}, "formats": {}, "mcp_write_operations": 0}
    try:
        initialized = mcp.initialize()
        if initialized["serverInfo"]["name"] != "bluearch-aws-steward":
            raise AssertionError(initialized)

        assessment_id, findings = _assess(mcp, EKS_RULES)
        terminal_result = mcp.call(
            "bluearch_get_scan_results",
            {"assessment_id": assessment_id, "generate_pdf_report": False},
        )
        findings = _query_all(mcp, assessment_id)
        returned_rules = {str(item.get("rule") or "") for item in findings}
        if returned_rules != set(EKS_RULES):
            raise AssertionError(
                json.dumps(
                    {"expected": sorted(EKS_RULES), "returned": sorted(returned_rules)},
                    indent=2,
                )
            )
        for marker in sorted({value for values in HEALTHY_MARKERS.values() for value in values}):
            if any(marker in str(item.get("resource") or "") for item in findings):
                raise AssertionError(f"Healthy fixture unexpectedly matched: {marker}")

        for rule in EKS_RULES:
            selected = _finding(findings, rule, EXPECTED_RESOURCE[rule])
            dossier = mcp.call(
                "bluearch_investigate_resource",
                {"assessment_id": assessment_id, "finding_id": selected["opportunity_id"]},
            )
            evidence = selected.get("evidence") or {}
            rule_receipt = {
                "resource": selected.get("resource"),
                "expected_evidence_confirmed": EXPECTED_EVIDENCE[rule] in evidence,
                "investigation_completed": dossier.get("status") == "completed",
                "inside_cluster_evidence_collected": bool(
                    dossier.get("inside_cluster_evidence_collected")
                ),
                "unsupported_claims": _unsupported_claims(rule, dossier),
                "write_operations": int(evidence.get("kubernetes_write_operations") or 0),
            }
            if not all(
                rule_receipt[key] is True
                for key in (
                    "expected_evidence_confirmed",
                    "investigation_completed",
                    "inside_cluster_evidence_collected",
                )
            ):
                raise AssertionError(json.dumps({rule: rule_receipt}, indent=2, sort_keys=True))
            if rule_receipt["unsupported_claims"] or rule_receipt["write_operations"] != 0:
                raise AssertionError(json.dumps({rule: rule_receipt}, indent=2, sort_keys=True))
            receipt["rules"][rule] = rule_receipt

        control_plane = _finding(findings, CONTROL_PLANE_RULE, "bluearch-eks-vulnerable")
        workload = _finding(findings, WORKLOAD_RULE, "/deployment/missing-requests-api")
        ambiguous = _finding(findings, AMBIGUOUS_RULE, "/pod/crashloop-api-")
        generated_documents: dict[str, JSON] = {}
        for patch_format in FORMATS:
            selected = (
                control_plane
                if patch_format in {"terraform", "cloudformation", "eksctl"}
                else workload
            )
            validation = _generate_and_validate(
                mcp,
                assessment_id,
                selected,
                patch_format,
            )
            generated_documents[patch_format] = validation["generated"]
            receipt["formats"][patch_format] = {
                "generated": True,
                "validated": True,
                "validation_level": validation["validated"].get("validation_level"),
            }

        input_required = mcp.call(
            "bluearch_generate_iac_patch",
            {
                "assessment_id": assessment_id,
                "finding_id": ambiguous["opportunity_id"],
                "format": "kubernetes-yaml",
                "inputs": {},
            },
        )
        if input_required.get("status") != "input_required":
            raise AssertionError(json.dumps(input_required, indent=2, sort_keys=True))

        _apply_disposable_kind_patch(generated_documents["kubernetes-yaml"])
        verified_assessment_id, verified_findings = _assess(mcp, (WORKLOAD_RULE,))
        finding_removed = not any(
            item.get("rule") == WORKLOAD_RULE
            and "/deployment/missing-requests-api" in str(item.get("resource") or "")
            for item in verified_findings
        )
        if not finding_removed:
            raise AssertionError(json.dumps(verified_findings, indent=2, sort_keys=True))

        artifact_dir.mkdir(parents=True, exist_ok=True)
        report_path = artifact_dir / f"eks-product-pack-{assessment_id}.pdf"
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
        if not report_path.exists() or report_path.stat().st_size == 0:
            raise AssertionError(json.dumps(exported, indent=2, sort_keys=True))

        summary = (terminal_result.get("result") or {}).get("summary") or {}
        receipt.update(
            {
                "assessment_id": assessment_id,
                "verified_assessment_id": verified_assessment_id,
                "rules_evaluated": len(returned_rules),
                "findings_returned": len(findings),
                "resources_scanned": summary.get("resources_scanned"),
                "scan_errors": summary.get("scan_errors"),
                "finding_removed_after_lab_apply": finding_removed,
                "workload_ready": True,
                "ambiguous_patch_requires_input": True,
                "pdf_report": str(report_path),
                "pdf_bytes": report_path.stat().st_size,
                "mcp_source_files_modified": False,
                "mcp_cluster_writes": 0,
            }
        )
        return receipt
    finally:
        mcp.close()
        proxy.close()
        artifact_dir.mkdir(parents=True, exist_ok=True)
        (artifact_dir / "full-product-receipt.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint-url", default="http://localhost:4566")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--artifact-dir", default=str(ROOT / "tests/eks-lab/.artifacts"))
    args = parser.parse_args()
    receipt = run(args.endpoint_url, args.region, Path(args.artifact_dir))
    print(
        json.dumps(
            {
                "status": "passed",
                "rules": receipt["rules_evaluated"],
                "findings": receipt["findings_returned"],
                "pdf_report": receipt["pdf_report"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
