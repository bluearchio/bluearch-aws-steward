from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from bluearch_aws_steward.mcp_server import _tool_verify_remediation
from bluearch_aws_steward.recommendation_queue import (
    annotate_validation,
    consolidate_scan_results,
    recommendation_fingerprint,
)


def _finding(
    source: str,
    *,
    rule: str = "s3-versioning-disabled",
    resource: str = "s3://demo",
    account: str = "123456789012",
    region: str = "us-east-1",
) -> dict:
    return {
        "finding_id": f"{source}:{rule}:{resource}:{account}:{region}",
        "rule_id": rule,
        "rule_short_id": rule,
        "service": "s3",
        "resource": resource,
        "resource_ref": {
            "provider": "aws",
            "service": "s3",
            "resource_type": "aws.s3.bucket",
            "resource_id": resource,
            "account_id": account,
            "region": region,
        },
        "severity": "medium",
        "risk_detail": "operations",
        "scenario": "Versioning is disabled.",
        "evidence": {
            "finding_source": source,
            "observed_at": "2026-07-16T12:00:00Z",
            "mapping_status": "native" if source == "bluearch-steward" else "mapped",
        },
        "remediation": {
            "summary": "Enable versioning.",
            "safety_level": "low_risk",
            "requires_approval": True,
            "actions": ["Enable versioning."],
        },
    }


def _snapshot(source: str, findings: list[dict]) -> dict:
    return {
        "schema_version": "0.2",
        "generated_at": "2026-07-16T12:00:00Z",
        "provider": "aws-sdk",
        "region": "us-east-1",
        "findings": findings,
        "summary": {"finding_source": source, "scan_errors": 0},
    }


class RecommendationQueueTests(unittest.TestCase):
    def test_verify_accepts_unified_fingerprint_and_legacy_finding_id(self) -> None:
        finding = _finding("bluearch-steward")
        snapshot = _snapshot("bluearch-steward", [finding])
        fingerprint = recommendation_fingerprint(finding, snapshot)

        with patch(
            "bluearch_aws_steward.mcp_server._run_scan_payload",
            return_value=snapshot,
        ):
            result = _tool_verify_remediation(
                {"service": "s3", "finding_ids": [fingerprint, finding["finding_id"]]}
            )

        self.assertFalse(result["verified"])
        self.assertEqual(
            result["remaining_requested_finding_ids"],
            sorted([fingerprint, finding["finding_id"]]),
        )

    def test_same_problem_is_deduplicated_and_preserves_all_provenance(self) -> None:
        native = _finding("bluearch-steward")
        native_snapshot = _snapshot("bluearch-steward", [native])
        native_snapshot["summary"]["service_summaries"] = {
            "s3": {"resources_scanned": 1, "findings": 1}
        }
        security_hub = annotate_validation(
            _finding("security-hub"),
            "confirmed",
            observed_at="2026-07-16T12:00:00Z",
        )

        result = consolidate_scan_results(
            [
                native_snapshot,
                _snapshot("security-hub", [security_hub]),
            ]
        )

        self.assertEqual(result["summary"]["signals_received"], 2)
        self.assertEqual(result["summary"]["deduplicated_signals"], 1)
        self.assertEqual(len(result["findings"]), 1)
        finding = result["findings"][0]
        self.assertEqual(finding["sources"], ["bluearch-steward", "security-hub"])
        self.assertEqual(finding["validation"]["status"], "confirmed")
        self.assertEqual(len(finding["evidence"]["provenance"]), 2)
        self.assertGreater(finding["priority"]["score"], 0)
        self.assertEqual(result["summary"]["service_summaries"]["s3"]["resources_scanned"], 1)

    def test_rule_account_and_region_are_identity_boundaries(self) -> None:
        findings = [
            _finding("bluearch-steward"),
            _finding("security-hub", rule="s3-no-lifecycle"),
            _finding("prowler-json", account="999999999999"),
            _finding("prowler-json", region="us-west-2"),
        ]

        result = consolidate_scan_results([_snapshot("mixed", findings)])

        self.assertEqual(len(result["findings"]), 4)
        self.assertEqual(
            len({item["recommendation_fingerprint"] for item in result["findings"]}), 4
        )

    def test_resolved_only_signal_does_not_enter_active_queue(self) -> None:
        stale = annotate_validation(
            _finding("prowler-json"),
            "resolved_or_stale",
            reason="Native detector did not reproduce it.",
        )

        result = consolidate_scan_results([_snapshot("prowler-json", [stale])])

        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["resolved_or_stale_recommendations"], 1)

    def test_fingerprint_is_stable_across_source_ids_and_timestamps(self) -> None:
        left = _finding("security-hub")
        right = _finding("prowler-json")
        right["evidence"]["observed_at"] = "2025-01-01T00:00:00Z"

        self.assertEqual(recommendation_fingerprint(left), recommendation_fingerprint(right))

    def test_five_thousand_signals_consolidate_without_quadratic_behavior(self) -> None:
        findings = [
            _finding("prowler-json", resource=f"s3://bucket-{index}") for index in range(5000)
        ]
        started = time.monotonic()

        result = consolidate_scan_results([_snapshot("prowler-json", findings)])

        self.assertEqual(len(result["findings"]), 5000)
        self.assertLess(time.monotonic() - started, 5.0)


if __name__ == "__main__":
    unittest.main()
