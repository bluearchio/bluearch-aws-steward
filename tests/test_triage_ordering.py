import unittest

from bluearch_aws_steward.mcp_server import StewardMcpServer
from tests.support_triage import call_tool, completed_result, triage_scan_result


class TriageOrderingTests(unittest.TestCase):
    def test_root_access_key_outranks_higher_severity_findings(self) -> None:
        server = StewardMcpServer()
        submitted = call_tool(
            server,
            1,
            "bluearch_assess",
            {
                "prompt": "Assess this account.",
                "scan_result": triage_scan_result(),
                "objectives": ["all"],
                "services": ["iam"],
            },
        )
        result = completed_result(server, submitted["assessment_id"])
        rules = [item["rule"] for item in result["opportunities"]]
        self.assertGreater(len(rules), 5)
        self.assertIn("iam-root-access-key-present", rules[:5])
        root_rank = rules.index("iam-root-access-key-present")
        # Under the old severity-then-alphabetical fallback, all six "high"
        # findings below sort ahead of the "medium" root access key, pushing
        # it to 7th place. The contextual risk score must reverse that: the
        # root key has to rank strictly above every one of them.
        for high_severity_rule in (
            "api-gateway-access-logging-disabled",
            "api-gateway-execution-logging-disabled",
            "api-gateway-method-authorization-missing",
            "ecs-unsafe-task-definition",
            "iam-access-key-older-than-90-days",
            "kms-key-rotation-disabled",
        ):
            self.assertLess(root_rank, rules.index(high_severity_rule))

    def test_every_opportunity_is_scored(self) -> None:
        server = StewardMcpServer()
        submitted = call_tool(
            server,
            10,
            "bluearch_assess",
            {
                "prompt": "Assess this account.",
                "scan_result": triage_scan_result(),
                "objectives": ["all"],
                "services": ["iam"],
            },
        )
        result = completed_result(server, submitted["assessment_id"])
        for item in result["opportunities"]:
            self.assertIsInstance(item["priority"]["score"], (int, float))


class GroupPriorityTests(unittest.TestCase):
    def test_group_priority_is_the_maximum_not_the_sum(self) -> None:
        from bluearch_aws_steward.mcp_server import _group_solution_cards

        groups = _group_solution_cards(
            [
                {
                    "objective": "all",
                    "rule": "s3-no-lifecycle",
                    "severity": "low",
                    "resource": f"s3://bucket-{index}",
                    "priority": {"score": 12.0},
                }
                for index in range(50)
            ]
        )
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["priority_score"], 12.0)

    def test_single_dangerous_finding_outranks_a_large_low_risk_group(self) -> None:
        from bluearch_aws_steward.mcp_server import _group_solution_cards

        cards = [
            {
                "objective": "all",
                "rule": "s3-no-lifecycle",
                "severity": "low",
                "resource": f"s3://bucket-{index}",
                "priority": {"score": 12.0},
            }
            for index in range(50)
        ]
        cards.append(
            {
                "objective": "all",
                "rule": "iam-root-access-key-present",
                "severity": "medium",
                "resource": "iam://account/root",
                "priority": {"score": 80.0},
            }
        )
        groups = _group_solution_cards(cards)
        ranked = sorted(groups, key=lambda group: -group["priority_score"])
        self.assertEqual(ranked[0]["rule"], "iam-root-access-key-present")

    def test_missing_priority_defaults_to_zero(self) -> None:
        from bluearch_aws_steward.mcp_server import _group_solution_cards

        groups = _group_solution_cards(
            [{"objective": "all", "rule": "s3-no-lifecycle", "resource": "s3://b"}]
        )
        self.assertEqual(groups[0]["priority_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
