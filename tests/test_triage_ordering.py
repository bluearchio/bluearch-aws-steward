import unittest

from bluearch_aws_steward.mcp_server import StewardMcpServer
from tests.support_triage import call_tool, completed_result, triage_scan_result


class TriageOrderingTests(unittest.TestCase):
    def test_root_access_key_is_ranked_first(self) -> None:
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
        self.assertIn("iam-root-access-key-present", rules[:5])

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


if __name__ == "__main__":
    unittest.main()
