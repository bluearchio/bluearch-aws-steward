"""Every MCP tool must declare its mutation contract via annotations.

Fail-closed MCP classifiers (cloudarch-eval among them) treat a tool
without annotations as a write; Steward's read-only tools were being
classified as writes for exactly that reason. The product declares the
truth its behavior already demonstrates: everything is read-only except
the guarded apply.
"""

from __future__ import annotations

import unittest

from bluearch_aws_steward.mcp_server import _tools


class ToolAnnotationTests(unittest.TestCase):
    def test_every_tool_declares_mutation_annotations(self) -> None:
        tools = _tools()
        self.assertGreaterEqual(len(tools), 25)
        for tool in tools:
            annotations = tool.get("annotations")
            self.assertIsInstance(annotations, dict, f"{tool['name']} has no annotations")
            if tool["name"] == "bluearch_apply_remediation":
                self.assertEqual(
                    annotations,
                    {"readOnlyHint": False, "destructiveHint": True},
                )
            else:
                self.assertEqual(
                    annotations,
                    {"readOnlyHint": True},
                    f"{tool['name']} must declare readOnlyHint true",
                )


if __name__ == "__main__":
    unittest.main()
