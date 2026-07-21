from __future__ import annotations

import re
import unittest
from pathlib import Path


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.workflow = (
            Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")

    def test_publication_is_tag_only(self) -> None:
        self.assertIn('      - "v*"', self.workflow)
        self.assertNotIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("pull_request:", self.workflow)
        self.assertIn("preview workflow refuses stable versions", self.workflow)
        self.assertIn('git merge-base --is-ancestor "${GITHUB_SHA}" origin/main', self.workflow)

    def test_publish_jobs_use_oidc_without_repository_tokens(self) -> None:
        self.assertEqual(self.workflow.count("id-token: write"), 2)
        self.assertNotIn("PYPI_API_TOKEN", self.workflow)
        self.assertNotIn("TWINE_PASSWORD", self.workflow)
        self.assertIn("environment:\n      name: testpypi", self.workflow)
        self.assertIn("environment:\n      name: pypi", self.workflow)

    def test_release_actions_are_immutable(self) -> None:
        actions = (
            "actions/upload-artifact",
            "actions/download-artifact",
            "pypa/gh-action-pypi-publish",
        )
        for action in actions:
            pattern = rf"uses: {re.escape(action)}@[0-9a-f]{{40}}"
            self.assertRegex(self.workflow, pattern)


if __name__ == "__main__":
    unittest.main()
