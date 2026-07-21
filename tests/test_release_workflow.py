from __future__ import annotations

import re
import unittest
from pathlib import Path


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
        self.workflow = (workflows / "release.yml").read_text(encoding="utf-8")
        self.publish_workflow = (workflows / "publish-pypi.yml").read_text(encoding="utf-8")

    def test_publication_is_tag_only(self) -> None:
        self.assertIn('      - "v*"', self.workflow)
        self.assertNotIn("workflow_dispatch:", self.workflow)
        self.assertNotIn("pull_request:", self.workflow)
        self.assertIn("preview workflow refuses stable versions", self.workflow)
        self.assertIn(
            'gh api "repos/${GITHUB_REPOSITORY}/compare/${tagged_sha}...main"',
            self.workflow,
        )
        self.assertIn("--draft", self.workflow)
        self.assertNotIn("https://upload.pypi.org/legacy/", self.workflow)

    def test_pypi_publication_requires_a_published_prerelease(self) -> None:
        self.assertIn("types: [published]", self.publish_workflow)
        self.assertIn("github.event.release.prerelease == true", self.publish_workflow)
        self.assertIn("PyPI preview workflow refuses stable versions", self.publish_workflow)
        self.assertIn("sha256sum --check", self.publish_workflow)

    def test_publish_jobs_use_oidc_without_repository_tokens(self) -> None:
        combined = self.workflow + self.publish_workflow
        self.assertEqual(combined.count("id-token: write"), 2)
        self.assertEqual(combined.count("compare/${tagged_sha}...main"), 2)
        self.assertNotIn("git fetch", combined)
        self.assertNotIn("PYPI_API_TOKEN", combined)
        self.assertNotIn("TWINE_PASSWORD", combined)

    def test_release_actions_are_immutable(self) -> None:
        actions = (
            "actions/upload-artifact",
            "actions/download-artifact",
            "pypa/gh-action-pypi-publish",
        )
        combined = self.workflow + self.publish_workflow
        for action in actions:
            pattern = rf"uses: {re.escape(action)}@[0-9a-f]{{40}}"
            self.assertRegex(combined, pattern)


if __name__ == "__main__":
    unittest.main()
