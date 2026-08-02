from __future__ import annotations

import re
import unittest
from pathlib import Path


class ReleaseWorkflowTests(unittest.TestCase):
    def setUp(self) -> None:
        root = Path(__file__).resolve().parents[1]
        workflows = root / ".github" / "workflows"
        self.readme = (root / "README.md").read_text(encoding="utf-8")
        self.package_readme = (root / "PYPI_README.md").read_text(encoding="utf-8")
        self.pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        self.public_installation = (root / "docs" / "public-installation.md").read_text(
            encoding="utf-8"
        )
        self.ci_workflow = (workflows / "ci.yml").read_text(encoding="utf-8")
        self.workflow = (workflows / "release.yml").read_text(encoding="utf-8")
        self.publish_workflow = (workflows / "publish-pypi.yml").read_text(encoding="utf-8")

    def test_public_docs_lead_with_complete_plain_pip_install(self) -> None:
        combined = self.readme + self.public_installation
        self.assertIn("python -m pip install --upgrade bluearch-aws-steward", combined)
        self.assertIn("EKS and Kubernetes support is included", combined)
        self.assertNotIn("bluearch-aws-steward[eks]", combined)
        self.assertNotIn("The package is not published yet", combined)

    def test_pypi_description_is_a_short_public_quickstart(self) -> None:
        self.assertIn('readme = "PYPI_README.md"', self.pyproject)
        self.assertLessEqual(len(self.package_readme.splitlines()), 160)
        self.assertIn("pip install --upgrade bluearch-aws-steward", self.package_readme)
        self.assertIn("bluearch-steward mcp install --client codex", self.package_readme)
        self.assertIn("EKS and Kubernetes support is included", self.package_readme)

    def test_ci_validates_plain_pip_install_on_every_supported_python(self) -> None:
        self.assertIn(
            'python-version: ["3.10", "3.11", "3.12", "3.13"]',
            self.ci_workflow,
        )
        self.assertIn("name: Plain pip install", self.ci_workflow)
        self.assertIn(
            "python -m pip install --disable-pip-version-check dist/*.whl", self.ci_workflow
        )
        self.assertIn('python -c "import kubernetes"', self.ci_workflow)
        self.assertIn("bluearch-steward mcp smoke", self.ci_workflow)
        self.assertRegex(
            self.ci_workflow,
            r"uses: actions/upload-artifact@[0-9a-f]{40}",
        )
        self.assertRegex(
            self.ci_workflow,
            r"uses: actions/download-artifact@[0-9a-f]{40}",
        )

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
        self.assertIn("test-files.pythonhosted.org", self.workflow)
        self.assertIn('"${WHEEL_REQUIREMENT}"', self.workflow)
        self.assertNotIn("unsafe-best-match", self.workflow)

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
