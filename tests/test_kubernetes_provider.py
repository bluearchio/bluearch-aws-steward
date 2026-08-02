from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from bluearch_aws_steward.providers.kubernetes import (
    KubernetesProviderError,
    _kubeconfig_binding,
    _validate_kubeconfig_authentication,
)


class KubernetesConnectionBindingTests(unittest.TestCase):
    def test_context_endpoint_and_ca_match_the_selected_eks_cluster(self) -> None:
        ca = base64.b64encode(b"fixture-ca").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig.json"
            path.write_text(json.dumps(_kubeconfig(ca)), encoding="utf-8")
            yaml = SimpleNamespace(safe_load=json.loads)
            with patch(
                "bluearch_aws_steward.providers.kubernetes.import_module",
                return_value=yaml,
            ):
                binding = _kubeconfig_binding(
                    str(path),
                    "selected-context",
                    expected_cluster_name="selected-cluster",
                    expected_endpoint="https://selected.eks.example",
                    expected_certificate_authority_data=ca,
                )

        self.assertTrue(binding["context_cluster_match"])
        self.assertTrue(binding["endpoint_match"])
        self.assertTrue(binding["certificate_authority_match"])
        self.assertNotIn("fixture-ca", json.dumps(binding))

    def test_context_mismatch_is_rejected_before_kubernetes_reads(self) -> None:
        ca = base64.b64encode(b"fixture-ca").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig.json"
            path.write_text(json.dumps(_kubeconfig(ca)), encoding="utf-8")
            yaml = SimpleNamespace(safe_load=json.loads)
            with patch(
                "bluearch_aws_steward.providers.kubernetes.import_module",
                return_value=yaml,
            ):
                with self.assertRaisesRegex(
                    KubernetesProviderError,
                    "API endpoint differs from eks:DescribeCluster",
                ):
                    _kubeconfig_binding(
                        str(path),
                        "selected-context",
                        expected_cluster_name="another-cluster",
                        expected_endpoint="https://another.eks.example",
                        expected_certificate_authority_data=ca,
                    )

    def test_fixture_binding_requires_a_loopback_kubernetes_endpoint(self) -> None:
        ca = base64.b64encode(b"fixture-ca").decode("ascii")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig.json"
            path.write_text(json.dumps(_kubeconfig(ca)), encoding="utf-8")
            yaml = SimpleNamespace(safe_load=json.loads)
            with patch(
                "bluearch_aws_steward.providers.kubernetes.import_module",
                return_value=yaml,
            ):
                with self.assertRaisesRegex(KubernetesProviderError, "loopback"):
                    _kubeconfig_binding(
                        str(path),
                        "selected-context",
                        expected_cluster_name=None,
                        expected_endpoint=None,
                        expected_certificate_authority_data=None,
                        require_loopback_endpoint=True,
                    )

    def test_file_backed_certificate_authority_is_rejected(self) -> None:
        ca = base64.b64encode(b"fixture-ca").decode("ascii")
        document = _kubeconfig(ca)
        document["clusters"][0]["cluster"].pop("certificate-authority-data")
        document["clusters"][0]["cluster"]["certificate-authority"] = "/tmp/untrusted-ca"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            yaml = SimpleNamespace(safe_load=json.loads)
            with patch(
                "bluearch_aws_steward.providers.kubernetes.import_module",
                return_value=yaml,
            ):
                with self.assertRaisesRegex(KubernetesProviderError, "must be embedded"):
                    _kubeconfig_binding(
                        str(path),
                        "selected-context",
                        expected_cluster_name=None,
                        expected_endpoint=None,
                        expected_certificate_authority_data=None,
                    )

    def test_standard_aws_eks_get_token_authentication_is_allowed(self) -> None:
        document = _kubeconfig_with_user(
            {
                "exec": {
                    "command": "aws",
                    "args": [
                        "--region",
                        "us-east-1",
                        "eks",
                        "get-token",
                        "--cluster-name",
                        "selected-cluster",
                        "--output",
                        "json",
                    ],
                    "env": [{"name": "AWS_PROFILE", "value": "sandbox"}],
                }
            }
        )
        self._validate_authentication(document, expected_cluster_name="selected-cluster")

    def test_arbitrary_kubeconfig_exec_authentication_is_rejected(self) -> None:
        document = _kubeconfig_with_user({"exec": {"command": "sh", "args": ["-c", "echo unsafe"]}})
        with self.assertRaisesRegex(KubernetesProviderError, "aws eks get-token"):
            self._validate_authentication(document, expected_cluster_name="selected-cluster")

    def test_file_backed_kubeconfig_credentials_are_rejected(self) -> None:
        document = _kubeconfig_with_user({"tokenFile": "/tmp/untrusted-token"})
        with self.assertRaisesRegex(KubernetesProviderError, "must not load"):
            self._validate_authentication(document, expected_cluster_name=None)

    def test_static_credentials_cannot_accompany_eks_exec_authentication(self) -> None:
        document = _kubeconfig_with_user(
            {
                "token": "untrusted-static-token",
                "exec": {
                    "command": "aws",
                    "args": [
                        "eks",
                        "get-token",
                        "--cluster-name",
                        "selected-cluster",
                    ],
                },
            }
        )
        with self.assertRaisesRegex(KubernetesProviderError, "static kubeconfig credentials"):
            self._validate_authentication(document, expected_cluster_name="selected-cluster")

    def _validate_authentication(
        self, document: dict, *, expected_cluster_name: str | None
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "kubeconfig.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            yaml = SimpleNamespace(safe_load=json.loads)
            with patch(
                "bluearch_aws_steward.providers.kubernetes.import_module",
                return_value=yaml,
            ):
                _validate_kubeconfig_authentication(
                    str(path),
                    "selected-context",
                    expected_cluster_name=expected_cluster_name,
                )


def _kubeconfig(ca: str) -> dict:
    return {
        "contexts": [
            {
                "name": "selected-context",
                "context": {"cluster": "selected-kubeconfig-cluster"},
            }
        ],
        "clusters": [
            {
                "name": "selected-kubeconfig-cluster",
                "cluster": {
                    "server": "https://selected.eks.example",
                    "certificate-authority-data": ca,
                },
            }
        ],
    }


def _kubeconfig_with_user(user: dict) -> dict:
    document = _kubeconfig(base64.b64encode(b"fixture-ca").decode("ascii"))
    document["contexts"][0]["context"]["user"] = "selected-user"
    document["users"] = [{"name": "selected-user", "user": user}]
    return document


if __name__ == "__main__":
    unittest.main()
