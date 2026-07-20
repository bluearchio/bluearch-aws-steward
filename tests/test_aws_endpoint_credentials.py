from __future__ import annotations

import unittest
from unittest.mock import patch

from bluearch_aws_steward.aws_cli import AwsCli, AwsCliConfig
from bluearch_aws_steward.aws_endpoints import (
    is_loopback_aws_endpoint,
    validate_explicit_aws_endpoint,
)
from bluearch_aws_steward.providers.aws_sdk import AwsSdkProvider, AwsSdkProviderConfig


class FakeBoto3:
    def __init__(self) -> None:
        self.session_options: dict[str, object] = {}

    def Session(self, **options: object) -> object:  # noqa: N802 - mirrors boto3 API
        self.session_options = options
        return object()


class AwsEndpointCredentialTests(unittest.TestCase):
    def test_recognizes_only_static_loopback_endpoint_hosts(self) -> None:
        self.assertTrue(is_loopback_aws_endpoint("http://localhost:4566"))
        self.assertTrue(is_loopback_aws_endpoint("http://127.0.0.1:4566"))
        self.assertTrue(is_loopback_aws_endpoint("http://[::1]:4566"))
        self.assertTrue(is_loopback_aws_endpoint("http://localhost.localstack.cloud:4566"))
        self.assertFalse(is_loopback_aws_endpoint("https://example.com"))
        self.assertFalse(is_loopback_aws_endpoint(None))

    def test_cli_uses_dummy_credentials_for_loopback_endpoint_without_profile(self) -> None:
        cli = AwsCli(AwsCliConfig(endpoint_url="http://localhost:4566"))

        with patch.dict(
            "os.environ",
            {
                "AWS_ACCESS_KEY_ID": "ambient-access-key",
                "AWS_SECRET_ACCESS_KEY": "ambient-secret-key",  # pragma: allowlist secret
                "AWS_SESSION_TOKEN": "ambient-session-token",  # pragma: allowlist secret
            },
            clear=True,
        ):
            environment = cli._environment()

        self.assertEqual(environment["AWS_ACCESS_KEY_ID"], "test")
        self.assertEqual(environment["AWS_SECRET_ACCESS_KEY"], "test")
        self.assertEqual(environment["AWS_SESSION_TOKEN"], "test")

    def test_rejects_remote_endpoint_before_creating_a_provider(self) -> None:
        with self.assertRaisesRegex(ValueError, "restricted to loopback emulators"):
            AwsCli(AwsCliConfig(endpoint_url="https://example.com"))
        with self.assertRaisesRegex(ValueError, "restricted to loopback emulators"):
            validate_explicit_aws_endpoint("http://169.254.169.254/latest/meta-data")

    def test_rejects_non_http_and_credentialed_loopback_endpoints(self) -> None:
        with self.assertRaisesRegex(ValueError, r"HTTP\(S\) loopback URL"):
            validate_explicit_aws_endpoint("file://localhost/tmp/aws")
        credentialed_endpoint = (
            "http://" + "fixture-user" + ":" + "fixture-value" + "@localhost:4566"
        )
        with self.assertRaisesRegex(ValueError, "cannot contain credentials"):
            validate_explicit_aws_endpoint(credentialed_endpoint)

    def test_sdk_uses_dummy_credentials_for_loopback_endpoint_without_profile(self) -> None:
        boto3 = FakeBoto3()

        with patch("bluearch_aws_steward.providers.aws_sdk.import_module", return_value=boto3):
            AwsSdkProvider(AwsSdkProviderConfig(endpoint_url="http://localhost:4566"))

        self.assertEqual(boto3.session_options["aws_access_key_id"], "test")
        self.assertEqual(boto3.session_options["aws_secret_access_key"], "test")
        self.assertEqual(boto3.session_options["aws_session_token"], "test")

    def test_sdk_keeps_explicit_profile_for_loopback_endpoint(self) -> None:
        boto3 = FakeBoto3()

        with patch("bluearch_aws_steward.providers.aws_sdk.import_module", return_value=boto3):
            AwsSdkProvider(
                AwsSdkProviderConfig(
                    profile="fixture-profile",
                    endpoint_url="http://localhost:4566",
                )
            )

        self.assertEqual(boto3.session_options["profile_name"], "fixture-profile")
        self.assertNotIn("aws_access_key_id", boto3.session_options)

    def test_sdk_rejects_remote_endpoint_before_loading_boto3(self) -> None:
        with self.assertRaisesRegex(ValueError, "restricted to loopback emulators"):
            AwsSdkProvider(AwsSdkProviderConfig(endpoint_url="https://example.com"))


if __name__ == "__main__":
    unittest.main()
