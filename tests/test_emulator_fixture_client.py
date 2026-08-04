from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from types import ModuleType


def _load_extended_fixtures() -> ModuleType:
    path = Path(__file__).parent / "aws-emulator" / "scripts" / "extended_fixtures.py"
    if not path.is_file():
        raise unittest.SkipTest(
            "AWS emulator fixture scripts are not included in the source package"
        )
    spec = importlib.util.spec_from_file_location("bluearch_extended_fixtures", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load extended fixtures from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXTENDED_FIXTURES = _load_extended_fixtures()


class FixtureClientTimeoutTests(unittest.TestCase):
    """LocalEmu implements ec2.run_instances by starting a nested container.

    On a cold CI runner that takes minutes. Botocore's default 60s read timeout
    turned it into a ReadTimeoutError that broke the LocalEmu gate on main, so
    the generous timeout below is load-bearing rather than decorative.
    """

    def test_fixture_clients_allow_minutes_for_a_single_call(self) -> None:
        config = EXTENDED_FIXTURES.fixture_client_config()
        self.assertGreaterEqual(config.read_timeout, 300)

    def test_fixture_clients_retry_adaptively(self) -> None:
        retries = EXTENDED_FIXTURES.fixture_client_config().retries
        self.assertEqual(retries["mode"], "adaptive")
        self.assertGreaterEqual(retries["max_attempts"], 3)

    def test_each_client_gets_its_own_config(self) -> None:
        first = EXTENDED_FIXTURES.fixture_client_config()
        second = EXTENDED_FIXTURES.fixture_client_config()
        self.assertIsNot(first, second)
        self.assertIsNot(first.retries, second.retries)

    def test_every_fixture_client_carries_the_config(self) -> None:
        fixtures = EXTENDED_FIXTURES.ExtendedFixtures(
            endpoint_url="http://localhost:4566",
            region="us-east-1",
            prefix="bluearch-steward",
        )
        client = fixtures.client("ec2")
        self.assertGreaterEqual(client.meta.config.read_timeout, 300)
        self.assertEqual(client.meta.config.retries["mode"], "adaptive")


if __name__ == "__main__":
    unittest.main()
