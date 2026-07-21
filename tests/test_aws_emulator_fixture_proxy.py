from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path
from types import ModuleType


def _load_fixture_proxy() -> ModuleType:
    path = Path(__file__).parent / "aws-emulator" / "scripts" / "fixture_proxy.py"
    if not path.is_file():
        raise unittest.SkipTest(
            "AWS emulator fixture scripts are not included in the source package"
        )
    spec = importlib.util.spec_from_file_location("bluearch_fixture_proxy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load fixture proxy from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE_PROXY = _load_fixture_proxy()


class FixtureProxyTests(unittest.TestCase):
    def test_response_header_allowlist_rejects_injected_or_unknown_headers(self) -> None:
        allowed_name = FIXTURE_PROXY._FORWARDED_RESPONSE_HEADERS.get("content-type")
        allowed_value = FIXTURE_PROXY._SAFE_RESPONSE_HEADER_VALUE.fullmatch("application/json")
        injected_value = FIXTURE_PROXY._SAFE_RESPONSE_HEADER_VALUE.fullmatch(
            "application/json\r\nX-Injected: true"
        )

        self.assertEqual(allowed_name, "Content-Type")
        self.assertIsNotNone(allowed_value)
        self.assertIsNone(injected_value)
        self.assertIsNone(FIXTURE_PROXY._FORWARDED_RESPONSE_HEADERS.get("x-untrusted"))

    def test_xml_parser_rejects_entity_expansion(self) -> None:
        payload = b'<!DOCTYPE root [<!ENTITY repeated "expanded">]><root>&repeated;</root>'

        self.assertIsNone(FIXTURE_PROXY._parse_xml(payload))

    def test_xml_parser_accepts_normal_fixture_payload(self) -> None:
        root = FIXTURE_PROXY._parse_xml(b"<root><value>safe</value></root>")

        self.assertIsNotNone(root)
        self.assertEqual(root.findtext("value"), "safe")

    def test_serves_live_recommendation_source_fixtures(self) -> None:
        security_hub = json.loads(
            FIXTURE_PROXY.fixture_signal_response("AWSSecurityHub_20180626.GetFindings")
        )
        compute_optimizer = json.loads(
            FIXTURE_PROXY.fixture_signal_response(
                "ComputeOptimizerService.GetEC2InstanceRecommendations"
            )
        )
        cost_hub = json.loads(
            FIXTURE_PROXY.fixture_signal_response("CostOptimizationHubService.ListRecommendations")
        )

        self.assertEqual(len(security_hub["Findings"]), 1)
        self.assertEqual(len(compute_optimizer["instanceRecommendations"]), 1)
        self.assertEqual(len(cost_hub["items"]), 1)
        self.assertEqual(
            compute_optimizer["instanceRecommendations"][0]["instanceArn"],
            cost_hub["items"][0]["resourceArn"],
        )

    def test_patches_old_lambda_date_for_rest_list_functions_path(self) -> None:
        payload = json.dumps(
            {
                "Functions": [
                    {
                        "FunctionName": "bluearch-steward-unused",
                        "LastModified": "2026-07-14T00:00:00Z",
                    },
                    {
                        "FunctionName": "bluearch-steward-active",
                        "LastModified": "2026-07-14T00:00:00Z",
                    },
                ]
            }
        ).encode()

        patched = FIXTURE_PROXY.patch_fixture_response(
            b"",
            "",
            payload,
            request_path="/2015-03-31/functions/?Marker=next",
        )
        functions = json.loads(patched)["Functions"]

        self.assertEqual(functions[0]["LastModified"], FIXTURE_PROXY.OLD_TIMESTAMP)
        self.assertEqual(functions[1]["LastModified"], "2026-07-14T00:00:00Z")

    def test_does_not_patch_unrelated_lambda_path(self) -> None:
        payload = json.dumps(
            {
                "Functions": [
                    {
                        "FunctionName": "bluearch-steward-unused",
                        "LastModified": "2026-07-14T00:00:00Z",
                    }
                ]
            }
        ).encode()

        patched = FIXTURE_PROXY.patch_fixture_response(
            b"",
            "",
            payload,
            request_path="/2015-03-31/functions/example",
        )

        self.assertEqual(patched, payload)


if __name__ == "__main__":
    unittest.main()
