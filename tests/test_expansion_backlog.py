from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any

BACKLOG_PATH = Path(__file__).resolve().parents[1] / "docs" / "expansion-backlog.json"


class ExpansionBacklogTests(unittest.TestCase):
    def test_backlog_is_machine_readable_and_has_required_fields(self) -> None:
        backlog = _load_backlog()

        self.assertEqual(backlog["schema_version"], "0.2")
        self.assertEqual(backlog["owner"], "bluearch-aws-steward")
        self.assertGreaterEqual(len(_items(backlog)), 20)

        allowed_statuses = set(backlog["status_values"])
        allowed_objectives = set(backlog["objective_values"])
        allowed_remediation_modes = set(backlog["remediation_modes"])
        allowed_localemu_modes = set(backlog["localemu_modes"])

        for item in _items(backlog):
            with self.subTest(short_id=item.get("short_id")):
                self.assert_non_empty_text(item, "short_id")
                self.assert_non_empty_text(item, "title")
                self.assert_non_empty_text(item, "service")
                self.assert_non_empty_text(item, "runtime_scope")
                self.assert_non_empty_text(item, "evidence_kind")
                self.assert_non_empty_text(item, "status")
                self.assertIn(item["status"], allowed_statuses)
                if item["status"] == "native":
                    self.assert_non_empty_text(item, "completed_in_version")
                    native_rule = item.get("native_rule")
                    self.assertIsInstance(native_rule, dict)
                    self.assert_non_empty_text(native_rule, "short_id")
                    self.assert_non_empty_text(native_rule, "source_id")
                    self.assert_non_empty_text(native_rule, "localemu_fixture")
                self.assert_required_list(item, "objectives")
                self.assertTrue(set(item["objectives"]) <= allowed_objectives)
                self.assert_required_list(item, "provider_capabilities")
                self.assert_required_list(item, "iac_targets")

                localemu = item.get("localemu")
                self.assertIsInstance(localemu, dict)
                self.assertIn(localemu.get("mode"), allowed_localemu_modes)
                self.assert_non_empty_text(localemu, "fixture")

                remediation = item.get("remediation")
                self.assertIsInstance(remediation, dict)
                self.assertIn(remediation.get("mode"), allowed_remediation_modes)
                self.assertIsInstance(remediation.get("guarded_apply_candidate"), bool)
                self.assert_non_empty_text(remediation, "summary")

    def test_backlog_short_ids_are_unique_and_waves_have_targets(self) -> None:
        backlog = _load_backlog()
        short_ids = [item["short_id"] for item in _items(backlog)]

        self.assertEqual(len(short_ids), len(set(short_ids)))
        for wave in backlog["waves"]:
            with self.subTest(wave=wave.get("id")):
                self.assert_non_empty_text(wave, "id")
                self.assert_non_empty_text(wave, "description")
                self.assertIsInstance(wave.get("selection_target"), int)
                self.assertGreater(wave["selection_target"], 0)
                self.assertGreaterEqual(len(wave.get("items") or []), 1)

    def assert_non_empty_text(self, value: dict[str, Any], key: str) -> None:
        self.assertIsInstance(value.get(key), str)
        self.assertTrue(value[key].strip(), f"{key} must not be blank")

    def assert_required_list(self, value: dict[str, Any], key: str) -> None:
        self.assertIsInstance(value.get(key), list)
        self.assertGreaterEqual(len(value[key]), 1, f"{key} must not be empty")


def _load_backlog() -> dict[str, Any]:
    return json.loads(BACKLOG_PATH.read_text(encoding="utf-8"))


def _items(backlog: dict[str, Any]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for wave in backlog["waves"]:
        items.extend(wave["items"])
    return items


if __name__ == "__main__":
    unittest.main()
