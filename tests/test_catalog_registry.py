from __future__ import annotations

import unittest

from bluearch_aws_steward.catalog_registry import (
    catalog_coverage,
    load_catalog_rules,
    search_catalog_rules,
)


class CatalogRegistryTests(unittest.TestCase):
    def test_bundled_registry_contains_every_source_rule(self) -> None:
        rules = load_catalog_rules()

        self.assertEqual(len(rules), 650)
        self.assertEqual(len({rule["id"] for rule in rules}), 650)
        self.assertTrue(all(rule.get("evaluation") for rule in rules))

    def test_registry_exposes_honest_evaluation_modes(self) -> None:
        coverage = catalog_coverage()

        self.assertEqual(coverage["catalog_rule_count"], 650)
        self.assertEqual(coverage["automated_rule_count"], 121)
        self.assertEqual(coverage["unevaluated_rule_count"], 529)
        self.assertEqual(
            coverage["rules_by_evaluation_mode"],
            {
                "native": 121,
                "native_alias": 7,
                "manual_review": 117,
                "metadata_required": 191,
                "signal_required": 5,
                "specification_required": 209,
            },
        )

    def test_search_spans_non_executable_catalog_knowledge(self) -> None:
        results = search_catalog_rules(service="well-architected", query="COST01-BP02")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["evaluation"]["mode"], "manual_review")
        self.assertFalse(results[0]["evaluation"]["automated"])

    def test_automated_filter_returns_only_native_rules(self) -> None:
        rules = search_catalog_rules(automated_only=True)

        self.assertEqual(len(rules), 121)
        self.assertTrue(all(rule["evaluation"]["mode"] == "native" for rule in rules))
        self.assertTrue(
            all(rule["evaluation"].get("access_tier") in {"free", "premium"} for rule in rules)
        )

    def test_open_source_rule_baseline_contains_all_native_rules(self) -> None:
        rules = search_catalog_rules(automated_only=True)
        free_rules = [rule for rule in rules if rule["evaluation"].get("access_tier") == "free"]

        self.assertEqual(len(free_rules), 121)
        self.assertGreaterEqual(len(rules), len(free_rules))


if __name__ == "__main__":
    unittest.main()
