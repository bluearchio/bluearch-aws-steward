from __future__ import annotations

import unittest

from bluearch_aws_steward.mcp_server import (
    _explicit_objective_from_prompt,
    _infer_prompt_fields,
)


class ObjectiveInferenceTests(unittest.TestCase):
    """A prompt that names several pillars must not be narrowed to one.

    The token cascade returned the first objective it matched, and "cost" was
    checked first. A live account-wide request naming all five pillars was
    assessed against 32 cost rules only, returning 79 findings where a full
    assessment of the same account returns 1428.
    """

    def test_a_prompt_naming_several_pillars_assesses_all_of_them(self) -> None:
        prompt = (
            "Review our whole AWS account against the Well-Architected Framework. "
            "I want to know what is most dangerous first, across security, cost, "
            "reliability, performance and operations."
        )
        self.assertEqual(_explicit_objective_from_prompt(prompt), "all")

    def test_that_prompt_does_not_narrow_to_a_cost_rule_filter(self) -> None:
        # The observable symptom: a 32-rule cost filter on a five-pillar request.
        prompt = (
            "Review our whole AWS account against the Well-Architected Framework "
            "across security, cost, reliability, performance and operations."
        )
        self.assertIsNone(_infer_prompt_fields(prompt)["rule_filter"])

    def test_two_pillars_are_not_reduced_to_the_first(self) -> None:
        self.assertEqual(
            _explicit_objective_from_prompt("Check cost and security in this account."), "all"
        )

    def test_an_explicit_breadth_request_wins_over_an_incidental_pillar_word(self) -> None:
        # "well-architected" was already a breadth signal, but sat below "cost"
        # in the cascade and so was never reached.
        self.assertEqual(
            _explicit_objective_from_prompt("Run a Well-Architected review of our spend posture."),
            "all",
        )

    def test_a_single_pillar_still_resolves_to_that_pillar(self) -> None:
        for prompt, expected in (
            ("Where can we cut cost?", "cost_optimization"),
            ("Find public buckets and exposure.", "security"),
            ("Do we have backups we can restore from?", "reliability"),
            ("Review our operational readiness.", "operations"),
        ):
            with self.subTest(prompt=prompt):
                self.assertEqual(_explicit_objective_from_prompt(prompt), expected)

    def test_a_prompt_naming_no_objective_stays_unresolved(self) -> None:
        self.assertIsNone(_explicit_objective_from_prompt("Look at the bucket named reports."))


if __name__ == "__main__":
    unittest.main()
