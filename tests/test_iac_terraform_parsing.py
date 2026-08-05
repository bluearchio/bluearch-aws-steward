from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from bluearch_aws_steward.iac_context import parse_iac_context

# Written the way a person writes Terraform: quoted labels, quoted string
# values, a nested block, and a policy built with jsonencode.
TERRAFORM = """
resource "aws_s3_bucket" "reports" {
  bucket = "reports-archive"
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration {
    status = "Suspended"
  }
}

resource "aws_iam_policy" "application" {
  name   = "contextual-application"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}
"""


class TerraformParsingTests(unittest.TestCase):
    """Pin the shape the IaC rules read, because breaking it is silent.

    python-hcl2 8 is the concrete threat and the reason pyproject.toml pins
    `<8`. It keeps quotes on string literals, so a resource type arrives as
    '"aws_s3_bucket"' and matches nothing — a valid workspace reviews as empty.
    Its strip_string_quotes option is not the fix: it also strips quotes inside
    interpolation expressions, which is why the wildcard test below exists.
    """

    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp())
        (self.root / "main.tf").write_text(TERRAFORM)
        self.context = parse_iac_context(
            {
                "workspace_root": str(self.root),
                "paths": ["main.tf"],
                "format": "terraform",
            }
        )
        self.by_address = {str(r["address"]): r for r in self.context["resources"]}

    def test_every_resource_is_recognised(self) -> None:
        self.assertEqual(
            self.context["resource_count"],
            3,
            f"expected all three resources to parse, warnings: {self.context['warnings']}",
        )

    def test_no_resource_is_dismissed_as_an_unsupported_type(self) -> None:
        unsupported = [
            w for w in self.context["warnings"] if w.get("reason") == "unsupported_resource_type"
        ]
        self.assertEqual(unsupported, [])

    def test_resource_addresses_carry_no_literal_quotes(self) -> None:
        for address in self.by_address:
            self.assertNotIn('"', address)

    def test_string_attributes_are_unquoted_scalars(self) -> None:
        bucket = self.by_address["aws_s3_bucket.reports"]
        self.assertEqual(bucket["facts"]["bucket"], "reports-archive")

    def test_nested_block_values_reach_the_rules(self) -> None:
        versioning = self.by_address["aws_s3_bucket_versioning.reports"]
        self.assertIn("Suspended", str(versioning["facts"]))

    def test_quotes_survive_inside_an_interpolation_expression(self) -> None:
        # An admin wildcard is detected by matching Action = "*" inside the
        # jsonencode expression. A parser that strips quotes in there yields
        # Action = *, the rule stops firing, and a policy granting everything
        # reports as clean. Loud breakage is acceptable here; this is not.
        policy = str(self.by_address["aws_iam_policy.application"]["facts"]["policy"])
        self.assertIn('"Action": "*"', policy)


if __name__ == "__main__":
    unittest.main()
