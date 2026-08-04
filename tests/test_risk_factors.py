import unittest

from bluearch_aws_steward.risk_factors import risk_factors


class RiskFactorTests(unittest.TestCase):
    def test_root_credential_scores_highest(self) -> None:
        result = risk_factors({"rule": "iam-root-access-key-present"})
        self.assertEqual(result["total"], 40.0)
        self.assertEqual([factor["id"] for factor in result["factors"]], ["root_credential"])
        self.assertTrue(result["factors"][0]["rationale"])

    def test_publicly_readable_resource(self) -> None:
        result = risk_factors({"rule": "s3-public-bucket"})
        self.assertEqual(result["total"], 30.0)
        self.assertEqual([factor["id"] for factor in result["factors"]], ["publicly_readable"])

    def test_internet_exposed_port(self) -> None:
        result = risk_factors({"rule": "ec2-security-group-ssh-open"})
        self.assertEqual(result["total"], 25.0)

    def test_administrative_privilege(self) -> None:
        result = risk_factors({"rule": "iam-policy-full-admin"})
        self.assertEqual(result["total"], 20.0)

    def test_aged_credential(self) -> None:
        result = risk_factors({"rule": "iam-access-key-older-than-90-days"})
        self.assertEqual(result["total"], 10.0)

    def test_unremarkable_finding_scores_zero(self) -> None:
        result = risk_factors({"rule": "s3-no-lifecycle"})
        self.assertEqual(result["total"], 0.0)
        self.assertEqual(result["factors"], [])

    def test_missing_rule_is_not_an_error(self) -> None:
        self.assertEqual(risk_factors({})["total"], 0.0)

    def test_malformed_input_is_not_an_error(self) -> None:
        self.assertEqual(risk_factors({"rule": None})["total"], 0.0)
        self.assertEqual(risk_factors({"rule": 12345})["total"], 0.0)

    def test_factors_are_sorted_by_points_descending(self) -> None:
        result = risk_factors({"rule": "iam-root-access-key-present"})
        points = [factor["points"] for factor in result["factors"]]
        self.assertEqual(points, sorted(points, reverse=True))


if __name__ == "__main__":
    unittest.main()
