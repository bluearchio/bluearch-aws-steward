from __future__ import annotations

import unittest

from bluearch_aws_steward.contextual_review import prepare_contextual_review
from bluearch_aws_steward.knowledge_packs import validate_knowledge_packs

# One natural-language prompt per runtime scope. Each names its resource the way a
# person would in chat, without an ARN or a scheme URI, because those two forms
# already worked and are covered separately below.
NATURAL_PROMPTS = {
    "s3": "Review the S3 bucket named reports-archive.",
    "lambda": "Review the lambda function named checkout-handler.",
    "rds": "Review the RDS database named orders-primary.",
    "eks": "Review the EKS cluster named prod-east.",
    "dynamodb": "Review the DynamoDB table named sessions.",
    "sqs": "Review the SQS queue named ingest.",
    "sns": "Review the SNS topic named alerts.",
    "ec2": "Review the EC2 instance i-0abc123def456789a.",
    "efs": "Review the EFS file system fs-0123456789abcdef.",
    "kms": "Review the KMS key alias/app-data.",
    "ecs": "Review the ECS service named checkout-api.",
    "alb": "Review the ALB load balancer named public-edge.",
    "api-gateway": "Review the API Gateway rest api named orders.",
    "cloudtrail": "Review the CloudTrail trail named org-trail.",
    "cloudwatch": "Review the CloudWatch log group named app-events.",
    "iam": "Review the IAM role named deploy-role.",
    "secrets-manager": "Review the Secrets Manager secret named prod-db.",
}


def _reason(prompt: str) -> str:
    """Return the refinement reason, or 'resolved' when focus was accepted.

    Two refusals mean different things and must not be conflated:
    `architectural_review_focus_required` means the resource was not identified,
    while `architectural_review_context_required` means it WAS identified and the
    bounded context questions are being asked.
    """
    prepared, refinement = prepare_contextual_review(
        {"prompt": prompt, "assessment_mode": "architectural_review"}
    )
    if refinement:
        return str(refinement.get("reason"))
    return "resolved"


class PromptFocusTests(unittest.TestCase):
    def test_every_runtime_scope_is_reachable_from_natural_language(self) -> None:
        scopes = set(validate_knowledge_packs()["runtime_scopes"])
        self.assertEqual(
            set(NATURAL_PROMPTS),
            scopes,
            "every runtime scope needs a natural-language prompt case",
        )
        unresolved = [
            scope
            for scope, prompt in NATURAL_PROMPTS.items()
            if _reason(prompt) == "architectural_review_focus_required"
        ]
        self.assertEqual(unresolved, [], f"scopes not reachable from a prompt: {unresolved}")

    def test_arn_identifies_the_resource(self) -> None:
        self.assertNotEqual(
            _reason("Review arn:aws:s3:::reports-archive for compliance."),
            "architectural_review_focus_required",
        )

    def test_scheme_uri_identifies_the_resource(self) -> None:
        self.assertNotEqual(
            _reason("Review s3://reports-archive before I change it."),
            "architectural_review_focus_required",
        )

    def test_a_vague_prompt_is_refused_rather_than_guessed(self) -> None:
        self.assertEqual(_reason("Review my architecture."), "architectural_review_focus_required")

    def test_an_ambiguous_prompt_is_refused_rather_than_guessed(self) -> None:
        # Names two services at once: a CloudWatch log group whose name contains
        # "lambda". Guessing either one would be worse than asking.
        self.assertEqual(
            _reason("Review the CloudWatch log group /aws/lambda/api."),
            "architectural_review_focus_required",
        )


if __name__ == "__main__":
    unittest.main()
