# Contextual Architecture Reviews

`architectural_review` is Steward's default decision-support workflow. It
reviews one existing AWS resource or proposed Terraform/CloudFormation change,
selects only relevant Well-Architected knowledge, and reads a bounded dependency
neighborhood. It does not perform an account scan unless the user explicitly
chooses one.

## Request Contract

```json
{
  "prompt": "Review the S3 bucket I am deploying.",
  "assessment_mode": "architectural_review",
  "review_context": {
    "operation": "create",
    "resource_refs": [],
    "iac": {
      "workspace_root": "/workspace",
      "paths": ["infra/storage.tf"],
      "terraform_plan_json_path": null,
      "format": "auto"
    },
    "answers": {},
    "max_relationship_hops": 1
  }
}
```

Supported operations are `create`, `update`, `review`, `delete`,
`troubleshoot`, and `optimize`. A request may contain at most five focus
resources, 20 explicit IaC files, one Terraform plan JSON file, two relationship
hops, and 25 graph nodes.

## Progressive Input

Steward resolves focus in this order:

1. Explicit `resource_refs`.
2. Changed resources in a supplied Terraform plan.
3. Exact ARN, Steward URI, or supported resource identifier in the prompt.
4. User selection inside one service scope.

It never guesses between candidates. With no exact focus, the MCP result offers
three choices: select an existing resource, review proposed IaC, or explicitly
run a full assessment.

After focus, Steward asks at most five questions per round. Questions cover only
facts that alter applicability or change safety, such as environment,
criticality, owner, data classification, access pattern, retention, recovery,
traffic, growth, consumers, exposure, and compliance. Answers and skipped
unknowns remain only in the 15-minute assessment.

## Knowledge Selection

The bundled, versioned knowledge packs cover all 17 executable scopes in five
families:

| Family | Scopes |
| --- | --- |
| Account foundation | IAM, CloudTrail, CloudWatch |
| Storage and protection | S3, EFS, EC2/EBS, KMS, Secrets Manager |
| Compute and runtime | EC2, Lambda, ECS, EKS/Kubernetes |
| Data platforms | RDS, DynamoDB |
| Edge and integration | ALB, API Gateway, SNS, SQS |

Each profile declares applicable operations, required context, WAF practices,
native rules, relationship collectors, evidence requirements, business impact,
safe correction, and verification. Package validation fails when a profile
references an unknown catalog rule or WAF practice. Native rules without a
defensible direct WAF mapping are explicitly recorded as unmapped.

Practice statuses are `risk`, `aligned`, `requires_input`, `unknown`,
`not_applicable`, `not_evaluated`. Manual practices never become `aligned`
because evidence is missing.

## Evidence And Graph Limits

Steward collects the focus node first. Direct AWS relationship collectors and
AWS Config history may add typed edges such as `encrypted_by`, `assumes_role`,
`invoked_by`, `publishes_to`, `routes_to`, `logs_to`, `backed_up_by`,
`deployed_in`, and `protected_by`.

Every edge contains source, confidence, observation time, and evidence
provenance. AWS Config evidence is marked as potentially stale. Partial
permissions appear as relationship errors. An unobserved edge never proves that
a dependency does not exist.

The review enforces:

- 50 deduplicated AWS reads;
- 25 graph nodes;
- one relationship hop by default, two maximum;
- no persistent AWS inventory;
- zero AWS writes.

Budget exhaustion and unavailable evidence are visible limitations, not passing
controls. The evidence ledger records every attempted read, status, parameters
after redaction, cache hits, and source-file reads.

## Safe IaC Context

Terraform HCL, Terraform plan JSON, and CloudFormation JSON/YAML are supported.
Steward reads only explicit paths below `workspace_root` and rejects:

- symlink escapes;
- `.tfstate`, `.tfvars`, `.env`, and credential files;
- files larger than 5 MiB;
- unsupported extensions;
- more than 20 source paths.

Steward never runs Terraform, CloudFormation transforms, macros, custom
resources, or dynamic references. Unresolved expressions and intrinsic
functions remain unknown. Review and patch previews do not modify source files.

## Result Contract

A completed result adds:

- `focus`: resolution source, resources, and selected knowledge;
- `architecture_neighborhood`: typed nodes, edges, errors, and bounds;
- `context_questions`: ephemeral answers and unknown facts;
- `well_architected_review`: practices grouped by pillar and status;
- `recommendations`: evidence, business impact, confidence, correction, and verification;
- `hidden_relevant_concerns`: high-impact cross-pillar findings preserved despite ranking intent;
- `evidence_ledger`: operation provenance and write count;
- `excluded_scope`: services intentionally not collected;
- `limitations`: incomplete or unavailable evidence.

JSON, CSV, Markdown, HTML, SARIF, and PDF reports preserve this context.
`bluearch_get_resource_details` returns the selected resource's captured
relationships and WAF context without adding a separate MCP tool.

## Examples

Existing resource:

> Review `s3://my-application-data` before deletion. Show observed dependencies,
> retention and recovery risks, unknown consumers, business impact, safe
> correction, and verification.

Proposed Terraform:

> Review `aws_s3_bucket.application_data` in `infra/storage.tf` under this
> repository root. Do not run Terraform or modify source.

Explicit full assessment:

> Run a comprehensive assessment across every supported service. Show only
> resources caught by rules and report skipped rules and coverage.

The third prompt is intentionally broader and follows the established full-scan
workflow rather than `architectural_review`.
