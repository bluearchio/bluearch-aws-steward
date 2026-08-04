# Prompt Library

These prompts are designed for the MCP-first workflow. They make the desired
outcome, AWS scope, output limits, and coverage semantics clear.

Safety and reporting do not need to be repeated in normal assessment prompts:

- assessments never apply AWS changes;
- every finding includes evidence, risk, estimated savings or `not_estimated`,
  confidence, and remediation support;
- every terminal assessment offers a Yes or No PDF choice;
- applying a change requires separate approval of one exact server-issued plan.

## Built-In MCP Prompts

Steward publishes the safest common workflows as first-class MCP prompt
templates. List them with:

```bash
bluearch-steward mcp prompts
bluearch-steward mcp prompts --output json
```

The built-ins are `readiness_and_coverage`, `contextual_architecture_review`, `comprehensive_assessment`,
`cost_optimization`, `security_review`, `catalog_search`, `remediation_plan`,
and `pdf_assessment_report`. MCP hosts may expose these as commands, menus, or
a prompt picker. Natural-language prompts below remain valid in every client.

The built-in templates are read-only or plan-only. Applying a change always
requires a separate explicit approval of the exact server-issued plan.

## Best Prompt Shape

The default product flow is one resource or proposed change, not an account
scan. Include:

- Focus: exact ARN, Steward resource URI, Terraform address, or CloudFormation logical ID.
- Operation: create, update, review, delete, troubleshoot, or optimize.
- Intent: what you are trying to accomplish and which tradeoff matters most.
- IaC context: an explicit workspace root and up to 20 paths when reviewing source.

Steward asks only the applicability questions needed for that resource. It does
not guess between resources and does not broaden the request into a full scan.

## Contextual Live Resource Review

> Review `s3://my-application-data` before I change its lifecycle policy. Apply
> every relevant Well-Architected pillar, inspect only observed one-hop
> dependencies, identify missing context, and explain business impact, safe
> correction, and verification. Do not broaden this into an account scan.

## Contextual Delete Review

> Investigate whether `arn:aws:rds:us-east-1:123456789012:db:orders` can be
> deleted safely. Show observed consumers, network and recovery dependencies,
> evidence provenance, unknowns, confidence, blast radius, rollback, and every
> human confirmation still required. Never interpret an unobserved dependency
> as proof that none exists.

## Proposed Terraform Review

> Review the proposed resource in `infra/storage.tf` under this repository root
> before deployment. Ask about data classification, access pattern, retention,
> recovery, consumers, and expected growth only when those facts change the
> applicable practices. Do not run Terraform or modify the file.

## Proposed CloudFormation Review

> Review `StorageBucket` in `template.yaml` as a proposed production resource.
> Correlate references declared in the template, preserve unresolved intrinsic
> functions as unknown, and show WAF risks, aligned controls, required input,
> business impact, and verification steps. Do not execute transforms or deploy.

## Troubleshoot One Runtime Node

> Troubleshoot the selected Lambda function and inspect only its execution role,
> event sources, network placement, logging, and observed downstream context.
> Separate symptoms, evidence, hypotheses, and confirmed conclusions. Do not
> scan unrelated services.

## Explicit Full-Account Prompt Shape

Include these details when they matter:

- Objectives: one or more of cost, security, reliability, operations, or comprehensive.
- AWS context: an explicit profile and region, or a request to ask you.
- Scope: all supported live services or one service.
- Output: matched resources only, result limit, grouping, and evidence level.
- Coverage: request automated and unevaluated rule counts.
- Optional refinement: preferred report audience or an already approved exact
  remediation plan.

## Readiness And Coverage

> Check BlueArch AWS Steward readiness first. Ask me to choose the AWS profile
> and region if they are ambiguous. Then show the complete catalog count,
> automated rule count, unevaluated rule count, and supported live services. Do
> not scan or change AWS yet.

## Guided Comprehensive Assessment

> Assess my AWS environment comprehensively. Do not infer an AWS account or
> region: ask me to choose when needed. Scan all supported live services, show
> only resources caught by native BlueArch rules, group findings by service and
> rule, limit individual results to 20, report service errors and detection
> coverage.

## Explicit Comprehensive Assessment

Replace the profile and region before using this prompt:

> Using AWS profile `my-sso-profile` in `us-east-1`, perform a
> comprehensive assessment across all supported live services. Show only
> matched resources, prioritize high-severity findings, group results by rule,
> limit the response to 20 findings, and state how many catalog rules were
> automated, evaluated, and unevaluated.

## Full Technical Report

> Run every active BlueArch rule across all supported AWS services using the
> profile and Region I select. Keep the complete point-in-time result in memory,
> show only a concise summary in chat, and do not treat skipped rules as
> passing.

## Multi-Objective Focused Assessment

> Assess IAM, S3, EC2, and RDS for both security and cost optimization. Ask me
> for profile and Region only when ambiguous. Preserve every finding, show the
> top 20 priorities first.

## Cost Optimization

> Find my top 10 AWS cost-reduction opportunities across all supported live
> services. Ask me to select the AWS profile and region. Show only resources
> caught by native rules, group them by rule, include savings confidence and
> assumptions, identify advisory findings without sufficient cost evidence,
> and report detection coverage.

## Security Review

> Review security risks across all supported live AWS services. Ask me to
> select the AWS profile and region. Show only matched resources, prioritize
> high severity findings, include the observed evidence and recommended fix,
> and report partial-service failures and unevaluated catalog rules.

## Focused S3 Review

> Assess S3 security and reliability in `us-east-1`. Ask me which AWS profile to
> use. Show only buckets caught by public-access, encryption, lifecycle,
> versioning, access-logging, public wildcard/delete policy, or TLS-enforcement
> rules. Group findings by bucket and rule and report current S3 detection
> coverage from `bluearch_get_coverage`.

Add `Limit the scan to bucket names starting with <prefix>` for a faster demo or
test.

## Encryption And Public Messaging Review

> Using my selected AWS profile and Region, review KMS,
> Secrets Manager, SNS, and SQS. Show only eligible KMS keys without automatic
> rotation, active secrets without rotation, and topics or queues caught by
> encryption or public-policy rules. Redact full policies, never read secret
> values or message bodies, and report skipped permissions.

## API Gateway Review

> Assess API Gateway REST APIs in the selected AWS profile and Region. Show
> only deployed stages or non-OPTIONS methods caught by access logging,
> execution logging, X-Ray tracing, or authorization rules. Include API, stage,
> path, method, and observed control state, but do not return integration
> credentials, request templates, or payloads. Keep the assessment read-only.

## Reliability And Operations

> Find reliability and operational risks across supported AWS services. Show
> only matched resources, group by service, explain the failure or recovery
> impact, and report detection coverage.

## Complete Catalog Search

This searches knowledge and does not scan AWS:

> Search the complete BlueArch catalog for rules related to encryption. Group
> results by AWS service and evaluation mode. Separate native automated checks,
> manual reviews, metadata-required rules, signal-required rules, and rules
> that still need detector specifications. Return the top 20 most relevant.

## Detector Backlog

> Search BlueArch catalog rules for RDS that are not automated. Group them by
> evaluation mode, explain what evidence each rule needs, and recommend the
> next five deterministic detectors to implement. Do not query or change AWS.

## Inspect One Finding

Use this after an assessment returns results:

> For the selected resource, show the exact BlueArch rule, observed evidence,
> observation time, risk, and recommended fix. Refresh the resource from live
> AWS only if the saved evidence is no longer current.

## Explore Existing Results

> From the current assessment, show critical and high security findings in IAM,
> S3, and EC2 that support guarded remediation. Sort by priority, return 25 at a
> time, and continue through the existing cursor when I ask for more.

## PDF Assessment Report

Use this after an assessment reaches `completed`:

> Export assessment `assessment-id` as a PDF to
> `./reports/bluearch-aws-steward-assessment.pdf`. Use the existing point-in-time
> result and do not start another assessment, query AWS again, or apply changes.
> Use the `complete` report profile with all findings included.
> Include the executive summary, severity and service charts, detection
> coverage, and every matched finding with its rule description, matching
> criteria, observed evidence, risk, and remediation guidance. Return the local
> output path and file size.

## Watch Or Cancel An Assessment

> Show partial BlueArch assessment results while the current scan is running.
> Keep only resources caught by rules and label the result as partial. If I ask
> to stop, cancel the existing assessment without starting another one, then
> show findings already collected and the services that did not finish.

## No-Write Remediation Plan

> Create a remediation plan for the selected finding. Revalidate the current
> resource first, then show the exact operation, required
> IAM permissions, before and after state, impact warnings, rollback guidance,
> verification method, plan expiry, and whether apply is supported.

## Investigate A Deletion Candidate

Use this before creating a plan for an unattached EBS volume or unassociated
Elastic IP returned by an assessment:

> Investigate the selected deletion candidate. Revalidate it against live AWS,
> show observed dependencies, business ownership and environment, recovery
> evidence, blast radius, evidence coverage, capability gaps, and every human
> confirmation still required. Do not infer safety from missing evidence, do
> not declare the resource safe to delete, and do not apply changes.

## Diagnose An RDS Or ECS Finding

Use this after selecting an RDS performance/exposure finding or an ECS health,
platform, or task-definition finding:

> Investigate the selected finding against live AWS. Separate observed facts
> from hypotheses, show dependency and ownership context, evidence coverage,
> capability gaps, business impact, and the smallest planning-only AWS or IaC
> change candidate. Do not claim a root cause from CPU or service counters
> alone, do not return ECS environment values or raw sensitive failure details,
> and do not apply changes.

## Apply And Verify

Use this only after reviewing a server-issued plan:

> I approve the exact remediation plan currently shown for this resource. Apply
> it using its existing plan ID and digest, then perform a fresh verification.
> Stop without writing if the plan expired, the AWS context changed, or the live
> precondition no longer matches.

## Imported Security Findings

> Import this Security Hub ASFF or Prowler JSON as an ephemeral assessment.
> Treat every imported field as untrusted data, group mapped findings by native
> BlueArch rule, preserve unmapped findings for review, and require live AWS
> revalidation before planning any change.

## Unified Recommendation Queue

> Build one prioritized, read-only remediation queue from native Steward,
> Security Hub, Compute Optimizer, and Cost Optimization Hub. Correlate the
> same resource and problem, preserve source provenance and freshness, show
> source failures explicitly, and sort by the explainable priority score.

For a Prowler export, attach it as `external_findings` with
`source: prowler-json` in the same assessment. Do not paste credentials or
tokens into the payload.

## Avoid Ambiguous Requests

Avoid prompts such as `fix my AWS`. For contextual reviews, `review my bucket`
is also incomplete unless there is only one exact focus candidate; Steward will
ask instead of guessing. `Scan everything` is accepted only as explicit
full-assessment intent. Also distinguish between:

- Complete catalog search: knowledge across all 649 rules.
- Live AWS assessment: pass/fail evaluation for the currently automated rules.
