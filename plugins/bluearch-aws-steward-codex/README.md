# BlueArch AWS Steward Codex Plugin

This plugin makes BlueArch AWS Steward available as an MCP-first AWS assistant
inside Codex. Users describe an outcome in natural language; Codex starts and
monitors a point-in-time assessment, presents solution cards, and coordinates
approved remediation without asking the user to operate a scan CLI.

## Runtime Setup

Until a packaged binary is published, install the runtime once from the
repository root:

```bash
uv sync --extra tui
```

The plugin launches `bluearch-steward-mcp` automatically over stdio. The AWS SDK
is bundled as the default provider, so the AWS CLI is not required for scanning.
AWS credentials still come from the user's normal SDK credential chain, including
AWS SSO profiles. Initial SSO configuration and browser sign-in still use the
AWS CLI because credentials and tokens must stay outside the MCP conversation.
The MCP registration deliberately leaves profile and region unset so Steward
can ask the user when more than one valid AWS context exists.

See `docs/prompt-library.md` in the repository for comprehensive, cost,
security, catalog-search, remediation, and verification prompts.

The MCP server also publishes validated read-only and plan-only templates via
`prompts/list` and `prompts/get`. Run `bluearch-steward mcp prompts` to inspect
them. Whether they appear as commands or a picker depends on the MCP client, so
the plugin starter prompts remain the Codex-compatible fallback.

## User Flow

Ask Codex a request such as:

> Find my top AWS cost-reduction opportunities.

The plugin then:

1. Starts with `bluearch_assess` in guided, focused, or full-report mode.
2. Presents multi-select objective and service choices and accepts an equivalent natural-language answer.
3. Discovers local profile metadata safely and asks for a profile or region only when needed.
4. Validates the selected caller identity before creating an assessment.
5. Starts a background assessment and polls `bluearch_get_scan_status` without restarting it.
6. Reads partial or final solution cards with `bluearch_get_scan_results` and can cancel on request.
7. Uses `bluearch_query_results` to filter, facet, sort, and paginate the complete snapshot without rescanning.
8. Opens evidence with `bluearch_get_resource_details` when requested.
9. Exports complete or filtered executive, technical, remediation, or complete reports.
10. Revalidates and plans a fix using the assessment ID and finding ID.
11. Presents the exact operation, IAM permissions, warnings, rollback guidance, expiry, and digest.
12. Applies only with the returned plan ID and digest plus `allow_write: true`, then verifies live AWS state.

For example, a vague request such as `Review my AWS environment` returns
choices including comprehensive, cost, security, reliability, and operational
assessments. Objectives and services accept multiple selections; `all` cannot
be combined with narrower choices. A cost request with no service named returns `All supported
services` plus IAM, KMS, Secrets Manager, CloudTrail, CloudWatch Logs, S3,
EC2/EBS, EFS, Lambda, ECS, RDS, SNS, SQS, API Gateway, and ALB choices. The
plugin waits for the user's choice before reading AWS configuration or calling
AWS.

Profile discovery returns names, credential type, and configured region only.
It never returns credentials or SSO tokens. If SSO is expired, Codex shows the
local `aws sso login --profile ...` action and waits for the user to finish.

Assessments are kept only in process memory and expire after 15 minutes. They
are point-in-time observations, not a persistent AWS inventory database.
Conversational limits never cap report data. A 50,000-finding guard is explicit
and marks the result incomplete instead of silently dropping findings.

## Current Coverage

The bundled knowledge registry contains all 631 `aws-misconfig-db` rules across
47 catalog service groups. Executable coverage contains 100 canonical rules
across 16 runtime scopes: IAM, KMS, Secrets Manager, CloudTrail, CloudWatch
Logs, DynamoDB, S3, EC2, EFS, Lambda, ECS, RDS, SNS, SQS, API Gateway, and ALB. Guarded remediation covers eight narrowly scoped
controls; all other rules remain planning-only or unevaluated. Use
`bluearch_get_coverage` for the authoritative breakdown and never treat
unevaluated rules as passing.
