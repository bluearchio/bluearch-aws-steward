# MCP And Codex Plugin

BlueArch AWS Steward is MCP-first. Codex or another agent host launches the
local server, sends natural-language assessment requests, monitors work, and
coordinates approved remediation. Users do not operate Steward scan commands.

## Architecture

```text
User prompt
  -> Codex / IDE MCP client
      -> BlueArch AWS Steward MCP server
          -> complete BlueArch knowledge catalog
          -> reviewed executable detector registry
          -> Security Hub / Compute Optimizer / Cost Optimization Hub adapters
          -> fingerprinted recommendation queue
          -> assessment and remediation engine
          -> AWS SDK provider (default)
          -> live user-owned AWS account
```

The AWS APIs are the source of truth. Assessment state exists only in the MCP
process, expires after 15 minutes, and is never treated as a persistent resource
inventory. The store keeps every matched finding, matched resource, coverage
receipt, skipped rule, capability error, service state, and AWS context
separately from conversational limits. The AWS CLI remains an optional compatibility provider. A future AWS
MCP provider can be added behind the same provider contract.

## Exporting Reports

After an assessment reaches `completed`, call `bluearch_export_report` with the
assessment ID and one of `json`, `markdown`, `html`, `csv`, `sarif`, or `pdf`.
Choose `executive`, `technical`, `remediation`, or `complete` as the report
profile. Report generation uses the complete point-in-time result already held in memory; it
does not call AWS again and never applies writes. Pass `output_path` to save a
local file:

```json
{
  "assessment_id": "assessment-id",
  "format": "html",
  "output_path": "./reports/aws-assessment.html"
}
```

Reports include matched resources, evaluated-rule coverage, service errors, and
limitations. Unevaluated catalog rules are never presented as passing. PDF is
also supported and requires a local path ending in `.pdf`:

```json
{
  "assessment_id": "assessment-id",
  "format": "pdf",
  "report_profile": "complete",
  "include_all_findings": true,
  "output_path": "./reports/aws-assessment.pdf"
}
```

PDF generation is local and includes an executive summary, severity and service
charts, detection coverage, a findings index, and detailed matching criteria,
evidence, risk, and remediation guidance. Because PDF is binary, the MCP result
returns the path and byte size instead of embedding the document in JSON.

Explore the same completed snapshot without another AWS call:

```json
{
  "assessment_id": "assessment-id",
  "filters": {
    "services": ["iam", "s3"],
    "severities": ["critical", "high"],
    "objectives": ["security"],
    "remediation_supported": true
  },
  "sort": "priority",
  "page_size": 25,
  "cursor": null
}
```

`bluearch_query_results` returns complete and filtered counts, facets, an opaque
`next_cursor`, coverage limitations, and suggested actions. Reuse the cursor
with the same filters and sort until it returns `null`.

## One-Time Runtime Setup

Until a packaged binary is published, install the runtime from this repository:

```bash
make dev-sync
```

The installation provides `bluearch-steward-mcp`. Configure an MCP client with:

```json
{
  "mcpServers": {
    "bluearch-aws-steward": {
      "command": "/absolute/path/bluearch-aws-steward/.venv/bin/bluearch-steward-mcp",
      "args": [],
      "env": {
        "PYTHONUNBUFFERED": "1",
        "AWS_SDK_LOAD_CONFIG": "1"
      }
    }
  }
}
```

Generate the correct absolute paths with
`uv run python -m bluearch_aws_steward mcp config`. Run `make dev-sync` after
changing source, then restart the MCP server or start a new agent task. MCP
startup uses the already validated environment and does not resynchronize it.

The configuration intentionally does not set `AWS_PROFILE`, `AWS_REGION`, or
credentials. This lets Steward ask the user to select ambiguous AWS context.
Use the examples in `docs/prompt-library.md` for explicit or guided requests.

## Discoverable Workflow Prompts

Steward advertises the MCP `prompts` capability and implements `prompts/list`
and `prompts/get`. The built-in templates are:

- `readiness_and_coverage`
- `comprehensive_assessment`
- `cost_optimization`
- `security_review`
- `catalog_search`
- `remediation_plan`
- `pdf_assessment_report`

List their arguments without starting the server manually:

```bash
bluearch-steward mcp prompts
bluearch-steward mcp prompts --output json
```

Every assessment template is read-only, and the remediation template is
plan-only. There is deliberately no apply template. Prompt names and arguments
are validated before rendering; invalid names, missing required arguments, and
unsupported scopes return MCP invalid-parameter errors.

MCP standardizes prompt discovery but does not prescribe the client UI. A host
may show these templates as commands, menus, or a prompt picker. If a host does
not expose them, use natural language or the Codex plugin starter prompts; all
paths invoke the same tools and safety gates.

AWS credentials use the normal SDK credential chain. Named AWS profiles,
including SSO profiles, are selected through MCP arguments. Steward discovers
only non-secret local profile metadata. When multiple profiles are available
and none is active, it uses native MCP form elicitation to let the user select
one. The MCP host must ask the user instead of choosing an account. Provider
selection does not change the read/write safety policy.

### Least-Privilege IAM Policies

The typed capability registry generates two separate policies:

- `iam/read-policy.json` contains only the control-plane reads needed by the
  100 executable rules.
- `iam/remediation-policy.json` contains only the eight guarded write actions.

Run `make iam-policies` after changing a collector or remediation capability,
and commit the generated policy changes with the registry change. Keep the read
and remediation roles separate. A write action is needed only after Steward
creates a reviewed plan and the user approves that exact plan.

Tool responses include both serialized JSON text and MCP `structuredContent`.
This follows the MCP structured-result pattern and lets hosts reliably detect
clarification states. On clients that advertise the MCP `elicitation`
capability, Steward sends `elicitation/create`, validates the accepted form,
merges only the requested fields, and resumes the original tool call. Objective
and service forms use independent boolean choices so clients can select
multiple values. `all` is mutually exclusive with narrower choices. The same
question remains in the structured result as a portable fallback for clients
without form elicitation.

When an assessment reaches `completed`, or reaches `cancelled` with preserved
read-only results, `bluearch_get_scan_results` opens a native Yes/No form asking
whether to generate a PDF. A response with `status: running` is explicitly
marked `final_response_allowed: false`; agents must keep polling or ask before
cancelling instead of presenting a partial scan as the final account review.

These behaviors are defaults and do not need to be repeated in user prompts:

- every terminal assessment offers the local PDF choice;
- every presented finding includes evidence, risk, estimated monthly savings or
  an explicit `not_estimated` value, cost confidence, and remediation support;
- assessment and report generation never apply AWS writes;
- guarded remediation is always one finding on one resource and requires the
  user to approve the exact live-revalidated plan before `allow_write=true`.

Before profile discovery, `bluearch_assess` checks whether the request contains
an explicit objective and supported AWS service scope. If either is unclear, it
returns `status: input_required` without reading AWS configuration or calling
AWS. The result includes:

- `questions`: structured multi-select objective and service fields for capable clients.
- `possible_responses`: concise labels, natural-language replies, and exact tool arguments.
- `input_request`: a form-compatible schema.
- `resume`: the original tool call and the fields to merge before retrying.

This is progressive: Steward asks only for missing intent, then profile, then
region or authentication when required. The host must not answer these
questions on the user's behalf.

## Primary Tools

| Tool | Purpose | Writes To AWS |
| --- | --- | --- |
| `bluearch_list_aws_profiles` | List profile names, profile types, and configured regions without credentials. | No |
| `bluearch_import_findings` | Normalize Security Hub, Prowler, Compute Optimizer, or Cost Optimization Hub JSON into an ephemeral assessment. | No |
| `bluearch_status` | Check runtime, credentials, caller identity, and coverage. | No |
| `bluearch_assess` | Refine intent, resolve AWS context, then start a background assessment and return an ID. | No |
| `bluearch_get_scan_status` | Poll the existing assessment without repeating AWS work. | No |
| `bluearch_get_scan_results` | Return grouped solution cards; `include_partial: true` exposes findings collected so far. | No |
| `bluearch_query_results` | Filter, facet, sort, and paginate the complete snapshot without rescanning. | No |
| `bluearch_export_report` | Export filtered or complete JSON, Markdown, HTML, CSV, SARIF, or PDF. | No |
| `bluearch_cancel_assessment` | Request cancellation and preserve findings already collected. | No |
| `bluearch_get_resource_details` | Inspect captured evidence or request a live refresh. | No |
| `bluearch_get_coverage` | Report complete catalog coverage, evaluation modes, executable rules, and apply support. | No |
| `bluearch_rules_search` | Search all bundled rules, including manual and not-yet-automated entries. | No |
| `bluearch_explain_finding` | Explain one returned finding. | No |
| `bluearch_plan_remediation` | Revalidate one finding and build a short-lived, digest-bound no-write plan. | No |
| `bluearch_verify_remediation` | Re-read AWS and verify selected findings. | No |
| `bluearch_apply_remediation` | Apply one server-held plan after context and precondition checks, then verify it. | Only with `plan_id`, `plan_digest`, and `allow_write: true` |

`bluearch_advise`, `bluearch_scan_aws`, `bluearch_find_opportunities`, and
`bluearch_doctor` remain available for backwards
compatibility and advanced clients. New clients should use the primary tools.

## Agent Flow

1. Call `bluearch_assess` with the user's natural-language goal.
2. Let native MCP elicitation collect and resume missing input when available. If the tool still returns `input_required`, present the labels in `possible_responses` and ask the returned question as the compatibility fallback.
3. Wait for the user's selection or equivalent natural-language answer, merge that response's `arguments` into `resume.arguments`, and retry `resume.tool`.
4. If it returns `authentication_required`, show the external AWS sign-in action and wait for completion. Never request credentials in chat.
5. Poll `bluearch_get_scan_status` only after an assessment ID is returned.
6. Call `bluearch_get_scan_results` after completion, or with
   `include_partial: true` while it runs when the user asks to see progress.
7. Present grouped totals and returned solution cards, not raw account inventory. For every displayed card, include evidence, risk, estimated monthly savings or `not_estimated`, cost confidence, and remediation support.
8. Call `bluearch_query_results` to refine, facet, sort, or paginate the same snapshot. Do not start another scan.
9. Use `bluearch_get_resource_details` for one selected resource.
10. Explain or plan using `assessment_id` and `finding_id`. Planning re-reads live AWS and may ask for retention or lifecycle settings.
11. Present the exact plan, IAM permissions, warnings, rollback guidance, expiry, and digest. Ask for explicit approval of that plan.
12. Call apply only after separate approval of one exact plan, using the server-issued `plan_id`, `plan_digest`, and `allow_write: true`. Steward rechecks the account, region, and live resource state before writing, then verifies it.
13. Always obtain the terminal Yes/No PDF choice from `bluearch_get_scan_results`; the user does not need to request reporting in the original prompt.

Do not start another assessment to refine completed results. Use
`bluearch_cancel_assessment` when the user asks to stop; completed service
results remain available. Use `bluearch_query_results` for service, severity,
rule, objective, and remediation filters. Start a narrower assessment only when
the AWS collection scope itself must change. If a
Steward tool fails, do not reimplement its checks with ad hoc shell commands.
Status responses include the current service, services completed, resources
scanned, findings discovered, and isolated service-error count when available.

## Example

Start with a vague assessment request:

```json
{
  "prompt": "Review my AWS environment"
}
```

No assessment is created yet. Steward returns guided choices such as:

```json
{
  "status": "input_required",
  "reason": "assessment_refinement_required",
  "message": "Before scanning, what outcome and AWS resource scope should Steward prioritize?",
  "possible_responses": [
    {
      "label": "Comprehensive assessment across supported services",
      "arguments": {"objective": "all", "service": "all"}
    },
    {
      "label": "Cost optimization across supported services",
      "arguments": {"objective": "cost_optimization", "service": "all"}
    },
    {
      "label": "S3 security assessment",
      "arguments": {"objective": "security", "service": "s3"}
    }
  ],
  "resume": {
    "tool": "bluearch_assess",
    "arguments": {"prompt": "Review my AWS environment"},
    "merge_user_input": ["objective_security", "objective_cost_optimization", "service_s3", "service_ec2"]
  }
}
```

The host presents those labels and waits. The user may select more than one
objective and more than one service. Steward normalizes those choices into
`objectives` and `services` while preserving singular `objective` and `service`
compatibility. If multiple profiles are configured, Steward then returns:

```json
{
  "status": "input_required",
  "reason": "aws_profile_required",
  "message": "Steward found multiple AWS profiles and will not guess which account to inspect. Which AWS profile should it use?",
  "choices": [
    {"value": "engineering-sso", "label": "engineering-sso (sso)"},
    {"value": "production-sso", "label": "production-sso (sso)"}
  ],
  "possible_responses": [
    {
      "label": "engineering-sso (sso)",
      "arguments": {"profile": "engineering-sso"}
    },
    {
      "label": "production-sso (sso)",
      "arguments": {"profile": "production-sso"}
    }
  ],
  "resume": {
    "tool": "bluearch_assess",
    "arguments": {
      "prompt": "Review my AWS environment",
      "objective": "cost_optimization",
      "service": "all"
    },
    "merge_user_input": ["profile"]
  }
}
```

The host again asks the user, merges the selected `profile`, and retries. If the
selected profile has no configured region and the request includes regional
services, Steward asks for `region` next. It validates the final selection with
STS before starting the background job. Expired SSO returns
`authentication_required` with `aws sso login --profile <name>`; credentials
and tokens must never be pasted into the conversation.

After context validation, the response contains an ID and a status tool call:

```json
{
  "assessment_id": "assessment_abc123",
  "status": "queued",
  "ephemeral": true,
  "point_in_time": true,
  "next": {
    "tool": "bluearch_get_scan_status",
    "arguments": {
      "assessment_id": "assessment_abc123"
    }
  }
}
```

Retrieve results after completion:

```json
{
  "assessment_id": "assessment_abc123"
}
```

Inspect captured evidence for a returned resource:

```json
{
  "assessment_id": "assessment_abc123",
  "resource": "ebs://vol-example",
  "refresh": false
}
```

Set `refresh` to `true` only when the user needs current evidence. Steward then
re-reads the relevant service and rule from AWS; it does not trust the earlier
assessment as current truth.

Plan a returned finding:

```json
{
  "assessment_id": "assessment_abc123",
  "finding_id": "steward-example"
}
```

The response contains a short-lived `plan_id`, `plan_digest`, exact AWS API
operation, before/after preview, IAM actions, warnings, rollback guidance, and
verification contract. Apply only after the user approves that exact plan:

```json
{
  "plan_id": "plan_abc123",
  "plan_digest": "<digest returned by bluearch_plan_remediation>",
  "allow_write": true
}
```

Do not reconstruct or edit plan contents in the client. Plans expire after ten
minutes, cannot be replayed, and are invalidated if the relevant live evidence
changes. A fresh plan is required for another account, region, resource, or
desired setting.

## Import Existing Findings

Use `bluearch_assess.signal_sources` to select any combination of `native`,
`security-hub`, `compute-optimizer`, and `cost-optimization-hub`. Steward reads
the live APIs, deduplicates by account, Region, canonical resource, and
canonical problem, and keeps all source receipts in `evidence.provenance`.
Query by `sources` or `validation_statuses`; priority sorting uses an
explainable score composed from risk, freshness/confidence, estimated savings,
remediation readiness, corroboration, and implementation effort.

Use `bluearch_import_findings` with `source: securityhub-asff`,
`source: prowler-json`, `source: compute-optimizer-json`, or
`source: cost-optimization-hub-json` and the corresponding JSON object or array. The adapter
auto-detects Prowler's current JSON-OCSF and legacy flat JSON, maps known
external checks to executable Steward rule IDs, expands multi-resource records,
preserves unmapped findings for review, skips passed/inactive records, and
creates an ephemeral assessment. Prowler records from non-AWS providers are
rejected because this runtime can only revalidate AWS resources. Imported
titles, descriptions, resource identifiers, and remediation text are marked as
untrusted data and are never promoted to executable guidance. Imported evidence
is never sufficient for a write: planning must reproduce the mapped rule
against the current AWS resource first. Equivalent configuration checks may be
marked `resolved_or_stale` after successful native revalidation. Broader AWS
recommendation signals are correlated but are not invalidated by a narrower
native detector.

## Coverage And Safety

The complete bundled catalog contains 631 rules across 47 catalog service
groups. It includes 100 canonical `native` rules, seven catalog aliases, 117
`manual_review`, 191 `metadata_required`, five `signal_required`, and 211
`specification_required` entries. Only canonical native rules produce live
pass/fail results; aliases never increase the executable coverage count.

The executable registry covers 100 canonical rules across 16 runtime scopes:
IAM, KMS, Secrets Manager, CloudTrail, CloudWatch Logs, DynamoDB, S3, EC2,
EFS, Lambda, ECS, RDS, SNS, SQS, API Gateway, and ALB.
`ebs` and `networking` route to the EC2 collector. Guarded apply is limited to
`s3-public-bucket`, `s3-no-default-encryption`, `s3-no-lifecycle`,
`s3-server-access-logging-disabled`, `s3-versioning-disabled`,
`cloudwatch-log-retention-missing`, `cloudtrail-log-validation-disabled`, and
`alb-access-logging-disabled`. Logging remediation requires a validated,
pre-existing same-Region bucket,
SSE-S3, and a compatible `s3:PutObject` bucket-policy statement for
`logging.s3.amazonaws.com` or
`logdelivery.elasticloadbalancing.amazonaws.com`. Steward checks these
conditions during planning and again before applying, but never creates or
updates the destination policy. Every other rule is planning-only until its
write path has dedicated permission, impact, rollback, precondition, and
verification controls.

Every live result includes `summary.detection_coverage`. Clients must report
that object and must not call an account or service fully clean when
`complete_catalog_evaluation` is false. A zero-finding result means only that
none of `automated_rules_evaluated` matched; all
`unevaluated_catalog_rules` remain unknown.

Broad results are capped and grouped. Partial service failures are reported
before an account can be described as clean. AWS resource names and evidence
remain local; Steward has no hosted telemetry or sign-in dependency.
