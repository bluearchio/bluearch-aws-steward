# BlueArch AWS Steward MCP Demo Runbook

## Goal

Demonstrate that a user can assess live AWS, inspect evidence, plan a change,
and verify safety entirely through Codex and Steward MCP.

## One-Time Setup

Install the development runtime from the repository root:

```bash
make dev-sync
```

The installation provides `bluearch-steward-mcp`. Configure Codex with:

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

Generate this configuration with
`uv run python -m bluearch_aws_steward mcp config`. After source changes, run
`make dev-sync` and restart the MCP server.

Use the repo-local plugin at `plugins/bluearch-aws-steward-codex` when testing
the complete Codex workflow. Start a new Codex task after installing or updating
the plugin so the tool and skill definitions reload.

Additional production-style prompts are in `docs/prompt-library.md`.

Have at least one AWS profile configured before the demo. Do not put the profile
name in the first prompt; the profile-selection and SSO-recovery flow is part of
the product demonstration. Do not name a service in the cost prompt either; the
guided service-scope response is also part of the demonstration.

## Demo 1: Readiness And Coverage

Prompt:

> Check whether BlueArch AWS Steward can access AWS, then show its current coverage.

Expected behavior:

- Codex calls `bluearch_status`.
- If several profiles exist, Steward opens a native MCP selector in Codex; clients without elicitation support receive the same `input_required` choices as structured text.
- If the selected SSO session is expired, Codex shows the local sign-in action and waits.
- The successful response identifies the AWS SDK provider, selected region, and caller identity.
- Codex calls `bluearch_get_coverage` if detailed coverage is requested.
- The result reports all 631 knowledge rules and their evaluation modes, plus
  100 canonical executable rules across 16 runtime scopes.
- Codex states that the remaining 531 catalog entries are not canonical native
  rules rather than treating them as passed.
- No AWS write occurs.

## Demo 2: Natural-Language Cost Assessment

Prompt:

> Find my top 10 AWS cost-reduction opportunities. Show only resources caught by BlueArch rules.

Expected behavior:

1. Codex calls `bluearch_assess` once.
2. Steward returns service-scope choices because the prompt already identifies cost as the objective.
3. Codex presents the response labels, waits, and resumes with the user's choice.
4. Codex resolves any later profile or region question in the same way.
5. Steward validates STS caller identity and returns an `assessment_id`.
6. Codex polls `bluearch_get_scan_status` using that ID.
7. Codex calls `bluearch_get_scan_results` after completion.
8. The answer starts with totals and grouped rules.
9. Only returned matching resources are shown.
10. Each result carries point-in-time observation metadata.

The agent must not start duplicate assessments while polling or fall back to ad
hoc AWS shell checks after a Steward error.

## Demo 3: Resource Evidence

Select one returned resource and ask:

> Explain why this resource was selected and show the evidence Steward observed.

Expected behavior:

- Codex calls `bluearch_get_resource_details` with the assessment ID and resource.
- Steward returns the matching rules, evidence, observation time, and fix guidance.
- The default response uses the assessment snapshot.
- A request for "check it again now" sets `refresh: true` and performs a new read.

## Demo 4: Plan And Approval Guard

Prompt:

> Create a remediation plan for this finding, but do not change AWS.

Expected behavior:

- Codex calls `bluearch_plan_remediation` with assessment and finding IDs.
- The response identifies the exact operation, before/after state, IAM permissions,
  impact warnings, rollback guidance, expiry, digest, and whether apply is supported.
- No write occurs.

Then ask Codex to attempt apply without approval in a test environment. The MCP
tool must refuse unless the server-issued plan ID, exact digest, and
`allow_write: true` are present.

For a real approved demonstration, use an intentionally created LocalEmu S3
fixture rather than an arbitrary production resource. Approval must identify
the target and action clearly before Codex sends the returned plan ID and digest
with `allow_write: true`.

## Demo 5: Verify Current State

After an approved S3 remediation, ask:

> Verify that the selected finding is resolved.

Expected behavior:

- Codex calls `bluearch_verify_remediation` with the assessment ID and finding ID.
- Steward performs a fresh AWS read.
- The result distinguishes resolved findings from remaining findings.

## Developer Validation

Before the demo, maintainers should run:

```bash
make test
make emulator-mvp
```

The first command validates MCP protocol, async assessment behavior, provider
contracts, and safety guards. The second validates 13 executable rules against
S3, EC2, CloudWatch Logs, IAM, and Lambda through both providers, then applies
and verifies the four supported low-risk S3 fixes.

## Troubleshooting

- MCP process missing: reinstall the project so `bluearch-steward-mcp` is on the host PATH.
- AWS identity failure: refresh the selected SSO profile, then call `bluearch_status` again.
- Assessment still running: keep polling the same ID; do not start a duplicate.
- Assessment expired: start a new assessment because stored results are intentionally ephemeral.
- Partial service failure: report it before describing the account as clean.
- Too many results: query the completed assessment by service, severity, rule, objective, or remediation support. Start a narrower assessment only when the AWS collection scope must change.
