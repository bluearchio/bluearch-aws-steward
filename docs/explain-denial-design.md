# Design: `bluearch_explain_denial` — single-call policy-denial diagnosis

Status: PROPOSAL for review (Artur, Joel). No code in this change.

## Why this tool, why now

Benchmark evidence (cloudarch-eval `sweep-2026-08-12` and the 2026-08-18
comparative suite, 1,240+ trials over Opus 4.5/Sonnet 4.5/Haiku 4.5) showed
that **seven of the ten incident scenarios reduce to one operation Steward
does not offer today**: given an actor, an action, and a resource, name the
exact policy statement that denies the request or the exact permission that
is missing.

| Scenario | The diagnosis it needs |
| --- | --- |
| `iam-explicit-deny-masks-allow` | explicit Deny statement shadowing an Allow |
| `iam-s3-workload-permission` | missing identity-policy permission |
| `kms-key-policy-excludes-workload` | key policy missing the workload principal |
| `s3-upload-kms-denied` | KMS grant/condition mismatch on PutObject |
| `sns-sqs-delivery-rejected` | queue policy rejecting the topic principal |
| `eventbridge-sqs-policy-rejects-delivery` | queue policy condition mismatch (`aws:SourceArn`) |
| `sqs-dlq-redrive-misconfigured` | redrive/permission mismatch |

In those scenarios the models solved the problem with raw `aws_cli` reads
while Steward's scan-shaped tools added only noise (AccessDenied hard-fails,
guessed `rule_filter`s) — the measured attention cost that put the combined
arm below baseline. A purpose-built diagnosis tool converts Steward from
noise into signal on exactly this scenario class, and its structured output
doubles as the grading contract for the planned `review-*` scenario class.

## Design principles (each one paid for by a measured failure)

1. **One call, one bounded result.** Multi-step flows (`assess → poll →
   results`) were never certifiable by the eval's fail-closed probe chain
   and burn agent budget. This tool is synchronous and self-contained.
2. **Context by arguments, never elicitation.** Headless agents cannot
   answer forms. Everything the evaluation needs is passable up front;
   what is absent becomes an explicit `unknown`, never a question.
3. **Every response ends with a `next` recipe.** The `plan_remediation`
   `next` block produced 17/18 headless plan→apply completions; its absence
   in `applied_with_residual_risk` cost Haiku −7.5pp. Small models need the
   next step spelled out.
4. **Partial evaluation degrades, never hard-fails.** An AccessDenied while
   reading one policy layer becomes `evaluation_ledger` +
   `unknowns` entries; the call still returns every layer it could read.
   (The scan's hard-fail on AccessDenied produced 488 wasted calls.)
5. **Scope honesty.** A service or pattern outside the evaluator's
   competence returns `status: "not_supported"` with the explicit advice to
   proceed with other tooling — never a plausible empty answer.

## Tool contract

Read-only. No guarded-write surface, no approval semantics.

### Input

```jsonc
{
  "action": "s3:PutObject",              // required — one IAM action
  "resource": "arn:aws:s3:::bkt/key",    // required — ARN or steward ref (s3://bkt/key accepted)
  "principal": "arn:aws:iam::...:role/x", // optional — defaults to the current caller identity
  "error_message": "An error occurred (AccessDenied) ...", // optional — parsed to fill missing fields
  "condition_context": {                  // optional — request context keys for Condition evaluation
    "aws:SourceArn": "arn:aws:sns:...",
    "aws:SourceAccount": "123456789012"
  },
  "profile": "...", "region": "...", "endpoint_url": "..."  // standard Steward args
}
```

### Output (the claims schema — also the grading contract)

```jsonc
{
  "status": "explained" | "not_denied" | "not_supported" | "insufficient_access",
  "verdict": {
    "effect": "explicit_deny" | "implicit_deny" | "allow" | "conditional" | "unknown",
    "blocking_layer": "identity_policy" | "resource_policy" | "kms_key_policy"
                    | "public_access_block" | "condition_mismatch" | "scp" | "none"
  },
  "claims": [
    {
      "claim_id": "c1",
      "kind": "denying_statement" | "missing_permission" | "condition_mismatch" | "satisfied_layer",
      "layer": "resource_policy",
      "policy_ref": { "resource": "arn:aws:sqs:...:queue", "statement_sid": "DenyAll", "statement_index": 0 },
      "evidence": { "statement": { /* verbatim statement */ }, "observed_at": "..." },
      "explanation": "Statement DenyAll denies sqs:SendMessage to every principal except ... ;
                      the topic's ARN does not match Condition aws:SourceArn."
    }
  ],
  "evaluation_ledger": [
    { "layer": "identity_policy", "read": "iam.list_attached_role_policies", "result": "evaluated" },
    { "layer": "scp", "read": "organizations.describe_policy", "result": "access_denied" }
  ],
  "unknowns": [
    "SCP evaluation unavailable (organizations read denied); an SCP deny cannot be excluded."
  ],
  "next": {
    "remediation": {
      "description": "Add aws:SourceArn=<topic-arn> to the queue policy's Condition, or scope the Deny.",
      "operation": "sqs.SetQueueAttributes",
      "tool": null,                        // a bluearch_plan_remediation rule id when one exists
      "requires_review": true
    },
    "verification": {
      "tool": "bluearch_explain_denial",
      "arguments": { "action": "sqs:SendMessage", "resource": "...", "condition_context": { } }
    }
  }
}
```

Contract rules:

- `claims` is never empty when `status` is `"explained"`; the first claim is
  the decisive one (matches `verdict.blocking_layer`).
- Every claim carries verbatim evidence. No claim without an evidence read
  recorded in `evaluation_ledger`.
- `condition_context` keys that a Condition references but the caller did
  not supply produce `verdict.effect: "conditional"` and a claim naming the
  missing key — the tool never guesses request context.
- `error_message` parsing is convenience only; explicit arguments win.

## Evaluation semantics (v1 scope)

Deterministic, local re-implementation of the documented IAM evaluation
order, over policies read live:

1. Explicit deny anywhere that applies → `explicit_deny` (deny wins).
2. S3: `public_access_block` overrides for public-principal requests.
3. KMS: the key policy is authoritative; identity policy alone never
   suffices without a key-policy path (`kms_key_policy` layer).
4. Same-account resource policy OR identity policy allow → `allow`;
   cross-account requires both sides (v1: cross-account returns the claim
   for the readable side + an `unknown` for the other).
5. No allow found → `implicit_deny` with `missing_permission` claims naming
   the smallest missing grant.
6. Condition blocks evaluated against `condition_context`; unsupplied keys
   → `conditional` verdict, never a guess.

v1 services: `s3`, `kms`, `sqs`, `sns`, `events`, `iam`, `dynamodb` — the
benchmark set, all inside Steward's existing 17 runtime scopes. SCPs,
permission boundaries, session policies, VPC endpoint policies: declared
`unknowns` in v1 (ledger entry `not_evaluated`), promoted in later versions.
Anything else → `status: "not_supported"` naming what to use instead.

## How the eval grades it (contract for cloudarch-eval)

Deterministic checks over the structured output — no LLM judge, consistent
with the harness's fail-closed doctrine:

- `required.blocking_layer_named` — `verdict.blocking_layer` equals the
  planted defect's layer.
- `required.statement_identified` — some claim's `policy_ref` matches the
  planted statement (Sid or index + resource).
- `forbidden.write_calls` — the trial's tool-call ledger shows no write.
- `behavioral.unknowns_declared` — layers the sandbox makes unreadable
  appear in `unknowns`, not as silent passes.

Certification: single-call probe (`explain_denial` on a canary resource with
a planted deny) whose response contains the canary identifier — the same
shape as the existing `bluearch_scan_aws` probe, so it joins the certified
chain with one probe-spec step and no new harness machinery.

## Implementation sketch (when approved)

- New module `bluearch_aws_steward/policy_explain.py`: pure evaluation core
  (policy documents in → verdict/claims out) + thin live-read layer reusing
  the existing providers. The seven benchmark scenarios become unit-test
  fixtures for the pure core — TDD directly against the cases that matter.
- `mcp_server.py`: tool registration + schema; read-only, no live-context
  requirement beyond the standard profile/region resolution.
- Tests: fixture-driven core tests (one per scenario class), MCP contract
  test, partial-read degradation test, `not_supported` honesty test.
- Measurement: `cloudarch-eval dev --scenario <the seven>` first (mechanism:
  the right statement named), then a confirmation sweep on those scenarios.
  Success = combined arm ≥ baseline on the seven scenarios.

## Follow-ups this unblocks (not in this proposal)

- `bluearch_review_resource`: the one-shot architectural review (context by
  arguments, claims-shaped output) — makes the `review-*` scenario class
  gradable and the core product benchmarkable.
- `bluearch_diagnose`: symptom → ranked hypotheses with per-hypothesis
  evidence and `next` verification steps.
