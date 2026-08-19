# Design: `bluearch_explain_denial` — single-call policy-denial diagnosis

Status: PROPOSAL for review (Artur, Joel). Implementation: PR #54
(`blocking_control` claim kind added there for the public-access-block layer,
which is a control, not a statement).

## Why this tool, why now

Benchmark evidence (cloudarch-eval `sweep-2026-08-12` and the 2026-08-18
comparative suite, 1,240+ trials over Opus 4.5/Sonnet 4.5/Haiku 4.5) showed
that **six of the ten incident scenarios reduce to one operation Steward
did not offer**: given an actor, an action, and a resource, name the
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
| `sqs-dlq-redrive-misconfigured` | ~~redrive/permission mismatch~~ **CORRECTED 2026-08-19: the planted fault is a RedrivePolicy configuration loop, not a policy denial — outside this tool's class (family stays at six; see "Non-denial outcomes" below)** |

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
  "schema_version": "1",                   // graders pin against this
  "status": "explained" | "not_denied" | "not_supported" | "insufficient_access",
  "verdict": {
    "effect": "explicit_deny" | "implicit_deny" | "allow" | "conditional" | "unknown",
    "blocking_layer": "identity_policy" | "resource_policy" | "kms_key_policy"
                    | "public_access_block" | "condition_mismatch" | "scp" | "none"
                    | "unknown"
  },
  "claims": [
    {
      "claim_id": "c1",
      "kind": "denying_statement" | "missing_permission" | "condition_mismatch" | "satisfied_layer" | "blocking_control",
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
    {
      "layer": "scp",                      // same frozen vocabulary as blocking_layer
      "reason": "read_denied" | "not_evaluated_v1" | "not_applicable",
      "detail": "organizations read denied; an SCP deny cannot be excluded."  // free text, not graded
    }
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
- **Frozen vocabularies, versioned by `schema_version`:** the
  `blocking_layer` / `unknowns[].layer` enum and the `unknowns[].reason`
  enum are closed sets — graders string-match against them, so any addition
  bumps `schema_version`. Free text lives only in `explanation` and
  `unknowns[].detail`, which are never graded.
- **Response size budget (the graded artifact is the *recorded* output,
  post-redaction and capped by the harness — 16 KiB for CLI tools, an MCP
  char bound of its own):** at most 5 claims (decisive first; overflow
  becomes `claims_truncated: n`); `evidence.statement` is the referenced
  statement only, never the whole policy document, trimmed to 2 KiB with
  `evidence_truncated: true` plus a sha256 digest when trimmed. Target: a
  typical response ≤ 8 KiB, comfortably under every recording cap so the
  grader never sees truncated JSON.

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

Reviewed against the harness code by its owner (2026-08-18). Deterministic
checks over the structured output — no LLM judge, consistent with the
harness's fail-closed doctrine. `GradeReport`/`CheckResult` need no change;
the harness-side extension is passing the trial's already-snapshotted
`ToolCallRecord`s into diagnosis-family graders (a small, localized change
at the single production call site, planned as its own vertical slice on
the cloudarch-eval side).

**Selection rule (which call is graded):** the LAST successful
`bluearch_explain_denial` call in the trial. Deterministic, allows honest
iteration toward a conclusion, and never rewards spray-and-pray across
actors/resources — grading any-call-matches would measure the tool's power,
not the model's diagnosis.

- `required.blocking_layer_named` — `verdict.blocking_layer` equals the
  planted defect's layer (string equality against the frozen vocabulary).
- `required.statement_identified` — some claim's `policy_ref` matches the
  planted statement, **Sid-first**: planted statements always carry a
  canary-unique Sid, so a fabricated or echoed claim cannot match without
  the tool having actually read the deny. `statement_index` + resource is a
  documented fallback only.
- `forbidden.write_calls` — a fold over the trial's `ToolCallRecord`
  classifications: no WRITE.
- `behavioral.unknowns_declared` — the per-scenario, fixed set of
  sandbox-unreadable layers appears in `unknowns` with the frozen
  vocabulary, not as silent passes.

Certification: single-call probe (`explain_denial` on a canary resource
**with a planted deny**, exercising the denial path — the certification
owns the throwaway LocalEmu, so the upgrade is free) whose response contains
the canary identifier — the same shape as the existing `bluearch_scan_aws`
probe, so it joins the certified chain with one probe-spec step and no new
harness machinery.

## Non-denial outcomes (contract note, 2026-08-19)

Verified against the shipped v1 code, for graders and future scenario
design:

- A request an existing Allow statement satisfies returns
  `status: "not_denied"` with a non-empty `claims` list — `kind:
  "satisfied_layer"` carrying the real `policy_ref` (Sid) of the allowing
  statement. An "expected-none" grading form over this shape is a viable
  contract evolution (schema stays at version 1; the check would pin
  `status` + the satisfied statement's Sid).
- A service-managed flow with NO policy present is a declared v1
  limitation: v1 returns `implicit_deny`/`missing_permission` on the
  resource-policy layer, which is wrong for flows that IAM does not
  govern — SQS DLQ redrive is governed by `RedriveAllowPolicy`, not a
  queue policy. This is exactly why `sqs-dlq-redrive-misconfigured` is
  out of the diagnosis family: the planted defect is a configuration
  loop, and pointing this tool at it would produce a misleading verdict.
  v2 candidates: model `RedriveAllowPolicy`, or return `not_supported`
  for service-managed flows v1 cannot decide.

## Scenario family (harness-owner-reviewed decision)

A new `diagnosis-*` family that **reuses the planted defects and seed
derivation of the six in-class incident scenarios as a shared library — never the
scenario ids**. A grading toggle on the same id would fork the meaning of
`descriptor_hash`/`grader_hash` in history and confuse coverage/resume.
Comparability comes from same-defect + same-seed across families:
`iam-explicit-deny` vs `iam-explicit-deny-diagnosis` as separate, honest
rows.

## Open questions for review (Artur / Joel)

1. **Scoreboard framing:** the mcp-standalone arm was removed from the site
   scoreboard under fix-grading (where it has a structural ceiling).
   Diagnosis grading is exactly the framing where that arm becomes
   meaningful again — should it return to the published scoreboard for
   `diagnosis-*` rows?
2. **v1 evaluation scope:** same-account only, SCPs/permission boundaries as
   declared unknowns — acceptable for the first release, or is any of these
   layers a must-have?

## Implementation sketch (when approved)

- New module `bluearch_aws_steward/policy_explain.py`: pure evaluation core
  (policy documents in → verdict/claims out) + thin live-read layer reusing
  the existing providers. The six in-class benchmark scenarios become unit-test
  fixtures for the pure core — TDD directly against the cases that matter.
- `mcp_server.py`: tool registration + schema; read-only, no live-context
  requirement beyond the standard profile/region resolution.
- Tests: fixture-driven core tests (one per scenario class), MCP contract
  test, partial-read degradation test, `not_supported` honesty test.
- Measurement: `cloudarch-eval dev --scenario <the six>` first (mechanism:
  the right statement named), then a confirmation sweep on those scenarios.
  Success = combined arm ≥ baseline on the six in-class scenarios.

## Follow-ups this unblocks (not in this proposal)

- `bluearch_review_resource`: the one-shot architectural review (context by
  arguments, claims-shaped output) — makes the `review-*` scenario class
  gradable and the core product benchmarkable.
- `bluearch_diagnose`: symptom → ranked hypotheses with per-hypothesis
  evidence and `next` verification steps.
