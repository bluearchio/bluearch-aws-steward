# Triage and Prioritization — Design

Date: 2026-08-04
Status: approved
Scope: sub-project A of the Steward improvement roadmap, plus one blocking fix
pulled in from sub-project B.

## Problem

A read-only assessment of a live AWS account (1606 resources, 17 services,
160 seconds) produced 1428 findings and exposed a single dominant failure: the
tool found the most dangerous item in the account and buried it.

`iam-root-access-key-present` — an active access key on the account root — was
delivered at **position 23**, with `priority: {}` empty. Ordering was
alphabetical inside each severity bucket (api-gateway, ecs, iam, kms, rds, s3,
secrets-manager, sns, sqs), and the rule carries `severity: medium` in the
catalog while `sns-topic-encryption-disabled` carries `high`.

Supporting symptoms from the same run:

- 761 of 1428 findings (53%) come from one rule, `ecs-inactive-task-definition`.
- The PDF rendered 208 pages, one finding at a time.
- `grouped_solutions` already contained a correct 45-entry rollup that no
  report consumed.

## Root cause

The triage machinery already exists. None of it is connected.

| Capability | State |
| --- | --- |
| `priority_score()` (`recommendation_queue.py:302`) | Complete and well designed. Only runs inside the unified-queue merge path, so the default native scan never scores. |
| `grouped_solutions` | Built correctly (45 entries with counts, samples, fixes, savings). `reports.py` and `pdf_report.py` never reference it. |
| `REPORT_PROFILES` = executive, technical, remediation, complete | Declared in `models.py`. `report_profile` is stored in the model and has no effect on output. |
| `suggested_actions` "Top priorities" (`result_query.py:162`) | Exists and sorts by `priority` — defeated by the empty field. |
| `result_query` sort (`result_query.py:240`) | Already reads `item["priority"]["score"]` with a `0.0` fallback. Inert, not broken. |
| Contextual risk layer | Does not exist. The only genuinely new component. |

This is a wiring project, not a construction project. That is what keeps it
small.

## Scope

In scope:

1. A contextual risk layer that raises priority for genuinely dangerous
   findings.
2. Wiring `priority_score()` so every finding is scored, not only merged ones.
3. Implementing the four declared report profiles, with `executive` as the new
   default.
4. Making reports consume `grouped_solutions`.
5. Fixing `pdf_report.py:532`, which blocks acceptance criterion 2.

Out of scope — tracked in the roadmap at the end of this document: multi-region
scanning, workload granularity, EKS without kubeconfig, cost estimation depth,
remediation coverage, relationship graph depth, and repositioning the product
narrative.

## Key decisions

**Severity is never modified.** The risk layer changes *priority*, never
`severity`. The catalog remains the source of truth for severity, so
`rules sync` has nothing to overwrite and the layer survives catalog updates.
This also sidesteps the unresolved `aws-misconfig-db` divergence: no upstream
change is required for this work to land.

**Group priority is the maximum of its members, never the sum.** A group of 761
low-risk inactive task definitions must not outrank a group of one containing
the root access key. Summing would invert precisely the pathology being fixed.

**`executive` becomes the default report profile.** Callers who ask for nothing
get top-N plus the grouped rollup. `technical`, `remediation` and `complete`
remain available by parameter.

**Scoring must be idempotent.** Re-scoring an already-scored finding must
produce an identical result, because the unified-queue path will continue to
score during merge.

## Components

### 1. `risk_factors.py` — new

A pure function. No I/O, no AWS calls, no dependency on the scan pipeline.

```python
risk_factors(finding, resource_ref) -> {
    "factors": [
        {
            "id": "root_credential",
            "points": 40,
            "rationale": "Root account credential; compromise bypasses every IAM control.",
        }
    ],
    "total": 40.0,
}
```

Initial factors: root credential, internet-exposed, publicly readable, aged
access key, administrative privilege.

Point values are calibrated against one constraint: acceptance criterion 1 must
hold on the real-account fixture. Absolute values matter less than the
resulting order, so calibration is driven by the ordering test rather than
chosen up front.

Every factor carries a `rationale`. The product's existing discipline is that
no claim ships without evidence; a priority number is a claim, so it must be
defensible. This also makes the layer reviewable by a human who disagrees with
a ranking.

### 2. `priority_score()` — extended

Gains `contextual_risk` as a seventh component beside risk,
freshness_and_confidence, estimated_savings, remediation_readiness,
corroboration and implementation_effort. The 0-100 scale is preserved. This
remains the only place that knows how to turn factors into a number.

### 3. Single stamping point

Apply `priority_score()` to every finding where the assessment result is
assembled, instead of only inside the merge path. One write; `result_query`,
`suggested_actions`, the reports and the PDF all begin working without changes
of their own.

The exact function in `mcp_server.py` is deliberately not named here. That file
is large and the correct seam should be identified during planning rather than
guessed now.

### 4. Report profiles implemented

- `executive` (new default): the 10 highest-priority findings, then the grouped
  rollup, then coverage and limitations. Ten is a starting value, chosen to fit
  a single screen; it is a constant, not a parameter, until there is evidence a
  parameter is needed.
- `technical`: current finding-by-finding behaviour.
- `remediation`: only findings with supported remediation.
- `complete`: everything.

Unknown profile continues to raise `ValueError`. That is input validation, not
a data error.

### 5. Reports consume `grouped_solutions`

`build_report_model` passes the groups through; renderers use them. This is what
removes the 208 pages.

### 6. PDF capability-errors fix

`pdf_report.py:532` calls `len()` on `summary["capability_errors"]`, which
arrives as an `int` on live accounts while the top-level field is a list. Any
account with capability errors — common, an EKS cluster without kubeconfig is
enough — raises `TypeError` on PDF export.

The defect predates this work; it originates in commit `215b848` (0.7.0). It is
pulled in here only because acceptance criterion 2 cannot be verified without
it. The sibling reads of `service_errors` and `rules_skipped` on the same lines
should be checked for the same int/list inconsistency.

## Data flow

```
native scan
   └─> finding {severity, evidence, remediation, cost_estimate, resource_ref}
            │
            ▼
   risk_factors(finding, resource_ref)        new, pure
            │  {factors: [...], total: 40.0}
            ▼
   priority_score(finding + factors)          existing, extended
            │  {score: 92, components: {...}, explanation}
            ▼
   finding["priority"]  ─── single write point
            │
            ├─> grouped_solutions   (existing; now carries group priority = max)
            │
            └─> stored result
                     │
     ┌───────────────┼────────────────────┐
     ▼               ▼                    ▼
 query_results   build_report_model   suggested_actions
 sort=priority   (profile)            "Top priorities"
 already works                        already works
                      │
                      ▼
              md · html · csv · sarif · pdf
```

## Error handling

`risk_factors` never raises. A malformed finding or a missing `resource_ref`
yields an empty factor list, and the base score is still computed. The layer is
additive by construction: at worst it contributes nothing and behaviour
degrades to today's. A 1606-resource scan must not fail because one finding is
shaped oddly.

`priority_score()` is already defensive, using `_mapping()` and defaults
(`or "medium"`, `or 1`) on every read. The extension follows that pattern.

## Testing

| Target | Type |
| --- | --- |
| `risk_factors` | Table-driven unit tests: root credential, public bucket, open security group, aged key, admin policy — and the negative cases, which matter as much |
| Idempotency | Scoring the same finding twice yields an identical result |
| Unified queue | Existing merge-path scores unchanged (backwards compatibility) |
| Ordering | Real-account fixture: the root access key must land in the top 5 |
| Profiles | `executive` output is materially smaller and leads with groups |
| PDF | Export succeeds when `capability_errors` is an int |

The ordering test uses the real account result as a fixture with identifiers
redacted. It is the most valuable test in the set: it encodes the exact failure
that motivated the work — *found the worst thing and delivered it 23rd* — and
starts failing if anyone reintroduces it.

## Acceptance criteria

1. `iam-root-access-key-present` appears in the top 5 of default output
   (currently 23rd).
2. The `executive` PDF is 15 pages or fewer for the same 1428 findings
   (currently 208).
3. The existing 240 tests still pass.

## Observable change

Delivery order changes for every current consumer: alphabetical-within-severity
becomes risk-ranked. This is the intended correction, but it is observable
behaviour and needs a CHANGELOG entry. The default report profile also changes
from `technical` to `executive`.

## Roadmap — remaining sub-projects

Specified separately; listed here so this document reflects the whole
improvement set rather than implying A is all there is.

**B. Point fixes.** Remainder of the PDF/int-list audit beyond line 532.

**C. Scope coverage.** Multi-region scanning; EKS rules without an explicit
kubeconfig (10 rules skipped on the live run); and workload granularity. The
last is the deepest conceptual gap: AWS Well-Architected is defined at
*workload* scope, while Steward offers account-wide and single-resource and
nothing in between.

**D. Evidence depth.** Cost estimates in USD (only 6 of 200 returned a figure
while 65% of findings are cost_optimization); remediation coverage (supported
on 223 of 1428); relationship graph depth (a real S3 bucket review produced a
1-node neighborhood).

**E. Proposition and positioning.** Reframing the 16.8% catalog coverage;
converting the 529 non-native rules into a guided questionnaire, reusing the
contextual-question mechanism that already exists; and leading the pitch with
the defensible differentiators — MCP-native, local with no account data
leaving the machine, pre-deployment IaC review, evidence discipline — rather
than catalog breadth, where AWS-native tooling competes directly.
