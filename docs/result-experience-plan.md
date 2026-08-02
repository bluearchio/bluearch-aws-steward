# Result Experience Plan

Large AWS accounts can produce more than one thousand valid recommendations.
Returning all of them in conversation is technically complete but operationally
poor. Steward should preserve the complete snapshot while presenting a small,
explainable action queue.

## Design Principles

1. Summary first, details on demand.
2. Prioritize work, not finding volume.
3. Never hide coverage gaps, skipped rules, or failed sources.
4. Separate observed facts from inferred risk and estimated savings.
5. Keep the complete result queryable and exportable without rescanning AWS.
6. Require explicit approval for every write plan.

## Default MCP Response

The terminal assessment response should contain five bounded sections:

### 1. Assessment Receipt

- account and Region;
- observation time and freshness;
- requested and completed sources/services;
- resources scanned and recommendations after deduplication;
- capability errors, incomplete sources, skipped rules, and coverage;
- explicit confirmation that no AWS writes were applied.

### 2. Outcome Scorecard

Show findings and confidence by objective:

- security;
- reliability;
- cost optimization;
- operations;
- performance; and
- sustainability when supported by evidence.

A score must describe its denominator and evaluated coverage. It must not imply
that unevaluated catalog rules passed.

### 3. Top Action Queue

Return at most ten recommendations by default. Each action card contains:

- priority and severity;
- resource and owner when known;
- concise observed evidence;
- impact and why it matters now;
- source corroboration and freshness;
- confidence and score explanation;
- estimated monthly savings or `not_estimated`;
- effort and blast-radius estimate;
- remediation mode: explain-only, IaC patch, guarded AWS write, or prohibited;
- next safe action.

The user can request the next page or filter the complete in-memory result.

### 4. Portfolio View

Group the remaining queue into concise facets rather than listing resources:

- service;
- objective;
- severity;
- source;
- confidence;
- remediation safety;
- estimated effort;
- owner/team; and
- account/Region when orchestration is implemented.

### 5. Next Decisions

Offer specific actions through MCP choices:

- inspect the top recommendation;
- focus on a service or objective;
- show quick wins;
- show highest-confidence savings;
- create a read-only remediation plan;
- mark an item for accepted-risk review; or
- generate PDF/HTML/CSV/SARIF report.

## Priority Model

The priority score should remain explainable and include independent components:

```text
priority = impact + exploitability/urgency + corroboration + confidence
         + savings + policy importance - effort - blast radius - staleness
```

Every component must be returned with its contribution. Missing savings or
usage metrics must remain unknown and must not be interpreted as zero.

Recommended bands:

| Band | Meaning | Default treatment |
| --- | --- | --- |
| P0 | Immediate critical exposure or active high-impact failure. | Show first and require explicit acknowledgement. |
| P1 | High-confidence, high-impact work. | Include in the top action queue. |
| P2 | Important planned remediation. | Group and expose through filters. |
| P3 | Hygiene, optimization, or context-dependent recommendation. | Keep queryable; do not flood the conversation. |
| Review | Missing context, conflicting sources, or low confidence. | Ask for owner/policy context before prioritizing. |

## Noise Controls

Steward needs user-owned local policy rather than silently weakening rules.
The planned policy model supports:

- mandatory policy packs;
- environment-aware severity overrides;
- tag-based ownership;
- temporary suppression with reason and expiry;
- accepted risk with approver and reference;
- resource/rule exclusions;
- minimum confidence and savings thresholds for conversational display.

Suppressed and accepted-risk items remain in reports and counts. They are never
reported as passing. Expired exceptions return to the active queue.

## Validation Program

Before stable release, run blind review on at least three AWS accounts:

1. Export the complete result and select a stratified sample by service,
   severity, source, and confidence.
2. Have an AWS owner label each item as valid/actionable, valid/accepted risk,
   duplicate, stale, insufficient context, or false positive.
3. Measure precision, duplicate rate, accepted-risk rate, and top-ten actionability.
4. Tune mappings and priority weights without hiding low-confidence evidence.
5. Record only aggregate local metrics; do not add hosted telemetry by default.

Initial preview targets:

- at least 80% of the top ten labeled valid and actionable;
- less than 5% duplicate recommendations after correlation;
- 100% of displayed items include evidence, confidence, freshness, and safety;
- 100% of skipped rules and incomplete sources disclosed;
- zero write operations without an exact approved plan.

## Delivery Sequence

1. Add the bounded terminal summary and top-ten queue.
2. Add complete facets and cursor pagination through `bluearch_query_results`.
3. Add priority explanations and effort/blast-radius fields.
4. Add local ownership and policy-pack schema.

## Deletion-Readiness Evidence

The first implementation covers unattached EBS volumes, unassociated Elastic
IPs, inactive ECS task definitions, inactive unmounted EFS file systems, unused
Lambda functions, and idle RDS instances through `bluearch_investigate_resource`.
The same tool produces operational-diagnosis dossiers for RDS CPU, rightsizing,
read-scaling, and exposure findings plus ECS health, platform, and unsafe
task-definition findings. It produces a separate read-only dossier after a
finding is revalidated. The dossier distinguishes:

- live AWS facts and observed relationships;
- recovery evidence and its limitations;
- selected ownership and environment tags;
- optional AWS Config and Route 53 relationship coverage;
- capability errors and evidence that could not be collected; and
- explicit human confirmations that cannot be inferred from AWS.

Evidence coverage is not a safety probability. The tool never reports a
resource as safe to delete, and missing relationships or permissions remain
unknown rather than passing. IaC/source references, application traffic,
external DNS, allowlists, and business procedures remain future evidence
adapters.

Operational dossiers additionally distinguish observed facts, unconfirmed
hypotheses, missing logs/traces/code context, planning-only candidate changes,
and post-change verification. `root_cause_confirmed` remains false until a
future investigator obtains service-specific evidence that supports that claim.
5. Add expiring suppression and accepted-risk records.
6. Run the multi-account recommendation-quality benchmark.
7. Promote the contract to stable only after thresholds are met.
