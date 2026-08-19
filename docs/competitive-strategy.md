# BlueArch AWS Steward Competitive Strategy

## Strategic Thesis

BlueArch AWS Steward should not compete on detector count alone. Configuration
checks are increasingly commoditized, AWS owns authoritative native signals,
Prowler owns broad open-source posture coverage, compliance platforms own audit
workflow, and enterprise CNAPP products own large-scale correlation.

Steward should own the shortest safe path from a recommendation to a reviewed
and verified fix inside Codex, Claude Code, Cursor, and other MCP hosts.

The product category is:

> A local, MCP-native AWS recommendation-to-remediation engine.

Within that category, Steward's defensible advantage is being a genuine AWS
expert rather than a benchmark-tuned tool: a deterministic evaluation engine
that computes what AWS will actually do — IAM evaluation order, policy-layer
precedence, condition semantics — exactly, like a compiler, where language
models can only approximate from training. The north-star outcome is model
uplift: a small model plus Steward should outperform both the small model and
the next model class alone, at a lower total cost per task. Enabling weak
models to operate above their class is the product's use case.

## Market Boundaries

| Category | Existing strength | Steward relationship |
| --- | --- | --- |
| AWS native services | Authoritative configuration, security, cost, health, and optimization signals | Consume signals, refresh evidence, and complete the fix workflow. |
| Open-source CSPM | Broad check libraries and compliance mappings | Import findings rather than duplicating every detector. |
| Compliance automation | Evidence, controls, policy, and audit workflow | Produce technical evidence and developer-ready remediation. |
| Enterprise CNAPP | Graphs, attack paths, broad correlation, and organization scale | Offer a focused local workflow for AWS developers and smaller teams. |
| IaC and policy tools | Build-time checks and policy enforcement | Connect live findings to source, patch them, validate them, and verify AWS. |
| Frontier LLM agents with a raw CLI | Broad reasoning; approximate AWS semantics from training | Compute evaluation exactly, hand the agent evidence-grade verdicts, and replace multi-call exploration with one diagnostic call. |

Steward is not another CSPM dashboard, a persistent inventory, or an autonomous
AWS administrator.

## Product Priorities

1. **Finding aggregation**: normalize and deduplicate native findings, Security
   Hub, Prowler, Compute Optimizer, and Cost Optimization Hub.
2. **Fix in IaC**: map a live resource to Terraform, CloudFormation, CDK, or
   Kubernetes, then generate and validate a minimal patch.
3. **Investigation playbooks**: diagnose EKS performance, Lambda errors, RDS
   pressure, ALB health, IAM privilege, and S3 exposure using live evidence and
   repository context. The deterministic policy-denial explainer
   (`bluearch_explain_denial`) is the template: one read-only call that names
   the exact blocking statement with verbatim evidence, declared unknowns, and
   a next step — never a confident verdict without read evidence.
4. **Business-value ranking**: prioritize by risk reduction, estimated savings,
   confidence, blast radius, implementation effort, ownership, and
   Well-Architected pillar.
5. **Safe remediation**: expose evidence, preconditions, IAM, exact changes,
   rollback, plan digest, individual approval, and post-fix verification.
6. **Frictionless MCP onboarding**: make installation, AWS context selection,
   partial progress, concise results, and reports predictable across agent
   hosts.

Selective rule additions remain important when they unlock one of these
workflows. Rule count itself is not the product's primary success metric.

## Packaging Boundary

### Open Source

- Permanent 100-rule high-confidence baseline.
- Local MCP and single-account assessment.
- LocalEmu fixtures and public coverage matrix.
- Explanations and no-write remediation plans.
- JSON, CSV, Markdown, SARIF, HTML, and basic PDF reports.
- Limited guarded low-risk remediation.
- Security Hub and Prowler import.

### Commercial Candidates

- Compute Optimizer and Cost Optimization Hub workflow packs.
- Advanced EKS, FinOps, and performance investigations.
- Multi-account and all-Region orchestration.
- Live-resource-to-IaC source mapping and pull-request generation.
- Advanced guarded remediation and approval workflows.
- Scheduled comparison, ownership, policy packs, and expiring exceptions.
- GitHub, Jira, Slack, and branded reporting integrations.
- Team support and governance.

Prefer workspace or team pricing. Per-finding pricing discourages broad scans
and makes successful detection feel punitive. Premium rule packs may support a
workflow, but the customer should pay for reduced investigation and remediation
time rather than access to a larger number of checks.

## Flagship Workflow

```text
import external findings
  -> add fresh Steward evidence
  -> deduplicate and prioritize
  -> map selected finding to source
  -> generate a minimal patch
  -> run plan, policy, and repository validation
  -> obtain explicit approval
  -> deploy through the user's normal workflow
  -> re-read AWS and export verification evidence
```

## Expert Trajectory

The diagnosis engine advances in measured phases; each phase must move a
benchmark ruler, and no phase advances before the previous ruler reads
(delivery sequencing lives in [`expansion-plan.md`](expansion-plan.md)):

1. **Diagnosis honesty** — no confident verdict without read evidence: real
   KMS key-policy precedence, `insufficient_access` when reads are missing,
   attached-to-inline policy fallback, action-first next blocks, graceful
   partial coverage on denied reads.
2. **Call economy** — one diagnostic call replaces the five-to-eight CLI
   reads an agent performs alone: the relevant policy graph in one snapshot,
   next-bearing responses that eliminate round trips, error-message parsing
   that fills arguments.
3. **Evaluation-engine expansion** — promote declared-unknown layers to
   actually-evaluated: SCPs, permission boundaries, session policies, VPC
   endpoint policies, full condition-key semantics. This exactness is the
   moat no model alone reaches.
4. **Wider diagnosable surface** — non-denial outcomes without misleading
   verdicts (service-managed flows such as SQS redrive via
   `RedriveAllowPolicy`), and the one-shot architectural review
   (`review_resource`), the core product.

**Anti-overfit rule:** every change motivated by a benchmark failure must
first be defensible as correct behavior on a real AWS account. A change that
only makes sense to pass a scenario does not ship. Benchmark scenarios are
evidence of real-world failure classes, never the specification. Hardcoding
by resource or scenario name is prohibited.

## Success Measures

| Area | Target direction |
| --- | --- |
| Activation | First useful recommendation in under ten minutes from install. |
| Signal quality | Increasing percentage of findings with complete evidence, confidence, and an actionable next step. |
| Noise | Fewer duplicate and confirmed false-positive recommendations. |
| Remediation | Lower median time from finding to validated patch or plan. |
| Verification | Increasing percentage of fixes verified against live AWS after deployment. |
| Model uplift | A small model with Steward outperforms the small model and the next model class alone on diagnosis-graded benchmarks. |
| Task cost | Fewer total tool calls (and tokens) per solved task with Steward than without it. |
| Commercial | Conversion for IaC remediation, investigation, multi-account workflow, and governance rather than raw rule access. |

## Decision Test

Before accepting a roadmap item, answer:

1. Does it shorten the path from finding to verified fix?
2. Does it add evidence or context that existing scanners do not provide?
3. Can it remain local-first and keep customer credentials and inventory under
   customer control?
4. Can it be demonstrated as an observable user outcome?
5. Is it feasible for a small team to support safely?
6. If a benchmark failure motivated it, is it defensible as correct behavior
   on a real AWS account first?

Items that only increase the check count should normally rank below signal
aggregation, source mapping, investigation, remediation, and onboarding work.

## Documentation Ownership

- This document explains competitive positioning and packaging.
- [`expansion-plan.md`](expansion-plan.md) owns delivery sequencing and release
  gates.
- [`future-architecture.md`](future-architecture.md) owns technical boundaries.
- [`expansion-backlog.json`](expansion-backlog.json) owns candidate rule and
  fixture status.
- [`rule-coverage.md`](rule-coverage.md) owns released native coverage.

Review vendor comparisons and packaging assumptions before each major roadmap
revision because external product capabilities change over time.
