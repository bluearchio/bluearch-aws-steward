# Changelog

All notable changes to BlueArch AWS Steward are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Versions marked
as preview are not covered by a stable API compatibility promise.

## [Unreleased]

### Added

- New native rule `s3-policy-public-read` (high severity) that flags bucket
  policies granting read access to a public principal, including when the
  public access block already blocks the exposure. This closes the detection
  gap found in benchmark sweep-2026-08-12, where a public-read policy became
  invisible to every S3 rule once the public access block was enabled.

### Changed

- `bluearch_apply_remediation` now performs an outcome check after the write.
  When the applied change removes the original finding but a mapped residual
  exposure remains (for `s3-public-bucket`: the bucket policy still grants
  public access), the response status is `applied_with_residual_risk` with a
  `residual_risks` list instead of an unqualified "verified clean" signal.
  Benchmark trials showed agents rationally trusted the previous
  false-positive completion message and stopped before the resource was safe.

## [0.9.0b1] - Preview candidate

### Added

- Contextual Well-Architected reviews that focus on an explicit live resource,
  proposed Terraform or CloudFormation resource, or user-selected service
  instead of scanning the whole account by default.
- Five versioned knowledge-pack families covering all 17 executable runtime
  scopes, with validated mappings between native rules and applicable
  Well-Architected practices.
- A bounded architecture-neighborhood graph with typed relationships,
  provenance, confidence, timestamps, explicit unknowns, a 25-node limit, and
  a 50-operation read budget.
- Safe Terraform HCL, Terraform plan JSON, and CloudFormation JSON/YAML parsing
  with workspace confinement, sensitive-file rejection, unresolved-expression
  handling, and no source modification.
- Contextual focus, questions, WAF ledger, excluded scope, read ledger,
  recommendations, and limitations in JSON, CSV, Markdown, HTML, SARIF, and PDF
  reports.
- Natural-language focus resolution for all 17 runtime scopes. Ten scopes,
  including EFS, KMS, ECS, IAM, and Secrets Manager, previously required an ARN
  or scheme URI because plain-language phrasing was refused.
  Vague and ambiguous prompts are still refused rather than guessed.
- Golden contextual scenarios and a real stdio MCP LocalEmu gate that prove
  focused collection, no unrelated service reads, complete provenance, and
  zero writes.

### Changed

- Findings are now ranked by contextual risk instead of alphabetically within
  severity. Contextual risk is a ranking tier of its own: root credentials,
  publicly reachable resources and internet-exposed administrative ports rank
  above every finding without contextual risk, whatever its catalog severity or
  composite score. Delivery order changes for every consumer.
- The default report profile is now `executive`, which leads with the ten
  highest-priority findings and the grouped rollup. Request `technical`,
  `remediation` or `complete` for the previous finding-by-finding output.
  Summary totals continue to reflect every finding; only the displayed list is
  capped, and Markdown, HTML and PDF state how many findings they show out of
  the total. CSV, SARIF and JSON always serialise the complete finding set.
- All four report profiles now behave differently: `remediation` reports only
  findings whose remediation Steward supports, and `complete` reports every
  finding with no caps at all.
- Full-account assessment now requires explicit full-scan intent; ambiguous
  prompts return guided focus choices instead of guessing a resource.
- Assessment objectives influence recommendation ranking but do not suppress a
  confirmed high-impact concern from another Well-Architected pillar.
- Resource details now include the captured architecture neighborhood and
  contextual Well-Architected practices.

### Fixed

- A prompt naming several Well-Architected pillars is now assessed against all
  of them. Objective inference returned the first pillar it recognised, so an
  account-wide request naming five pillars was filtered to cost rules and
  returned a fraction of the available findings with nothing reporting the
  narrowing. A prompt naming one pillar still resolves to that pillar.
- Account-wide reports now name the Region and provider they were observed in,
  read from the scan's routing record. Markdown and HTML printed `unknown` and
  CSV left the column empty on every row, in the formats most likely to be
  filed or ingested elsewhere.
- PDF export no longer fails with `TypeError` when a summary reports capability
  errors, service errors or skipped rules as counts rather than lists.
- Grouped rollups in Markdown, HTML and PDF reports no longer print `None` and a
  zero priority for contextual architecture reviews, whose groups use a
  different shape from native solution-card groups.
- Contextual risk factors are now detected for raw scan findings, not only for
  translated opportunities, so the unified recommendation queue no longer holds
  two contradictory priorities for the same issue.

## [0.8.0b1] - Preview candidate

### Added

- A read-only `bluearch_investigate_resource` MCP tool for deletion-readiness
  investigations. The initial EBS, Elastic IP, ECS task-definition, EFS, and
  Lambda investigators revalidate live state, gather direct and optional AWS
  Config relationships, expose recovery and ownership context, and preserve
  unknowns without declaring a resource safe to delete.
- A Docker-backed healthy ECS control fixture that proves a task and container
  are running, plus a hybrid LocalEmu and four-node `kind` EKS functional lab.
- Idle RDS deletion readiness and operational diagnosis for RDS CPU,
  rightsizing, read scaling, and public exposure plus ECS service health,
  platform version, and unsafe task definitions. Diagnoses return redacted
  evidence and unconfirmed hypotheses, never automatic changes.
- Twenty read-only EKS and Kubernetes rules covering control-plane, node-group,
  add-on, workload configuration, runtime, performance, and cost risks.
- Rule-specific EKS investigations that correlate AWS and inside-cluster
  evidence while excluding Secrets, logs, exec, proxy, port-forward, and writes.
- Planning-only Terraform, CloudFormation, eksctl, Kubernetes YAML, Helm, and
  Kustomize patch generation with digest verification and temporary validation.
- A real stdio MCP product gate that validates all 20 rules, investigations,
  patch flow, post-fix assessment, PDF export, healthy controls, and zero writes.

## [0.7.0b4] - Preview candidate

### Changed

- The MCP workflow is now a branded, CDN-hosted diagram that renders
  consistently on GitHub and PyPI.

## [0.7.0b3] - Preview candidate

### Fixed

- TestPyPI verification installs the exact SHA-256-pinned wheel and resolves
  dependencies only from PyPI, avoiding cross-index dependency confusion.

## [0.7.0b2] - Preview candidate

### Fixed

- Release provenance checks now use the read-only GitHub compare API, allowing
  private repositories to keep checkout credentials unpersisted.

## [0.7.0b1] - Preview candidate

### Added

- A unified recommendation queue for native Steward, Prowler, Security Hub,
  Compute Optimizer, and Cost Optimization Hub signals.
- One hundred native AWS rules across sixteen runtime scopes.
- Interactive, multi-objective MCP assessments with partial results and
  cancellation.
- JSON, Markdown, HTML, CSV, SARIF, and PDF report exports.
- Deterministic LocalEmu coverage and real stdio MCP validation.
- Versioned `uvx` MCP configuration and release-candidate package validation.
- Safe MCP client registration for Codex, Cursor, and Claude Code, including
  dry runs, backups, and targeted uninstall.
- Tag-only TestPyPI publishing and draft-release-approved PyPI Trusted Publishing.

### Changed

- AWS remains the point-in-time source of truth; assessment state is ephemeral.
- Findings now include structured evidence, source provenance, confidence,
  freshness, priority, risk, and remediation safety.

### Security

- AWS reads use a typed operation allowlist and generated IAM reference policy.
- Guarded writes require an exact short-lived plan, digest, live revalidation,
  and explicit approval.
