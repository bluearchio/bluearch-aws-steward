# Changelog

All notable changes to BlueArch AWS Steward are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Versions marked
as preview are not covered by a stable API compatibility promise.

## [Unreleased]

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
