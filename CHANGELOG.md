# Changelog

All notable changes to BlueArch AWS Steward are documented in this file.

The project follows [Semantic Versioning](https://semver.org/). Versions marked
as preview are not covered by a stable API compatibility promise.

## [Unreleased]

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
