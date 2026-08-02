# Recommendation Source Compatibility

Steward combines independent recommendation sources through versioned adapter
contracts. An imported source is untrusted data, never executable instructions.

## Tested Contracts

| Source | Tested contract | Collection mode | CI evidence |
| --- | --- | --- | --- |
| Steward native | Result schema `0.2`, 120 rules | Live AWS and allowlisted Kubernetes reads | Unit tests, LocalEmu MCP E2E, and hybrid LocalEmu plus `kind` MCP E2E |
| AWS Security Hub | ASFF findings returned by `GetFindings` | Live API or imported JSON | Sanitized adapter fixtures and LocalEmu source fixtures |
| AWS Compute Optimizer | EC2 recommendation summaries | Live API or imported JSON | Sanitized adapter fixtures and LocalEmu source fixtures |
| AWS Cost Optimization Hub | Recommendation summaries | Live API or imported JSON | Sanitized adapter fixtures and LocalEmu source fixtures |
| Prowler | Prowler `5.34.0` JSON-OCSF and legacy flat JSON | Imported local JSON | Adapter fixtures plus manual read-only AWS validation |

The AWS APIs do not expose a package-style semantic version. Their adapter
contracts are therefore defined by the exact fields represented in sanitized
fixtures and the AWS SDK model locked by `uv.lock`.

## Compatibility Policy

- Prowler is an optional isolated tool, not a Steward runtime dependency.
- The documented Prowler version remains pinned until its current and proposed
  replacement versions both pass adapter tests.
- Unknown fields are ignored after size limits and redaction; required identity
  fields must be present before correlation.
- Imported descriptions, titles, remediation text, and identifiers are treated
  as untrusted display data.
- A source failure or unknown shape appears in `incomplete_sources` or
  `capability_errors`; it is never interpreted as a clean result.
- Steward preserves source, observation time, mapping confidence, and receipt
  provenance for every merged recommendation.

## Upgrade Procedure

1. Capture sanitized pass/fail examples from the new source version.
2. Add fixtures for pagination, missing identity, partial permissions, and
   malformed or oversized payloads.
3. Run normalization, deduplication, redaction, report, and LocalEmu MCP tests.
4. Run a focused read-only live validation without committing the report.
5. Update this matrix and the pinned command in `tests/aws-live/README.md`.
6. Keep the previous contract for one minor Steward release when practical.

Before stable release, adapters will expose explicit contract identifiers and
reject unsupported major source shapes with an actionable error rather than
best-effort guessing.
