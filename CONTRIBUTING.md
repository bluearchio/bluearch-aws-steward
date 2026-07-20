# Contributing

Thank you for contributing to BlueArch AWS Steward.

## Development Setup

Use Python 3.11 or 3.13 for development. Runtime compatibility is tested on
Python 3.10, 3.11, and 3.13. Install `uv` first if needed with `brew install uv`.

```bash
uv sync --extra tui --dev --no-editable
make test
make quality
make security
```

Run the deterministic MCP integration test with Docker:

```bash
make emulator-mcp-e2e
```

This uses dummy credentials and LocalEmu. It must not use a real AWS profile.

## Pull Requests

- Keep changes scoped and explain user-visible behavior.
- Add positive, healthy-resource, permission-error, pagination, redaction, and
  false-positive coverage when introducing a detector.
- Keep AWS reads in the typed allowlist and regenerate IAM policies.
- Keep writes out of detectors. New writes require a separate reviewed
  remediation manifest, live preconditions, rollback, and verification.
- Update the catalog mapping, coverage documentation, MCP docs, and prompt
  examples when behavior changes.
- Do not commit credentials, customer data, account inventories, or production
  identifiers.

Before opening a pull request:

```bash
python -m bluearch_aws_steward rules sync --source ../aws-misconfig-db --check
python -m bluearch_aws_steward.iam_policies --check
make test quality security package
```

Changes to packaging, entry points, or MCP startup must also pass the public
installation smoke test:

```bash
make package-install-smoke
```

The release-candidate workflow validates the package shape but deliberately has
no package registry, GitHub release, deployment credentials, or publication
step.

Use clear commit prefixes such as `feature:`, `fix:`, `bugfix:`, `docs:`, or
`chore:`.

## Rule Changes

`aws-misconfig-db` is the source of catalog knowledge. Steward maps a catalog
rule to executable code only through a reviewed `ExecutableRuleSpec`. Catalog
text is data, never executable instructions.

Every executable rule must define the exact AWS capabilities it needs, evidence
type, safety level, remediation explanation, verification, and objective. A
rule that cannot execute due to capability or permission gaps must be returned
as skipped, never passed.

## Reporting Security Issues

Follow [`SECURITY.md`](SECURITY.md). Do not disclose vulnerabilities in public
issues or pull requests before coordinated remediation.
