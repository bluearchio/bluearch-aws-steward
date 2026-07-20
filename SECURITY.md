# Security Policy

## Supported Versions

Security fixes are applied to the latest released minor version. Upgrade to the
latest release before reporting behavior that may already be fixed.

## Report A Vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub private
vulnerability reporting in the repository's Security tab. If that surface is
unavailable, email `support@bluearch.io` with:

- the affected version or commit;
- impact and prerequisites;
- minimal reproduction steps;
- whether AWS write access or sensitive data is involved; and
- any suggested mitigation.

Do not include real credentials, session tokens, customer data, or complete AWS
resource inventories. Use redacted identifiers and a dedicated test account.

BlueArch will acknowledge a complete report within five business days, assess
severity, coordinate a fix and disclosure date, and credit reporters who want
public attribution. Please allow a reasonable remediation window before public
disclosure.

## Security Boundary

Steward runs locally with user-owned AWS credentials. AWS is the source of
truth; assessment state is kept in memory for 15 minutes and is not a durable
inventory. The project has no hosted login, BlueArch telemetry, or BlueArch Core
dependency.

Scanning uses an explicit read-operation allowlist. Write operations are kept
separate and require a server-held short-lived plan, live revalidation, a plan
digest, and `allow_write=true`. Never grant the remediation policy to a routine
read-only role.

See [`iam/read-policy.json`](iam/read-policy.json) and
[`iam/remediation-policy.json`](iam/remediation-policy.json) for generated
reference policies.

Explicit AWS endpoints are restricted to HTTP(S) loopback emulators so signed
AWS requests cannot be redirected to a remote host. Report exports create new
files and refuse to overwrite existing paths. The full threat model and
remaining review scope are documented in
[`docs/security-threat-model.md`](docs/security-threat-model.md).
