# Security Threat Model

This document defines the current Steward security boundary and the scope that
must be independently reviewed before a stable release.

## Assets

- user-owned AWS credentials and SSO sessions;
- AWS resource configuration and metadata;
- assessment evidence and exported reports;
- short-lived remediation plans and digests;
- local source code and IaC repositories inspected by the MCP client; and
- the integrity of bundled rules, generated IAM policies, and package artifacts.

## Trust Boundaries

1. Natural-language user and model output entering MCP tool arguments.
2. The local MCP client launching the Steward stdio process.
3. Imported Prowler and AWS recommendation JSON entering normalization.
4. Steward calling AWS through the SDK or explicit AWS CLI operations.
5. Generated reports and future IaC patches crossing into the local filesystem.
6. Optional guarded remediation crossing from read-only analysis into AWS writes.

Catalog text, imported findings, AWS resource names/tags, and model-generated
arguments are untrusted data.

## Threats And Current Controls

| Threat | Current controls | Residual risk |
| --- | --- | --- |
| Prompt injection in imported findings or resource metadata | Imported fields are normalized as data, size-limited, redacted, and never dispatched as tools. | MCP clients can still render hostile text; independent client-side testing is required. |
| Credential exfiltration through a custom AWS endpoint | Explicit endpoints are limited to HTTP(S) loopback hosts; live AWS uses normal endpoint resolution. Loopback emulators without a profile receive only dummy credentials. | DNS behavior of compatibility hostnames and proxy configuration require review. |
| Arbitrary shell execution | AWS CLI operations come from a typed allowlist and use argument arrays without a shell. | New operation mappings require code review and generated-policy checks. |
| Excessive AWS permissions | Separate generated read and remediation policies; missing permissions are reported as capability errors. | Users may still run Steward with administrator credentials despite guidance. |
| Unapproved AWS writes | Writes are separate from detectors and require a server-held plan, expiry, digest, live revalidation, unchanged context, and `allow_write=true`. | The current MCP approval depends on the client representing user intent correctly. |
| Destructive or broad remediation | Delete, stop, traffic, migration, credential rotation, and permission-removal workflows remain planning-only. | Future IaC and remediation expansion increases blast radius. |
| File overwrite through report export | Reports use exclusive file creation and reject existing paths. Generated reports are ignored by Git. | A user-approved new path can still create directories within the process permissions. |
| Sensitive evidence leakage | Evidence is minimal and redacted; ECS environment values and complete IAM documents are excluded. | New detectors can accidentally expose fields without dedicated redaction tests. |
| Denial of service from large accounts/imports | Imported payload limits, bounded conversational output, cursor pagination, cancellation, result expiry, and finding guards. | Large live accounts can still consume significant API quota, memory, and time. |
| Dependency or build compromise | Locked dependencies, pinned Actions, CodeQL, Bandit, dependency audit, secret scan, clean package build, and isolated install smoke. | PyPI publication, provenance, and an external audit are not configured yet. |
| Cross-account or Region confusion | Account/Region/resource identity is included in evidence and remediation plans. | Multi-account/multi-Region orchestration is not implemented and must preserve isolation. |

## Security Invariants

- No assessment applies an AWS write.
- A skipped, failed, suppressed, or unevaluated rule is never reported as passing.
- No AWS credential or SSO token is accepted through a conversation or stored by Steward.
- No imported content can select an operation or bypass the typed AWS allowlist.
- No report export overwrites an existing file.
- No explicit remote endpoint receives a signed AWS request.
- Every AWS write is tied to one exact, fresh, user-approved plan.

## Independent Review Scope

The stable-release review should include:

1. MCP JSON-RPC parsing, elicitation/resume behavior, and approval confusion.
2. Prompt injection through imported JSON, tags, names, and evidence strings.
3. Endpoint, proxy, DNS, and credential-chain behavior.
4. All read and write operation registries and generated IAM policies.
5. Plan storage, expiry, digest, TOCTOU revalidation, rollback, and verification.
6. Report paths, symlinks, filesystem permissions, and sensitive evidence.
7. Package build, dependency lock, Actions permissions, provenance, and release identity.
8. Resource/time exhaustion and API-throttling behavior on large accounts.

An internal scan can prepare this review but cannot satisfy the independent
review requirement. Critical and high findings must be fixed or explicitly
accepted by project maintainers before a stable release.
