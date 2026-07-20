# Public Release Readiness

This checklist converts the current launch blockers into verifiable work. It
distinguishes a public technical preview from a stable release. Opening the
source and publishing a stable product are separate decisions.

## Launch Levels

### Technical Preview

The preview is a local, single-account, single-Region, read-only-first MCP tool.
Remediation is experimental and limited to explicitly documented guarded
operations. The preview must not be described as a complete CSPM, an autonomous
AWS administrator, or an organization-wide compliance product.

### Stable Release

A stable release requires measured recommendation quality, durable local policy
controls, multi-account and multi-Region orchestration, stable source contracts,
and a reviewed support and security process.

## Blocker Register

| Blocker | Current action | Preview gate | Stable gate |
| --- | --- | --- | --- |
| Large unpublished implementation | Review, commit, push, and retain a clean tree. | Remote branch contains the reviewed implementation. | Release tag is cut only from a protected green commit. |
| CI has not run remotely | Run CI, CodeQL, LocalEmu MCP E2E, and release-candidate validation. | Every required workflow is green on the pushed commit. | Required checks and branch protection prevent bypass. |
| Developer-oriented installation | Validate wheel, `uv tool`, `uvx`, entry points, upgrades, and MCP config. | A new user completes install and first smoke test without cloning. | PyPI trusted publishing, provenance, rollback, and upgrade policy are operational. |
| Overwhelming result volume | Implement progressive disclosure and task-oriented queues. | Default response contains summary plus a bounded top-action queue. | Account benchmarks show acceptable precision and action completion. |
| No accepted-risk workflow | Define local policy packs, suppressions, ownership, reason, and expiry. | Document temporary rule/resource filtering and all limitations. | Versioned local policy schema and expiring exceptions are implemented and tested. |
| Single-account/single-Region scope | Design Organizations discovery, role assumption, Region selection, budgets, and aggregation. | Limitation is prominent in onboarding and reports. | Failure-isolated multi-account/multi-Region assessment is implemented. |
| Limited remediation | Classify rules as explain-only, IaC-fixable, guarded AWS write, or prohibited. | Read-only remains default and supported writes are explicit. | IaC patch/review flow and a broader safe remediation set are proven. |
| External-source drift | Pin supported source/schema versions and keep contract fixtures. | Prowler compatibility matrix and import caveats are published. | Versioned adapters, fixture corpus, deprecation window, and drift CI exist. |
| Independent security review | Maintain a threat model and commission an external review. | Local security gates and threat model are complete; preview is labeled. | Independent findings are remediated or formally accepted before GA. |
| Generated/private artifacts | Ignore generated reports and remove local system files. | Secret/history scan and clean Git tree are verified. | Release automation rejects forbidden artifacts and sensitive fixtures. |

## Workstreams

### 1. Source And CI Baseline

- [x] Commit the `0.7.0` implementation locally with generated catalogs and IAM policy in sync.
- [ ] Publish the validated clean-history root commit to the recreated repository.
- [ ] Verify successful remote CI, CodeQL, LocalEmu E2E, and release-candidate validation runs.
- [x] Keep Actions pinned to immutable commit SHAs.
- [ ] Enable branch protection after the first green remote run.
- [ ] Require pull requests and successful checks for future changes.
- [x] Group weekly Dependabot updates into at most one Python PR and one GitHub
  Actions PR per cycle.

### 2. Public Distribution

- [x] Define `uv tool install bluearch-aws-steward` as the primary install path.
- [x] Generate installed and exact-version `uvx` MCP configurations.
- [x] Smoke-test the built wheel as an isolated `uv` tool.
- [x] Add a validation-only release-candidate pipeline.
- [ ] Reserve the PyPI project and configure trusted publishing later.
- [ ] Test a prerelease through TestPyPI.
- [ ] Validate install, upgrade, and uninstall on macOS and Linux.
- [ ] Add package provenance/SBOM and signed release attestations.

#### CI Budget Controls

- Pull requests run unit tests only on the minimum and newest supported Python
  versions, plus quality/package and CodeQL checks.
- The Docker-based LocalEmu E2E has a separate path-filtered workflow. It runs
  on relevant `main` changes and manual dispatch, not on every workflow or
  documentation update.
- Release-candidate validation is manual and must be started only for an actual
  preview or release decision.
- Documentation-only changes skip CI and CodeQL.
- Every job has a short timeout, and concurrency cancellation stops superseded
  runs on the same branch.

### 3. Recommendation Experience

- [x] Define the progressive result contract in `result-experience-plan.md`.
- [ ] Return an executive summary and bounded top-action queue by default.
- [ ] Add facets for objective, service, severity, source, confidence, effort,
  owner, remediation safety, and freshness.
- [ ] Explain every priority score and show why an item should be handled now.
- [ ] Measure precision using reviewed findings from at least three AWS accounts.
- [ ] Track false positive, accepted risk, duplicate, actioned, and unresolved outcomes.

### 4. Local Policy And Exceptions

- [ ] Define `.bluearch/steward.yaml` with a versioned JSON Schema.
- [ ] Support rule, resource, account, Region, and tag-based policy scopes.
- [ ] Require owner, reason, creation time, expiry, and ticket/reference for suppressions.
- [ ] Keep policy local and user-owned; do not add hosted login or telemetry.
- [ ] Include applied policy and expired-exception warnings in every report.
- [ ] Never convert a skipped or suppressed rule into a passing result.

### 5. Multi-Account And Multi-Region

- [ ] Discover accounts through Organizations only with explicit user approval.
- [ ] Use configured role names/external IDs without collecting credentials.
- [ ] Distinguish global and regional services to avoid duplicate evaluation.
- [ ] Add account/Region concurrency and API request budgets.
- [ ] Preserve partial results and exact per-account capability failures.
- [ ] Aggregate recommendations without losing account and Region identity.

### 6. Remediation And IaC

- [ ] Map findings to CloudFormation, Terraform, CDK, or source ownership evidence.
- [ ] Generate a patch and tests before considering a live AWS write.
- [ ] Require per-plan user approval; never batch-approve destructive changes.
- [ ] Keep deletes, traffic changes, credential rotation, and migrations planning-only.
- [ ] Add post-change verification and rollback evidence to reports.
- [ ] Expand guarded writes only after threat modeling and dedicated integration tests.

### 7. Source Compatibility

- [x] Publish a matrix of Steward, Prowler, ASFF, Compute Optimizer, and Cost
  Optimization Hub schemas tested in CI.
- [ ] Keep sanitized fixtures for every supported schema version.
- [ ] Reject unknown major versions with an actionable error instead of guessing.
- [ ] Preserve source timestamp, mapping confidence, receipt, and raw-data redaction.
- [ ] Run adapter contract tests on every dependency update.

The initial tested matrix is published in `source-compatibility.md`; explicit
contract identifiers and drift CI remain stable-release work.

### 8. Security And Operations

- [x] Document assets, trust boundaries, attacker capabilities, MCP threats,
  imported-data prompt injection, file-output safety, and AWS write controls.
- [ ] Commission an independent review of the MCP server and remediation boundary.
- [ ] Enable GitHub private vulnerability reporting and verify the response path.
- [ ] Define supported versions, response SLA, release rollback, and revocation procedures.
- [x] Run Gitleaks, detect-secrets, Bandit, and dependency-audit checks against
  the clean public snapshot and its complete one-commit history.

The internal threat model is published in `security-threat-model.md`. The
independent review remains intentionally open and cannot be self-certified.

## Technical Preview Gate

Publish a preview only when all items below have evidence:

1. The pushed commit has green CI, CodeQL, LocalEmu E2E, and package validation.
2. A clean machine can install, start MCP, complete a read-only assessment, and uninstall.
3. The default result is bounded and explains coverage and limitations.
4. Documentation prominently states single-account/single-Region and remediation limits.
5. No credentials, customer identifiers, generated reports, or private operations exist in Git history.
6. Security threat modeling is complete and no known critical/high issue remains.
7. The version is marked `alpha`, `beta`, or `preview`, not stable.

## Stable Release Gate

Stable release additionally requires:

1. Review of real findings in at least three structurally different AWS accounts.
2. Measured false-positive and recommendation-action rates with agreed thresholds.
3. Local policy packs and expiring accepted-risk records.
4. Multi-account/multi-Region failure-isolated execution.
5. Stable external-source compatibility contracts.
6. Independent security review closure.
7. Published support, upgrade, deprecation, and incident-response procedures.
