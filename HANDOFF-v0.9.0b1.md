# Steward v0.9.0b1 Implementation Handoff

## Objective

Finish the approved `Steward v0.9.0b1: Contextual Well-Architected Reviews`
implementation. Do not publish, commit, or push unless the user explicitly asks.
Do not run the Codex Security plugin; the user explicitly disabled it because it
breaks their Codex session.

Repository:

```text
/Users/arturhenrique/Documents/bluearch/bluearch-aws-steward
```

Branch at task start: `main`, clean and synchronized at:

```text
a39e9e5 feature: add read-only EKS investigations (#20)
```

## Implemented Product Work

- Added `architectural_review` as an additive assessment mode.
- Added contextual focus resolution for explicit resource refs, IaC resources,
  exact prompt identifiers, and service selection without guessing ambiguity.
- Added bounded context questions, resumable input, a 50-read budget, a 25-node
  graph limit, and at most two relationship hops.
- Added five versioned knowledge-pack families with profiles for all 17 runtime
  scopes and mappings for all 120 native rules.
- Added WAF practice statuses, source URL, catalog revision, review date,
  evidence, explicit unknowns, excluded scope, and limitations.
- Added targeted typed relationship collectors for all 17 scopes with redacted
  provenance and best-effort AWS Config fallback.
- Added safe Terraform HCL, Terraform plan JSON, and CloudFormation JSON/YAML
  parsing for all 17 scopes.
- Added path confinement, symlink escape protection, file count/size limits,
  sensitive-file rejection, and unresolved-expression handling.
- Added contextual fields to MCP results, resource details, JSON, CSV,
  Markdown, HTML, SARIF, and PDF reports.
- Added contextual MCP prompts, golden scenarios, deterministic benchmark, and
  focused LocalEmu E2E coverage.
- Updated package version to `0.9.0b1` and included `python-hcl2` plus bundled
  `knowledge/packs.json` in the wheel.
- Updated README, PyPI README, MCP docs, prompt library, coverage docs,
  installation/publishing docs, future architecture, expansion plan, changelog,
  release readiness, and package description.

## Main New Files

```text
bluearch_aws_steward/contextual_review.py
bluearch_aws_steward/iac_context.py
bluearch_aws_steward/iac_review.py
bluearch_aws_steward/knowledge/packs.json
bluearch_aws_steward/knowledge_packs.py
bluearch_aws_steward/relationships.py
docs/contextual-architecture-reviews.md
tests/contextual/golden-scenarios.json
tests/contextual/generic-agent-baseline.json
tests/contextual/run_benchmark.py
tests/test_contextual_reviews.py
tests/test_iac_context.py
tests/test_relationships.py
```

## Other Modified Areas

```text
Makefile
README.md
PYPI_README.md
CHANGELOG.md
pyproject.toml
uv.lock
.github/workflows/emulator.yml
bluearch_aws_steward/__init__.py
bluearch_aws_steward/assessments.py
bluearch_aws_steward/mcp_prompts.py
bluearch_aws_steward/mcp_server.py
bluearch_aws_steward/models.py
bluearch_aws_steward/pdf_report.py
bluearch_aws_steward/reports.py
docs/mcp-and-codex-plugin.md
docs/prompt-library.md
docs/public-installation.md
docs/publishing-preview.md
docs/public-release-readiness.md
docs/rule-coverage.md
docs/future-architecture.md
docs/expansion-plan.md
tests/aws-emulator/scripts/e2e-mcp.py
tests/aws-emulator/scripts/extended_fixtures.py
tests/aws-emulator/scripts/fixture_proxy.py
tests/aws-emulator/scripts/seed.sh
tests/eks-lab/scripts/full.py
tests/eks-lab/scripts/phase.py
tests/eks-lab/scripts/remediation.py
tests/package/smoke-wheel.py
tests/test_mcp_first.py
```

## Validation Already Completed

The following results are confirmed for the current product implementation:

- Ruff check and format passed over all product files before the iCloud issue,
  then passed again over all 24 changed Python files after the final test-harness
  edits.
- mypy passed: `Success: no issues found in 65 source files`.
- Full unit suite passed: `240 tests`, before the final EKS-harness-only edits.
- `make test` passed, including MCP smoke, prompt discovery, 17 knowledge
  profiles, 120 native rules, contextual benchmark, IAM policy sync, and rule
  search smoke tests.
- Catalog sync passed against `../aws-misconfig-db`.
- Contextual benchmark passed all five pack families with 100% applicable
  practice recall, 0 unrelated recommendation rate, 0 unsupported claims, and
  approximately 17 ms focused IaC p95.
- LocalEmu clean E2E passed using the real stdio MCP server:
  - contextual S3 review: 214.66 ms completion;
  - only S3 scanned;
  - 10 read operations with provenance;
  - no EC2/RDS unrelated collectors;
  - questions, partial/final results, resource details, investigation, and HTML
    report verified;
  - zero writes;
  - full AWS-only baseline: 100 rules, 130 findings, 2736 resources.
- Package build passed:
  - `bluearch_aws_steward-0.9.0b1.tar.gz`;
  - `bluearch_aws_steward-0.9.0b1-py3-none-any.whl`;
  - `twine check` passed;
  - wheel smoke passed and bundled knowledge validation passed.
- Clean `uv tool` install passed with both entry points and MCP smoke.
- `uvx --from <wheel>` passed with version and MCP smoke.
- `uv lock --check --python /private/tmp/bluearch-steward-v090-venv/bin/python`
  passed: 93 packages resolved.
- EKS/kind gate passed against the clean installed wheel:
  - all 20 EKS/Kubernetes rules evaluated;
  - 21 expected findings;
  - healthy controls excluded;
  - investigations completed;
  - patch generation/validation completed;
  - the disposable harness applied one Kubernetes patch and verified the
    finding disappeared;
  - PDF report generated;
  - zero MCP cluster writes.

EKS receipt and PDF are under:

```text
/private/tmp/bluearch-steward-eks-v090-artifacts
```

Built distributions are under:

```text
/Users/arturhenrique/Documents/bluearch/bluearch-aws-steward/dist
```

## Important iCloud/Dataless Issue

The checkout is on iCloud-managed storage. Several unchanged source files,
test files, bytecode files, and old generated artifacts are marked
`compressed,dataless`. Commands that read all files can hang indefinitely.

Known examples:

```text
bluearch_aws_steward/aws_endpoints.py
tests/test_aws_cli_provider.py
tests/__pycache__/test_aws_cli_provider.cpython-313.pyc
tests/eks-lab/fixture-map.yml
tests/eks-lab/scripts/__pycache__/phase.cpython-313.pyc
tests/eks-lab/.artifacts/*
```

Because of this:

- a final repeated global Ruff run hung, but scoped Ruff over every changed file
  passed;
- a final repeated 240-test run hung on an unchanged dataless test, but the
  complete suite had already passed before the EKS-harness-only changes;
- `git status` and `git diff` can hang while iCloud files are evicted.

Recommended recovery: make the repository fully available offline in Finder or
clone a fresh copy to a non-iCloud directory, then copy/apply the working-tree
changes. Do not assume a hung command indicates a product failure.

## Temporary Validation Environment

Hydrated Python environments:

```text
/private/tmp/bluearch-steward-v090-venv
/private/tmp/bluearch-steward-v090-wheel-venv
```

Temporary hydrated EKS fixture map:

```text
/private/tmp/bluearch-steward-eks-fixture-map-v090.yml
```

The disposable `kind` cluster and LocalEmu were intentionally left running for
continuation after the user requested this handoff.

Inspect them with:

```bash
kind get clusters
docker ps
kubectl config current-context
```

Clean them after validation:

```bash
make eks-lab-down
make emulator-down
```

## Final Work Remaining

Status as of the 2026-08-03 continuation session. See `## Continuation Session`
below for the full record.

1. DONE. A clean non-iCloud checkout now exists at `/private/tmp/steward-clean`.
2. DONE. The working-tree diff matches the intended file set exactly. One gap
   was found and fixed: `tests/contextual/.artifacts/` was not ignored.
3. DONE except `catalog-check`, which is blocked by the iCloud fault. Gates run
   in the clean checkout:

```bash
make quality PYTHON=/private/tmp/bluearch-steward-v090-venv/bin/python
make test PYTHON=/private/tmp/bluearch-steward-v090-venv/bin/python
make catalog-check PYTHON=/private/tmp/bluearch-steward-v090-venv/bin/python
UV_CACHE_DIR=/private/tmp/steward-uv-cache uv lock --check \
  --python /private/tmp/bluearch-steward-v090-venv/bin/python
make package PYTHON=/private/tmp/bluearch-steward-v090-venv/bin/python
```

4. DONE. `twine check` passed both artifacts and every contextual report format
   was rendered and inspected.
5. DONE. The kind cluster and LocalEmu are stopped and removed.
6. DONE. Git status in the clean checkout contains only intended files.
7. NOT STARTED. Still requires explicit user approval: commit with a local
   conventional prefix, push, observe remote CI/CodeQL/LocalEmu/package gates,
   and prepare the protected `0.9.0b1` preview release.

## EKS Wheel Gate Command

If it must be repeated, keep the checkout out of the package import path:

```bash
AWS_ACCESS_KEY_ID=test \
AWS_SECRET_ACCESS_KEY=test \
AWS_SESSION_TOKEN=test \
AWS_DEFAULT_REGION=us-east-1 \
BLUEARCH_STEWARD_USE_INSTALLED_PACKAGE=1 \
BLUEARCH_STEWARD_MCP_CWD=/private/tmp \
BLUEARCH_STEWARD_EKS_FIXTURE_MAP=/private/tmp/bluearch-steward-eks-fixture-map-v090.yml \
BLUEARCH_STEWARD_EKS_METRICS_FILE=/Users/arturhenrique/Documents/bluearch/bluearch-aws-steward/tests/eks-lab/metrics.json \
PYTHONPYCACHEPREFIX=/private/tmp/bluearch-steward-wheel-pycache-v090 \
/private/tmp/bluearch-steward-v090-wheel-venv/bin/python \
tests/eks-lab/scripts/full.py \
  --endpoint-url http://localhost:4566 \
  --region us-east-1 \
  --artifact-dir /private/tmp/bluearch-steward-eks-v090-artifacts
```

## Release Caveats

- No real AWS sandbox contextual-family validation was run for this change.
- No remote CI has run for this uncommitted working tree.
- No release was published.
- No commit or push was performed.
- No Codex Security plugin was run, per explicit user instruction.

## Continuation Session (2026-08-03)

### iCloud Root Cause

The hangs are now fully explained. `Documents` is synced by iCloud Desktop &
Documents. The disk is 95% full, so macOS evicted file contents, and `bird` has
been stuck at high CPU with sync retries failing for hours. Evicted files are
flagged `dataless`.

The decisive detail: a `dataless` file blocks forever in `mmap()`, and Git
`mmap()`s loose objects. That is why `git log` and `git status` hang and why
`ruff`/`pytest` sweeps hang. A plain `read()` sometimes succeeds, so partial
success is misleading.

Measured in the iCloud checkout:

- 3173 `dataless` files, including inside `.git`;
- 51 of 135 probed source files are permanently unreadable;
- all 46 v0.9.0b1 work files ARE readable, so no work was lost.

Note: `find . -flags dataless` reports nothing. The correct probe is
`find . -flags +dataless`.

### Clean Checkout

```text
/private/tmp/steward-clean
```

Cloned from origin at `a39e9e5`, then the 46 work files were copied in. Its
`git status` reproduces the iCloud working tree exactly, which is what proves
the file set is complete and unpolluted.

`make dev-sync` built `.venv` from `uv.lock` inside that checkout.

### Gate Results in the Clean Checkout

- `make quality` passed. Ruff check, `ruff format --check` over 117 files, and
  mypy clean over 65 source files. This is the first time the global Ruff sweep
  completed rather than hanging.
- `make test` passed. 240 unit tests, MCP smoke, 42 `test_mcp_first` tests, 17
  knowledge profiles, 120 native rules, contextual benchmark, IAM policy sync,
  and rule search.
- `uv lock --check` passed. 93 packages resolved.
- `make package` passed. `twine check` PASSED on both artifacts and the wheel
  smoke test passed.
- LocalEmu contextual E2E re-run and passed, reproducing the earlier baseline
  exactly: 100 rules, 130 findings, 2736 resources, contextual review scoped to
  one S3 bucket in 223 ms with 0 write operations.

The wheel built from the clean checkout is byte-identical to the previously
validated `dist/` wheel: all 74 members match by SHA-256. The earlier EKS/kind
gate therefore still applies to this exact tree.

### Fix Applied

`tests/contextual/.artifacts/` was not covered by `.gitignore`, so the generated
contextual benchmark output would have been committed. A rule was added, in the
per-directory style already used in that file, to both the clean checkout and
the iCloud working tree. This is the only source change made this session.

### Contextual Report Formats Verified

A pure-Terraform contextual review was rendered to every format. JSON, Markdown,
HTML, CSV, SARIF all carry contextual content, and the PDF is a valid 6-page
document. Each Well-Architected practice carries `status`, `source_url`,
`catalog_revision`, `reviewed_at`, `evidence`, `applicability`,
`missing_context`, and `unresolved_iac_fields`. CSV emits dedicated
`well_architected_practice` rows.

### Blocked: catalog-check

`make catalog-check` could NOT be validated.

Against a fresh clone of `aws-misconfig-db` main, the check fails, and syncing
would REGRESS the bundled catalog from 120 to 102 executable rules and from 649
to 631 full rules. The committed catalog is ahead of upstream `main`, so the
local `../aws-misconfig-db` holds catalog work that was never pushed. The synced
catalog was reverted; the bundled catalog is untouched at 120/649.

The local catalog repo cannot be read to confirm this: 165 of its 169 files are
`dataless` and 51 of 52 probed JSON files hang, including all Git metadata.

Two consequences to resolve before release:

1. The 120-rule bundled catalog is what the knowledge packs map against, so
   syncing to current upstream `main` would break the contextual mapping.
2. `aws-misconfig-db` main must be brought up to date, or the release must
   explicitly document that it depends on unpushed catalog content.

### Environment State

The kind cluster and LocalEmu are stopped and removed. `docker ps` is empty and
`kind get clusters` reports none.

### Pull Request

Committed and pushed from the clean checkout on user instruction.

```text
branch: feature/contextual-well-architected-reviews
PR:     https://github.com/bluearchio/bluearch-aws-steward/pull/23
```

46 files, about 8000 insertions. `HANDOFF-v0.9.0b1.md` was deliberately NOT
committed; it is an internal working document. Nothing was tagged or published.

### Problems CI Found That Local Validation Had Missed

The original handoff never ran `make security`, and never ran the emulator gate
with a repository-relative interpreter. Three real defects surfaced.

1. Bandit B506 in the new `iac_context.py`. The existing `# noqa: S506` is a
   Ruff suppression that bandit ignores. The loader is genuinely safe, so a
   targeted `# nosec B506` was added rather than a global skip.
2. Two vulnerable pins: `aiohttp` 3.14.2 (CVE-2026-69244, reaches users
   transitively through `kubernetes`) and `cryptography` 49.0.0
   (CVE-2026-69247, a Linux-only dev transitive). The second is invisible on
   macOS because `cryptography` is never installed there. Both were bumped.
   All 92 locked packages were then audited directly against OSV and are clean.
3. A regression introduced by this change in `tests/aws-emulator/scripts/seed.sh`.
   It replaced a PATH-resolved `python3` with `"$BLUEARCH_STEWARD_TEST_PYTHON"`
   inside a subshell that has already changed directory, so CI's relative
   `.venv/bin/python` stopped resolving. Fixed once in `lib.sh`, where the
   variable is already defaulted, so every call site is protected.

Reproducing this class of failure locally requires running `make` from the
checkout so `PYTHON` defaults to the relative `.venv/bin/python`. Running a
script directly with an absolute interpreter hides it.

### Gate Coverage Notes

- `ci.yml` runs tests, `make quality`, `make security`, and `make package` on
  pull requests. It does NOT run `catalog-check`, so the catalog divergence
  does not block CI.
- `emulator.yml` (LocalEmu) runs only on push to `main` or manual dispatch, so
  it does not gate pull requests. It was dispatched manually against the branch,
  which is how defect 3 was caught.
- `eks-lab.yml` and `eks-aws-live.yml` are manual dispatch only.

### Recommended Next Steps

1. Fix the iCloud/eviction problem for real. As of this session it is NOT
   resolved: `bird` still burns CPU, 2275 files remain dataless, and `git
   status` plus many source reads still hang forever. Freeing disk from 11 GiB
   to 18 GiB was not sufficient. Until this is fixed the working copy cannot run
   Git or full-tree tooling, and all work must happen in a non-iCloud clone.
2. Resolve the `aws-misconfig-db` catalog divergence and re-run
   `make catalog-check` before tagging any release.
3. Review and merge PR #23, then let `emulator.yml` run on `main`.
4. Only after that, prepare the protected `0.9.0b1` preview release.
