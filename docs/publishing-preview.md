# Publishing The Preview

This runbook publishes an immutable Python preview while the GitHub repository
may remain private. The wheel and source distribution published to PyPI are
public and contain the packaged Python source.

## Safety Properties

- Only a `v*` tag can start `.github/workflows/release.yml`.
- The tagged commit must be on `origin/main`.
- The package version must exactly match the tag and must be a PEP 440 preview.
- Pull requests, branch pushes, and manual workflow dispatch cannot publish.
- TestPyPI and PyPI use short-lived GitHub OIDC credentials; no package token is stored.
- PyPI receives the checksummed artifacts that passed tests and TestPyPI verification.
- PyPI publication requires a maintainer to publish the generated draft prerelease.
- Existing PyPI versions are never overwritten or silently skipped.

## One-Time PyPI Configuration

Create accounts on both [PyPI](https://pypi.org/) and
[TestPyPI](https://test.pypi.org/). The account databases are separate.

On each index, create a pending GitHub Trusted Publisher with these values:

| Field | PyPI | TestPyPI |
| --- | --- | --- |
| Project | `bluearch-aws-steward` | `bluearch-aws-steward` |
| GitHub owner | `bluearchio` | `bluearchio` |
| Repository | `bluearch-aws-steward` | `bluearch-aws-steward` |
| Workflow | `publish-pypi.yml` | `release.yml` |
| Environment | Leave blank | Leave blank |

Do not create a PyPI API token for this workflow.

## Approval Boundary

Private repositories on the current GitHub plan do not provide environment
reviewer protection. The release therefore uses a durable draft-release gate
instead of silently weakening approval.

`release.yml` can publish only to TestPyPI and creates a draft prerelease. It
cannot publish to PyPI. `publish-pypi.yml` runs only for a published prerelease,
revalidates the tag against `main`, verifies every asset checksum, and then uses
its own PyPI Trusted Publisher identity. Do not add package or AWS credentials
to either workflow.

## Candidate Validation

Before tagging, confirm the worktree is clean and the candidate is on `main`:

```bash
git status --short --branch
git fetch origin
git rev-parse HEAD
git rev-parse origin/main
```

Run the local release boundary:

```bash
make test quality security package-install-smoke
```

Run the manual `Release candidate validation` workflow on the same commit. Do
not create the release tag until CI, CodeQL, LocalEmu MCP E2E, and the release
candidate workflow are green.

## Publish `0.9.0b1`

Create an annotated tag from the validated `main` commit. Preview tags may be
unsigned because publishing is bound to this repository and workflow through
OIDC. Require a verified signed tag before publishing a stable release:

```bash
git tag -a v0.9.0b1 -m "BlueArch AWS Steward 0.9.0b1"
git push origin v0.9.0b1
```

The workflow will:

1. build and validate the wheel and source distribution;
2. publish them to TestPyPI;
3. install the TestPyPI package with `uv tool` and run MCP smoke tests;
4. create a draft GitHub prerelease containing the same files and checksums.

Review the TestPyPI job, release notes, and attached checksums. Publishing the
draft prerelease is the explicit approval that starts `publish-pypi.yml`. That
workflow downloads the release assets, verifies their checksums, and publishes
them to PyPI.

## Verify The Public Package

Use a machine or container without the repository checkout:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install 'bluearch-aws-steward==0.9.0b1'
bluearch-steward --version
bluearch-steward mcp smoke
python -c "import kubernetes"
bluearch-steward mcp install --client cursor --runtime installed --dry-run
deactivate

uv tool install 'bluearch-aws-steward==0.9.0b1'
bluearch-steward mcp smoke
uv tool uninstall bluearch-aws-steward
```

Then install the package normally and register the user's preferred client as
documented in `public-installation.md`.

## Failure And Rollback

PyPI files are immutable. Never delete and recreate a tag or attempt to replace
an uploaded distribution.

If a published preview is broken:

1. yank the affected PyPI release;
2. document the reason in the changelog and GitHub release;
3. fix and validate the issue on `main`; and
4. publish the next preview, such as `0.7.0b5`.

Yanking discourages new automatic installations but does not remove files that
existing users may already have downloaded.
