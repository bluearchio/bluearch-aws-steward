# Publishing The Preview

This runbook publishes an immutable Python preview to PyPI. The wheel and
source distribution are public and contain the packaged Python source.

Substitute the version being published for `<version>` throughout, for example
`0.9.0b2`. The tag is always `v<version>` and the workflows refuse to publish
unless it matches `bluearch_aws_steward.__version__` exactly.

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

Both Trusted Publishers are already configured for `bluearch-aws-steward`. This
section applies to a new project, a revoked publisher, or a rename.

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

No tag push can reach PyPI on its own. `release.yml` publishes only to TestPyPI
and creates a draft prerelease; it has no PyPI identity. `publish-pypi.yml` runs
only for a published prerelease, revalidates the tag against `main`, verifies
every asset checksum, and then uses its own PyPI Trusted Publisher identity.
Publishing the draft is the approval. Do not add package or AWS credentials to
either workflow.

The draft gate was chosen because environment reviewer protection was
unavailable to private repositories on the plan in use at the time. This
repository is now public, so protected environments are available and would
move the approval into GitHub's own audited review flow instead of resting on
the draft state. The draft gate remains sound on its own; treat the environment
as a strengthening step rather than a correction.

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

## Publish `<version>`

Create an annotated tag from the validated `main` commit. Preview tags may be
unsigned because publishing is bound to this repository and workflow through
OIDC. Require a verified signed tag before publishing a stable release:

```bash
git tag -a "v<version>" -m "BlueArch AWS Steward <version>"
git push origin "v<version>"
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
python -m pip install "bluearch-aws-steward==<version>"
bluearch-steward --version
bluearch-steward mcp smoke
python -c "import kubernetes"
bluearch-steward mcp install --client cursor --runtime installed --dry-run
deactivate

uv tool install "bluearch-aws-steward==<version>"
bluearch-steward mcp smoke
uv tool uninstall bluearch-aws-steward
```

PyPI's project-level JSON API is CDN-cached and can report the previous version
as latest for a few minutes after upload. The simple index and the per-version
endpoint update immediately, so confirm there rather than concluding the upload
failed:

```bash
curl -s -H "Accept: application/vnd.pypi.simple.v1+json" \
  https://pypi.org/simple/bluearch-aws-steward/ | grep "<version>"
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
4. publish the next preview.

Yanking discourages new automatic installations but does not remove files that
existing users may already have downloaded.
