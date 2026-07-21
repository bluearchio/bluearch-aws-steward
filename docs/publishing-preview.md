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
- PyPI receives the same artifact that passed tests and TestPyPI verification.
- The `pypi` GitHub environment must require manual approval.
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
| Workflow | `release.yml` | `release.yml` |
| Environment | `pypi` | `testpypi` |

Do not create a PyPI API token for this workflow.

## One-Time GitHub Configuration

Create repository environments named exactly `testpypi` and `pypi`.

For `testpypi`:

- restrict deployment branches and tags to protected tags matching `v*`;
- do not add package credentials or AWS credentials.

For `pypi`:

- restrict deployment branches and tags to protected tags matching `v*`;
- require at least one trusted reviewer;
- prevent self-review when another reviewer is available;
- do not add package credentials or AWS credentials.

The workflow requests `id-token: write` only inside the two package publishing
jobs. The build job and the GitHub prerelease job cannot mint PyPI credentials.

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

## Publish `0.7.0b1`

Create a signed tag from the validated `main` commit:

```bash
git tag -s v0.7.0b1 -m "BlueArch AWS Steward 0.7.0b1"
git push origin v0.7.0b1
```

The workflow will:

1. build and validate the wheel and source distribution;
2. publish them to TestPyPI;
3. install the TestPyPI package with `uv tool` and run MCP smoke tests;
4. pause at the protected `pypi` environment;
5. publish the same files to PyPI after approval; and
6. create a GitHub prerelease with checksums.

Review the TestPyPI job before approving `pypi`. A waiting environment approval
does not consume a running GitHub-hosted runner.

## Verify The Public Package

Use a machine or container without the repository checkout:

```bash
uv tool install 'bluearch-aws-steward==0.7.0b1'
bluearch-steward --version
bluearch-steward mcp smoke
bluearch-steward mcp install --client cursor --runtime installed --dry-run
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
4. publish the next preview, such as `0.7.0b2`.

Yanking discourages new automatic installations but does not remove files that
existing users may already have downloaded.
