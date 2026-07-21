# Public Installation

This document defines the supported public installation contract. The package
is not published yet; current automation only builds and validates it.

## Recommended Installation

Install `uv` on macOS or Linux with its official standalone installer:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Alternatively, macOS users can run `brew install uv`. The standalone installer
and `uv` can provide the compatible Python runtime required by Steward.

Install Steward as an isolated persistent tool:

```bash
uv tool install 'bluearch-aws-steward==0.7.0b4'
uv tool update-shell
bluearch-steward --version
bluearch-steward mcp smoke
```

Register Steward with one or more supported MCP clients:

```bash
bluearch-steward mcp install --client codex
bluearch-steward mcp install --client cursor
bluearch-steward mcp install --client claude
```

Repeat `--client` to configure multiple clients, or use `--client all` to
configure detected clients. Use `--dry-run` to inspect the exact path or native
client command before changing anything. Steward backs up existing client
configuration files and preserves unrelated MCP servers. Restart each client
after changing MCP configuration.

For an unsupported stdio MCP client, print the portable JSON instead:

```bash
bluearch-steward mcp config --runtime installed
```

Steward does not start a separate HTTP service. The MCP client starts the stdio
process when needed.

## Zero-Install MCP Runtime

`uvx` can resolve an exact released Steward version and cache its isolated
environment:

```bash
bluearch-steward mcp config --runtime uvx
```

For preview version `0.7.0b4`, the generated server executes the equivalent of:

```bash
uvx --from bluearch-aws-steward==0.7.0b4 bluearch-steward-mcp
```

Persistent `uv tool install` is the default recommendation because startup does
not depend on package resolution and upgrades happen only when the user asks.
The `uvx` shape is useful for disposable environments and clients that manage
their own MCP process cache.

## Development Checkout

Before the package is published, or when contributing:

```bash
git clone https://github.com/bluearchio/bluearch-aws-steward.git
cd bluearch-aws-steward
make dev-sync
make runtime-info
uv run bluearch-steward mcp config
```

After source or dependency changes, run `make dev-sync` and restart the MCP
client. A running Python MCP process does not hot reload code.

## AWS Authentication

Do not put access keys, SSO tokens, a default profile, or a default Region in
MCP configuration. Configure credentials through the standard AWS SDK chain.
For AWS IAM Identity Center:

```bash
aws configure sso
aws sso login --profile my-sso-profile
```

Steward lists configured profiles and asks the user to choose when the context
is ambiguous. Routine assessments should use the generated read-only IAM
policy in `iam/read-policy.json`.

## Upgrade And Remove

```bash
uv tool upgrade bluearch-aws-steward
bluearch-steward --version
bluearch-steward mcp smoke
```

Restart MCP clients after every upgrade. Remove Steward with:

```bash
uv tool uninstall bluearch-aws-steward
```

Remove only Steward's MCP registration while preserving other MCP servers:

```bash
bluearch-steward mcp uninstall --client codex
```

## Release Validation

Maintainers validate the same package boundary without publishing anything:

```bash
make package-install-smoke
```

The release-candidate GitHub Actions workflow builds the wheel and source
distribution, installs the wheel as a `uv` tool, checks both entry points, runs
the MCP smoke test, and verifies the version-pinned `uvx` configuration. It does
not upload to PyPI, create a GitHub release, or deploy artifacts.

The separate `release.yml` workflow runs only for an explicit version tag. It
publishes the validated artifacts to TestPyPI, installs and smoke-tests that
upload, then creates a draft GitHub prerelease containing the same artifacts
and their checksums. A separate `publish-pypi.yml` workflow uploads those assets
to PyPI only after a maintainer manually publishes the draft release. Both
package indexes use short-lived OIDC credentials, not stored API tokens.

Before public package publication, the remaining manual steps are:

1. Configure pending Trusted Publishers for PyPI and TestPyPI.
2. Push the annotated `v0.7.0b4` tag only after the latest commit passes all gates.
3. Review the TestPyPI verification and draft release assets.
4. Publish the draft GitHub prerelease to approve PyPI publication.
