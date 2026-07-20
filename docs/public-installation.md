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
uv tool install bluearch-aws-steward
uv tool update-shell
bluearch-steward --version
bluearch-steward mcp smoke
```

Generate MCP JSON that points to the installed environment:

```bash
bluearch-steward mcp config --runtime installed
```

Paste the generated `bluearch-aws-steward` server entry into Codex, Cursor,
Claude Desktop, VS Code, or another stdio MCP client. Restart the client after
changing MCP configuration.

Steward does not start a separate HTTP service. The MCP client starts the stdio
process when needed.

## Zero-Install MCP Runtime

`uvx` can resolve an exact released Steward version and cache its isolated
environment:

```bash
bluearch-steward mcp config --runtime uvx
```

For version `0.7.0`, the generated server executes the equivalent of:

```bash
uvx --from bluearch-aws-steward==0.7.0 bluearch-steward-mcp
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

## Release Validation

Maintainers validate the same package boundary without publishing anything:

```bash
make package-install-smoke
```

The release-candidate GitHub Actions workflow builds the wheel and source
distribution, installs the wheel as a `uv` tool, checks both entry points, runs
the MCP smoke test, and verifies the version-pinned `uvx` configuration. It does
not upload to PyPI, create a GitHub release, or deploy artifacts.

Before public package publication, the remaining manual steps are:

1. Reserve and verify the `bluearch-aws-steward` project on PyPI.
2. Configure a protected `pypi` GitHub environment with trusted publishing.
3. Test the workflow against TestPyPI from an explicit prerelease tag.
4. Require an approved release environment for production publication.
5. Publish a preview version before declaring a stable release.
