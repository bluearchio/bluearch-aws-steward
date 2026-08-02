# Public Installation

This document defines the supported public installation contract. Steward
requires Python 3.10 or newer. `pip` and `uv` install the same complete wheel,
including EKS and Kubernetes support.

## Install With pip

Use a virtual environment so Steward does not modify the system Python:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade bluearch-aws-steward
bluearch-steward --version
bluearch-steward mcp smoke
```

On Windows, activate the environment with:

```powershell
.venv\Scripts\activate
```

The `bluearch-steward` and `bluearch-steward-mcp` commands are installed in the
active environment. EKS and Kubernetes support is included; no optional extra
is required.

## Install As An Isolated Tool

[`uv`](https://docs.astral.sh/uv/) can manage a compatible Python runtime and a
persistent isolated environment:

```bash
uv tool install --upgrade bluearch-aws-steward
uv tool update-shell
bluearch-steward --version
bluearch-steward mcp smoke
```

Restart the shell after `uv tool update-shell` if the command is not yet on
`PATH`.

## Connect An MCP Client

Register the installed runtime with one or more supported clients:

```bash
bluearch-steward mcp install --client codex
bluearch-steward mcp install --client cursor
bluearch-steward mcp install --client claude
```

Repeat `--client` or use `--client all` to configure detected clients. Use
`--dry-run` to preview the exact change. Steward preserves unrelated MCP
servers and backs up changed configuration files. Restart the client after
registration.

For any other stdio MCP client, print portable configuration:

```bash
bluearch-steward mcp config --runtime installed
```

Steward does not start a separate HTTP service. The MCP client starts the
stdio process when needed.

## Resolve A Pinned Runtime With uvx

An MCP client can resolve and cache an exact published version on demand:

```bash
bluearch-steward mcp config --runtime uvx
```

For `0.8.0b1`, the generated server command is equivalent to:

```bash
uvx --from bluearch-aws-steward==0.8.0b1 bluearch-steward-mcp
```

Persistent `pip` or `uv tool` installation remains the default because startup
does not depend on package resolution. The `uvx` form is useful for disposable
environments and MCP clients that manage their own process cache.

## Included And External Components

The standard wheel contains the Steward application, rule catalog, report
renderers, AWS SDK provider, MCP server, and EKS/Kubernetes Python support.
External executables are not embedded in a Python wheel:

- AWS CLI is needed for interactive AWS SSO login and AWS CLI compatibility
  workflows.
- `kubectl` is needed for operator-side Kubernetes inspection and lab commands,
  not for Steward's allowlisted Kubernetes API reads.
- Docker, `kind`, Terraform/OpenTofu, Helm, and Kustomize are development or
  infrastructure-validation tools used only by their documented workflows.

## AWS Authentication

Do not put access keys, SSO tokens, a default profile, or a default Region in
MCP configuration. Configure credentials through the standard AWS SDK chain.
For AWS IAM Identity Center:

```bash
aws configure sso
aws sso login --profile my-sso-profile
```

Steward lists configured profiles and asks the user to choose when the context
is ambiguous. Routine assessments should use the generated read-only policy in
`iam/read-policy.json`.

## Upgrade And Remove

For a pip environment:

```bash
source .venv/bin/activate
python -m pip install --upgrade bluearch-aws-steward
bluearch-steward mcp smoke
python -m pip uninstall bluearch-aws-steward
```

For a uv tool:

```bash
uv tool upgrade bluearch-aws-steward
bluearch-steward mcp smoke
uv tool uninstall bluearch-aws-steward
```

Restart MCP clients after every upgrade. Remove only Steward's registration
while preserving other MCP servers with:

```bash
bluearch-steward mcp uninstall --client codex
```

## Development Checkout

Use a source checkout only when contributing or testing an unpublished
candidate:

```bash
git clone https://github.com/bluearchio/bluearch-aws-steward.git
cd bluearch-aws-steward
make dev-sync
make runtime-info
uv run bluearch-steward mcp config
```

After source or dependency changes, run `make dev-sync` and restart the MCP
client. A running Python MCP process does not hot reload code.

## Release Validation

Maintainers validate the package boundary without publishing:

```bash
make package-install-smoke
```

CI builds the wheel once, verifies its metadata, and installs that wheel with
plain `pip` on Python 3.10, 3.11, 3.12, and 3.13. Each clean job imports the
Kubernetes client and runs the Steward version and MCP smoke commands. Release
workflows additionally validate an isolated `uv tool` and version-pinned `uvx`
configuration before guarded TestPyPI and PyPI publication.

The complete EKS-inclusive package contract starts with `0.8.0b1`. Until that
candidate is published, PyPI continues to serve the previous preview.
