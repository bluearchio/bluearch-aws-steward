# Interactive TUI Dashboard

BlueArch AWS Steward includes an interactive terminal dashboard for developer
testing and legacy demos. The supported end-user experience is the MCP server
and agent plugin; the TUI is not a competing product interface.
The default dashboard uses Textual so the demo has real widgets, styled panes,
clickable metric cards, rule chips, a matched-resource card grid, a scan
monitor, and a right-side evidence/remediation panel instead of raw
character-table rendering.

The dashboard is intentionally a presentation layer only. The scanner emits
backend scan events, and the dashboard consumes those events. Future MCP, IDE,
or CI integrations should consume the same scan engine rather than depending on
terminal UI code.

## UI Direction

The product UI should be Textual-first. Textual gives us a Python-native app
model with CSS-style layouts, buttons, scrollable panes, focus states, loading
indicators, and a much better path to a futuristic terminal experience.

The old curses implementation is still available as a fallback:

```bash
python3 -m bluearch_aws_steward dashboard aws --ui classic
```

Do not keep adding product UX to curses unless Textual becomes unusable in a
target environment. The important contract is the scan event stream, not the
terminal framework.

## Run With LocalEmu

From the repository root:

```bash
make emulator-dashboard
```

Controls:

| Key | Action |
| --- | --- |
| `arrow keys` or `j` / `k` / `l` | Move between matched resource cards |
| `r` | Move to the next rule filter |
| `c` | Clear filters |
| `u` | Update/re-run the scan |
| `enter` | Copy the selected remediation command |
| `q` | Quit after scan completion |

Mouse users can also click metric cards, resource cards, rule chips, the update
button, and the copy-remediation button. The resource grid intentionally shows
only resources caught by at least one rule; the scan monitor still reports total
resources scanned. The right-side detail pane updates with the selected
resource, matched rule, remediation actions, verification step, evidence, and
the exact guarded remediation command.

The dashboard writes the final scan report to:

```text
tests/aws-emulator/.artifacts/dashboard.s3.json
```

## Run Against Real AWS Fixtures

Seed temporary empty S3 buckets:

```bash
AWS_PROFILE=my-sso-profile AWS_REGION=us-east-1 tests/aws-live/scripts/seed-s3.sh
```

Load the generated prefix:

```bash
. tests/aws-live/.artifacts/env.sh
```

Open the modern dashboard:

```bash
python3 -m bluearch_aws_steward dashboard aws \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --bucket-prefix "$BLUEARCH_STEWARD_LIVE_PREFIX" \
  --output-file tests/aws-live/.artifacts/dashboard.s3.json
```

Clean up the fixture buckets:

```bash
AWS_PROFILE=my-sso-profile AWS_REGION=us-east-1 make aws-live-clean
```

## Backend Contract

The dashboard consumes scan events:

- `scan_started`
- `resource_started`
- `finding`
- `resource_completed`
- `scan_completed`

That event stream is produced by the detector layer and is independent of
curses. This is the same contract we should use for:

- MCP progress updates.
- IDE scan panels.
- CI logs.
- Hosted dashboards.

## AWS MCP Status

The current MVP does not call AWS MCP yet. Today the AWS adapter uses the AWS
SDK by default, with the AWS CLI retained as a compatibility provider.

The next architecture step is to add an AWS MCP adapter behind the same scanner
interface. The TUI should not change when that happens because it already
consumes normalized scanner events rather than provider output.

Current implementation:

```text
TUI -> scan event stream -> AWS SDK adapter -> AWS APIs
```

The AWS MCP integration belongs at the provider-adapter boundary, not inside
the TUI. The detector layer calls a provider interface for AWS operations;
that provider can be backed by the default SDK adapter, the AWS CLI
compatibility adapter, or a future AWS MCP adapter.

Next target:

```text
MCP server / IDE plugin / developer TUI
  -> scan event stream
  -> detector engine
  -> AWS provider adapter
  -> AWS MCP adapter
  -> AWS APIs
```

Recommended module shape:

```text
bluearch_aws_steward/providers/aws_cli.py   # current behavior moved behind provider contract
bluearch_aws_steward/providers/aws_mcp.py   # future AWS MCP-backed implementation
bluearch_aws_steward/providers/base.py      # shared AWS operation contract
```

## Safety

The dashboard is read-only. It shows live scan progress and resource details,
but it does not apply remediation. Write actions remain behind the explicit
`remediate --allow-write` command.
