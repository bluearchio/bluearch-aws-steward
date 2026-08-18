# BlueArch AWS Steward

Local, MCP-first contextual AWS architecture reviews for Codex, Claude Code,
Cursor, and other MCP clients.

Steward reviews one live AWS resource or proposed Terraform/CloudFormation
change and the dependencies relevant to that decision. It applies validated
AWS Well-Architected knowledge, explains evidence and business impact, and
builds a reviewable correction plan. Full-account scans run only when explicitly
requested. Reviews are read-only by default.

> Beta: use Steward as decision support. Review every recommendation and plan
> before changing production infrastructure.

## Install

Steward requires Python 3.10 or newer. Install it in a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade bluearch-aws-steward
bluearch-steward --version
bluearch-steward mcp smoke
```

Windows activation:

```powershell
.venv\Scripts\activate
```

For an isolated command without manually managing a virtual environment:

```bash
uv tool install --upgrade bluearch-aws-steward
uv tool update-shell
bluearch-steward mcp smoke
```

EKS and Kubernetes support is included in the standard package. AWS CLI,
`kubectl`, Terraform/OpenTofu, Helm, Kustomize, Docker, and `kind` remain
external tools used only by workflows that need them.

## Connect Your Agent

```bash
bluearch-steward mcp install --client codex
bluearch-steward mcp install --client cursor
bluearch-steward mcp install --client claude
```

Use `--dry-run` to preview configuration changes. Restart the client after
registration. For another stdio MCP client:

```bash
bluearch-steward mcp config --runtime installed
```

## Run Your First Review

Authenticate outside the agent conversation. AWS IAM Identity Center users can
run:

```bash
aws sso login --profile my-sso-profile
```

Then ask your MCP client about one exact resource:

> Review `s3://my-application-data` before I change its lifecycle policy. Ask
> only for context that changes which Well-Architected practices apply.

For a proposed change, give the agent a declared workspace root and explicit
Terraform or CloudFormation path. Steward never searches arbitrary local files,
executes Terraform, or modifies source. If no resource is identified, it asks
for one instead of guessing.

Steward returns a bounded architecture neighborhood, WAF practice ledger,
contextual recommendations, explicit unknowns, and excluded scope. Results are
ephemeral and exportable as JSON, Markdown, HTML, CSV, SARIF, or PDF.

Use an explicit prompt only when you really need breadth:

> Run a comprehensive assessment across all supported services. Show only
> resources caught by rules and report skipped rules and coverage.

## Included In This Preview

- 121 native rules across 17 AWS runtime scopes.
- Versioned contextual knowledge packs for all 17 scopes and bounded typed
  relationship collection with a 50-read operation budget.
- Safe Terraform HCL, Terraform plan JSON, and CloudFormation JSON/YAML review.
- A 20-rule EKS and Kubernetes assessment and investigation pack.
- Searchable knowledge for the bundled BlueArch AWS misconfiguration catalog.
- Native, Security Hub, Compute Optimizer, Cost Optimization Hub, and optional
  imported Prowler findings in one deduplicated queue.
- Evidence, risk, confidence, freshness, remediation safety, and cost estimate
  status on presented findings.
- Read-only resource investigation and planning-only AWS/IaC change previews.
- Guarded writes for a small documented set of low-risk operations only.

Steward is standalone. It does not require BlueArch Core, hosted login, hosted
telemetry, or a local AWS inventory database. AWS remains the source of truth.

## Safety And Scope

- No assessment applies changes.
- Most recommendations are planning-only.
- Guarded writes require a fresh finding, exact short-lived plan, explicit
  approval, state revalidation, and post-change verification.
- Missing permissions or unavailable evidence are reported as incomplete, not
  as passing.
- The current preview is single-account and single-Region per assessment.

Full documentation:

- [Installation and upgrades](https://github.com/bluearchio/bluearch-aws-steward/blob/main/docs/public-installation.md)
- [Prompt examples](https://github.com/bluearchio/bluearch-aws-steward/blob/main/docs/prompt-library.md)
- [Rule coverage](https://github.com/bluearchio/bluearch-aws-steward/blob/main/docs/rule-coverage.md)
- [Security policy](https://github.com/bluearchio/bluearch-aws-steward/blob/main/SECURITY.md)
- [Source repository](https://github.com/bluearchio/bluearch-aws-steward)

![BlueArch AWS Steward MCP workflow](https://dist.bluearch.io/assets/bluearch-aws-steward/readme/mcp-workflow-v1.png)
