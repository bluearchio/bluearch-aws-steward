# BlueArch AWS Steward

**BlueArch AWS Steward Beta: an MCP-first, contextual AWS architecture
reviewer.**

BlueArch AWS Steward reviews one live resource or proposed infrastructure
change and the dependencies that matter to that decision. It applies validated
AWS Well-Architected knowledge, evaluates live AWS and declared Terraform or
CloudFormation, explains business impact, and builds evidence-backed correction
plans. Full-account scanning remains available only when explicitly requested.

Steward is standalone. It does not use BlueArch Core, hosted login, hosted
telemetry, or a local AWS inventory database. AWS remains the source of truth.

## What It Provides

- Contextual architecture reviews for one to five focus resources, with typed
  relationships, explicit unknowns, excluded scope, and a complete read ledger.
- Validated Well-Architected knowledge packs for all 17 executable scopes,
  backed by the bundled `aws-misconfig-db` catalog.
- 120 native rules across 17 runtime scopes, including a 20-rule EKS/Kubernetes pack.
- Searchable knowledge for all 649 `aws-misconfig-db` catalog entries.
- Safe Terraform HCL, Terraform plan JSON, and CloudFormation JSON/YAML review
  without executing plans, transforms, macros, custom resources, or dynamic references.
- Point-in-time, read-only assessments using user-owned AWS credentials.
- MCP-native clarification for focus, architecture context, objective, service,
  profile, and Region.
- Guided, focused, and full-report assessment modes with multi-objective and
  multi-service selection.
- Background assessments with status, partial results, and cancellation.
- Complete ephemeral findings with filtered, cursor-paginated exploration that
  does not rescan AWS.
- Local JSON, Markdown, HTML, CSV, SARIF, and PDF report exports.
- Automatic terminal PDF choice; prompts do not need to request reporting.
- Evidence, risk, cost estimate status/confidence, and remediation safety on every presented finding.
- No assessment applies AWS changes; guarded writes require approval of one exact short-lived plan.
- Structured resource identity and redacted evidence using schema `0.2`.
- Planning for every native finding and guarded apply for eight low-risk rules.
- One prioritized queue combining native Steward, live Security Hub, Compute
  Optimizer, Cost Optimization Hub, and optional Prowler/exported JSON signals.
- Source-independent deduplication with provenance, freshness, confidence,
  evidence, live-validation status, and an explainable 0-100 priority score.

Steward complements broad scanners such as Prowler and AWS Security Hub. It is
not a replacement for either product, a continuous inventory, or an autonomous
AWS administrator. Its focus is the local last mile from a finding to a
reviewed AWS or IaC fix and post-fix verification. See
[`docs/competitive-strategy.md`](docs/competitive-strategy.md) and
[`docs/expansion-plan.md`](docs/expansion-plan.md) for positioning and roadmap.

## Install

Steward requires Python 3.10 or newer. A standard Python installation creates
an isolated environment and installs the complete application from PyPI:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade bluearch-aws-steward
bluearch-steward --version
bluearch-steward mcp smoke
```

On Windows, activate the environment with `.venv\Scripts\activate`. EKS and
Kubernetes support is included in the standard package; there is no separate
EKS extra to install. AWS CLI, `kubectl`, Terraform/OpenTofu, Helm, Kustomize,
Docker, and `kind` are external tools and are required only by workflows that
explicitly use them.

For a persistent command that is isolated without manually managing a virtual
environment, install the same complete wheel with `uv`:

```bash
uv tool install --upgrade bluearch-aws-steward
uv tool update-shell
bluearch-steward --version
bluearch-steward mcp smoke
```

Register the installed runtime with one or more supported MCP clients:

```bash
bluearch-steward mcp install --client codex
bluearch-steward mcp install --client cursor
bluearch-steward mcp install --client claude
```

Use `--dry-run` to preview changes. Existing client configuration is preserved,
and changed configuration files are backed up before installation. Restart the
client after registration.

For clients that should resolve the exact released package on demand, generate
a version-pinned `uvx` configuration:

```bash
bluearch-steward mcp config --runtime uvx
```

Published packages are available from PyPI. The standard wheel includes the
MCP server, reports, contextual knowledge packs, IaC parsers, native rules, and
EKS/Kubernetes support. To test the current checkout or contribute:

```bash
git clone https://github.com/bluearchio/bluearch-aws-steward.git
cd bluearch-aws-steward
make dev-sync
```

Configure an MCP client to start the repository runtime over stdio. Use the
absolute repository path in local installations:

```json
{
  "mcpServers": {
    "bluearch-aws-steward": {
      "command": "/absolute/path/bluearch-aws-steward/.venv/bin/bluearch-steward-mcp",
      "args": [],
      "env": {
        "AWS_SDK_LOAD_CONFIG": "1",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

`uv run python -m bluearch_aws_steward mcp config` generates this shape with an
absolute environment path. After changing source, run `make dev-sync` and then
restart the MCP server or start a new agent task. This reinstalls the current
checkout instead of allowing an MCP startup to mutate the environment; an
already running Python process does not hot reload modules.

See [`docs/public-installation.md`](docs/public-installation.md) for package,
upgrade, uninstall, and MCP-client setup flows. Maintainers should follow
[`docs/publishing-preview.md`](docs/publishing-preview.md) for the guarded
TestPyPI and PyPI release procedure.

Verify the active runtime at any time:

```bash
make runtime-info
```

The checkout version, installed package metadata version, and runtime version
must match. The check runs outside the repository so a stale package cannot be
hidden by Python importing the working directory.

Do not put credentials, SSO tokens, a default profile, or a default Region in
the MCP configuration. Steward uses the AWS SDK credential chain and asks the
user when multiple contexts are possible.

## First Contextual Review

1. Configure AWS credentials outside the conversation. AWS SSO users can run:

   ```bash
   aws sso login --profile my-sso-profile
   ```

2. Restart or reconnect the MCP client.
3. Review one existing resource by exact ARN or resource URI:

   > Review `s3://my-application-data` before I change its lifecycle policy.
   > Ask only for context that changes which Well-Architected practices apply.

   Or review a proposed change by giving the agent an explicit workspace root
   and Terraform or CloudFormation path:

   > Review the S3 resource proposed in `infra/storage.tf`. Consider its access
   > pattern, consumers, retention, recovery, and expected growth. Do not modify
   > the file or AWS.

Steward returns an assessment ID immediately. The client polls status, may read
partial results, and retrieves a focused architecture neighborhood, WAF practice
ledger, contextual recommendations, unknowns, and excluded scope without
starting the review again. Context exists only in process memory for 15 minutes.

If the request does not identify one resource or proposed change, Steward asks
the user to select one rather than guessing. A full account assessment is a
separate explicit choice:

> Run a comprehensive assessment across all supported services. Show only
> resources caught by rules and report skipped rules and coverage.

Full assessments preserve every finding for querying and reporting. A
50,000-finding guard reports `incomplete=true` and an exact reason instead of
silently truncating a complete assessment.

Read-only assessment, finding evidence and risk, cost estimate status and
confidence, individual-plan approval, and the terminal PDF choice are product
defaults; users do not need to request them in the prompt.

See [`docs/contextual-architecture-reviews.md`](docs/contextual-architecture-reviews.md)
for the review contract and [`docs/prompt-library.md`](docs/prompt-library.md)
for contextual, full-assessment, planning, and verification prompts.

### Unified Recommendation Queue

Native rules remain the default. Select additional AWS recommendation sources
when the account has them enabled:

```json
{
  "prompt": "Build one prioritized queue from all available recommendation sources.",
  "services": ["all"],
  "objectives": ["all"],
  "signal_sources": [
    "native",
    "security-hub",
    "compute-optimizer",
    "cost-optimization-hub"
  ]
}
```

Steward reads each selected source during the same point-in-time assessment.
It fingerprints account, Region, canonical resource, and canonical problem;
merges corroborating signals; preserves every source receipt; and returns one
recommendation. Current native evidence can resolve an equivalent stale config
finding, but a narrower native detector never invalidates a broader Compute
Optimizer or Cost Optimization Hub recommendation. Missing permissions or an
AWS service that is not enabled appears under `capability_errors` and
`incomplete_sources`; it is never reported as clean.

`bluearch_query_results` can filter the queue by `sources` and
`validation_statuses`. Every report format includes the fingerprint, source
list, freshness, priority score, evidence, risk, savings estimate/confidence,
and remediation safety.

## MCP Workflow

![BlueArch AWS Steward MCP workflow from user intent through live AWS assessment and guarded remediation](https://dist.bluearch.io/assets/bluearch-aws-steward/readme/mcp-workflow-v1.png)

Primary tools:

| Tool | Purpose | AWS write |
| --- | --- | --- |
| `bluearch_assess` | Resolve intent and start a background assessment. | No |
| `bluearch_validate_eks_connection` | Bind one explicit kubeconfig context to one EKS endpoint and CA before workload reads. | No |
| `bluearch_list_aws_profiles` | List non-secret AWS profile metadata for user selection. | No |
| `bluearch_import_findings` | Import supported external finding JSON into an ephemeral assessment. | No |
| `bluearch_get_scan_status` | Return progress without repeating work. | No |
| `bluearch_get_scan_results` | Return final or `include_partial` results. | No |
| `bluearch_query_results` | Filter, sort, facet, and paginate the stored snapshot without rescanning. | No |
| `bluearch_export_report` | Export a completed result, including local PDF with charts. | No |
| `bluearch_cancel_assessment` | Stop pending work and preserve completed reads. | No |
| `bluearch_get_resource_details` | Inspect or refresh one matched resource. | No |
| `bluearch_investigate_resource` | Revalidate one finding and build its deletion-readiness or operational-diagnosis dossier with live evidence, dependencies, hypotheses, impact, confidence, and a planning-only change preview. | No |
| `bluearch_generate_iac_patch` | Generate a reviewable EKS/Kubernetes patch fragment without modifying files or clusters. | No |
| `bluearch_validate_iac_patch` | Validate a generated patch in a temporary directory. | No |
| `bluearch_get_coverage` | Report catalog and native detector coverage. | No |
| `bluearch_status` | Check runtime, AWS identity, and rule coverage. | No |
| `bluearch_rules_search` | Search all 649 catalog rules. | No |
| `bluearch_explain_finding` | Explain evidence and impact. | No |
| `bluearch_plan_remediation` | Revalidate and create a short-lived plan. | No |
| `bluearch_apply_remediation` | Apply an exact approved plan. | Guarded |
| `bluearch_verify_remediation` | Re-read AWS and verify selected findings. | No |

The legacy CLI and Textual dashboard remain developer diagnostics. The normal
user flow is MCP.

## Detection Coverage

`bluearch_get_coverage` and the package-build knowledge validator generate the
authoritative counts. The current source manifest reports:

| Measure | Current candidate |
| --- | ---: |
| Catalog rules | 649 |
| Native canonical rules | 120 |
| Native aliases | 7 |
| Runtime scopes | 17 |
| Catalog automation | 18.49% |

Runtime scopes are `iam`, `cloudtrail`, `cloudwatch`, `dynamodb`, `s3`, `ec2`,
`rds`, `lambda`, `efs`, `ecs`, `eks`, `alb`, `kms`, `secrets-manager`, `sns`,
`sqs`, and `api-gateway`. The aliases `ebs` and `networking` route to the EC2 collector
and do not increase the canonical rule count.

All 120 current rules have `access_tier: free`. The original 100-rule AWS pack
and the 20-rule EKS/Kubernetes pack are the open-source baseline. Future canonical rules are reserved for a
`premium` tier unless the project governance explicitly promotes them. v0.7.0
does not add hosted login, licensing calls, or telemetry; entitlement enforcement
is a separate future boundary.

Every result distinguishes evaluated, skipped, and unevaluated rules. A rule
blocked by provider capability or AWS permissions is skipped with a reason; it
is never reported as passing. Zero findings means only that no evaluated rule
matched.

See [`docs/rule-coverage.md`](docs/rule-coverage.md) for the complete native
rule list and evidence type.

## Release Status

The current `0.9.0b1` work is a preview candidate, not a stable release.
Public-preview and stable-release gates are tracked in
[`docs/public-release-readiness.md`](docs/public-release-readiness.md). The
planned progressive result experience is documented in
[`docs/result-experience-plan.md`](docs/result-experience-plan.md).
Source adapter contracts and the security boundary are documented in
[`docs/source-compatibility.md`](docs/source-compatibility.md) and
[`docs/security-threat-model.md`](docs/security-threat-model.md).

## Safety Model

Read access is generated from the typed operation registry:

- [`iam/read-policy.json`](iam/read-policy.json)
- [`iam/remediation-policy.json`](iam/remediation-policy.json)

Keep those policies on separate roles. Routine assessment needs only the read
policy.

### Read-Only Investigations

Call `bluearch_investigate_resource` with an assessment and finding ID before
proposing a change. It selects one of two contracts:

- deletion readiness for unattached EBS volumes, unassociated Elastic IPs,
  inactive ECS task-definition revisions, inactive unmounted EFS file systems,
  unused Lambda functions, and idle RDS instances;
- operational diagnosis for RDS CPU, rightsizing, read-scaling, and public
  exposure findings plus ECS service health, platform-version, and unsafe
  task-definition findings.

Investigators re-read live AWS, inspect direct relationships and recovery or
runtime evidence, use AWS Config relationships when a recorder is available,
and return unresolved business, IaC, application, and external-dependency
questions. Operational hypotheses are never presented as confirmed root cause.

The dossier reports evidence coverage separately from deletion readiness. It
never treats a missing permission, disabled AWS Config recorder, absent metric,
or zero observed relationships as proof that deletion is safe. Human
confirmations are recorded separately from AWS evidence. Even a
`candidate_for_approval` remains `safe_to_delete: false`; deletion and address
release stay planning-only.

EKS investigations correlate control-plane, node group, managed add-on, node,
workload, pod, Service, PDB, HPA, ingress, and event evidence. Kubernetes access
requires an explicit `kubernetes_context` and `eks_cluster_name`; a supplied
kubeconfig never causes Steward to use its active context implicitly. Steward
compares the selected API endpoint and CA fingerprint with
`eks:DescribeCluster` before reading workloads. Access is allowlisted and cannot read
Secrets or logs, execute commands, proxy traffic,
port-forward, or write resources. EKS and Kubernetes remediation is always
planning-only through generated Terraform, CloudFormation, eksctl, Kubernetes
YAML, Helm, or Kustomize fragments.

Most findings are planning-only. Guarded apply is limited to:

- S3 public access block, default encryption, lifecycle, versioning, and server
  access logging;
- CloudWatch Logs retention;
- CloudTrail log file validation; and
- ALB access logging.

S3 and ALB logging require a pre-existing destination in the selected Region,
SSE-S3 encryption, and a bucket policy that grants `s3:PutObject` to the
appropriate AWS log-delivery service principal for the requested prefix. An S3
server-access-log destination must not have server access logging enabled; an
ALB prefix must not contain `AWSLogs`. Steward validates these conditions when
planning and immediately before applying. It never creates destination buckets,
bucket policies, credentials, or supporting infrastructure. It does not
automatically delete resources, rotate keys, remove permissions, stop workloads,
change traffic, or perform migrations.

Every write requires:

1. a fresh read that reproduces the finding;
2. a server-held plan with exact operation, preconditions, IAM, rollback, and
   verification;
3. a short expiry and digest;
4. unchanged account, Region, and live resource state; and
5. explicit `allow_write=true` for that exact plan.

## Architecture

```text
MCP client
  -> focus, operation, intent, and AWS-context refinement
  -> ephemeral assessment store
      -> contextual Well-Architected review
      -> bounded architecture neighborhood
      -> evidence and operation ledger
      -> contextual recommendation queue
      -> filtered exploration and complete report export
  -> versioned applicability and knowledge packs
  -> safe Terraform and CloudFormation parsers
  -> collector registry + ExecutableRuleSpec registry
  -> live recommendation-source adapters + deterministic deduplication
  -> AWS SDK provider (default) or AWS CLI compatibility provider
  -> typed read allowlist + assessment-local metric cache
  -> detectors + structured evidence
  -> plan store + explicit guarded writes
```

Contextual reviews resolve knowledge before AWS calls, read the primary resource
first, and traverse at most two typed relationship hops. They are limited to 25
graph nodes and 50 deduplicated AWS reads. A missing edge never proves a missing
dependency. Full assessments continue to run service collectors with bounded
concurrency; a service snapshot is reused between rules, and `rule_filter`
narrows both rules and AWS calls.
Twenty-seven signal rules batch CloudWatch `GetMetricData` requests or consume
explicit assessment-local Kubernetes historical metric fixtures through an
assessment-local cache. Missing metric data is unknown, never zero.

This release does not include multi-account traversal, all-Region orchestration,
CDK/Pulumi source review, attack graphs, hosted history, telemetry, or an AWS MCP provider.
See [`docs/expansion-plan.md`](docs/expansion-plan.md) for multi-account,
cross-Region, source mapping, performance, and IaC remediation expansion.

## Development

Install quality tools with Python 3.10, 3.11, or 3.13:

```bash
make dev-sync
make test
make quality
make security
make package
```

Run the actual stdio MCP protocol against deterministic LocalEmu fixtures:

```bash
make emulator-doctor
make emulator-mcp-e2e
```

The E2E proves both `full assessment -> partial/final results -> unified source
deduplication -> paginated query -> PDF -> plan -> verify` and `vague request ->
focus -> contextual questions -> focused review -> resource details ->
investigation -> report`. It verifies the focused S3 flow does not call EC2 or
RDS collectors, remains below the read budget, and performs zero writes.
`make emulator-coverage` also
requires a positive finding for every one of the 100 active rules through the
AWS SDK and AWS CLI providers. Eighty-eight fixtures use LocalEmu APIs directly;
twelve historical, account-level, metric-dimension, or synthetic-size states use
a test-only loopback response overlay documented in
[`tests/aws-emulator/rule-map.yml`](tests/aws-emulator/rule-map.yml).
LocalEmu remains running unless `make emulator-down` is called.

Run the complete hybrid EKS product gate with Docker, `kind`, and `kubectl`:

```bash
uv sync --dev
make eks-lab-full
```

This resets a disposable `kind` cluster, validates all 20 EKS/Kubernetes rules
through one real MCP stdio process, investigates every rule, validates six IaC
formats, applies one patch only through the test harness, re-scans, and exports
a PDF. The MCP operation log must contain zero writes.

The manual, billable AWS parity gate creates separate vulnerable and healthy
EKS clusters in an explicitly allowlisted sandbox account:

```bash
make eks-aws-lab-preflight
make eks-aws-lab-plan
make eks-aws-lab-full
```

It validates a wheel-installed runtime, endpoint/CA binding, EKS access entries,
read-only RBAC, real Container Insights datapoints, every rule and investigation,
CloudTrail/audit logs, reports, and mandatory teardown. Read the required safety
controls in [`tests/aws-eks-live/README.md`](tests/aws-eks-live/README.md) first.

For a manual read-only AWS validation:

```bash
AWS_PROFILE=my-sso-profile AWS_REGION=us-east-1 make aws-live-cost-parity
AWS_PROFILE=my-sso-profile AWS_REGION=us-east-1 make aws-live-mcp
```

Never place AWS credentials in GitHub Actions. CI uses dummy credentials with
LocalEmu and never selects an AWS profile. LocalStack remains available only as
an optional compatibility target through `make localstack-compat-coverage`.

## Catalog And IAM Artifacts

Refresh the catalog from a sibling `aws-misconfig-db` checkout:

```bash
.venv/bin/python -m bluearch_aws_steward rules sync --source ../aws-misconfig-db
make catalog-check CATALOG_SOURCE=../aws-misconfig-db
.venv/bin/python -m bluearch_aws_steward.iam_policies
.venv/bin/python -m bluearch_aws_steward.iam_policies --check
```

`make test` is standalone and does not require a sibling catalog checkout.
`make catalog-check` is the explicit maintainer gate that compares the bundled
catalog with a selected `aws-misconfig-db` checkout.

Catalog text is untrusted data. Only reviewed `ExecutableRuleSpec` mappings may
drive AWS calls or pass/fail results.

## Contributing And Security

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a pull request. Report
vulnerabilities privately according to [`SECURITY.md`](SECURITY.md). The
project is licensed under Apache-2.0; see [`LICENSE`](LICENSE).
