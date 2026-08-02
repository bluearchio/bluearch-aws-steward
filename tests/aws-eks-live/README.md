# Real AWS EKS validation lab

This manual gate creates two disposable EKS clusters in an explicitly authorized sandbox account. It proves that Steward binds one kubeconfig context to one EKS control plane, detects and investigates all 20 EKS/Kubernetes rules, ignores healthy controls, and performs no MCP writes.

This lab is intentionally excluded from push and pull-request CI. It creates billable AWS resources and changes regional GuardDuty Runtime Monitoring temporarily. The cleanup path restores GuardDuty and destroys every tagged lab resource.

## Required controls

- Use an isolated AWS sandbox with no production workloads.
- Set the exact 12-digit account ID. Preflight compares it to STS before Terraform.
- Use a dedicated provisioning profile or the protected OIDC workflow.
- Restrict the operator CIDR to `/24` or narrower.
- Pin every fixture image by digest.
- Keep the TTL at eight hours or less and the budget at US$30 or less.

Local example:

```bash
export AWS_PROFILE=my-sandbox-profile
export AWS_REGION=us-east-1
export EKS_LAB_ALLOWED_ACCOUNT_ID=123456789012
export EKS_LAB_ADMIN_CIDR=203.0.113.10/32
export EKS_LAB_NGINX_IMAGE='public.ecr.aws/example/nginx@sha256:<64 hex characters>'
export EKS_LAB_BUSYBOX_IMAGE='public.ecr.aws/example/busybox@sha256:<64 hex characters>'
export EKS_LAB_PYTHON_IMAGE='public.ecr.aws/example/python@sha256:<64 hex characters>'
export EKS_LAB_TTL_HOURS=8
export EKS_LAB_BUDGET_USD=30
export EKS_LAB_NODEGROUP_DEGRADE_TIMEOUT_MINUTES=45
export BLUEARCH_EKS_LAB_ACK=I_UNDERSTAND_THIS_IS_DESTRUCTIVE
```

Do not copy the sample account ID or image placeholders. Supply values owned by the sandbox operator.

## Commands

Run the complete gate with mandatory cleanup:

```bash
make eks-aws-lab-full
```

Or use the staged flow for diagnosis. Do not invoke `eks-aws-lab-full` after `up`; it starts a separate complete run.

```bash
make eks-aws-lab-preflight
make eks-aws-lab-plan
make eks-aws-lab-up
make eks-aws-lab-seed
make eks-aws-lab-validate-connection
make eks-aws-lab-rules
make eks-aws-lab-investigate
make eks-aws-lab-down
make eks-aws-lab-verify-clean
```

`make eks-aws-lab-full` runs preflight, plan, provisioning, fixture seeding, the real stdio MCP flow, report export, audit checks, and mandatory teardown. An exit trap invokes cleanup after success, failure, interruption, or cancellation.

OpenTofu can validate the Terraform-compatible configuration locally:

```bash
make TERRAFORM=tofu eks-aws-lab-plan
```

## Functional gate

The harness builds the standard wheel and installs `bluearch-aws-steward` into a temporary non-editable environment. This proves the public package includes EKS support without an extra. In one MCP process it executes:

```text
initialize
-> bluearch_validate_eks_connection
-> negative context/cluster mismatch
-> healthy 20-rule assessment
-> 20 focused vulnerable assessments
-> complete assessment with partial-result polling
-> 20 bluearch_investigate_resource calls
-> JSON and PDF exports
-> CloudTrail and Kubernetes audit-log checks
```

The MCP role is separate from the provisioning role. Its AWS policy is limited to the EKS, Container Insights, GuardDuty, SSM, and STS reads used by this gate. Its EKS access entry maps to a custom Kubernetes group that can only `get` and `list` the resources used by Steward. Secrets, `pods/log`, exec, proxy, port-forward, and all mutations remain outside both the provider API and the RBAC role.

## Real fixtures

- The vulnerable control plane has a public endpoint, no private endpoint, incomplete logs, and a version at real support risk.
- Managed node groups reproduce version skew, an older AL2023 release, and real `NodeCreationFailure` in an isolated subnet.
- CoreDNS is pinned to a compatible non-default version.
- ADOT is created without its required `cert-manager` prerequisite and must expose a real unhealthy add-on state.
- Kubernetes deployments reproduce the ten workload/runtime rules with pinned public images.
- Container Insights must publish at least six real CPU and memory datapoints.
- Only the deterministic 14-day overprovisioning history is file-backed and is labeled `synthetic_historical_validation`.
- GuardDuty Runtime Monitoring is enabled for the healthy baseline, disabled for the focused vulnerable check, and restored afterward.

If AWS cannot reproduce a fixture, the gate fails. It does not replace that response with a mock.
The failing node group may take tens of minutes to publish its terminal health issue. The timeout is bounded to 25-60 minutes and recorded by preflight; cleanup waits for external node groups and add-ons to be fully deleted before destroying their cluster and subnet.

## Protected GitHub workflow

`.github/workflows/eks-aws-live.yml` is `workflow_dispatch` only. Configure the protected `eks-aws-validation` environment with required reviewers and these environment secrets:

```text
EKS_LAB_OIDC_ROLE_ARN
EKS_LAB_ALLOWED_ACCOUNT_ID
EKS_LAB_ADMIN_CIDR
```

The account ID and operator CIDR are secrets rather than workflow inputs so they do not become public run metadata. The OIDC role is the test provisioner. It requires temporary permissions to create and destroy the resources in `infra/`, assume the generated MCP read role, read CloudTrail and EKS audit logs, and restore GuardDuty. No long-lived AWS key is stored in GitHub.

## Cost and cleanup

Preflight selects versions using `DescribeClusterVersions` and estimates control-plane and node cost before planning. The AWS Budget records and alerts on tagged spend; it is not a hard spending limit, so the eight-hour cleanup deadline remains mandatory. EKS currently charges different hourly control-plane rates for standard and extended support; verify the current [EKS pricing](https://aws.amazon.com/eks/pricing/) before each run.

Runtime artifacts, Terraform state, account identifiers, kubeconfigs, and reports remain under ignored `.artifacts/`. GitHub uploads only redacted receipts; reports are intentionally not uploaded because they contain sandbox resource details. `make eks-aws-lab-verify-clean` checks tags, cluster names, IAM role names, budgets, and temporary kubeconfigs before declaring cleanup complete.
