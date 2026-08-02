# EKS And Kubernetes Functional Lab

This disposable hybrid lab validates the EKS Product Pack through the actual
Steward stdio MCP server. LocalEmu provides deterministic AWS EKS, node group,
add-on, GuardDuty, EC2, ALB, SSM, and metric responses. A four-node `kind`
cluster provides real Kubernetes nodes, namespaces, workloads, pods, Services,
PDBs, HPAs, and events. `fixture-map.yml` correlates both sides.
Every MCP assessment selects the exact `kind-bluearch-eks-lab` context; Steward
does not consume the workstation's active Kubernetes context implicitly.

The lab does not emulate the managed EKS data plane. A final preview still
requires approved read-only validation against an AWS EKS cluster.

## Prerequisites

- Docker with Compose
- `kind` 0.32.0
- `kubectl`
- `uv`

Install the locked development environment, including the optional Kubernetes
client:

```bash
uv sync --extra tui --dev --no-editable --locked
```

## Run

```bash
make eks-lab-up
make eks-lab-status
make eks-lab-phase-0
make eks-lab-phase-1
make eks-lab-phase-2
make eks-lab-phase-3
make eks-lab-phase-4
make eks-lab-remediation
make eks-lab-full
make eks-lab-down
```

`make eks-lab-full` resets the disposable cluster and runs one MCP process
through initialize, assess, status, complete and queried results, all 20
investigations, patch generation and validation, harness-only patch apply,
post-fix assessment, and PDF export.

## Functional Contract

Each rule receipt must prove:

- the vulnerable fixture was detected;
- the healthy counterpart was not detected;
- rule-specific expected evidence was present;
- the investigation completed with inside-cluster evidence;
- no unsupported conclusion was presented;
- Kubernetes write operations remained zero.

The 20 rules cover EKS control-plane exposure, logging, support status,
GuardDuty, node groups, managed add-ons, workload configuration, dangerous
privileges, pod runtime failures, CPU and memory pressure, and
overprovisioning. Phase 0 separately proves that a healthy workload remains
clean and that investigation does not invent a root cause.

MCP never applies EKS or Kubernetes changes. The remediation harness may apply
one generated patch only to the disposable `kind` namespace, then verifies the
finding is gone and the workload remains Ready. Local receipts and reports are
written to `.artifacts/`, which is excluded from Git.
