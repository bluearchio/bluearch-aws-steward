# AWS Emulator Fixture Environment

This directory creates intentionally misconfigured AWS resources so BlueArch
AWS Steward can test discovery, detection, remediation planning, write safety,
and verification without touching a real AWS account.

LocalEmu 1.1.0 is the default emulator. The deterministic suite requires a
positive finding for all 100 AWS-only executable rules across 16 runtime scopes through
the AWS SDK provider, AWS CLI provider, and actual stdio MCP server.

Eighty-eight rules use only resources and metric datapoints created through
LocalEmu's AWS-compatible APIs. Twelve rules depend on account, historical,
synthetic-size, or dimension-isolation states that public APIs or LocalEmu
cannot reproduce deterministically. A loopback-only test proxy overlays only
those response fields while retaining real LocalEmu resources underneath:

- root access-key presence;
- IAM access-key creation time;
- EBS snapshot creation time;
- Lambda last-modified time;
- DynamoDB table size; and
- resource-specific DynamoDB and RDS CloudWatch series.

The same loopback proxy supplies deterministic read-only Security Hub,
Compute Optimizer, and Cost Optimization Hub responses because LocalEmu does
not implement those managed recommendation services. The stdio MCP E2E
combines them with native resources and a Prowler JSON fixture, proves
cross-source deduplication and provenance, exports PDF, creates a no-write plan,
and verifies the active finding. These API fixtures validate adapters and queue
semantics; they do not claim managed-service emulator parity.

The proxy is fixture code, is not packaged, and does not alter production
providers, thresholds, or detector behavior. See `rule-map.yml` for the exact
boundary.

The Compose file pins the tested LocalEmu release. Change `LOCALEMU_IMAGE` only
when validating an upgrade, then update the version, image digest, and coverage
evidence in the same change.

An emulator is not a substitute for a real AWS sandbox. Provider parity,
permission boundaries, pagination, and service-specific edge cases still need
unit tests and approved read-only AWS validation.

## Prerequisites

- Docker with Compose support.
- AWS CLI v2.
- Python 3.10 or newer.
- The repository development environment installed with `make dev-sync`.
- No real AWS credentials. Every fixture command uses dummy credentials.

## Quick Start

From the repository root:

```bash
make emulator-doctor
make emulator-coverage
```

`emulator-coverage` replaces the LocalEmu service container with a clean one,
recreates all fixtures, requires at least one matched resource for every active
rule with both providers, and exercises the actual stdio MCP server. Replacing
the dummy local container prevents terminated instances and inactive task
definition revisions from accumulating in emulator implementations that do not
fully delete those resources. It proves:

```text
assess -> status -> partial results -> unified source queue -> final results -> PDF -> plan -> verify
```

No write tool is called by the coverage target. To also test the four supported
low-risk S3 remediations and verify the resulting state, run:

```bash
make emulator-mvp
```

## Native Fixture Coverage

| Runtime scope | Rules exercised | Required positive proofs |
| --- | ---: | ---: |
| IAM | 11 | 11 |
| CloudTrail | 4 | 4 |
| CloudWatch Logs | 1 | 1 |
| DynamoDB | 5 | 5 |
| S3 | 14 | 14 |
| EC2/EBS/networking | 19 | 19 |
| RDS | 10 | 10 |
| Lambda | 11 | 11 |
| EFS | 5 | 5 |
| ECS | 4 | 4 |
| ALB/ACM | 6 | 6 |
| KMS | 1 | 1 |
| Secrets Manager | 1 | 1 |
| SNS | 2 | 2 |
| SQS | 2 | 2 |
| API Gateway | 4 | 4 |
| **Total** | **100** | **100** |

Some resources intentionally match more than one rule, so the total finding
count can be greater than 100. Assertions require all active rule IDs and their
authoritative resource proofs instead of relying on a fragile exact total.

## Fixture Resources

### S3

| Bucket | Purpose |
| --- | --- |
| `bluearch-steward-public` | Public policy with public access block disabled. |
| `bluearch-steward-unencrypted` | Missing default server-side encryption. |
| `bluearch-steward-no-lifecycle` | Missing lifecycle configuration. |
| `bluearch-steward-no-tiering` | Lifecycle exists, but no lower-cost storage tier transition is configured. |
| `bluearch-steward-versioning-disabled` | Versioning intentionally suspended. |
| `bluearch-steward-policy-all-actions-public` | Public `s3:*` policy; also matches public delete. |
| `bluearch-steward-policy-public-delete` | Explicit public `s3:DeleteObject` policy. |
| `bluearch-steward-tls-missing` | Missing insecure-transport deny policy. |
| `bluearch-steward-secure` | Healthy S3 control resource. |

Every S3 fixture except `tls-missing` has the expected TLS deny statement, so
findings remain isolated to the intended rules.

### Other Services

| Resource | Purpose |
| --- | --- |
| Tagged unencrypted, unattached EBS volume | Exercises encryption and unused-volume rules. |
| Tagged unassociated Elastic IP | Exercises unused-address detection. |
| `bluearch-steward-no-retention` log group | Missing retention policy. |
| `bluearch-steward-retention-30-days` log group | Healthy log-retention control. |
| `bluearch-steward-no-tracing` function | Lambda X-Ray mode is `PassThrough`. |
| `bluearch-steward-active-tracing` function | Healthy Lambda tracing control. |
| LocalEmu root account | Reports `AccountMFAEnabled=0`. |
| IAM console user, access key, and direct full-admin policy | Exercises console MFA, key age, direct attachment, and full-admin rules. |
| Single-region CloudTrail without validation, KMS, or CloudWatch Logs | Exercises all CloudTrail rules. |
| Inactive, infrequent-access, and underused provisioned DynamoDB tables | Exercises all DynamoDB rules. |
| Public, unencrypted, single-AZ gp2 RDS instances with low/high CPU and read-heavy signals | Exercises all RDS rules. |
| Unencrypted and overprovisioned EFS file systems without lifecycle or mounts | Exercises all EFS rules. |
| Public admin-port and unused security groups, low/high CPU EC2 instances, EBS volumes, snapshot, and default VPC | Exercises EC2, EBS, and networking rules. |
| Admin-role, shared-role, unused, timeout, memory-pressure, throttled, and high-error Lambda functions | Exercises all Lambda rules. |
| Unsafe and inactive ECS task definitions plus outdated and degraded Fargate service | Exercises all ECS rules. |
| Healthy ECS service with a long-running, non-privileged BusyBox task | Proves that LocalEmu can start a real Docker-backed ECS task and provides a healthy control. |
| HTTP-only and weak-TLS ALBs, target groups, and short-lived ACM certificate | Exercises all ALB rules. |
| Customer-managed symmetric KMS key with rotation disabled | Exercises KMS rotation detection. |
| Secrets Manager secret without rotation | Exercises metadata-only secret rotation detection. |
| Unencrypted SNS topic with an unconditioned public policy | Exercises both SNS rules. |
| Unencrypted SQS queue with an unconditioned public policy | Exercises both SQS rules. |
| REST API with an unauthenticated GET method and uninstrumented stage | Exercises all API Gateway rules. |

Dynamic EC2 identifiers are matched by URI pattern. Fixture tags are validated
inside the setup scripts and are not copied into user-facing finding evidence.

## ECS And EKS Boundaries

The ECS fixture includes an actual long-running container. Assertions inspect
the task definition, task status, and container status and require the healthy
task to be `RUNNING`. LocalEmu 1.1.0 does not reliably reconcile ECS service
`runningCount` and `pendingCount`, so those counters are not used as proof of
container health. That divergence remains useful for the separate degraded
service finding.

LocalEmu can create and describe an EKS control-plane object, including endpoint
access, logging, encryption, and version fields. In the tested release the
cluster settles in `CREATE_FAILED`, and its generated Kubernetes endpoint is
not a reachable API server. Therefore:

- AWS-side EKS rule fixtures may use LocalEmu for deterministic control-plane
  responses;
- Kubernetes workload, scheduling, probe, rollout, and live debugging tests
  must use a real local cluster such as `kind`;
- static manifests and provider stubs remain appropriate for isolated unit
  tests, but cannot be presented as a functional cluster proof;
- production validation still requires an approved read-only AWS EKS sandbox.

The implemented EKS fixture pack is intentionally hybrid: LocalEmu owns the AWS
API surface and `kind` owns the Kubernetes API and workloads. Steward correlates
the two fixture identities without claiming that either emulator reproduces the
managed EKS data plane. Run it separately with `make eks-lab-full`; see
[`../eks-lab/README.md`](../eks-lab/README.md). The regular
`make emulator-coverage` gate remains the 100-rule AWS-only baseline.

## Useful Targets

```bash
make emulator-recreate   # replace container, seed, and validate resource state
make emulator-coverage   # run both providers and the real stdio MCP E2E
make emulator-mcp-e2e    # exercise only the stdio MCP flow after recreation
make emulator-scan       # scan the four remediable S3 controls
make emulator-mvp        # broad coverage plus guarded S3 apply and verification
make emulator-logs       # follow LocalEmu logs
make emulator-down       # stop LocalEmu
```

Artifacts are written under `tests/aws-emulator/.artifacts/`. Expected findings
are declared in `expected/findings.native.json`; rule-to-test-mode ownership is
documented in `rule-map.yml`.

## LocalStack Compatibility

LocalStack is retained only as an optional parity target during the migration:

```bash
make localstack-compat-coverage
make localstack-compat-down
```

The old `localstack-*` target names select this compatibility profile. New
development and CI must use `emulator-*`, which runs LocalEmu by default.

## Safety Expectations

- All fixture traffic uses the explicit `http://localhost:4566` endpoint.
- The response-overlay proxy accepts only an explicit loopback upstream.
- Scripts inject dummy credentials and never require an AWS profile.
- Broad coverage scans are read-only.
- Writes still require an explicit approval contract.
- Destructive EC2 recommendations are detected but never auto-applied.
- Remediation tests verify state after apply.
