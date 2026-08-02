# Native Rule Coverage

BlueArch AWS Steward v0.8.0b1 contains 120 canonical native rules across 17
runtime scopes. Aliases are routing conveniences and do not increase this
count. The complete knowledge catalog contains 649 entries; therefore native
automation coverage is 18.49%. All 120 rules are in the open-source `free`
access tier; future canonical additions after this baseline default to
`premium` unless project governance promotes them.

Use `bluearch_get_coverage` for the runtime-authoritative result. A rule that is
skipped because of missing provider capability or AWS permission is not
evaluated and must never be interpreted as passing.

## IAM (11)

- `iam-root-mfa-disabled`
- `iam-root-access-key-present`
- `iam-password-policy-missing`
- `iam-console-user-mfa-disabled`
- `iam-access-key-older-than-90-days`
- `iam-policy-full-admin`
- `iam-policy-attached-directly-to-user`
- `iam-password-policy-number-missing`
- `iam-support-role-missing`
- `iam-role-wildcard-trust`
- `iam-root-hardware-mfa-missing`

## CloudTrail (4)

- `cloudtrail-multi-region-logging-disabled`
- `cloudtrail-log-validation-disabled`
- `cloudtrail-kms-encryption-disabled`
- `cloudtrail-cloudwatch-integration-missing`

## CloudWatch (1)

- `cloudwatch-log-retention-missing`

## DynamoDB (5)

- `dynamodb-inactive-table` (CloudWatch signal)
- `dynamodb-on-demand-low-utilization` (CloudWatch signal)
- `dynamodb-standard-ia-candidate`
- `dynamodb-read-capacity-underutilized` (CloudWatch signal)
- `dynamodb-write-capacity-underutilized` (CloudWatch signal)

## S3 (14)

- `s3-public-bucket`
- `s3-no-default-encryption`
- `s3-no-lifecycle`
- `s3-intelligent-tiering-missing`
- `s3-versioning-disabled`
- `s3-policy-all-actions-public`
- `s3-policy-public-delete`
- `s3-tls-enforcement-missing`
- `s3-server-access-logging-disabled`
- `s3-mfa-delete-disabled`
- `s3-object-lock-required`
- `s3-cloudtrail-access-logging-disabled`
- `s3-replication-required`
- `s3-kms-encryption-required`

## EC2 And Networking (19)

- `ec2-unattached-ebs-volume`
- `ec2-ebs-volume-unencrypted`
- `ec2-unassociated-elastic-ip`
- `ec2-security-group-ssh-open`
- `ec2-security-group-rdp-open`
- `ec2-default-security-group-not-restricted`
- `vpc-flow-logs-disabled`
- `ebs-orphaned-snapshot-or-ami`
- `ec2-ebs-delete-on-termination-disabled`
- `ec2-security-group-rule-count-high`
- `ec2-idle-instance` (CloudWatch signal)
- `ec2-unused-security-group`
- `ec2-gp2-volume-candidate`
- `ec2-previous-generation-instance`
- `ec2-dev-schedule-missing`
- `ec2-low-cpu-rightsizing` (CloudWatch signal)
- `ec2-high-cpu` (CloudWatch signal)
- `ebs-magnetic-volume-overutilized` (CloudWatch signal)
- `ebs-iops-saturation` (CloudWatch signal)

`ebs` and `networking` are aliases for this collector.

## RDS (10)

- `rds-publicly-accessible`
- `rds-storage-unencrypted`
- `rds-multi-az-disabled`
- `rds-gp2-storage`
- `rds-idle-instance` (CloudWatch signal)
- `rds-previous-generation-instance`
- `rds-storage-autoscaling-disabled`
- `rds-low-cpu-rightsizing` (CloudWatch signal)
- `rds-high-cpu` (CloudWatch signal)
- `rds-read-heavy-no-replica` (CloudWatch signal)

## Lambda (11)

- `lambda-xray-tracing-disabled`
- `lambda-admin-execution-role`
- `lambda-unused-function` (CloudWatch signal)
- `lambda-high-error-rate` (CloudWatch signal)
- `lambda-timeout-rate-high` (CloudWatch signal)
- `lambda-memory-underutilized` (CloudWatch signal)
- `lambda-memory-pressure` (CloudWatch signal)
- `lambda-throttling-detected` (CloudWatch signal)
- `lambda-shared-execution-role`
- `lambda-provisioned-concurrency-underused` (CloudWatch signal)
- `lambda-duration-near-timeout` (CloudWatch signal)

## EFS (5)

- `efs-encryption-disabled`
- `efs-lifecycle-policy-missing`
- `efs-inactive-unmounted` (CloudWatch signal)
- `efs-throughput-overprovisioned` (CloudWatch signal)
- `efs-customer-kms-key-missing`

## ECS (4)

- `ecs-unsafe-task-definition`
- `ecs-platform-version-outdated`
- `ecs-inactive-task-definition`
- `ecs-service-health-degraded`

ECS evidence never returns environment-variable values or complete secret
configuration.

## ALB (6)

- `alb-access-logging-disabled`
- `alb-https-listener-missing`
- `alb-weak-tls-policy`
- `alb-certificate-expiring`
- `alb-unhealthy-targets`
- `alb-idle-load-balancer` (CloudWatch signal)

## KMS (1)

- `kms-key-rotation-disabled`

Only eligible, enabled customer-managed symmetric keys with AWS-generated key
material are evaluated. AWS-managed, asymmetric, HMAC, imported-material,
custom-key-store, and pending-deletion keys are not findings for this rule.

## Secrets Manager (1)

- `secrets-manager-rotation-disabled`

The detector reads secret metadata only. It never calls `GetSecretValue` or
returns secret contents.

## SNS (2)

- `sns-topic-encryption-disabled`
- `sns-topic-public-access`

Public-policy evaluation recognizes owner, account, organization, principal,
VPC endpoint, and source ARN restrictions. Full policy documents are redacted.

## SQS (2)

- `sqs-queue-encryption-disabled`
- `sqs-queue-public-access`

Both SSE-SQS and KMS-backed encryption satisfy the encryption rule. The
detector never reads message bodies.

## API Gateway (4)

- `api-gateway-access-logging-disabled`
- `api-gateway-execution-logging-disabled`
- `api-gateway-xray-tracing-disabled`
- `api-gateway-method-authorization-missing`

API Gateway findings expose API, stage, path, method, and control state only.
They do not return request payloads, integration credentials, or templates.

## EKS And Kubernetes (20)

- `eks-public-endpoint-open`
- `eks-private-endpoint-disabled`
- `eks-control-plane-logging-incomplete`
- `eks-version-support-risk`
- `eks-guardduty-runtime-monitoring-disabled`
- `eks-nodegroup-version-skew`
- `eks-nodegroup-ami-outdated`
- `eks-nodegroup-health-degraded`
- `eks-managed-addon-unhealthy`
- `eks-managed-addon-update-available`
- `k8s-workload-missing-resource-requests`
- `k8s-workload-missing-memory-limit`
- `k8s-workload-missing-probes`
- `k8s-workload-disruption-unprotected`
- `k8s-workload-dangerous-privileges`
- `k8s-pod-restart-loop`
- `k8s-pod-unschedulable`
- `k8s-pod-cpu-limit-pressure`
- `k8s-pod-memory-pressure`
- `eks-workload-overprovisioned`

EKS control-plane, node-group, add-on, GuardDuty, and SSM evidence is correlated
with allowlisted Kubernetes nodes, workloads, pods, Services, PDBs, HPAs,
ingresses, and events. Steward never reads Secrets, pod logs, exec sessions,
proxies, or port forwards. An explicit `eks_cluster_name` binds the selected
kubeconfig context to the endpoint and CA returned by `eks:DescribeCluster`.
CPU and memory pressure use live Container Insights data; only the deterministic
14-day overprovisioning history can use a file and is labeled
`synthetic_historical_validation`. EKS and Kubernetes remediation remains
planning-only.

## Thresholds

| Rule family | Default |
| --- | --- |
| IAM access-key age | 90 days |
| Orphaned snapshot or AMI age | 90 days |
| Lambda without invocation | 30 days |
| EC2 idle lookback | 14 days |
| RDS idle lookback | 7 days |
| ALB idle lookback | 7 days |
| ALB certificate warning | 30 days |
| ALB certificate high severity | 7 days |
| EC2 low CPU | 14 complete days below 10% |
| EC2 high CPU | at least 4 of 14 days at or above 90% |
| RDS low CPU | 7 complete days below 10% |
| RDS high CPU | at least 3 of 7 days at or above 90% |
| DynamoDB inactivity | 30 complete days with no consumed capacity |

CloudWatch-backed rules require complete metric evidence. Missing datapoints are
unknown and suppress the finding; they are never interpreted as zero.

## Test Ownership

- The 100 AWS-only rules require at least one positive resource proof against
  LocalEmu 1.1.0 through both the AWS SDK and AWS CLI providers.
- The AWS-only real stdio MCP E2E requires the same 100 rule IDs and proves `assess ->
  status -> partial results -> final results -> plan -> verify` without writes.
- The 20 EKS/Kubernetes rules use the hybrid LocalEmu plus `kind` lab. Every
  rule must detect its vulnerable fixture, ignore its healthy counterpart, and
  complete a live MCP investigation with expected inside-cluster evidence and
  zero writes.
- The manual AWS parity gate uses distinct vulnerable and healthy EKS clusters,
  a wheel-installed stdio MCP runtime, access-entry/RBAC validation, real
  Container Insights metrics, CloudTrail and Kubernetes audit logs, and mandatory
  cleanup. AWS responses are never replaced by mocks in this gate.
- Eighty-eight rules are backed only by LocalEmu resources and metric datapoints.
- Twelve rules use a loopback-only fixture response overlay for state no public
  create API can set or behavior LocalEmu cannot preserve accurately: root-key
  presence, access-key age, snapshot age, Lambda last-modified time, DynamoDB
  synthetic size, and resource-specific RDS/DynamoDB metric dimensions. Their
  underlying LocalEmu resources and CloudWatch datapoints remain real.
- Mocked-provider tests remain responsible for pagination, permission failures,
  redaction, healthy resources, and edge cases. Approved read-only AWS tests
  remain responsible for real-service parity.

See [`../tests/aws-emulator/rule-map.yml`](../tests/aws-emulator/rule-map.yml) for
the AWS-only rule assignment and [`../tests/eks-lab/README.md`](../tests/eks-lab/README.md)
for the EKS Product Pack functional contract.
See [`../tests/aws-eks-live/README.md`](../tests/aws-eks-live/README.md) for the
billable sandbox parity gate.
