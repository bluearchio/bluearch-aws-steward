#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_emulator

PUBLIC_BUCKET="$(fixture_bucket public)"
UNENCRYPTED_BUCKET="$(fixture_bucket unencrypted)"
NO_LIFECYCLE_BUCKET="$(fixture_bucket no-lifecycle)"
NO_TIERING_BUCKET="$(fixture_bucket no-tiering)"
VERSIONING_DISABLED_BUCKET="$(fixture_bucket versioning-disabled)"
ALL_ACTIONS_BUCKET="$(fixture_bucket policy-all-actions-public)"
PUBLIC_DELETE_BUCKET="$(fixture_bucket policy-public-delete)"
TLS_MISSING_BUCKET="$(fixture_bucket tls-missing)"
SECURE_BUCKET="$(fixture_bucket secure)"

for bucket in \
  "$PUBLIC_BUCKET" \
  "$UNENCRYPTED_BUCKET" \
  "$NO_LIFECYCLE_BUCKET" \
  "$NO_TIERING_BUCKET" \
  "$VERSIONING_DISABLED_BUCKET" \
  "$ALL_ACTIONS_BUCKET" \
  "$PUBLIC_DELETE_BUCKET" \
  "$TLS_MISSING_BUCKET" \
  "$SECURE_BUCKET"; do
  reset_bucket_to_empty_baseline "$bucket"
done

# Public bucket: isolate the public-access finding by keeping the rest healthy.
disable_public_access_block "$PUBLIC_BUCKET"
enable_default_encryption "$PUBLIC_BUCKET"
enable_lifecycle "$PUBLIC_BUCKET"
enable_versioning "$PUBLIC_BUCKET"

public_policy_file="$(mktemp)"
cat > "$public_policy_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadFixture",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::$PUBLIC_BUCKET/*"
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$PUBLIC_BUCKET",
        "arn:aws:s3:::$PUBLIC_BUCKET/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
JSON
"${AWS_CMD[@]}" s3api put-bucket-policy \
  --bucket "$PUBLIC_BUCKET" \
  --policy "file://$public_policy_file" \
  >/dev/null
rm -f "$public_policy_file"

# Unencrypted bucket: isolate the missing encryption finding.
enable_public_access_block "$UNENCRYPTED_BUCKET"
disable_default_encryption "$UNENCRYPTED_BUCKET"
enable_lifecycle "$UNENCRYPTED_BUCKET"
enable_versioning "$UNENCRYPTED_BUCKET"
put_tls_enforcement_policy "$UNENCRYPTED_BUCKET"

# No lifecycle bucket: isolate the lifecycle finding.
enable_public_access_block "$NO_LIFECYCLE_BUCKET"
enable_default_encryption "$NO_LIFECYCLE_BUCKET"
enable_versioning "$NO_LIFECYCLE_BUCKET"
put_tls_enforcement_policy "$NO_LIFECYCLE_BUCKET"

# No tiering bucket: lifecycle exists, but it expires objects without lower-cost tiering.
enable_public_access_block "$NO_TIERING_BUCKET"
enable_default_encryption "$NO_TIERING_BUCKET"
enable_expiration_only_lifecycle "$NO_TIERING_BUCKET"
enable_versioning "$NO_TIERING_BUCKET"
put_tls_enforcement_policy "$NO_TIERING_BUCKET"

# Versioning-disabled bucket: isolate the recovery/versioning finding.
enable_public_access_block "$VERSIONING_DISABLED_BUCKET"
enable_default_encryption "$VERSIONING_DISABLED_BUCKET"
enable_lifecycle "$VERSIONING_DISABLED_BUCKET"
put_tls_enforcement_policy "$VERSIONING_DISABLED_BUCKET"

# Public wildcard policy: naturally also exercises the public-delete rule.
disable_public_access_block "$ALL_ACTIONS_BUCKET"
enable_default_encryption "$ALL_ACTIONS_BUCKET"
enable_lifecycle "$ALL_ACTIONS_BUCKET"
enable_versioning "$ALL_ACTIONS_BUCKET"

all_actions_policy_file="$(mktemp)"
cat > "$all_actions_policy_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicWildcardFixture",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$ALL_ACTIONS_BUCKET",
        "arn:aws:s3:::$ALL_ACTIONS_BUCKET/*"
      ]
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$ALL_ACTIONS_BUCKET",
        "arn:aws:s3:::$ALL_ACTIONS_BUCKET/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
JSON
"${AWS_CMD[@]}" s3api put-bucket-policy \
  --bucket "$ALL_ACTIONS_BUCKET" \
  --policy "file://$all_actions_policy_file" \
  >/dev/null
rm -f "$all_actions_policy_file"
enable_public_access_block "$ALL_ACTIONS_BUCKET"

# Public delete policy: isolate explicit destructive public access.
disable_public_access_block "$PUBLIC_DELETE_BUCKET"
enable_default_encryption "$PUBLIC_DELETE_BUCKET"
enable_lifecycle "$PUBLIC_DELETE_BUCKET"
enable_versioning "$PUBLIC_DELETE_BUCKET"

public_delete_policy_file="$(mktemp)"
cat > "$public_delete_policy_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicDeleteFixture",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:DeleteObject",
      "Resource": "arn:aws:s3:::$PUBLIC_DELETE_BUCKET/*"
    },
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$PUBLIC_DELETE_BUCKET",
        "arn:aws:s3:::$PUBLIC_DELETE_BUCKET/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
JSON
"${AWS_CMD[@]}" s3api put-bucket-policy \
  --bucket "$PUBLIC_DELETE_BUCKET" \
  --policy "file://$public_delete_policy_file" \
  >/dev/null
rm -f "$public_delete_policy_file"
enable_public_access_block "$PUBLIC_DELETE_BUCKET"

# TLS-missing bucket: all other supported controls are healthy.
enable_public_access_block "$TLS_MISSING_BUCKET"
enable_default_encryption "$TLS_MISSING_BUCKET"
enable_lifecycle "$TLS_MISSING_BUCKET"
enable_versioning "$TLS_MISSING_BUCKET"

# Secure control bucket: expected to pass all initial S3 fixture checks.
enable_public_access_block "$SECURE_BUCKET"
enable_default_encryption "$SECURE_BUCKET"
enable_lifecycle "$SECURE_BUCKET"
enable_versioning "$SECURE_BUCKET"
put_tls_enforcement_policy "$SECURE_BUCKET"

# EC2 fixtures: one volume intentionally matches both EBS rules and one EIP is unassociated.
VOLUME_ID="$("${AWS_CMD[@]}" ec2 create-volume \
  --availability-zone "${AWS_DEFAULT_REGION}a" \
  --size 1 \
  --volume-type gp2 \
  --no-encrypted \
  --tag-specifications \
  "ResourceType=volume,Tags=[{Key=$BLUEARCH_STEWARD_FIXTURE_TAG,Value=ec2-unencrypted-unattached}]" \
  --query VolumeId \
  --output text)"
"${AWS_CMD[@]}" ec2 wait volume-available --volume-ids "$VOLUME_ID"

ALLOCATION_ID="$("${AWS_CMD[@]}" ec2 allocate-address \
  --domain vpc \
  --query AllocationId \
  --output text)"
"${AWS_CMD[@]}" ec2 create-tags \
  --resources "$ALLOCATION_ID" \
  --tags "Key=$BLUEARCH_STEWARD_FIXTURE_TAG,Value=ec2-unassociated-eip" \
  >/dev/null

# CloudWatch Logs fixtures include a failing group and a healthy control.
"${AWS_CMD[@]}" logs create-log-group --log-group-name "$BLUEARCH_STEWARD_LOG_NO_RETENTION" >/dev/null
"${AWS_CMD[@]}" logs create-log-group --log-group-name "$BLUEARCH_STEWARD_LOG_RETENTION" >/dev/null
"${AWS_CMD[@]}" logs put-retention-policy \
  --log-group-name "$BLUEARCH_STEWARD_LOG_RETENTION" \
  --retention-in-days 30 \
  >/dev/null

# Lambda fixtures share a minimal execution role and differ only in X-Ray mode.
lambda_assume_role_file="$(mktemp)"
cat > "$lambda_assume_role_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }
  ]
}
JSON
ROLE_ARN="$("${AWS_CMD[@]}" iam create-role \
  --role-name "$BLUEARCH_STEWARD_LAMBDA_ROLE" \
  --assume-role-policy-document "file://$lambda_assume_role_file" \
  --query Role.Arn \
  --output text)"
rm -f "$lambda_assume_role_file"

FIXTURE_DIR="$(cd "$SCRIPT_DIR/../fixtures" && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR/../.artifacts"
mkdir -p "$ARTIFACT_DIR"
LAMBDA_ZIP="$(cd "$ARTIFACT_DIR" && pwd)/lambda-fixture.zip"
rm -f "$LAMBDA_ZIP"
(
  cd "$FIXTURE_DIR"
  "$BLUEARCH_STEWARD_TEST_PYTHON" -m zipfile -c "$LAMBDA_ZIP" lambda_function.py
)

"${AWS_CMD[@]}" lambda create-function \
  --function-name "$BLUEARCH_STEWARD_LAMBDA_NO_TRACING" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler lambda_function.handler \
  --zip-file "fileb://$LAMBDA_ZIP" \
  --tracing-config Mode=PassThrough \
  >/dev/null
"${AWS_CMD[@]}" lambda create-function \
  --function-name "$BLUEARCH_STEWARD_LAMBDA_TRACING" \
  --runtime python3.11 \
  --role "$ROLE_ARN" \
  --handler lambda_function.handler \
  --zip-file "fileb://$LAMBDA_ZIP" \
  --tracing-config Mode=Active \
  >/dev/null

run_extended_fixtures seed

echo "Seeded AWS emulator BlueArch fixtures:"
printf '  - s3://%s\n' \
  "$PUBLIC_BUCKET" \
  "$UNENCRYPTED_BUCKET" \
  "$NO_LIFECYCLE_BUCKET" \
  "$VERSIONING_DISABLED_BUCKET" \
  "$ALL_ACTIONS_BUCKET" \
  "$PUBLIC_DELETE_BUCKET" \
  "$TLS_MISSING_BUCKET" \
  "$SECURE_BUCKET"
printf '  - ebs://%s\n' "$VOLUME_ID"
printf '  - eip://%s\n' "$ALLOCATION_ID"
printf '  - cloudwatch-logs://log-group/%s\n' "$BLUEARCH_STEWARD_LOG_NO_RETENTION" "$BLUEARCH_STEWARD_LOG_RETENTION"
printf '  - lambda://function/%s\n' "$BLUEARCH_STEWARD_LAMBDA_NO_TRACING" "$BLUEARCH_STEWARD_LAMBDA_TRACING"
printf '  - iam://account/root (AWS emulator root MFA disabled)\n'
printf '  - extended IAM, CloudTrail, RDS, EFS, ECS, EC2, Lambda, ALB, ACM, and metric fixtures\n'
