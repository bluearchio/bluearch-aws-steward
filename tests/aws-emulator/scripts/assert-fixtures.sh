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

assert_bucket_exists() {
  local bucket="$1"
  "${AWS_CMD[@]}" s3api head-bucket --bucket "$bucket" >/dev/null
}

assert_public_access_block_value() {
  local bucket="$1"
  local field="$2"
  local expected="$3"
  local actual

  actual="$("${AWS_CMD[@]}" s3api get-public-access-block \
    --bucket "$bucket" \
    --query "PublicAccessBlockConfiguration.$field" \
    --output text)"

  if [[ "$actual" != "$expected" ]]; then
    echo "Expected $bucket public access block $field=$expected, got $actual" >&2
    return 1
  fi
}

assert_encryption_enabled() {
  local bucket="$1"
  local algorithm

  algorithm="$("${AWS_CMD[@]}" s3api get-bucket-encryption \
    --bucket "$bucket" \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' \
    --output text)"

  if [[ "$algorithm" != "AES256" ]]; then
    echo "Expected $bucket default encryption AES256, got $algorithm" >&2
    return 1
  fi
}

assert_encryption_missing() {
  local bucket="$1"
  local rules

  if ! "${AWS_CMD[@]}" s3api get-bucket-encryption --bucket "$bucket" >/dev/null 2>&1; then
    return 0
  fi

  rules="$("${AWS_CMD[@]}" s3api get-bucket-encryption \
    --bucket "$bucket" \
    --query 'ServerSideEncryptionConfiguration.Rules' \
    --output text)"

  if [[ -z "$rules" || "$rules" == "None" ]]; then
    return 0
  fi

  echo "Expected $bucket to be missing default encryption" >&2
  return 1
}

assert_lifecycle_enabled() {
  local bucket="$1"
  local rule_count

  rule_count="$("${AWS_CMD[@]}" s3api get-bucket-lifecycle-configuration \
    --bucket "$bucket" \
    --query 'length(Rules)' \
    --output text)"

  if [[ "$rule_count" == "0" || "$rule_count" == "None" ]]; then
    echo "Expected $bucket to have lifecycle rules" >&2
    return 1
  fi
}

assert_lifecycle_missing() {
  local bucket="$1"

  if "${AWS_CMD[@]}" s3api get-bucket-lifecycle-configuration --bucket "$bucket" >/dev/null 2>&1; then
    echo "Expected $bucket to be missing lifecycle configuration" >&2
    return 1
  fi
}

assert_versioning_enabled() {
  local bucket="$1"
  local status

  status="$("${AWS_CMD[@]}" s3api get-bucket-versioning \
    --bucket "$bucket" \
    --query Status \
    --output text)"

  if [[ "$status" != "Enabled" ]]; then
    echo "Expected $bucket versioning Enabled, got $status" >&2
    return 1
  fi
}

assert_versioning_disabled() {
  local bucket="$1"
  local status

  status="$("${AWS_CMD[@]}" s3api get-bucket-versioning \
    --bucket "$bucket" \
    --query Status \
    --output text)"

  if [[ "$status" == "Enabled" ]]; then
    echo "Expected $bucket versioning to be disabled" >&2
    return 1
  fi
}

assert_bucket_policy_present() {
  local bucket="$1"
  "${AWS_CMD[@]}" s3api get-bucket-policy --bucket "$bucket" >/dev/null
}

assert_bucket_policy_missing() {
  local bucket="$1"
  if "${AWS_CMD[@]}" s3api get-bucket-policy --bucket "$bucket" >/dev/null 2>&1; then
    echo "Expected $bucket to have no bucket policy" >&2
    return 1
  fi
}

assert_ec2_fixtures() {
  local volume_count
  local volume_encrypted
  local volume_state
  local address_count
  local association_count

  volume_count="$("${AWS_CMD[@]}" ec2 describe-volumes \
    --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unencrypted-unattached" \
    --query 'length(Volumes)' \
    --output text)"
  if [[ "$volume_count" != "1" ]]; then
    echo "Expected one tagged EBS fixture, got $volume_count" >&2
    return 1
  fi

  volume_encrypted="$("${AWS_CMD[@]}" ec2 describe-volumes \
    --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unencrypted-unattached" \
    --query 'Volumes[0].Encrypted' \
    --output text)"
  volume_state="$("${AWS_CMD[@]}" ec2 describe-volumes \
    --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unencrypted-unattached" \
    --query 'Volumes[0].State' \
    --output text)"
  if [[ "$volume_encrypted" != "False" || "$volume_state" != "available" ]]; then
    echo "Expected unencrypted available EBS fixture, got encrypted=$volume_encrypted state=$volume_state" >&2
    return 1
  fi

  address_count="$("${AWS_CMD[@]}" ec2 describe-addresses \
    --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unassociated-eip" \
    --query 'length(Addresses)' \
    --output text)"
  association_count="$("${AWS_CMD[@]}" ec2 describe-addresses \
    --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unassociated-eip" \
    --query 'length(Addresses[?AssociationId!=null])' \
    --output text)"
  if [[ "$address_count" != "1" || "$association_count" != "0" ]]; then
    echo "Expected one unassociated EIP fixture, got addresses=$address_count associations=$association_count" >&2
    return 1
  fi
}

assert_log_fixtures() {
  local missing_retention
  local configured_retention

  missing_retention="$("${AWS_CMD[@]}" logs describe-log-groups \
    --log-group-name-prefix "$BLUEARCH_STEWARD_LOG_NO_RETENTION" \
    --query "logGroups[?logGroupName=='$BLUEARCH_STEWARD_LOG_NO_RETENTION'] | [0].retentionInDays" \
    --output text)"
  configured_retention="$("${AWS_CMD[@]}" logs describe-log-groups \
    --log-group-name-prefix "$BLUEARCH_STEWARD_LOG_RETENTION" \
    --query "logGroups[?logGroupName=='$BLUEARCH_STEWARD_LOG_RETENTION'] | [0].retentionInDays" \
    --output text)"
  if [[ "$missing_retention" != "None" ]]; then
    echo "Expected $BLUEARCH_STEWARD_LOG_NO_RETENTION to have no retention, got $missing_retention" >&2
    return 1
  fi
  if [[ "$configured_retention" != "30" ]]; then
    echo "Expected $BLUEARCH_STEWARD_LOG_RETENTION retention=30, got $configured_retention" >&2
    return 1
  fi
}

assert_lambda_fixtures() {
  local disabled_mode
  local active_mode

  disabled_mode="$("${AWS_CMD[@]}" lambda get-function-configuration \
    --function-name "$BLUEARCH_STEWARD_LAMBDA_NO_TRACING" \
    --query TracingConfig.Mode \
    --output text)"
  active_mode="$("${AWS_CMD[@]}" lambda get-function-configuration \
    --function-name "$BLUEARCH_STEWARD_LAMBDA_TRACING" \
    --query TracingConfig.Mode \
    --output text)"
  if [[ "$disabled_mode" != "PassThrough" || "$active_mode" != "Active" ]]; then
    echo "Expected Lambda tracing modes PassThrough/Active, got $disabled_mode/$active_mode" >&2
    return 1
  fi
}

assert_iam_fixture() {
  local account_mfa_enabled

  account_mfa_enabled="$("${AWS_CMD[@]}" iam get-account-summary \
    --query SummaryMap.AccountMFAEnabled \
    --output text)"
  if [[ "$account_mfa_enabled" != "0" ]]; then
    echo "Expected AWS emulator root MFA fixture to be disabled, got $account_mfa_enabled" >&2
    return 1
  fi
}

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
  assert_bucket_exists "$bucket"
done

assert_public_access_block_value "$PUBLIC_BUCKET" BlockPublicPolicy False
assert_public_access_block_value "$PUBLIC_BUCKET" RestrictPublicBuckets False
assert_encryption_enabled "$PUBLIC_BUCKET"
assert_lifecycle_enabled "$PUBLIC_BUCKET"
assert_versioning_enabled "$PUBLIC_BUCKET"

assert_public_access_block_value "$UNENCRYPTED_BUCKET" BlockPublicPolicy True
assert_encryption_missing "$UNENCRYPTED_BUCKET"
assert_lifecycle_enabled "$UNENCRYPTED_BUCKET"
assert_versioning_enabled "$UNENCRYPTED_BUCKET"

assert_public_access_block_value "$NO_LIFECYCLE_BUCKET" BlockPublicPolicy True
assert_encryption_enabled "$NO_LIFECYCLE_BUCKET"
assert_lifecycle_missing "$NO_LIFECYCLE_BUCKET"
assert_versioning_enabled "$NO_LIFECYCLE_BUCKET"

assert_public_access_block_value "$NO_TIERING_BUCKET" BlockPublicPolicy True
assert_encryption_enabled "$NO_TIERING_BUCKET"
assert_lifecycle_enabled "$NO_TIERING_BUCKET"
assert_versioning_enabled "$NO_TIERING_BUCKET"

assert_public_access_block_value "$VERSIONING_DISABLED_BUCKET" BlockPublicPolicy True
assert_encryption_enabled "$VERSIONING_DISABLED_BUCKET"
assert_lifecycle_enabled "$VERSIONING_DISABLED_BUCKET"
assert_versioning_disabled "$VERSIONING_DISABLED_BUCKET"

for bucket in "$ALL_ACTIONS_BUCKET" "$PUBLIC_DELETE_BUCKET"; do
  assert_public_access_block_value "$bucket" BlockPublicPolicy True
  assert_encryption_enabled "$bucket"
  assert_lifecycle_enabled "$bucket"
  assert_versioning_enabled "$bucket"
  assert_bucket_policy_present "$bucket"
done

assert_public_access_block_value "$TLS_MISSING_BUCKET" BlockPublicPolicy True
assert_encryption_enabled "$TLS_MISSING_BUCKET"
assert_lifecycle_enabled "$TLS_MISSING_BUCKET"
assert_versioning_enabled "$TLS_MISSING_BUCKET"
assert_bucket_policy_missing "$TLS_MISSING_BUCKET"

assert_public_access_block_value "$SECURE_BUCKET" BlockPublicPolicy True
assert_public_access_block_value "$SECURE_BUCKET" RestrictPublicBuckets True
assert_encryption_enabled "$SECURE_BUCKET"
assert_lifecycle_enabled "$SECURE_BUCKET"
assert_versioning_enabled "$SECURE_BUCKET"
assert_bucket_policy_present "$SECURE_BUCKET"

assert_ec2_fixtures
assert_log_fixtures
assert_lambda_fixtures
assert_iam_fixture
run_extended_fixtures assert

echo "AWS emulator BlueArch fixture assertions passed."
