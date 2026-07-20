#!/usr/bin/env bash
set -euo pipefail

export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-test}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_PAGER=""

EMULATOR_ENDPOINT="${EMULATOR_ENDPOINT:-http://localhost:4566}"
BLUEARCH_STEWARD_FIXTURE_PREFIX="${BLUEARCH_STEWARD_FIXTURE_PREFIX:-bluearch-steward}"
BLUEARCH_STEWARD_FIXTURE_TAG="bluearch-steward-fixture"
BLUEARCH_STEWARD_LAMBDA_ROLE="${BLUEARCH_STEWARD_FIXTURE_PREFIX}-lambda-role"
BLUEARCH_STEWARD_LAMBDA_NO_TRACING="${BLUEARCH_STEWARD_FIXTURE_PREFIX}-no-tracing"
BLUEARCH_STEWARD_LAMBDA_TRACING="${BLUEARCH_STEWARD_FIXTURE_PREFIX}-active-tracing"
BLUEARCH_STEWARD_LOG_NO_RETENTION="${BLUEARCH_STEWARD_FIXTURE_PREFIX}-no-retention"
BLUEARCH_STEWARD_LOG_RETENTION="${BLUEARCH_STEWARD_FIXTURE_PREFIX}-retention-30-days"
BLUEARCH_STEWARD_TEST_PYTHON="${BLUEARCH_STEWARD_TEST_PYTHON:-python3}"

AWS_CMD=(aws --endpoint-url "$EMULATOR_ENDPOINT" --region "$AWS_DEFAULT_REGION" --no-cli-pager)

run_extended_fixtures() {
  "$BLUEARCH_STEWARD_TEST_PYTHON" "$SCRIPT_DIR/extended_fixtures.py" "$1" \
    --endpoint-url "$EMULATOR_ENDPOINT" \
    --region "$AWS_DEFAULT_REGION" \
    --prefix "$BLUEARCH_STEWARD_FIXTURE_PREFIX"
}

fixture_bucket() {
  printf '%s-%s' "$BLUEARCH_STEWARD_FIXTURE_PREFIX" "$1"
}

wait_for_emulator() {
  local attempt

  for attempt in $(seq 1 60); do
    if "${AWS_CMD[@]}" sts get-caller-identity >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "AWS emulator is not reachable at $EMULATOR_ENDPOINT" >&2
  return 1
}

create_bucket() {
  local bucket="$1"

  if "${AWS_CMD[@]}" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$AWS_DEFAULT_REGION" == "us-east-1" ]]; then
    "${AWS_CMD[@]}" s3api create-bucket --bucket "$bucket" >/dev/null
  else
    "${AWS_CMD[@]}" s3api create-bucket \
      --bucket "$bucket" \
      --create-bucket-configuration "LocationConstraint=$AWS_DEFAULT_REGION" \
      >/dev/null
  fi
}

put_sample_object() {
  local bucket="$1"
  local object_file

  object_file="$(mktemp)"
  printf 'bluearch AWS emulator fixture\n' > "$object_file"
  "${AWS_CMD[@]}" s3api put-object \
    --bucket "$bucket" \
    --key sample.txt \
    --body "$object_file" \
    >/dev/null
  rm -f "$object_file"
}

enable_public_access_block() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-public-access-block \
    --bucket "$bucket" \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true \
    >/dev/null
}

disable_public_access_block() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-public-access-block \
    --bucket "$bucket" \
    --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false \
    >/dev/null
}

delete_bucket_policy() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api delete-bucket-policy \
    --bucket "$bucket" \
    >/dev/null 2>&1 || true
}

put_tls_enforcement_policy() {
  local bucket="$1"
  local policy_file

  policy_file="$(mktemp)"
  cat > "$policy_file" <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::$bucket",
        "arn:aws:s3:::$bucket/*"
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
    --bucket "$bucket" \
    --policy "file://$policy_file" \
    >/dev/null
  rm -f "$policy_file"
}

enable_default_encryption() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-bucket-encryption \
    --bucket "$bucket" \
    --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}' \
    >/dev/null
}

disable_default_encryption() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api delete-bucket-encryption \
    --bucket "$bucket" \
    >/dev/null 2>&1 || true
}

disable_lifecycle() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api delete-bucket-lifecycle \
    --bucket "$bucket" \
    >/dev/null 2>&1 || true
}

enable_versioning() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-bucket-versioning \
    --bucket "$bucket" \
    --versioning-configuration Status=Enabled \
    >/dev/null
}

disable_versioning() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-bucket-versioning \
    --bucket "$bucket" \
    --versioning-configuration Status=Suspended \
    >/dev/null 2>&1 || true
}

enable_lifecycle() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-bucket-lifecycle-configuration \
    --bucket "$bucket" \
    --lifecycle-configuration \
    '{"Rules":[{"ID":"transition-old-objects","Status":"Enabled","Filter":{"Prefix":""},"Transitions":[{"Days":30,"StorageClass":"STANDARD_IA"}]}]}' \
    >/dev/null
}

enable_expiration_only_lifecycle() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-bucket-lifecycle-configuration \
    --bucket "$bucket" \
    --lifecycle-configuration \
    '{"Rules":[{"ID":"expire-old-objects","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":365}}]}' \
    >/dev/null
}

delete_bucket_if_exists() {
  local bucket="$1"

  if ! "${AWS_CMD[@]}" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    return 0
  fi

  delete_bucket_policy "$bucket"
  disable_lifecycle "$bucket"
  disable_default_encryption "$bucket"
  disable_versioning "$bucket"
  "${AWS_CMD[@]}" s3 rm "s3://$bucket" --recursive >/dev/null 2>&1 || true
  "${AWS_CMD[@]}" s3api delete-bucket --bucket "$bucket" >/dev/null 2>&1 || true
}

reset_bucket_to_empty_baseline() {
  local bucket="$1"

  create_bucket "$bucket"
  delete_bucket_policy "$bucket"
  enable_public_access_block "$bucket"
  disable_default_encryption "$bucket"
  disable_lifecycle "$bucket"
  disable_versioning "$bucket"
  "${AWS_CMD[@]}" s3 rm "s3://$bucket" --recursive >/dev/null 2>&1 || true
  put_sample_object "$bucket"
}
