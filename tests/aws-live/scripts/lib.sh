#!/usr/bin/env bash
set -euo pipefail

export AWS_PROFILE="${AWS_PROFILE:-default}"
export AWS_REGION="${AWS_REGION:-us-east-1}"
export AWS_DEFAULT_REGION="$AWS_REGION"
export AWS_PAGER=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ARTIFACT_DIR="$REPO_ROOT/tests/aws-live/.artifacts"
ENV_FILE="$ARTIFACT_DIR/env.sh"

AWS_CMD=(aws --profile "$AWS_PROFILE" --region "$AWS_REGION" --no-cli-pager)

mkdir -p "$ARTIFACT_DIR"

account_id() {
  "${AWS_CMD[@]}" sts get-caller-identity --query Account --output text
}

load_live_env() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE"
  fi
}

new_live_prefix() {
  printf 'basw-live-%s-%s' "$(date +%Y%m%d%H%M%S)" "$RANDOM"
}

write_live_env() {
  local prefix="$1"

  cat > "$ENV_FILE" <<EOF
export BLUEARCH_STEWARD_LIVE_PREFIX="$prefix"
export AWS_PROFILE="$AWS_PROFILE"
export AWS_REGION="$AWS_REGION"
EOF
}

fixture_bucket() {
  local suffix="$1"
  printf '%s-%s' "$BLUEARCH_STEWARD_LIVE_PREFIX" "$suffix"
}

create_bucket() {
  local bucket="$1"

  if "${AWS_CMD[@]}" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$AWS_REGION" == "us-east-1" ]]; then
    "${AWS_CMD[@]}" s3api create-bucket --bucket "$bucket" >/dev/null
  else
    "${AWS_CMD[@]}" s3api create-bucket \
      --bucket "$bucket" \
      --create-bucket-configuration "LocationConstraint=$AWS_REGION" \
      >/dev/null
  fi
}

delete_bucket_policy() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api delete-bucket-policy --bucket "$bucket" >/dev/null 2>&1 || true
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

  "${AWS_CMD[@]}" s3api delete-bucket-encryption --bucket "$bucket" >/dev/null 2>&1 || true
}

enable_lifecycle() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api put-bucket-lifecycle-configuration \
    --bucket "$bucket" \
    --lifecycle-configuration \
    '{"Rules":[{"ID":"bluearch-steward-live-transition","Status":"Enabled","Filter":{"Prefix":""},"Transitions":[{"Days":30,"StorageClass":"STANDARD_IA"}]}]}' \
    >/dev/null
}

disable_lifecycle() {
  local bucket="$1"

  "${AWS_CMD[@]}" s3api delete-bucket-lifecycle --bucket "$bucket" >/dev/null 2>&1 || true
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

reset_bucket_to_empty_baseline() {
  local bucket="$1"

  create_bucket "$bucket"
  delete_bucket_policy "$bucket"
  enable_public_access_block "$bucket"
  disable_default_encryption "$bucket"
  disable_lifecycle "$bucket"
  disable_versioning "$bucket"
}

delete_bucket_if_exists() {
  local bucket="$1"

  if ! "${AWS_CMD[@]}" s3api head-bucket --bucket "$bucket" >/dev/null 2>&1; then
    return 0
  fi

  delete_bucket_policy "$bucket"
  enable_public_access_block "$bucket"
  disable_lifecycle "$bucket"
  disable_default_encryption "$bucket"
  disable_versioning "$bucket"
  "${AWS_CMD[@]}" s3 rm "s3://$bucket" --recursive >/dev/null 2>&1 || true
  "${AWS_CMD[@]}" s3api delete-bucket --bucket "$bucket" >/dev/null 2>&1 || true
}
