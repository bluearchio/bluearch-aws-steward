#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

wait_for_emulator

run_extended_fixtures reset

for function_name in "$BLUEARCH_STEWARD_LAMBDA_NO_TRACING" "$BLUEARCH_STEWARD_LAMBDA_TRACING"; do
  if "${AWS_CMD[@]}" lambda get-function --function-name "$function_name" >/dev/null 2>&1; then
    "${AWS_CMD[@]}" lambda delete-function --function-name "$function_name" >/dev/null
  fi
done

if "${AWS_CMD[@]}" iam get-role --role-name "$BLUEARCH_STEWARD_LAMBDA_ROLE" >/dev/null 2>&1; then
  "${AWS_CMD[@]}" iam delete-role --role-name "$BLUEARCH_STEWARD_LAMBDA_ROLE" >/dev/null
fi

for log_group in "$BLUEARCH_STEWARD_LOG_NO_RETENTION" "$BLUEARCH_STEWARD_LOG_RETENTION"; do
  if [[ "$("${AWS_CMD[@]}" logs describe-log-groups \
    --log-group-name-prefix "$log_group" \
    --query "length(logGroups[?logGroupName=='$log_group'])" \
    --output text)" != "0" ]]; then
    "${AWS_CMD[@]}" logs delete-log-group --log-group-name "$log_group" >/dev/null
  fi
done

for allocation_id in $("${AWS_CMD[@]}" ec2 describe-addresses \
  --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unassociated-eip" \
  --query 'Addresses[].AllocationId' \
  --output text); do
  "${AWS_CMD[@]}" ec2 release-address --allocation-id "$allocation_id" >/dev/null
done

for volume_id in $("${AWS_CMD[@]}" ec2 describe-volumes \
  --filters "Name=tag:$BLUEARCH_STEWARD_FIXTURE_TAG,Values=ec2-unencrypted-unattached" \
  --query 'Volumes[].VolumeId' \
  --output text); do
  "${AWS_CMD[@]}" ec2 delete-volume --volume-id "$volume_id" >/dev/null
done

for suffix in \
  public \
  unencrypted \
  no-lifecycle \
  no-tiering \
  versioning-disabled \
  policy-all-actions-public \
  policy-public-delete \
  tls-missing \
  secure; do
  delete_bucket_if_exists "$(fixture_bucket "$suffix")"
done

echo "AWS emulator BlueArch fixtures reset."
