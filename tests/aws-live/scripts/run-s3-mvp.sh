#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

"$SCRIPT_DIR/seed-s3.sh"
load_live_env

cleanup_on_exit() {
  "$SCRIPT_DIR/cleanup-s3.sh" >/dev/null 2>&1 || true
}
trap cleanup_on_exit EXIT

SCAN_JSON="$ARTIFACT_DIR/scan.s3.json"
SCAN_TEXT="$ARTIFACT_DIR/scan.s3.txt"
REMEDIATION_JSON="$ARTIFACT_DIR/remediation.s3.json"
REMEDIATION_TEXT="$ARTIFACT_DIR/remediation.s3.txt"
VERIFY_JSON="$ARTIFACT_DIR/verify.s3.json"
VERIFY_TEXT="$ARTIFACT_DIR/verify.s3.txt"

set +e
python3 -m bluearch_aws_steward.cli scan aws \
  --service s3 \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --bucket-prefix "$BLUEARCH_STEWARD_LIVE_PREFIX" \
  --output text \
  --output-file "$SCAN_JSON" | tee "$SCAN_TEXT"
scan_status="${PIPESTATUS[0]}"
set -e
if [[ "$scan_status" -ne 0 ]]; then
  echo "Scan failed with exit code $scan_status" >&2
  exit "$scan_status"
fi

python3 "$SCRIPT_DIR/assert-live-scan.py" --actual "$SCAN_JSON" --prefix "$BLUEARCH_STEWARD_LIVE_PREFIX"

set +e
python3 "$SCRIPT_DIR/apply-s3-fixtures-via-mcp.py" \
  --scan-file "$SCAN_JSON" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --bucket-prefix "$BLUEARCH_STEWARD_LIVE_PREFIX" \
  --output-file "$REMEDIATION_JSON" | tee "$REMEDIATION_TEXT"
remediation_status="${PIPESTATUS[0]}"
set -e
if [[ "$remediation_status" -ne 0 ]]; then
  echo "Remediation failed with exit code $remediation_status" >&2
  exit "$remediation_status"
fi

python3 -m bluearch_aws_steward.cli scan aws \
  --service s3 \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --bucket-prefix "$BLUEARCH_STEWARD_LIVE_PREFIX" \
  --output text \
  --output-file "$VERIFY_JSON" | tee "$VERIFY_TEXT"

python3 "$REPO_ROOT/tests/aws-emulator/scripts/assert-scan.py" --actual "$VERIFY_JSON" --expect-no-findings

"$SCRIPT_DIR/cleanup-s3.sh"
trap - EXIT
