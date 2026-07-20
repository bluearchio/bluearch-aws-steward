#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"

AWS_PROVIDER="${AWS_PROVIDER:-aws-cli}"
STEWARD_PYTHON="${STEWARD_PYTHON:-$REPO_ROOT/.venv/bin/python}"
if [[ ! -x "$STEWARD_PYTHON" ]]; then
  STEWARD_PYTHON="python3"
fi

CLOUDWATCH_JSON="$ARTIFACT_DIR/scan.cloudwatch.$AWS_PROVIDER.json"
EC2_JSON="$ARTIFACT_DIR/scan.ec2.$AWS_PROVIDER.json"

"$STEWARD_PYTHON" -m bluearch_aws_steward doctor \
  --provider "$AWS_PROVIDER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  >/dev/null
echo "AWS provider readiness passed: provider=$AWS_PROVIDER region=$AWS_REGION"

"$STEWARD_PYTHON" -m bluearch_aws_steward scan aws \
  --provider "$AWS_PROVIDER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --service cloudwatch \
  --rule-filter cloudwatch-log-retention-missing \
  --output json \
  --max-results 10 \
  --output-file "$CLOUDWATCH_JSON" \
  >/dev/null

"$STEWARD_PYTHON" -m bluearch_aws_steward scan aws \
  --provider "$AWS_PROVIDER" \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --service ec2 \
  --rule-filter ec2-unattached-ebs-volume \
  --output json \
  --max-results 10 \
  --output-file "$EC2_JSON" \
  >/dev/null

"$STEWARD_PYTHON" "$SCRIPT_DIR/assert-readonly-cost-scan.py" \
  --cloudwatch "$CLOUDWATCH_JSON" \
  --ec2 "$EC2_JSON" \
  --provider "$AWS_PROVIDER"
