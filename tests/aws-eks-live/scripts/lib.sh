#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ROOT="$(cd "${LAB_DIR}/../.." && pwd)"
ARTIFACT_DIR="${EKS_AWS_LAB_ARTIFACT_DIR:-${LAB_DIR}/.artifacts}"
if [[ "${ARTIFACT_DIR}" != /* ]]; then
  ARTIFACT_DIR="${ROOT}/${ARTIFACT_DIR}"
fi
INFRA_DIR="${LAB_DIR}/infra"
TFVARS_FILE="${ARTIFACT_DIR}/terraform.tfvars.json"
STATE_FILE="${ARTIFACT_DIR}/terraform.tfstate"
PLAN_FILE="${ARTIFACT_DIR}/terraform.plan"

require_preflight() {
  test -f "${ARTIFACT_DIR}/preflight.json" || {
    echo "EKS AWS lab preflight artifact is missing. Run make eks-aws-lab-preflight." >&2
    exit 2
  }
  test -f "${TFVARS_FILE}" || {
    echo "Terraform variables are missing. Run make eks-aws-lab-preflight." >&2
    exit 2
  }
}

load_context() {
  require_preflight
  AWS_PROFILE="$(jq -r '.aws_profile // empty' "${TFVARS_FILE}")"
  AWS_REGION="$(jq -r '.region' "${TFVARS_FILE}")"
  ALLOWED_ACCOUNT="${EKS_LAB_ALLOWED_ACCOUNT_ID:-}"
  ACK="${BLUEARCH_EKS_LAB_ACK:-}"
  if [[ -z "${ALLOWED_ACCOUNT}" || "${ACK}" != "I_UNDERSTAND_THIS_IS_DESTRUCTIVE" ]]; then
    echo "Account allowlist and destructive lab acknowledgement must remain set." >&2
    exit 2
  fi
  if [[ -n "${AWS_PROFILE}" ]]; then
    CURRENT_ACCOUNT="$(aws sts get-caller-identity --profile "${AWS_PROFILE}" --query Account --output text)"
    export AWS_PROFILE
  else
    CURRENT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
    unset AWS_PROFILE
  fi
  if [[ "${CURRENT_ACCOUNT}" != "${ALLOWED_ACCOUNT}" ]]; then
    echo "Active account no longer matches EKS_LAB_ALLOWED_ACCOUNT_ID; stopped." >&2
    exit 2
  fi
  EXPIRES_AT="$(jq -r '.expires_at' "${TFVARS_FILE}")"
  "$(python_binary)" -c 'from datetime import datetime, timezone; import sys; expires=datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")); assert datetime.now(timezone.utc) < expires, "EKS lab authorization expired"' "${EXPIRES_AT}"
  export AWS_REGION AWS_DEFAULT_REGION="${AWS_REGION}"
}

python_binary() {
  if [[ -n "${BLUEARCH_STEWARD_TEST_PYTHON:-}" ]]; then
    printf '%s\n' "${BLUEARCH_STEWARD_TEST_PYTHON}"
  elif [[ -x "${ROOT}/.venv/bin/python" ]]; then
    printf '%s\n' "${ROOT}/.venv/bin/python"
  else
    command -v python3
  fi
}

terraform_binary() {
  if [[ -n "${TERRAFORM:-}" ]]; then
    command -v "${TERRAFORM}"
    return
  fi
  command -v terraform || command -v tofu
}

terraform_init() {
  local tf
  tf="$(terraform_binary)"
  "${tf}" -chdir="${INFRA_DIR}" init -input=false
}

terraform_outputs() {
  local tf
  tf="$(terraform_binary)"
  "${tf}" -chdir="${INFRA_DIR}" output -state="${STATE_FILE}" -json
}
