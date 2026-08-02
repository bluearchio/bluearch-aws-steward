#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

load_context
terraform_init
tf="$(terraform_binary)"
if [[ ! -f "${PLAN_FILE}" ]]; then
  "${tf}" -chdir="${INFRA_DIR}" plan \
    -input=false \
    -lock-timeout=60s \
    -state="${STATE_FILE}" \
    -var-file="${TFVARS_FILE}" \
    -out="${PLAN_FILE}"
fi
"${tf}" -chdir="${INFRA_DIR}" apply \
  -input=false \
  -lock-timeout=60s \
  -state="${STATE_FILE}" \
  "${PLAN_FILE}"
terraform_outputs > "${ARTIFACT_DIR}/terraform-outputs.json"
echo "EKS control planes and managed nodes are ready. Run make eks-aws-lab-seed."
