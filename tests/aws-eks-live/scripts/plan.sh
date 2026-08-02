#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

load_context
terraform_init
tf="$(terraform_binary)"
"${tf}" -chdir="${INFRA_DIR}" plan \
  -input=false \
  -lock-timeout=60s \
  -state="${STATE_FILE}" \
  -var-file="${TFVARS_FILE}" \
  -out="${PLAN_FILE}"
echo "Terraform plan saved to ${PLAN_FILE}"
