#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

load_context
python="$(python_binary)"
"${python}" "${SCRIPT_DIR}/aws_lifecycle.py" delete-external-fixtures --artifact-dir "${ARTIFACT_DIR}"
"${python}" "${SCRIPT_DIR}/aws_lifecycle.py" restore-guardduty --artifact-dir "${ARTIFACT_DIR}"

if [[ -f "${STATE_FILE}" ]]; then
  terraform_init
  tf="$(terraform_binary)"
  "${tf}" -chdir="${INFRA_DIR}" destroy \
    -auto-approve \
    -input=false \
    -lock-timeout=60s \
    -state="${STATE_FILE}" \
    -var-file="${TFVARS_FILE}"
fi

rm -f "${ARTIFACT_DIR}"/*-admin.kubeconfig "${ARTIFACT_DIR}"/*-mcp.kubeconfig
rm -rf "${ARTIFACT_DIR}/rendered-manifests" "${ARTIFACT_DIR}/runtime"
"${python}" "${SCRIPT_DIR}/verify_clean.py" --artifact-dir "${ARTIFACT_DIR}"
