#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  "${SCRIPT_DIR}/down.sh"
  cleanup_status=$?
  set -e
  if [[ ${status} -ne 0 ]]; then
    exit "${status}"
  fi
  exit "${cleanup_status}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

"$(python_binary)" "${SCRIPT_DIR}/preflight.py" --artifact-dir "${ARTIFACT_DIR}"
"${SCRIPT_DIR}/plan.sh"
"${SCRIPT_DIR}/up.sh"
"${SCRIPT_DIR}/seed.sh"
"$(python_binary)" "${SCRIPT_DIR}/e2e_mcp.py" \
  --stage full \
  --artifact-dir "${ARTIFACT_DIR}" \
  2>&1 | tee "${ARTIFACT_DIR}/e2e.log"
