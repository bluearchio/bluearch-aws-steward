#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/lib.sh"

load_context
test -f "${ARTIFACT_DIR}/terraform-outputs.json" || {
  echo "Terraform outputs are missing. Run make eks-aws-lab-up first." >&2
  exit 2
}
"$(python_binary)" "${SCRIPT_DIR}/seed.py" --artifact-dir "${ARTIFACT_DIR}"
