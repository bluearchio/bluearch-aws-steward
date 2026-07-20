#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib.sh"
load_live_env

if [[ -z "${BLUEARCH_STEWARD_LIVE_PREFIX:-}" ]]; then
  echo "No BLUEARCH_STEWARD_LIVE_PREFIX found. Nothing to clean." >&2
  exit 0
fi

for suffix in public unencrypted no-lifecycle versioning-disabled secure; do
  delete_bucket_if_exists "$(fixture_bucket "$suffix")"
done

echo "Cleaned AWS live S3 fixture prefix: $BLUEARCH_STEWARD_LIVE_PREFIX"

