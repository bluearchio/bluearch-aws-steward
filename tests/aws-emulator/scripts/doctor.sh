#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
COMPOSE_FILE="$REPO_ROOT/tests/aws-emulator/docker-compose.yml"

require_command() {
  local command_name="$1"

  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "Missing required command: $command_name" >&2
    return 1
  fi
}

require_command docker
require_command aws
require_command python3

if ! docker compose version >/dev/null 2>&1; then
  echo "Docker Compose is not available through 'docker compose'." >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Docker is installed, but the daemon is not reachable. Start Docker Desktop or your Docker service." >&2
  exit 1
fi

docker compose -f "$COMPOSE_FILE" config >/dev/null

cat <<EOF
AWS emulator prerequisites look ready.

Next commands:
  make emulator-up
  make emulator-seed
  make emulator-assert

Or run the full resettable fixture path:
  make emulator-recreate

Run the multi-service detector gate:
  make emulator-coverage
EOF
