#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
kind delete cluster --name bluearch-eks-lab

# LocalEmu service implementations can create sibling containers without
# Compose labels. Remove only its deterministic lab name prefixes before
# asking Compose to remove the shared network.
for prefix in \
  '^/aws-emulator-localemu-1-' \
  '^/localemu-ec2-' \
  '^/localemu-imds-'; do
  for container_id in $(docker ps -aq --filter "name=$prefix"); do
    docker rm -f "$container_id" >/dev/null
  done
done

docker compose -f "$ROOT/tests/aws-emulator/docker-compose.yml" down --remove-orphans

for network_id in $(docker network ls -q --filter 'name=^localemu-vpc-' --filter 'name=^localemu-pubport-br$'); do
  docker network rm "$network_id" >/dev/null 2>&1 || true
done
