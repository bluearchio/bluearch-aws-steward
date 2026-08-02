#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KIND_CLUSTER="bluearch-eks-lab"
CONTEXT="kind-${KIND_CLUSTER}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"

for command in docker kind kubectl curl; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 2; }
done

docker info >/dev/null
docker compose -f "$ROOT/tests/aws-emulator/docker-compose.yml" up -d localemu

if ! kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER"; then
  kind create cluster --image "$KIND_NODE_IMAGE" --config "$ROOT/tests/eks-lab/kind-config.yaml"
fi

kubectl config use-context "$CONTEXT" >/dev/null
kubectl label node "${KIND_CLUSTER}-control-plane" eks.amazonaws.com/nodegroup=healthy-ng --overwrite
kubectl label node "${KIND_CLUSTER}-worker" eks.amazonaws.com/nodegroup=skew-ng --overwrite
kubectl label node "${KIND_CLUSTER}-worker2" eks.amazonaws.com/nodegroup=old-ami-ng --overwrite
kubectl label node "${KIND_CLUSTER}-worker3" eks.amazonaws.com/nodegroup=degraded-ng --overwrite
kubectl apply -f "$ROOT/tests/eks-lab/manifests/lab.yaml"
kubectl apply -f "$ROOT/tests/eks-lab/manifests/phase-0-healthy.yaml"

stable=(
  healthy-api
  missing-requests-api
  missing-memory-limit-api
  missing-probes-api
  unprotected-api
  privileged-worker
  cpu-pressure-api
  overprovisioned-api
  balanced-api
  runtime-healthy-api
)
for deployment in "${stable[@]}"; do
  kubectl -n bluearch-eks-lab rollout status "deployment/$deployment" --timeout=180s
done
kubectl -n kube-system rollout status deployment/coredns-fixture --timeout=180s
kubectl -n bluearch-eks-phase-0 rollout status deployment/healthy-api --timeout=180s

echo "EKS lab is running. LocalEmu remains available at http://localhost:4566."
echo "Kubernetes context: $CONTEXT"
