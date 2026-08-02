#!/usr/bin/env bash
set -euo pipefail

curl -fsS http://localhost:4566/_localstack/health >/dev/null 2>&1 || curl -fsS http://localhost:4566/ >/dev/null
kind get clusters | grep -qx bluearch-eks-lab
kubectl --context kind-bluearch-eks-lab get nodes -o wide
kubectl --context kind-bluearch-eks-lab -n bluearch-eks-lab get deployments,pods
kubectl --context kind-bluearch-eks-lab -n bluearch-eks-phase-0 get deployments,pods
