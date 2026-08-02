#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
kubectl config use-context kind-bluearch-eks-lab >/dev/null
kubectl delete namespace bluearch-eks-lab --ignore-not-found --wait=true
kubectl delete namespace bluearch-eks-phase-0 --ignore-not-found --wait=true
kubectl delete deployment aws-node-fixture coredns-fixture -n kube-system --ignore-not-found --wait=true
"$ROOT/tests/eks-lab/scripts/up.sh"
