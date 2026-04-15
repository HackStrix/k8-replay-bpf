#!/bin/bash
set -e

CLUSTER_NAME="dev-cluster"
REGISTRY_NAME="dev-registry"

echo "Tearing down k3d cluster '$CLUSTER_NAME'..."
k3d cluster delete $CLUSTER_NAME || echo "Cluster already deleted or not found."

echo "Tearing down k3d registry '$REGISTRY_NAME'..."
k3d registry delete $REGISTRY_NAME || echo "Registry already deleted or not found."

echo "All development resources have been cleaned up! 🧹"
