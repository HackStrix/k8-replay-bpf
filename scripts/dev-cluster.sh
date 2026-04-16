#!/bin/bash
set -e

CLUSTER_NAME="dev-cluster"
REGISTRY_NAME="dev-registry"

echo "Creating k3d registry '$REGISTRY_NAME'..."
k3d registry create $REGISTRY_NAME --port 5000 || echo "Registry already exists"

echo "Creating k3d cluster '$CLUSTER_NAME' for ebpf development..."
k3d cluster create $CLUSTER_NAME \
  --registry-use k3d-$REGISTRY_NAME:5000 \
  --agents 1 \
  --volume /sys/kernel/debug:/sys/kernel/debug@all \
  --k3s-arg "--disable=traefik@server:0" \
  --k3s-arg "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%@server:*"

echo "Cluster created successfully!"
echo "You can now run 'tilt ci' or 'tilt up' to start the development environment."
