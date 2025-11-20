#!/bin/bash
# Setup script for minikube ingress with LoadBalancer type
# This ensures minikube tunnel works correctly with the ingress controller

set -e

echo "Setting up minikube ingress for use with minikube tunnel..."

# Enable ingress addon if not already enabled
echo "Enabling ingress addon..."
minikube addons enable ingress

# Wait for ingress controller to be ready
echo "Waiting for ingress controller to be ready..."
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=120s

# Patch the ingress controller service to use LoadBalancer type
# This is required for minikube tunnel to work properly
echo "Patching ingress controller service to use LoadBalancer type..."
kubectl patch svc ingress-nginx-controller -n ingress-nginx \
  -p '{"spec":{"type":"LoadBalancer"}}'

# Verify the service has an external IP
echo "Verifying ingress controller service..."
kubectl get svc -n ingress-nginx ingress-nginx-controller

echo ""
echo "✅ Minikube ingress setup complete!"
echo ""
echo "Next steps:"
echo "1. Run 'minikube tunnel' in a separate terminal (requires sudo)"
echo "2. Update /etc/hosts to use 127.0.0.1:"
echo ""
echo "   sudo tee -a /etc/hosts <<EOF"
echo "   127.0.0.1 ui.stratium.local"
echo "   127.0.0.1 api.stratium.local"
echo "   127.0.0.1 auth.stratium.local"
echo "   127.0.0.1 grpc.stratium.local"
echo "   EOF"
echo ""
echo "3. Access services at http://*.stratium.local"