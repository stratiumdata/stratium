# Kubernetes Deployment

This directory contains raw Kubernetes manifests for deploying Stratium without Helm.

## Quick Start

For most deployments, we recommend using the **Helm chart** located in `deployment/helm/`. The Helm chart provides:

- Easier configuration management
- Built-in best practices
- Automated upgrades and rollbacks
- Production-ready defaults

See [Helm Deployment Guide](../helm/README.md) for details.

## Raw Kubernetes Manifests

If you prefer to use raw Kubernetes manifests or need to customize beyond what Helm provides, you can generate manifests from the Helm chart:

```bash
# Generate manifests without installing
helm template stratium ../helm/stratium -n stratium > stratium-manifests.yaml

# Review the generated manifests
less stratium-manifests.yaml

# Apply to cluster
kubectl apply -f stratium-manifests.yaml -n stratium
```

## Kustomize Support

You can also use Kustomize with the generated manifests:

```bash
# Create kustomization.yaml
cat <<EOF > kustomization.yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

namespace: stratium

resources:
  - stratium-manifests.yaml

# Add custom patches, ConfigMaps, Secrets, etc.
EOF

# Build and apply
kubectl apply -k .
```

## Manual Deployment

If you need to deploy manually without Helm, follow these steps:

### 1. Create Namespace

```bash
kubectl create namespace stratium
```

### 2. Create Secrets

```bash
kubectl create secret generic postgresql-secret \
  --from-literal=postgres-password=your-password \
  --from-literal=stratium-password=your-password \
  -n stratium

kubectl create secret generic keycloak-secret \
  --from-literal=admin-password=your-admin-password \
  -n stratium

kubectl create secret generic stratium-secret \
  --from-literal=database-password=your-password \
  --from-literal=key-manager-oidc-secret=your-secret \
  --from-literal=key-access-oidc-secret=your-secret \
  --from-literal=pap-oidc-secret=your-secret \
  -n stratium
```

### 3. Deploy Components

Generate and customize the manifests as needed, then apply in order:

1. PostgreSQL StatefulSet
2. Redis Deployment
3. Keycloak Deployment
4. Platform Service
5. Key Manager Service
6. Key Access Service
7. PAP Service
8. PAP UI
9. Envoy Proxy

## ArgoCD / GitOps

For GitOps deployments with ArgoCD:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: stratium
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/yourusername/stratium
    targetRevision: HEAD
    path: deployment/helm/stratium
    helm:
      valueFiles:
        - values-production.yaml
  destination:
    server: https://kubernetes.default.svc
    namespace: stratium
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

## Flux CD

For Flux CD deployments:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1beta2
kind: HelmRepository
metadata:
  name: stratium
  namespace: flux-system
spec:
  interval: 1h
  url: https://charts.stratium.io
---
apiVersion: helm.toolkit.fluxcd.io/v2beta1
kind: HelmRelease
metadata:
  name: stratium
  namespace: stratium
spec:
  interval: 10m
  chart:
    spec:
      chart: stratium
      version: "1.0.0"
      sourceRef:
        kind: HelmRepository
        name: stratium
        namespace: flux-system
  values:
    # Your custom values here
```

## See Also

- [Helm Deployment Guide](../helm/README.md) - Recommended deployment method
- [Docker Compose Deployment](../README.md) - For local development