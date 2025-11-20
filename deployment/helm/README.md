# Stratium Helm Chart

Production-ready Kubernetes deployment for Stratium Zero Trust Data Fabric platform.

## Overview

This Helm chart deploys a complete Stratium stack including:

- **Platform Service** - Authorization and entitlement decisions (gRPC)
- **Key Manager Service** - Cryptographic key management (gRPC)
- **Key Access Service** - Key wrapping and unwrapping operations (gRPC)
- **PAP Service** - Policy Administration Point REST API
- **PAP UI** - React-based web interface for policy management
- **Keycloak** - OpenID Connect identity provider
- **PostgreSQL** - Database for Keycloak and services
- **Redis** - Cache for PAP and Platform services
- **Envoy Proxy** - gRPC-Web gateway

## Prerequisites

- Kubernetes 1.24+
- Helm 3.8+
- PV provisioner support in the underlying infrastructure (for persistent volumes)
- Ingress controller (optional, for external access)

## Installation

### Local Development (Recommended for Testing)

For local Kubernetes testing (Docker Desktop, Minikube, or kind):

```bash
cd deployment/helm

# Build all Docker images
./build-images.sh

# Deploy with local-optimized settings
helm install stratium ./stratium \
  -n stratium \
  --create-namespace \
  -f stratium/values-local.yaml

# Start port forwards for easy access
./port-forward-all.sh
```

**See [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) for complete local setup guide.**

### Quick Start (Production)

```bash
# Add Stratium Helm repository (if available)
helm repo add stratium https://charts.stratium.io
helm repo update

# Install with default values
helm install stratium stratium/stratium -n stratium --create-namespace

# Or install from local chart
cd deployment/helm
helm install stratium ./stratium -n stratium --create-namespace
```

### Custom Installation

Create a `custom-values.yaml` file with your configuration:

```yaml
# custom-values.yaml
postgresql:
  auth:
    postgresPassword: "your-secure-password"
    password: "your-secure-password"
    stratiumPassword: "your-secure-password"

keycloak:
  auth:
    adminPassword: "your-secure-admin-password"
  config:
    hostname: "keycloak.yourdomain.com"
  ingress:
    enabled: true
    hosts:
      - host: keycloak.yourdomain.com
        paths:
          - path: /
            pathType: Prefix

papUI:
  ingress:
    enabled: true
    hosts:
      - host: stratium.yourdomain.com
        paths:
          - path: /
            pathType: Prefix
```

Install with custom values:

```bash
helm install stratium ./stratium -n stratium --create-namespace -f custom-values.yaml
```

### Environment Profiles & Overlay Files

The chart is designed to compose smaller overlay files so you can reuse the same manifests across environments:

| Scenario | Overlay files (in order) | Notes |
|----------|-------------------------|-------|
| Local development (port-forward) | `values-local.yaml` | Optimized for Docker Desktop/Minikube/kind |
| Local + Ingress (Minikube) | `values-local.yaml`, `values-local-ingress.yaml` | Uses the built-in NGINX ingress addon |
| AWS EKS (demo-arm64) | `values-ecr.yaml`, `values-free-tier.yaml`, `values-eks-demo-arm64.yaml` | Targets the existing `demo-arm64` cluster with ECR images, reduced resources, and ALB ingress |
| Production HTTPS ALB | `values-ecr.yaml`, `values-free-tier.yaml`, `values-ingress.yaml`, `values-public-urls.yaml` | Includes TLS + explicit public hostnames |

Feel free to copy one of these files as a starting point for new environments (e.g., `values-eks-staging.yaml`).
See [README-EKS.md](README-EKS.md) for the detailed AWS deployment walkthrough.

## Configuration

### Global Settings

| Parameter | Description | Default |
|-----------|-------------|---------|
| `global.imageRegistry` | Global Docker registry | `""` |
| `global.imagePullSecrets` | Global image pull secrets | `[]` |
| `global.storageClass` | Global storage class | `""` |

### PostgreSQL Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `postgresql.enabled` | Enable PostgreSQL | `true` |
| `postgresql.replicaCount` | Number of replicas | `1` |
| `postgresql.auth.postgresPassword` | PostgreSQL superuser password | `"keycloak_password"` |
| `postgresql.auth.stratiumPassword` | Stratium app user password | `"stratium"` |
| `postgresql.persistence.enabled` | Enable persistence | `true` |
| `postgresql.persistence.size` | PVC size | `20Gi` |

### Keycloak Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keycloak.enabled` | Enable Keycloak | `true` |
| `keycloak.replicaCount` | Number of replicas | `1` |
| `keycloak.auth.adminUser` | Admin username | `admin` |
| `keycloak.auth.adminPassword` | Admin password | `"admin"` |
| `keycloak.ingress.enabled` | Enable ingress | `false` |

### Service Configuration

#### Platform Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `platform.enabled` | Enable Platform service | `true` |
| `platform.replicaCount` | Number of replicas | `2` |
| `platform.config.port` | Service port | `50051` |
| `platform.autoscaling.enabled` | Enable HPA | `true` |
| `platform.autoscaling.minReplicas` | Minimum replicas | `2` |
| `platform.autoscaling.maxReplicas` | Maximum replicas | `10` |

#### Key Manager Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keyManager.enabled` | Enable Key Manager | `true` |
| `keyManager.replicaCount` | Number of replicas | `2` |
| `keyManager.config.port` | Service port | `50052` |
| `keyManager.config.oidcClientSecret` | OIDC client secret | `"stratium-key-manager-secret"` |

#### Key Access Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `keyAccess.enabled` | Enable Key Access | `true` |
| `keyAccess.replicaCount` | Number of replicas | `2` |
| `keyAccess.config.port` | Service port | `50053` |

#### PAP Service

| Parameter | Description | Default |
|-----------|-------------|---------|
| `pap.enabled` | Enable PAP | `true` |
| `pap.replicaCount` | Number of replicas | `2` |
| `pap.config.port` | Service port | `8090` |
| `pap.ingress.enabled` | Enable ingress | `false` |

#### PAP UI

| Parameter | Description | Default |
|-----------|-------------|---------|
| `papUI.enabled` | Enable PAP UI | `true` |
| `papUI.replicaCount` | Number of replicas | `2` |
| `papUI.ingress.enabled` | Enable ingress | `false` |

### Security Configuration

| Parameter | Description | Default |
|-----------|-------------|---------|
| `security.networkPolicy.enabled` | Enable network policies | `true` |
| `security.podSecurityContext.runAsNonRoot` | Run as non-root | `true` |
| `security.podSecurityContext.runAsUser` | User ID | `1000` |

### Secret Management

The chart now supports reusing externally managed Kubernetes secrets (e.g., synced from AWS Secrets Manager). Each secret can either be created by Helm or referenced by name:

```yaml
secrets:
  stratium:
    create: false
    name: stratium-aws-sm
  keycloak:
    create: false
    name: keycloak-aws-sm
  postgresql:
    create: false
    name: postgresql-aws-sm
```

- Set `create: false` to skip Helm-managed secrets.
- Ensure the referenced Kubernetes Secret already exists and contains the expected keys:
  - **Stratium secret**: `database-password`, `key-manager-oidc-secret`, `key-access-oidc-secret`, `pap-oidc-secret`
  - **Keycloak secret**: `admin-user`, `admin-password`
  - **PostgreSQL secret**: `postgres-password`, `username`, `password`, `stratium-user`, `stratium-password`
- Use `deployment/helm/sync-aws-secrets.sh` to pull JSON secrets from AWS Secrets Manager and apply them to the cluster.

## Upgrading

```bash
# Update with new values
helm upgrade stratium ./stratium -n stratium -f custom-values.yaml

# View upgrade history
helm history stratium -n stratium

# Rollback if needed
helm rollback stratium -n stratium
```

## Uninstalling

```bash
# Uninstall the chart
helm uninstall stratium -n stratium

# Delete the namespace (optional)
kubectl delete namespace stratium
```

## Production Deployment Guide

### 1. Prepare Custom Values

Create a production values file:

```yaml
# production-values.yaml

# Use production images
global:
  imageRegistry: "your-registry.azurecr.io"
  imagePullSecrets:
    - name: registry-credentials

# PostgreSQL
postgresql:
  auth:
    postgresPassword: "${POSTGRES_PASSWORD}"  # Use secret management
    stratiumPassword: "${STRATIUM_PASSWORD}"
  persistence:
    enabled: true
    size: 100Gi
    storageClass: "managed-premium"
  resources:
    limits:
      cpu: 4000m
      memory: 8Gi
    requests:
      cpu: 1000m
      memory: 2Gi

# Keycloak
keycloak:
  replicaCount: 2
  auth:
    adminPassword: "${KEYCLOAK_ADMIN_PASSWORD}"
  config:
    hostname: "auth.yourdomain.com"
    httpEnabled: false
    httpsEnabled: true
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: auth.yourdomain.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: keycloak-tls
        hosts:
          - auth.yourdomain.com

# Platform Service
platform:
  replicaCount: 3
  autoscaling:
    enabled: true
    minReplicas: 3
    maxReplicas: 20
  resources:
    limits:
      cpu: 2000m
      memory: 2Gi
    requests:
      cpu: 500m
      memory: 512Mi

# PAP UI
papUI:
  replicaCount: 3
  ingress:
    enabled: true
    className: nginx
    annotations:
      cert-manager.io/cluster-issuer: letsencrypt-prod
    hosts:
      - host: stratium.yourdomain.com
        paths:
          - path: /
            pathType: Prefix
    tls:
      - secretName: stratium-tls
        hosts:
          - stratium.yourdomain.com

# Security
security:
  networkPolicy:
    enabled: true
```

### 2. Build and Push Docker Images

```bash
# Build images
cd deployment
docker build -t your-registry.azurecr.io/stratium/platform-server:v1.0.0 \
  -f Dockerfile \
  --build-arg SERVICE_NAME=platform-server \
  --build-arg SERVICE_PORT=50051 \
  ..

docker build -t your-registry.azurecr.io/stratium/key-manager-server:v1.0.0 \
  -f Dockerfile \
  --build-arg SERVICE_NAME=key-manager-server \
  --build-arg SERVICE_PORT=50052 \
  ..

docker build -t your-registry.azurecr.io/stratium/key-access-server:v1.0.0 \
  -f Dockerfile \
  --build-arg SERVICE_NAME=key-access-server \
  --build-arg SERVICE_PORT=50053 \
  ..

docker build -t your-registry.azurecr.io/stratium/pap-server:v1.0.0 \
  -f Dockerfile.pap \
  ..

docker build -t your-registry.azurecr.io/stratium/pap-ui:v1.0.0 \
  -f ../pap-ui/Dockerfile \
  ../pap-ui

# Push images
docker push your-registry.azurecr.io/stratium/platform-server:v1.0.0
docker push your-registry.azurecr.io/stratium/key-manager-server:v1.0.0
docker push your-registry.azurecr.io/stratium/key-access-server:v1.0.0
docker push your-registry.azurecr.io/stratium/pap-server:v1.0.0
docker push your-registry.azurecr.io/stratium/pap-ui:v1.0.0
```

### 3. Create Kubernetes Secrets

```bash
# Create image pull secret
kubectl create secret docker-registry registry-credentials \
  --docker-server=your-registry.azurecr.io \
  --docker-username=${REGISTRY_USERNAME} \
  --docker-password=${REGISTRY_PASSWORD} \
  -n stratium

# Create secrets from environment variables or vault
kubectl create secret generic stratium-secrets \
  --from-literal=postgres-password=${POSTGRES_PASSWORD} \
  --from-literal=stratium-password=${STRATIUM_PASSWORD} \
  --from-literal=keycloak-admin-password=${KEYCLOAK_ADMIN_PASSWORD} \
  -n stratium
```

### 4. Deploy with Helm

```bash
# Install/upgrade
helm upgrade --install stratium ./stratium \
  -n stratium \
  --create-namespace \
  -f production-values.yaml \
  --wait \
  --timeout 10m
```

### 5. Verify Deployment

```bash
# Check all pods are running
kubectl get pods -n stratium

# Check services
kubectl get svc -n stratium

# Check ingress
kubectl get ingress -n stratium

# View logs
kubectl logs -n stratium -l app.kubernetes.io/component=platform --tail=100

# Test connectivity
kubectl port-forward -n stratium svc/stratium-platform 50051:50051
```

## Monitoring and Observability

### Enable Prometheus Monitoring

```yaml
monitoring:
  serviceMonitor:
    enabled: true
    interval: 30s
    labels:
      prometheus: kube-prometheus
```

### View Metrics

```bash
# Platform service metrics
kubectl port-forward -n stratium svc/stratium-platform 50051:50051
curl http://localhost:50051/metrics
```

### Logging

View logs for each component:

```bash
# Platform service
kubectl logs -n stratium -l app.kubernetes.io/component=platform -f

# Key Manager
kubectl logs -n stratium -l app.kubernetes.io/component=key-manager -f

# PAP
kubectl logs -n stratium -l app.kubernetes.io/component=pap -f
```

## High Availability Setup

For production HA deployment:

1. **Multiple Replicas**: Set `replicaCount >= 2` for all services
2. **Pod Disruption Budgets**: Enabled by default for critical services
3. **Horizontal Pod Autoscaling**: Enabled by default, scales based on CPU/memory
4. **Anti-Affinity**: Configure pod anti-affinity to spread across nodes

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: stratium
              app.kubernetes.io/component: platform
          topologyKey: kubernetes.io/hostname
```

## Backup and Disaster Recovery

### PostgreSQL Backup

```bash
# Manual backup
kubectl exec -n stratium stratium-postgresql-0 -- \
  pg_dumpall -U keycloak > stratium-backup-$(date +%Y%m%d).sql

# Restore
kubectl exec -i -n stratium stratium-postgresql-0 -- \
  psql -U keycloak < stratium-backup-20250101.sql
```

### Automated Backups

Consider using:
- [Velero](https://velero.io/) for cluster-level backups
- [PostgreSQL Operator](https://github.com/zalando/postgres-operator) for automated DB backups
- Cloud-native backup solutions (AWS Backup, Azure Backup, etc.)

## Troubleshooting

### Pods Not Starting

```bash
# Describe pod to see events
kubectl describe pod -n stratium <pod-name>

# Check logs
kubectl logs -n stratium <pod-name> --previous

# Check init containers
kubectl logs -n stratium <pod-name> -c wait-for-postgresql
```

### Database Connection Issues

```bash
# Test PostgreSQL connectivity
kubectl run -it --rm debug --image=postgres:15-alpine --restart=Never -n stratium -- \
  psql -h stratium-postgresql -U keycloak -d keycloak

# Check PostgreSQL logs
kubectl logs -n stratium -l app.kubernetes.io/component=postgresql
```

### Keycloak Issues

```bash
# Check Keycloak is ready
kubectl get pods -n stratium -l app.kubernetes.io/component=keycloak

# View Keycloak logs
kubectl logs -n stratium -l app.kubernetes.io/component=keycloak -f

# Access Keycloak admin console
kubectl port-forward -n stratium svc/stratium-keycloak 8080:8080
```

### Ingress Not Working

```bash
# Check ingress status
kubectl describe ingress -n stratium

# Verify ingress controller is running
kubectl get pods -n ingress-nginx

# Check ingress controller logs
kubectl logs -n ingress-nginx -l app.kubernetes.io/component=controller
```

## Contributing

Please see the main repository README for contribution guidelines.

## License

See LICENSE file in the repository root.

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/stratium/issues
- Documentation: https://docs.stratium.io
