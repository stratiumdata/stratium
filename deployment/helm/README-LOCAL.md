# Quick Start: Local Development with Helm

This is a simplified guide for getting Stratium running on your local Kubernetes cluster in 5 minutes.

## Prerequisites

- **Docker Desktop** with Kubernetes enabled (easiest option)
  - OR **Minikube**
  - OR **kind**
- **Helm 3.8+**
- **kubectl**

## 3-Step Local Install

### Step 1: Build Images (5 minutes)

```bash
cd deployment/helm
./build-images.sh
```

This builds all 5 Docker images needed for Stratium.

### Step 2: Deploy with Helm (2 minutes)

```bash
helm install stratium ./stratium \
  -n stratium \
  --create-namespace \
  -f stratium/values-local.yaml \
  --wait

# For Minikube ingress (no port-forwarding), add the overlay:
# -f stratium/values-local-ingress.yaml
```

Wait for all pods to be Running:
```bash
kubectl get pods -n stratium -w
```

### Step 3: Access Services (immediate)

```bash
# Start all port forwards
./port-forward-all.sh
```

Or manually:
```bash
kubectl port-forward -n stratium svc/stratium-pap-ui 3000:80
kubectl port-forward -n stratium svc/stratium-keycloak 8080:8080
kubectl port-forward -n stratium svc/stratium-pap 8090:8090
```

#### Optional: Minikube Ingress (no port forward)

1. Run the ingress setup script (one-time):
   ```bash
   ./setup-minikube-ingress.sh
   ```
   This enables nginx ingress and patches it for use with `minikube tunnel`.

2. Reinstall (or upgrade) with the ingress overlay:
   ```bash
   helm upgrade --install stratium ./stratium \
     -n stratium \
     --create-namespace \
     -f stratium/values-local.yaml \
     -f stratium/values-local-ingress.yaml \
     --wait
   ```

3. Start minikube tunnel (keep running in a separate terminal):
   ```bash
   minikube tunnel
   ```
   Enter your sudo password when prompted.

4. Point the hostnames to localhost:
   ```bash
   sudo tee -a /etc/hosts <<'EOF'
   127.0.0.1 ui.stratium.local
   127.0.0.1 api.stratium.local
   127.0.0.1 auth.stratium.local
   127.0.0.1 grpc.stratium.local
   EOF
   ```

5. Browse directly (no port-forwarding needed).

## Access Points

| Service | Port-Forward URL | Ingress Host (Minikube) | Credentials |
|---------|------------------|-------------------------|-------------|
| **PAP Web UI** | http://localhost:3000 | http://ui.stratium.local | - |
| **Keycloak Admin** | http://localhost:8080 | http://auth.stratium.local | admin / admin |
| **PAP REST API** | http://localhost:8090 | http://api.stratium.local | - |
| **Platform gRPC** | localhost:50051 | (via Envoy at grpc.stratium.local) | - |
| **Key Manager gRPC** | localhost:50052 | (via Envoy at grpc.stratium.local) | - |
| **Key Access gRPC** | localhost:50053 | (via Envoy at grpc.stratium.local) | - |

## Files for Local Development

| File | Purpose |
|------|---------|
| `values-local.yaml` | Optimized Helm values for local (single replicas, no persistence) |
| `values-local-ingress.yaml` | Host-based ingress overlay for Minikube |
| `setup-minikube-ingress.sh` | Configure ingress for minikube tunnel (one-time setup) |
| `build-images.sh` | Build all Docker images at once |
| `port-forward-all.sh` | Start all port forwards with one command |
| `LOCAL_DEVELOPMENT.md` | Complete local development guide |

## What's Different in Local Mode?

Compared to production deployment:

- ✅ Single replica per service (saves resources)
- ✅ No persistent volumes (faster cleanup)
- ✅ No autoscaling (static size)
- ✅ No network policies (easier debugging)
- ✅ Optional ingress overlay (skip port-forwarding on Minikube)
- ✅ Reduced CPU/memory limits
- ✅ Default passwords (dev only!)

**Minimum resources**: ~4GB RAM, 2 CPUs

## Common Commands

```bash
# View all pods
kubectl get pods -n stratium

# View logs
kubectl logs -n stratium -l app.kubernetes.io/component=platform -f

# Restart a service
kubectl rollout restart deployment/stratium-platform -n stratium

# Uninstall
helm uninstall stratium -n stratium

# Complete cleanup
helm uninstall stratium -n stratium
kubectl delete namespace stratium
```

## Rebuilding After Code Changes

1. Make code changes
2. Rebuild image:
   ```bash
   cd deployment/helm
   ./build-images.sh  # Rebuilds all images
   ```
3. Restart deployment:
   ```bash
   kubectl rollout restart deployment/stratium-platform -n stratium
   ```

## Troubleshooting

**Pods not starting?**
```bash
kubectl describe pod -n stratium <pod-name>
kubectl logs -n stratium <pod-name>
```

**Image not found?**
```bash
# Run build-images.sh first
cd deployment/helm
./build-images.sh
```

**Port already in use?**
```bash
# Kill existing port-forwards
pkill -f "port-forward"
```

## Full Documentation

- **[LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md)** - Complete local setup guide
- **[README.md](README.md)** - Full Helm chart documentation
- **[../KUBERNETES.md](../KUBERNETES.md)** - Kubernetes deployment overview

## Docker Compose Alternative

For even simpler local development, consider using Docker Compose:

```bash
cd deployment
docker-compose up
```

**When to use what:**
- **Docker Compose**: Daily development, quick testing
- **Helm/K8s**: Test production-like deployment, test K8s features
