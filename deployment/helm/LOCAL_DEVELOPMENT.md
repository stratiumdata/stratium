# Local Kubernetes Development Guide

This guide walks you through setting up Stratium on a local Kubernetes cluster for development and testing.

## Prerequisites

- Docker Desktop (with Kubernetes enabled) OR Minikube OR kind
- Helm 3.8+
- kubectl
- At least 8GB RAM available for Kubernetes

## Step 1: Set Up Local Kubernetes

### Option A: Docker Desktop (Recommended for macOS/Windows)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop/)
2. Open Docker Desktop preferences/settings
3. Go to **Kubernetes** section
4. Check **Enable Kubernetes**
5. Click **Apply & Restart**
6. Wait for Kubernetes to start (green indicator)

Verify:
```bash
kubectl cluster-info
kubectl config current-context
# Should show: docker-desktop
```

### Option B: Minikube

Install and start:
```bash
# Install (macOS)
brew install minikube

# Start with sufficient resources
minikube start --memory=8192 --cpus=4 --disk-size=20g

# Use minikube context
kubectl config use-context minikube

# Enable ingress addon (optional)
minikube addons enable ingress

# Enable metrics server (optional)
minikube addons enable metrics-server
```

Verify:
```bash
minikube status
kubectl cluster-info
```

### Option C: kind (Kubernetes in Docker)

Install and create cluster:
```bash
# Install (macOS)
brew install kind

# Create cluster with custom config
cat <<EOF | kind create cluster --name stratium --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraPortMappings:
  - containerPort: 30000
    hostPort: 30000
    protocol: TCP
  - containerPort: 30001
    hostPort: 30001
    protocol: TCP
EOF

# Use kind context
kubectl config use-context kind-stratium
```

Verify:
```bash
kind get clusters
kubectl cluster-info
```

## Step 2: Build Docker Images Locally

Since we're running locally, build the images on your machine:

```bash
# Navigate to deployment directory
cd deployment

# Build Platform service
docker build -t stratiumdata/platform:latest \
  -f Dockerfile \
  --build-arg SERVICE_NAME=platform-server \
  --build-arg SERVICE_PORT=50051 \
  ..

# Build Key Manager service
docker build -t stratiumdata/key-manager:latest \
  -f Dockerfile \
  --build-arg SERVICE_NAME=key-manager-server \
  --build-arg SERVICE_PORT=50052 \
  ..

# Build Key Access service
docker build -t stratiumdata/key-access:latest \
  -f Dockerfile \
  --build-arg SERVICE_NAME=key-access-server \
  --build-arg SERVICE_PORT=50053 \
  ..

# Build PAP service
docker build -t stratiumdata/pap:latest \
  -f Dockerfile.pap \
  ..

# Build PAP UI
docker build -t stratiumdata/pap-ui:latest \
  -f ../pap-ui/Dockerfile \
  ../pap-ui
```

### For Minikube: Load Images into Minikube

```bash
# Point Docker CLI to Minikube's Docker daemon
eval $(minikube docker-env)

# Now rebuild images (they'll go directly to Minikube)
docker build -t stratiumdata/platform:latest ...
# etc.

# Or load existing images
minikube image load stratiumdata/platform:latest
minikube image load stratiumdata/key-manager:latest
minikube image load stratiumdata/key-access:latest
minikube image load stratiumdata/pap:latest
minikube image load stratiumdata/pap-ui:latest
```

### For kind: Load Images into kind

```bash
# Load images into kind cluster
kind load docker-image stratiumdata/platform:latest --name stratium
kind load docker-image stratiumdata/key-manager:latest --name stratium
kind load docker-image stratiumdata/key-access:latest --name stratium
kind load docker-image stratiumdata/pap:latest --name stratium
kind load docker-image stratiumdata/pap-ui:latest --name stratium
```

## Step 3: Install Stratium with Helm

### Quick Install with Script

```bash
cd deployment/helm

# Set to use local values
export VALUES_FILE=stratium/values-local.yaml

# Run quick start
./quick-start.sh
```

### Manual Install

```bash
cd deployment/helm

# Install with local development values
helm install stratium ./stratium \
  --namespace stratium \
  --create-namespace \
  -f stratium/values-local.yaml \
  --wait \
  --timeout 10m

# Need ingress on Minikube? Add the overlay file as well:
#   -f stratium/values-local-ingress.yaml
```

### Watch the Deployment

```bash
# Watch pods starting
kubectl get pods -n stratium -w

# Check all resources
kubectl get all -n stratium

# View events
kubectl get events -n stratium --sort-by='.lastTimestamp'
```

## Step 4: Wait for All Pods to be Ready

This usually takes 2-5 minutes:

```bash
# Check pod status
kubectl get pods -n stratium

# Expected output (all should be Running):
NAME                                  READY   STATUS    RESTARTS   AGE
stratium-envoy-xxx                    1/1     Running   0          2m
stratium-keycloak-xxx                 1/1     Running   0          3m
stratium-key-access-xxx               1/1     Running   0          2m
stratium-key-manager-xxx              1/1     Running   0          2m
stratium-pap-xxx                      1/1     Running   0          2m
stratium-pap-ui-xxx                   1/1     Running   0          2m
stratium-platform-xxx                 1/1     Running   0          2m
stratium-postgresql-0                 1/1     Running   0          4m
stratium-redis-xxx                    1/1     Running   0          3m
```

If pods are stuck, check logs:
```bash
kubectl logs -n stratium <pod-name>
kubectl describe pod -n stratium <pod-name>
```

## Step 5: Access Services

### Option A: Minikube Ingress (no port forwards)

This option exposes Stratium through host-based ingress rules so you can open browsers directly.

1. Run the ingress setup script (once per cluster):
   ```bash
   cd deployment/helm
   ./setup-minikube-ingress.sh
   ```

   This script will:
   - Enable the nginx ingress addon
   - Patch the ingress controller to use LoadBalancer type (required for minikube tunnel)
   - Wait for the controller to be ready

2. Install or upgrade Stratium with the ingress overlay:
   ```bash
   helm upgrade --install stratium ./stratium \
     --namespace stratium \
     --create-namespace \
     -f stratium/values-local.yaml \
     -f stratium/values-local-ingress.yaml \
     --wait
   ```

3. Start minikube tunnel (requires sudo, keep this running in a separate terminal):
   ```bash
   minikube tunnel
   ```

   Enter your sudo password when prompted. This creates a network route to expose LoadBalancer services.

4. Map the hostnames to localhost:
   ```bash
   sudo tee -a /etc/hosts <<EOF
   127.0.0.1 ui.stratium.local
   127.0.0.1 api.stratium.local
   127.0.0.1 auth.stratium.local
   127.0.0.1 grpc.stratium.local
   EOF
   ```

5. Verify the ingress objects:
   ```bash
   kubectl get ingress -n stratium
   ```

6. Browse directly:
   - PAP UI: http://ui.stratium.local
   - PAP API: http://api.stratium.local
   - Keycloak: http://auth.stratium.local
   - gRPC (Envoy gRPC-Web): http://grpc.stratium.local

> The Helm chart also exposes a **native gRPC** listener (HTTP/2) on the
> Envoy service. When you install with `values-local-ingress.yaml`, the
> ingress for `grpc.stratium.local` now targets that port so native gRPC
> clients (like `ztdf-client` or `grpcurl`) can connect through nginx
> without going through the gRPC-Web translation layer.

### Option B: Port Forwarding

Open separate terminals for each service:

```bash
# Terminal 1: PAP Web UI
kubectl port-forward -n stratium svc/stratium-pap-ui 3000:80
# Access at: http://localhost:3000

# Terminal 2: Keycloak Admin Console
kubectl port-forward -n stratium svc/stratium-keycloak 8080:8080
# Access at: http://localhost:8080
# Login: admin / admin

> Note: `values-local.yaml` leaves both `keycloak.config.hostname` and
> `keycloak.config.frontendUrl` empty. With `KC_HOSTNAME_STRICT=false`, Keycloak
> simply echoes whatever Host header reaches it, so in-cluster services continue
> calling `http://stratium-keycloak:8080` while your port-forwarded browser
> sessions stay on `http://localhost:8080`—no conflicting hostname flags needed.

# Terminal 3: PAP REST API
kubectl port-forward -n stratium svc/stratium-pap 8090:8090
# Access at: http://localhost:8090

# Terminal 4: Platform Service (gRPC)
kubectl port-forward -n stratium svc/stratium-platform 50051:50051

# Terminal 5: Key Manager (gRPC)
kubectl port-forward -n stratium svc/stratium-key-manager 50052:50052

# Terminal 6: Key Access (gRPC)
kubectl port-forward -n stratium svc/stratium-key-access 50053:50053

# Terminal 7: Envoy gRPC-Web
kubectl port-forward -n stratium svc/stratium-envoy 8081:8081
```

### Use a Script for Multiple Port Forwards

Create `port-forward-all.sh`:

```bash
#!/bin/bash
# Save as: deployment/helm/port-forward-all.sh

echo "Starting port forwards for Stratium..."

kubectl port-forward -n stratium svc/stratium-pap-ui 3000:80 &
kubectl port-forward -n stratium svc/stratium-keycloak 8080:8080 &
kubectl port-forward -n stratium svc/stratium-pap 8090:8090 &
kubectl port-forward -n stratium svc/stratium-platform 50051:50051 &
kubectl port-forward -n stratium svc/stratium-key-manager 50052:50052 &
kubectl port-forward -n stratium svc/stratium-key-access 50053:50053 &
kubectl port-forward -n stratium svc/stratium-envoy 8081:8081 &

echo "Port forwards started!"
echo "PAP UI:       http://localhost:3000"
echo "Keycloak:     http://localhost:8080"
echo "PAP API:      http://localhost:8090"
echo "Platform:     localhost:50051"
echo "Key Manager:  localhost:50052"
echo "Key Access:   localhost:50053"
echo "Envoy:        localhost:8081"
echo ""
echo "Press Ctrl+C to stop all port forwards"

wait
```

Make it executable and run:
```bash
chmod +x deployment/helm/port-forward-all.sh
./deployment/helm/port-forward-all.sh
```

## Step 6: Test the Deployment

### Web UI
1. Open http://localhost:3000
2. You should see the Stratium PAP UI

### Keycloak
1. Open http://localhost:8080
2. Login with `admin` / `admin`
3. Navigate to the `stratium` realm

### PAP API
```bash
# Health check
curl http://localhost:8090/health

# List policies
curl http://localhost:8090/api/policies
```

### gRPC Services with grpcurl

```bash
# Install grpcurl if needed
brew install grpcurl

# List Platform services (pick one target)
grpcurl -plaintext localhost:50051 list
grpcurl -plaintext grpc.stratium.local:80 list  # via ingress

# Test Platform service
grpcurl -plaintext -d '{
  "subject": {"id": "user123", "attributes": {"role": "admin"}},
  "resource": {"id": "resource456", "type": "document"},
  "action": "read",
  "context": {}
}' localhost:50051 platform.PlatformService/GetDecision

### ztdf-client (Go CLI)

The Go `ztdf-client` speaks native gRPC directly to both the Key Manager
and Key Access services. Make sure those ports are reachable before you
run the CLI, otherwise you will see errors such as
`dial tcp [::1]:8081: connect: connection refused`.

**Option 1 – Port forwards (matches `port-forward-all.sh`):**

```bash
kubectl port-forward -n stratium svc/stratium-key-manager 50052:50052
kubectl port-forward -n stratium svc/stratium-key-access 50053:50053
```

Then run the CLI from the repo root:

```bash
go run ./cmd/ztdf-client wrap \
  --keycloak-url "http://localhost:8080/realms/stratium" \
  --username "<username>" \
  --password "<password>" \
  --resource "pap-api" \
  --text "local test" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

**Option 2 – Minikube ingress overlay:**

If you installed with `values-local-ingress.yaml` and added
`grpc.stratium.local` to `/etc/hosts`, you can point both services at
Envoy instead:

```bash
go run ./cmd/ztdf-client wrap \
  --keycloak-url "http://auth.stratium.local/realms/stratium" \
  --username "<username>" \
  --password "<password>" \
  --resource "pap-api" \
  --text "ingress test" \
  --km-addr "grpc.stratium.local:80" \
  --kas-addr "grpc.stratium.local:80"
```

Keep the ingress controller or the port-forward session running while
the CLI executes. Because Envoy now exposes a dedicated native gRPC
listener behind the ingress, the CLI can speak HTTP/2 gRPC all the way
through nginx without the policy JSON being mangled by the gRPC-Web
translator.

## External key sources

Kubernetes deployments can preload partner-supplied keys by mounting a
directory that contains `manifest.json`, `public.pem`, and (optionally)
`private.pem` for each key. Configure sources under
`keyManager.config.externalKeySources`:

```yaml
keyManager:
  config:
    externalKeysEnabled: true
    externalKeysEmergencyDisable: false
    externalKeySources:
      - name: partners
        type: volume
        volume:
          basePath: /var/run/stratium/external-keys
          manifestFile: manifest.json   # optional overrides
          publicKeyFile: public.pem
          privateKeyFile: private.pem
        awsSecretsManager:
          region: us-east-2            # default region for secret refs
          secretKeyField: pem          # optional JSON field selector
```

Directory layout example:

```
/var/run/stratium/external-keys/
└── partner-a/
    ├── manifest.json
    ├── public.pem
    └── private.pem      # optional if AWS Secrets Manager holds it
```

`manifest.json` must at least specify `key_id`, `name`, `key_type`, and
`provider_type`. All additional metadata is surfaced via gRPC. Example:

```json
{
  "key_id": "partner-a-key",
  "name": "Partner A envelope key",
  "key_type": "RSA2048",
  "provider_type": "software",
  "status": "active",
  "metadata": {
    "partner": "alpha"
  },
  "private_key_secret_ref": {
    "name": "arn:aws:secretsmanager:us-east-2:123456789012:secret:partner-a",
    "region": "us-east-2",
    "key_field": "pem"
  }
}
```

If `private.pem` is absent, the loader pulls the private key from AWS
Secrets Manager using `private_key_secret_ref`. Only the PEM blob should
live inside the secret; the manifest and public key remain on the volume.
`key_field` lets you extract a nested JSON property from the secret.

The loader executes during Key Manager startup. Restart pods any time a
new manifest is added. Flip `externalKeysEmergencyDisable` to `true` to
skip loading without mutating the source directories. Externally loaded
keys are immutable through the API—they cannot be rotated or deleted via
gRPC and must be updated at the manifest source.
```

## Development Workflow

### Making Code Changes

1. Make changes to your Go code
2. Rebuild the affected image:
   ```bash
   cd deployment
   docker build -t stratiumdata/platform:latest \
     -f Dockerfile \
     --build-arg SERVICE_NAME=platform-server \
     ..

   # For Minikube
   eval $(minikube docker-env)
   # Rebuild...

   # For kind
   kind load docker-image stratiumdata/platform:latest --name stratium
   ```

3. Restart the deployment:
   ```bash
   kubectl rollout restart deployment/stratium-platform -n stratium
   kubectl rollout status deployment/stratium-platform -n stratium
   ```

### View Logs

```bash
# Live tail logs
kubectl logs -n stratium -l app.kubernetes.io/component=platform -f

# All logs from a service
kubectl logs -n stratium -l app.kubernetes.io/component=platform --tail=100

# Specific pod
kubectl logs -n stratium <pod-name> -f

# Previous container logs (if pod crashed)
kubectl logs -n stratium <pod-name> --previous
```

### Access Pod Shell

```bash
# Get a shell in a pod
kubectl exec -it -n stratium <pod-name> -- /bin/sh

# Example: Access PostgreSQL
kubectl exec -it -n stratium stratium-postgresql-0 -- psql -U keycloak
```

### Database Access

```bash
# Port forward PostgreSQL
kubectl port-forward -n stratium svc/stratium-postgresql 5432:5432

# Connect with psql
psql -h localhost -U keycloak -d keycloak
# Password: keycloak_password

# Or use your favorite DB client
```

## Updating the Deployment

### Change Configuration

1. Edit `values-local.yaml`
2. Upgrade the release:
   ```bash
   helm upgrade stratium ./stratium \
     -n stratium \
     -f stratium/values-local.yaml
   ```

### Change Image Version

```bash
# Update specific service
helm upgrade stratium ./stratium \
  -n stratium \
  -f stratium/values-local.yaml \
  --set platform.image.tag=v1.1.0
```

## Cleanup

### Uninstall Stratium

```bash
# Uninstall the Helm release
helm uninstall stratium -n stratium

# Delete the namespace (removes everything)
kubectl delete namespace stratium

# Verify cleanup
kubectl get all -n stratium
```

### Stop Kubernetes Cluster

```bash
# Docker Desktop: Settings → Kubernetes → Disable

# Minikube
minikube stop
minikube delete  # Complete removal

# kind
kind delete cluster --name stratium
```

## Troubleshooting

### Pods in CrashLoopBackOff

```bash
# Check logs
kubectl logs -n stratium <pod-name>

# Check events
kubectl describe pod -n stratium <pod-name>

# Common causes:
# - Image not found (build and load images)
# - Database not ready (wait longer)
# - Configuration error (check ConfigMaps)
```

### Pods Stuck in Pending

```bash
# Check events
kubectl describe pod -n stratium <pod-name>

# Common causes:
# - Insufficient resources (reduce resource requests)
# - PVC not binding (disable persistence in values-local.yaml)
```

### ImagePullBackOff

```bash
# Image doesn't exist locally
# Solution: Build and load images as shown in Step 2
```

### Can't Connect to Services

```bash
# Ensure port-forward is running
kubectl get pods -n stratium  # Verify pod is Running
kubectl port-forward -n stratium svc/stratium-pap-ui 3000:80

# Check if service exists
kubectl get svc -n stratium
```

### Database Connection Errors

```bash
# Check PostgreSQL is running
kubectl get pods -n stratium -l app.kubernetes.io/component=postgresql

# Check PostgreSQL logs
kubectl logs -n stratium stratium-postgresql-0

# Verify service
kubectl get svc -n stratium stratium-postgresql
```

## Tips for Local Development

1. **Use values-local.yaml**: Optimized for local with reduced resources
2. **Disable persistence**: Faster cleanup, no PVC issues
3. **Single replicas**: Saves resources
4. **No network policies**: Easier debugging
5. **Watch logs**: Always tail logs while developing
6. **Use port-forward script**: Saves time opening multiple terminals
7. **Keep Docker Desktop running**: Ensures Kubernetes stability

## Comparing with Docker Compose

| Feature | Helm/K8s | Docker Compose |
|---------|----------|----------------|
| Setup time | 3-5 min | 1-2 min |
| Resource usage | Higher | Lower |
| Production-like | Yes | No |
| Auto-scaling test | Yes | No |
| Network policies | Yes | No |
| Hot reload | Manual | Manual |
| Best for | Testing K8s features | Quick dev work |

**Recommendation**: Use Docker Compose for daily development, use Helm/K8s for testing production-like deployments.

## Next Steps

- **Production Deployment**: See [README.md](README.md) for production configuration
- **CI/CD Integration**: See [KUBERNETES.md](../KUBERNETES.md) for ArgoCD/Flux examples
- **Monitoring**: Enable Prometheus/Grafana for local testing

## Need Help?

- Check logs: `kubectl logs -n stratium <pod-name>`
- Check events: `kubectl get events -n stratium`
- Check Helm status: `helm status stratium -n stratium`
- Check pod details: `kubectl describe pod -n stratium <pod-name>`
