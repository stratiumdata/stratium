# Stratium gRPC Services - Docker Deployment

This directory contains Docker Compose configurations for deploying and testing the Stratium gRPC services with different encryption algorithms. Unless otherwise noted, run the following commands from `deployment/docker`.

## Services

The deployment includes the following services:

### gRPC Services
1. **Platform Service** (port 50051) - Authorization and entitlement decisions
2. **Key Manager Service** (port 50052) - Cryptographic key management
3. **Key Access Service** (port 50053) - Key wrapping and unwrapping operations

### Web Services
4. **PAP Service** (port 8090) - Policy Administration Point REST API
5. **Web UI** (port 3000) - React-based web interface for policy management
6. **Keycloak** (port 8080) - OpenID Connect identity provider
7. **PostgreSQL** (port 5432) - Database for Keycloak and PAP
8. **Redis** (port 6379) - Cache for PAP service

## Quick Start

### Default Deployment (RSA)

```bash
cd deployment/docker
docker-compose up --build
```

Once all services are running, you can access:
- **Web UI**: http://localhost:3000
- **PAP API**: http://localhost:8090
- **Keycloak**: http://localhost:8080

Default Keycloak credentials:
- Username: `admin`
- Password: `admin`

### Testing Different Encryption Algorithms

The deployment supports testing with different encryption algorithm families. See [ALGORITHMS.md](ALGORITHMS.md) for detailed algorithm documentation.

#### RSA Encryption (RSA2048, RSA3072, RSA4096)
```bash
# Default: RSA2048
docker-compose -f docker-compose.yml -f docker-compose.rsa.yml up --build

# Test RSA4096
export RSA_ALGORITHM=RSA4096
docker-compose -f docker-compose.yml -f docker-compose.rsa.yml up --build
```

#### ECC Encryption (P256, P384, P521)
```bash
# Default: P256
docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up --build

# Test P384
export ECC_ALGORITHM=P384
docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up --build
```

#### Post-Quantum KEM (KYBER512, KYBER768, KYBER1024)
```bash
# Default: KYBER768
docker-compose -f docker-compose.yml -f docker-compose.kem.yml up --build

# Test KYBER1024
export KYBER_ALGORITHM=KYBER1024
docker-compose -f docker-compose.yml -f docker-compose.kem.yml up --build
```

## Environment Configuration

Copy `.env.example` to `.env` and customize as needed:

```bash
cp .env.example .env
```

### Available Environment Variables

#### Encryption Configuration
- `PLATFORM_ENCRYPTION_ALGORITHM` - Encryption algorithm for platform service
- `KEY_MANAGER_ENCRYPTION_ALGORITHM` - Encryption algorithm for key manager service
- `KEY_ACCESS_ENCRYPTION_ALGORITHM` - Encryption algorithm for key access service
- `KEY_ROTATION_ENABLED` - Enable automatic key rotation (true/false)

**Valid algorithm values:**
- **RSA:** `RSA2048`, `RSA3072`, `RSA4096`
- **ECC:** `P256`, `P384`, `P521`
- **Post-Quantum:** `KYBER512`, `KYBER768`, `KYBER1024`

See [ALGORITHMS.md](ALGORITHMS.md) for detailed information about each algorithm.

#### Service Discovery Configuration
- `PLATFORM_ADDR` - Address of the platform service (default: `platform:50051`)
- `KEY_MANAGER_ADDR` - Address of the key manager service (default: `key-manager:50052`)
- `KEY_ACCESS_ADDR` - Address of the key access service (default: `key-access:50053`)

These service discovery variables allow the services to find and communicate with each other. The default values use Docker service names for container-to-container communication. Override these when:
- Running services outside Docker (use `localhost:PORT`)
- Using custom networking configurations
- Testing with services on different hosts

## Service Dependencies

The services have the following dependency chain:
- **Key Access** depends on **Key Manager** (configured via `KEY_MANAGER_ADDR`)
- **Platform** is independent
- **Key Manager** is independent

## Networking

All services run on a bridge network named `stratium-network`. Services can communicate using their service names as hostnames:
- `platform:50051`
- `key-manager:50052`
- `key-access:50053`

## Health Checks

Each service includes health checks that verify the gRPC port is accessible:
- Interval: 10 seconds
- Timeout: 5 seconds
- Retries: 5

## Using the Web UI

The Web UI provides a user-friendly interface for managing policies, entitlements, and viewing audit logs.

### Accessing the Web UI

1. Open your browser to http://localhost:3000
2. The UI automatically connects to the PAP service via nginx proxy
3. All API requests to `/api/*` are proxied to the PAP service at `http://pap:8090`

### Features

- **Policies Page**: Create, edit, delete, and filter ABAC policies (OPA/XACML)
- **Entitlements Page**: Manage fine-grained access entitlements
- **Audit Logs Page**: View detailed audit trail of all operations
- **Dark Mode Support**: UI automatically adapts to system theme preferences

### Web UI Architecture

The Web UI is built with:
- **React 19** with TypeScript
- **Vite** for fast builds and development
- **TailwindCSS v4** for styling
- **React Router** for navigation
- **React Query** for data fetching and caching
- **Nginx** for serving static files and API proxying

The Dockerfile uses a multi-stage build:
1. Build stage: Installs dependencies and builds the React app
2. Production stage: Serves the built files with nginx

## Testing the Deployment

### Using grpcurl

Install grpcurl if not already installed:
```bash
# macOS
brew install grpcurl

# Linux
go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest
```

#### List available services:
```bash
# Platform Service
grpcurl -plaintext localhost:50051 list

# Key Manager Service
grpcurl -plaintext localhost:50052 list

# Key Access Service
grpcurl -plaintext localhost:50053 list
```

#### Test service endpoints:
```bash
# Platform Service - Get Decision
grpcurl -plaintext -d '{
  "subject": {"id": "user123", "attributes": {"role": "admin"}},
  "resource": {"id": "resource456", "type": "document"},
  "action": "read",
  "context": {}
}' localhost:50051 platform.PlatformService/GetDecision

# Key Manager Service - List Providers
grpcurl -plaintext localhost:50052 keymanager.KeyManagerService/ListProviders

# Key Access Service - WrapDEK (requires authentication token)
grpcurl -plaintext -H "authorization: Bearer YOUR_TOKEN" -d '{
  "key_id": "test-key-id",
  "plaintext_dek": "base64_encoded_key_here",
  "encryption_context": {"purpose": "test"}
}' localhost:50053 keyaccess.KeyAccessService/WrapDEK
```

### Using the built-in clients

From the project root:

```bash
# Build the client binaries
make build

# Test Platform Service
./bin/platform-client

# Test Key Manager Service
./bin/key-manager-client

# Test Key Access Service (ensure key-manager is running)
./bin/key-access-client
```

## Logs and Debugging

### View logs for all services:
```bash
docker-compose logs -f
```

### View logs for a specific service:
```bash
docker-compose logs -f platform
docker-compose logs -f key-manager
docker-compose logs -f key-access
docker-compose logs -f pap
docker-compose logs -f pap-ui
docker-compose logs -f keycloak
```

### Access a service container:
```bash
docker exec -it stratium-platform sh
docker exec -it stratium-key-manager sh
docker exec -it stratium-key-access sh
docker exec -it stratium-pap sh
docker exec -it stratium-pap-ui sh
```

## Stopping the Deployment

```bash
# Stop services but keep containers
docker-compose stop

# Stop and remove containers
docker-compose down

# Stop, remove containers, and clean up volumes
docker-compose down -v
```

## Development Workflow

### Testing Different Encryption Configurations

1. **Test RSA Configuration:**
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.rsa.yml up --build
   # Run your tests
   docker-compose down
   ```

2. **Test ECC Configuration:**
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.ecc.yml up --build
   # Run your tests
   docker-compose down
   ```

3. **Test KEM Configuration:**
   ```bash
   docker-compose -f docker-compose.yml -f docker-compose.kem.yml up --build
   # Run your tests
   docker-compose down
   ```

### Rebuilding After Code Changes

```bash
# Rebuild all services
docker-compose build --no-cache

# Rebuild a specific service
docker-compose build --no-cache platform
```

## Troubleshooting

### Service won't start
- Check logs: `docker-compose logs [service-name]`
- Verify port availability: `lsof -i :[port]`
- Ensure dependencies are healthy: `docker-compose ps`

### Connection refused errors
- Wait for health checks to pass
- Verify service networking: `docker network inspect stratium-network`
- Check firewall settings

### Build failures
- Ensure Go modules are up to date in `go/go.mod`
- Clear Docker cache: `docker-compose build --no-cache`
- Verify Dockerfile paths and build context

## Architecture Notes

### Multi-stage Builds
The Dockerfile uses multi-stage builds to:
1. Build the Go binaries in a full golang image
2. Copy only the binary to a minimal alpine image
3. Reduce final image size and attack surface

### Security Features
- Services run as non-root user (UID 1000)
- Minimal runtime image (Alpine Linux)
- CA certificates included for HTTPS
- No unnecessary packages or tools

## Service Discovery

The deployment uses environment variables for service discovery, allowing flexible configuration of how services communicate:

### In Docker Compose
Services use Docker service names as hostnames:
- `KEY_MANAGER_ADDR=key-manager:50052`
- `PLATFORM_ADDR=platform:50051`
- `KEY_ACCESS_ADDR=key-access:50053`

### Running Outside Docker
When running services locally without Docker, update the `.env` file or set environment variables:
```bash
export KEY_MANAGER_ADDR=localhost:50052
export PLATFORM_ADDR=localhost:50051
export KEY_ACCESS_ADDR=localhost:50053
```

### Custom Network Configurations
For testing services on different hosts or custom networks:
```bash
# In .env file
KEY_MANAGER_ADDR=192.168.1.100:50052
PLATFORM_ADDR=192.168.1.101:50051
KEY_ACCESS_ADDR=192.168.1.102:50053
```

### Command-line Override
You can also override service addresses via command-line flags when running the servers directly:
```bash
# Key Access server connecting to a remote Key Manager
./bin/key-access-server -key-manager=remote-host:50052
```

## Production Kubernetes Deployment

For production deployments, use the **Helm chart** located in `deployment/helm/`:

### Helm Deployment (Recommended)

```bash
# Quick start
cd deployment/helm
./quick-start.sh

# Or manually with custom values
helm install stratium ./stratium -n stratium --create-namespace -f custom-values.yaml
```

The Helm chart provides:
- **High Availability**: Multiple replicas with pod disruption budgets
- **Auto-scaling**: Horizontal Pod Autoscalers for all services
- **Security**: Network policies, pod security contexts, and secrets management
- **Monitoring**: ServiceMonitor integration for Prometheus
- **Ingress**: Built-in ingress configuration for external access
- **Production Ready**: Optimized resource limits and health checks

See the [Helm Chart Documentation](helm/README.md) for detailed configuration options and production deployment guide.

### Kubernetes Manifests

For raw Kubernetes manifests or GitOps deployments:

```bash
# Generate manifests from Helm chart
helm template stratium ./helm/stratium -n stratium > stratium-manifests.yaml

# Apply to cluster
kubectl apply -f stratium-manifests.yaml -n stratium
```

See [Kubernetes Deployment Guide](kubernetes/README.md) for ArgoCD and Flux CD integration examples.

## Next Steps

- **For Production**: Follow the [Helm Production Deployment Guide](helm/README.md#production-deployment-guide)
- Implement TLS/mTLS for secure communication between services
- Configure monitoring and metrics (Prometheus/Grafana)
- Implement distributed tracing (OpenTelemetry)
- Set up automated backups for PostgreSQL
- Configure external secret management (Azure Key Vault, AWS Secrets Manager, etc.)
