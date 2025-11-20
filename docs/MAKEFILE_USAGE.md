# Makefile Usage Guide

## Overview

The Stratium platform includes a comprehensive Makefile for building, testing, and deploying all services. This guide covers the available commands and common workflows.

## Quick Start

```bash
# Show all available commands
make help

# Build all services
make build

# Start all services with Docker
make quickstart
```

## Build Commands

### Build All Services
```bash
make build
```
Builds all service binaries to the `bin/` directory.

### Build Individual Services

```bash
# Platform Service
make build-platform

# Key Manager Service
make build-key-manager

# Key Access Service
make build-key-access

# PAP Service
make build-pap
```

### Clean Build Artifacts
```bash
make clean
```

## Run Commands (Local Development)

### Platform Service
```bash
make run-platform-server
```
Starts the platform gRPC server on port 50051.

### Key Manager Service
```bash
make run-key-manager-server
```
Starts the key manager gRPC server on port 50052.

### Key Access Service
```bash
make run-key-access-server
```
Starts the key access gRPC server on port 50053.

### PAP Service
```bash
make run-pap-server
```
Starts the PAP API server on port 8090.

**Note**: PAP server requires PostgreSQL and Redis to be running. The environment variables are pre-configured for local development.

## Test Commands

### Run All Tests
```bash
make test
```

### Run Individual Service Tests
```bash
# Platform Service
make test-platform

# Key Manager Service
make test-key-manager

# Key Access Service
make test-key-access

# PAP Service (includes pkg tests)
make test-pap
```

### Run Benchmarks
```bash
make bench
```

### Integration Tests
```bash
# Run all integration tests
make test-integration

# Run specific integration test
make test-platform-pdp    # Platform PDP integration test
make test-pap-auth        # PAP authentication test
```

## Docker Commands

### Build Docker Images
```bash
make docker-build
```

### Start All Services
```bash
make docker-up
```

**Services Available:**
- Platform: localhost:50051 (gRPC)
- Key Manager: localhost:50052 (gRPC)
- Key Access: localhost:50053 (gRPC)
- PAP API: http://localhost:8090
- Keycloak: http://localhost:8080
- PostgreSQL: localhost:5432
- Redis: localhost:6379

### Stop All Services
```bash
# Stop services (keep volumes)
make docker-down

# Stop services and remove volumes
make docker-down-volumes
```

### View Logs
```bash
# All services
make docker-logs

# Platform service only
make docker-logs-platform

# PAP service only
make docker-logs-pap

# Show running containers
make docker-ps
```

### Quick Start (Clean Restart)
```bash
make quickstart
```

This command:
1. Stops all services
2. Rebuilds Docker images
3. Starts all services
4. Waits for services to be healthy
5. Shows test commands

## Development Commands

### Dependencies
```bash
# Download dependencies
make mod-download

# Tidy dependencies
make mod-tidy
```

### Code Quality
```bash
# Format code
make fmt

# Run go vet
make vet
```

### Generate Protobuf Code
```bash
make generate
```

**Requires**: Protocol Buffers compiler (`protoc`) to be installed.

## Common Workflows

### Development Workflow

1. **Make changes to code**
2. **Format and check code:**
   ```bash
   make fmt
   make vet
   ```
3. **Build and test:**
   ```bash
   make build
   make test
   ```
4. **Run locally:**
   ```bash
   # In separate terminals
   make run-platform-server
   make run-pap-server
   ```

### Docker Development Workflow

1. **Make changes to code**
2. **Rebuild and restart:**
   ```bash
   make quickstart
   ```
3. **View logs:**
   ```bash
   make docker-logs-pap
   make docker-logs-platform
   ```
4. **Run integration tests:**
   ```bash
   make test-integration
   ```

### Adding New Services

To add a new service to the Makefile:

1. **Add build target:**
   ```makefile
   build-myservice:
       @echo "Building my service..."
       cd go && go build -o ../bin/myservice-server ./cmd/myservice-server
       @echo "My service build complete!"
   ```

2. **Add to build-all:**
   ```makefile
   build: build-platform build-key-manager build-key-access build-pap build-myservice
   ```

3. **Add test target:**
   ```makefile
   test-myservice:
       @echo "Running my service tests..."
       cd go && go test -v ./services/myservice
   ```

4. **Add to test-all:**
   ```makefile
   test: test-platform test-key-manager test-key-access test-pap test-myservice
   ```

5. **Add run target:**
   ```makefile
   run-myservice-server: build-myservice
       @echo "Starting my service server..."
       ./bin/myservice-server
   ```

6. **Update help text:**
   ```makefile
   @echo "My Service:"
   @echo "  build-myservice          - Build my service binary"
   @echo "  test-myservice           - Run my service tests"
   @echo "  run-myservice-server     - Start my service server"
   ```

7. **Add to clean:**
   ```makefile
   rm -f go/cmd/myservice-server/myservice-server
   ```

## Troubleshooting

### Build Failures

**Error**: `cannot find package`
```bash
# Download dependencies
make mod-download
```

**Error**: `permission denied`
```bash
# Make binaries executable
chmod +x bin/*
```

### Docker Issues

**Error**: `Cannot connect to Docker daemon`
```bash
# Start Docker
# On macOS: Open Docker Desktop
# On Linux: sudo systemctl start docker
```

**Error**: `port already allocated`
```bash
# Stop conflicting services or change ports in docker-compose.yml
make docker-down
```

**Error**: `service unhealthy`
```bash
# View logs to diagnose
make docker-logs-platform
make docker-logs-pap

# Reset everything
make docker-down-volumes
make docker-up
```

### Test Failures

**Error**: Integration tests fail
```bash
# Ensure services are running
make docker-up

# Wait for services to be healthy
sleep 10

# Run tests
make test-integration
```

## Environment Variables

### Platform Service
- `DATABASE_URL`: PostgreSQL connection string
- `CACHE_TYPE`: `redis` or `memory`
- `REDIS_ADDR`: Redis address (default: `localhost:6379`)
- `REDIS_PASSWORD`: Redis password
- `REDIS_DB`: Redis database number

### PAP Service
- `DATABASE_URL`: PostgreSQL connection string
- `CACHE_TYPE`: `redis` or `memory`
- `REDIS_ADDR`: Redis address
- `OIDC_ISSUER_URL`: Keycloak issuer URL
- `OIDC_CLIENT_ID`: OAuth client ID
- `OIDC_CLIENT_SECRET`: OAuth client secret

### Key Access Service
- `OIDC_ISSUER_URL`: Keycloak issuer URL
- `OIDC_CLIENT_ID`: OAuth client ID
- `OIDC_CLIENT_SECRET`: OAuth client secret

## References

- [Platform PDP Integration](./PLATFORM_PDP_INTEGRATION.md)
- [PAP API Guide](./PAP_API_GUIDE.md)
- [Caching Layer](./CACHING_LAYER.md)
- [Keycloak Setup](./KEYCLOAK_SETUP.md)
