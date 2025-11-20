# Customer Distribution Builds

This document explains how to build and distribute Docker images to customers **without proprietary features**.

## Overview

Customer distribution builds are production-quality Docker images with **NO feature flags** enabled. This ensures customers receive the core platform functionality without any proprietary optimizations, metrics, or advanced features.

## Key Characteristics

### What Customers Get ✓

- **Core Platform Functionality**
  - Policy Decision Point (PDP)
  - Key Management Service
  - Key Access Service
  - Policy Administration Point (PAP)

- **Standard Configuration**
  - Full logging (INFO level)
  - Production timeouts (30s)
  - Standard error handling
  - OIDC authentication support

### What's Excluded (Proprietary) ✗

- Advanced rate limiting
- Metrics collection & export
- Distributed tracing
- Performance optimizations
- Advanced caching strategies
- Custom feature flags

## Building Customer Images

### Build All Services

```bash
make build-customer
```

This builds all four services as customer distribution images with:
- `BUILD_MODE=production`
- `BUILD_FEATURES=""` (empty - no features)
- `BUILD_VERSION=eval-1.0.0` (default, can override)

### Build Individual Services

```bash
make build-customer-platform      # Platform service
make build-customer-key-manager   # Key manager service
make build-customer-key-access    # Key access service
make build-customer-pap           # PAP service
```

### Custom Version

```bash
make build-customer CUSTOMER_VERSION=eval-2.0.0
```

## Exporting for Distribution

### Save Images as TAR Files

```bash
# Export all services
docker save stratium/platform:customer > stratium-platform-eval.tar
docker save stratium/key-manager:customer > stratium-key-manager-eval.tar
docker save stratium/key-access:customer > stratium-key-access-eval.tar
docker save stratium/pap:customer > stratium-pap-eval.tar
```

### Compress for Smaller Size

```bash
# Export and compress
docker save stratium/platform:customer | gzip > stratium-platform-eval.tar.gz
docker save stratium/key-manager:customer | gzip > stratium-key-manager-eval.tar.gz
docker save stratium/key-access:customer | gzip > stratium-key-access-eval.tar.gz
docker save stratium/pap:customer | gzip > stratium-pap-eval.tar.gz
```

### Create Distribution Package

```bash
# Create distribution directory
mkdir -p dist/stratium-eval-1.0.0

# Export all images
docker save stratium/platform:customer | gzip > dist/stratium-eval-1.0.0/platform.tar.gz
docker save stratium/key-manager:customer | gzip > dist/stratium-eval-1.0.0/key-manager.tar.gz
docker save stratium/key-access:customer | gzip > dist/stratium-eval-1.0.0/key-access.tar.gz
docker save stratium/pap:customer | gzip > dist/stratium-eval-1.0.0/pap.tar.gz

# Copy docker-compose file
cp deployment/docker-compose.yml dist/stratium-eval-1.0.0/

# Create archive
cd dist && tar -czf stratium-eval-1.0.0.tar.gz stratium-eval-1.0.0/
```

## Customer Loading Instructions

Customers can load the images with:

```bash
# Load individual images
docker load < stratium-platform-eval.tar.gz
docker load < stratium-key-manager-eval.tar.gz
docker load < stratium-key-access-eval.tar.gz
docker load < stratium-pap-eval.tar.gz

# Verify images are loaded
docker images | grep stratium

# Run services
docker-compose up -d
```

## Testing Customer Builds Locally

### Run Customer Services

```bash
make docker-customer-up
```

This starts all services using the standard docker-compose.yml without any feature flag overrides.

### View Logs

```bash
make docker-customer-logs
```

### Stop Services

```bash
make docker-customer-down
```

## Verification

### Verify Configuration

```bash
make verify-customer
```

This displays:
- Build settings (mode, version, features)
- What customers receive
- What's excluded (proprietary)
- Export instructions

### Verify Build Artifacts

```bash
# Check image tags
docker images | grep stratium | grep customer

# Inspect image
docker inspect stratium/platform:customer

# Check build info from running container
docker run --rm stratium/platform:customer --version
```

## Comparison Matrix

| Feature | Customer Build | Demo Build | Production Build |
|---------|---------------|------------|------------------|
| **Mode** | production | demo | production |
| **Features** | NONE (empty) | rate-limiting, short-timeouts | Custom |
| **Logging** | Full (INFO) | Minimal (startup only) | Full (all levels) |
| **Timeouts** | 30s | 5s | 30s |
| **Rate Limiting** | ✗ Disabled | ✓ Strict limits | ✓ Configurable |
| **Metrics** | ✗ Disabled | ✗ Disabled | ✓ Optional |
| **Tracing** | ✗ Disabled | ✗ Disabled | ✓ Optional |
| **Purpose** | Customer eval | Internal demos | Production use |
| **Safe to Distribute** | ✓ Yes | ⚠️ Caution | ✗ No |

## Distribution Checklist

Before distributing to customers:

- [ ] Build customer images: `make build-customer`
- [ ] Verify configuration: `make verify-customer`
- [ ] Test locally: `make docker-customer-up`
- [ ] Check logs for proprietary info: `make docker-customer-logs`
- [ ] Export images: `docker save ... | gzip > ...`
- [ ] Create README for customers
- [ ] Include docker-compose.yml
- [ ] Include sample configuration files
- [ ] Document environment variables
- [ ] Specify support limitations
- [ ] Include license/terms

## Security Considerations

### What's Safe to Distribute

✓ Core application binaries
✓ Standard configuration schema
✓ Public API interfaces
✓ Basic error handling
✓ OIDC authentication support

### What Should NEVER Be Included

✗ Proprietary algorithms
✗ Performance optimizations
✗ Internal metrics collectors
✗ Advanced caching logic
✗ Rate limiting implementations
✗ Custom feature flags
✗ Source code
✗ Build secrets

## Support & Licensing

### Customer Support

Customer distribution builds include:
- **Basic support only**
- **No updates** (static snapshot)
- **Evaluation purposes**
- **Time-limited trial** (if applicable)

### Production Licensing

For production use, customers must:
1. Purchase full license
2. Receive production builds with features
3. Get access to updates
4. Receive full support

## Make Commands Reference

```bash
# Build customer images
make build-customer                    # All services
make build-customer-platform           # Platform only
make build-customer-key-manager        # Key manager only
make build-customer-key-access         # Key access only
make build-customer-pap                # PAP only

# Run customer services
make docker-customer-up                # Start services
make docker-customer-down              # Stop services
make docker-customer-logs              # View logs
make docker-customer-ps                # Show containers

# Verification
make verify-customer                   # Show configuration

# Custom version
make build-customer CUSTOMER_VERSION=eval-2.0.0
```

## Example Distribution README

When distributing to customers, include a README like this:

```markdown
# Stratium Platform - Evaluation Version

## Quick Start

1. Load Docker images:
   ```bash
   docker load < stratium-platform-eval.tar.gz
   docker load < stratium-key-manager-eval.tar.gz
   docker load < stratium-key-access-eval.tar.gz
   docker load < stratium-pap-eval.tar.gz
   ```

2. Start services:
   ```bash
   docker-compose up -d
   ```

3. Access services:
   - Platform: localhost:50051 (gRPC)
   - Key Manager: localhost:50052 (gRPC)
   - Key Access: localhost:50053 (gRPC)
   - PAP API: http://localhost:8090

## Evaluation Limitations

This is an evaluation version with:
- ✓ Core functionality
- ✗ No metrics or monitoring
- ✗ No advanced features
- ✗ Basic support only
- ✗ No updates included

For production use, please contact sales@example.com
```

## See Also

- [Feature Flags Documentation](FEATURE_FLAGS.md)
- [Demo Builds](../deployment/README.demo.md)
- [Makefile Commands](MAKEFILE_DEMO.md)