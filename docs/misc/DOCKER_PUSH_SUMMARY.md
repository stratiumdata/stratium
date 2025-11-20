# Docker Hub Push Commands - Summary

## Overview

Added make commands to push customer distribution Docker images to Docker Hub (hub.docker.com).

## New Commands

### Push All Customer Images
```bash
make push-customer
```

Pushes all four customer images with three tags each:
- `:customer` - Main customer tag
- `:eval` - Evaluation tag
- `:${CUSTOMER_VERSION}` - Version tag (default: eval-1.0.0)

### Push Individual Services
```bash
make push-customer-platform      # Push platform service
make push-customer-key-manager   # Push key-manager service
make push-customer-key-access    # Push key-access service
make push-customer-pap           # Push pap service
```

## Configuration

### Docker Hub Organization
Default organization: `stratiumdata`

Override with:
```bash
make push-customer DOCKER_HUB_ORG=yourorg
```

### Version Tag
Default version: `eval-1.0.0`

Override with:
```bash
make push-customer CUSTOMER_VERSION=eval-2.0.0
```

## Complete Workflow

### 1. Build Customer Images
```bash
make build-customer
```

### 2. Verify Images
```bash
make verify-customer
docker images | grep stratium
```

### 3. Login to Docker Hub
```bash
docker login
# Enter your Docker Hub credentials
```

### 4. Push Images
```bash
# Push all images
make push-customer

# Or push individual services
make push-customer-platform
```

## What Gets Pushed

Each service is tagged and pushed with THREE tags:

### Platform Service
```
stratiumdata/platform:customer
stratiumdata/platform:eval
stratiumdata/platform:eval-1.0.0
```

### Key Manager Service
```
stratiumdata/key-manager:customer
stratiumdata/key-manager:eval
stratiumdata/key-manager:eval-1.0.0
```

### Key Access Service
```
stratiumdata/key-access:customer
stratiumdata/key-access:eval
stratiumdata/key-access:eval-1.0.0
```

### PAP Service
```
stratiumdata/pap:customer
stratiumdata/pap:eval
stratiumdata/pap:eval-1.0.0
```

## Image Characteristics

All pushed images:
- ✓ NO proprietary features
- ✓ NO feature flags enabled
- ✓ Core functionality only
- ✓ Safe for customer distribution
- ✓ Production-mode builds

## Customer Pull Instructions

Customers can pull images with:

```bash
# Pull latest customer images
docker pull stratiumdata/platform:customer
docker pull stratiumdata/key-manager:customer
docker pull stratiumdata/key-access:customer
docker pull stratiumdata/pap:customer

# Or pull specific version
docker pull stratiumdata/platform:eval-1.0.0
docker pull stratiumdata/key-manager:eval-1.0.0
docker pull stratiumdata/key-access:eval-1.0.0
docker pull stratiumdata/pap:eval-1.0.0

# Run services
docker run -p 50051:50051 stratiumdata/platform:customer
docker run -p 50052:50052 stratiumdata/key-manager:customer
docker run -p 50053:50053 stratiumdata/key-access:customer
docker run -p 8090:8090 stratiumdata/pap:customer
```

## Example Usage

### Build and Push for Customer Distribution

```bash
# 1. Build customer images
make build-customer CUSTOMER_VERSION=eval-2.0.0

# 2. Verify build
make verify-customer

# 3. Test locally
make docker-customer-up

# 4. Login to Docker Hub
docker login

# 5. Push to Docker Hub
make push-customer CUSTOMER_VERSION=eval-2.0.0

# 6. Verify on Docker Hub
# Visit https://hub.docker.com/r/stratiumdata/platform
```

### Push to Different Organization

```bash
# Build images
make build-customer

# Push to your organization
make push-customer DOCKER_HUB_ORG=mycompany

# Images will be pushed as:
# mycompany/platform:customer
# mycompany/key-manager:customer
# etc.
```

## Output Example

When running `make push-customer`:

```
Tagging and pushing platform-server customer image to Docker Hub...
✓ Platform customer image pushed

Tagging and pushing key-manager-server customer image to Docker Hub...
✓ Key Manager customer image pushed

Tagging and pushing key-access-server customer image to Docker Hub...
✓ Key Access customer image pushed

Tagging and pushing pap-server customer image to Docker Hub...
✓ PAP customer image pushed

✓ All customer images pushed to Docker Hub!

Images available at:
  https://hub.docker.com/r/stratiumdata/platform
  https://hub.docker.com/r/stratiumdata/key-manager
  https://hub.docker.com/r/stratiumdata/key-access
  https://hub.docker.com/r/stratiumdata/pap
```

## Prerequisites

- Docker Hub account
- Docker login completed (`docker login`)
- Customer images built (`make build-customer`)
- Appropriate push permissions for Docker Hub organization

## Security Notes

✓ **Safe to push**: These images contain NO proprietary features
✓ **No secrets**: No build secrets or credentials included
✓ **Public distribution**: Safe for public Docker Hub repositories
✓ **Version control**: Multiple tags for flexibility

## Troubleshooting

### "unauthorized: authentication required"
```bash
# Login to Docker Hub
docker login

# Verify credentials
docker info | grep Username
```

### "denied: requested access to the resource is denied"
```bash
# Check organization name
make push-customer DOCKER_HUB_ORG=stratiumdata

# Verify you have push permissions to the organization
```

### Images not found locally
```bash
# Build images first
make build-customer

# Verify images exist
docker images | grep stratium
```

## Make Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DOCKER_HUB_ORG` | `stratiumdata` | Docker Hub organization name |
| `CUSTOMER_VERSION` | `eval-1.0.0` | Version tag for images |
| `CUSTOMER_FEATURES` | `""` (empty) | Feature flags (always empty for customer builds) |

## See Also

- [Customer Distribution Guide](../CUSTOMER_DISTRIBUTION.md)
- [Feature Flags Documentation](../FEATURE_FLAGS.md)
- [Makefile Demo Commands](../MAKEFILE_DEMO.md)
