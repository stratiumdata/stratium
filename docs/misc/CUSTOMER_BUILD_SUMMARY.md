# Customer Distribution Build - Summary

## Overview

Added make commands to build Docker images with **NO feature flags** for safe distribution to potential customers without exposing proprietary features.

## New Make Commands

### Build Commands
- `make build-customer` - Build all services for customer distribution
- `make build-customer-platform` - Build platform customer image
- `make build-customer-key-manager` - Build key-manager customer image
- `make build-customer-key-access` - Build key-access customer image
- `make build-customer-pap` - Build pap customer image

### Run Commands
- `make docker-customer-up` - Start all services in customer mode
- `make docker-customer-down` - Stop customer services
- `make docker-customer-logs` - View logs from customer services
- `make docker-customer-ps` - Show running customer containers

### Verification
- `make verify-customer` - Show what's included/excluded in customer builds

## Key Features

### Build Configuration

```makefile
BUILD_MODE: production
BUILD_FEATURES: "" (empty - NO features)
BUILD_VERSION: eval-1.0.0 (customizable)
```

### What Customers Get ✓

- Core platform functionality
- Full logging (INFO level)
- Production timeouts (30s)
- Standard configuration
- OIDC authentication support

### What's Excluded ✗

- Advanced rate limiting
- Metrics collection
- Distributed tracing
- Performance optimizations
- Advanced caching
- Custom feature flags

## Usage Examples

### Build Customer Images

\`\`\`bash
make build-customer
\`\`\`

### Verify Configuration

\`\`\`bash
make verify-customer
\`\`\`

Output shows:
- What customers receive
- What's excluded (proprietary)
- Export instructions

### Export for Distribution

\`\`\`bash
# Save as compressed TAR files
docker save stratium/platform:customer | gzip > stratium-platform-eval.tar.gz
docker save stratium/key-manager:customer | gzip > stratium-key-manager-eval.tar.gz
docker save stratium/key-access:customer | gzip > stratium-key-access-eval.tar.gz
docker save stratium/pap:customer | gzip > stratium-pap-eval.tar.gz
\`\`\`

### Custom Version

\`\`\`bash
make build-customer CUSTOMER_VERSION=eval-2.0.0
\`\`\`

## Image Tags

Each service gets two tags:
- `stratium/service:customer`
- `stratium/service:eval`

Both point to the same image for flexibility in distribution.

## Comparison: Customer vs Demo vs Production

| Aspect | Customer | Demo | Production |
|--------|----------|------|------------|
| Mode | production | demo | production |
| Features | NONE | rate-limiting, short-timeouts | Custom |
| Logging | Full | Minimal | Full |
| Timeouts | 30s | 5s | 30s |
| Safe to Distribute | ✓ YES | Caution | NO |

## Distribution Workflow

1. **Build**: `make build-customer`
2. **Verify**: `make verify-customer`
3. **Test**: `make docker-customer-up`
4. **Export**: `docker save ... | gzip > ...`
5. **Package**: Create tarball with images + docker-compose
6. **Distribute**: Send to customer with README

## Security

✅ **Safe to distribute:**
- Core binaries (no proprietary code)
- Standard configuration
- Public APIs
- Basic functionality

❌ **Never included:**
- Proprietary features
- Source code
- Build secrets
- Advanced optimizations

## Files Created/Modified

1. **Makefile** - Added customer build targets
2. **docs/CUSTOMER_DISTRIBUTION.md** - Complete documentation

## See Also

- [Customer Distribution Guide](../CUSTOMER_DISTRIBUTION.md) - Full documentation
- [Feature Flags](../FEATURE_FLAGS.md) - Feature flag system
- [Demo Builds](../MAKEFILE_DEMO.md) - Demo build commands

