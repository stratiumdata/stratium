# Makefile Demo Build Commands

Quick reference for building and running Stratium demo images using Make.

## Quick Start

```bash
# Show all available commands
make help

# Build all demo images
make build-demo

# Run demo services
make docker-demo-up

# Stop demo services
make docker-demo-down
```

## Available Demo Commands

### Building Demo Images

Build all services with demo feature flags:
```bash
make build-demo
```

Build individual services:
```bash
make build-demo-platform      # Build platform-server demo image
make build-demo-key-manager   # Build key-manager-server demo image
make build-demo-key-access    # Build key-access-server demo image
make build-demo-pap           # Build pap-server demo image
```

### Running Demo Services

Start all services in demo mode:
```bash
make docker-demo-up
```

This will:
- Build all demo images with feature flags
- Start all services using docker-compose
- Show demo mode configuration

Stop demo services:
```bash
make docker-demo-down
```

View logs from demo services:
```bash
make docker-demo-logs
```

View running demo containers:
```bash
make docker-demo-ps
```

### Testing & Verification

Run feature flag tests:
```bash
make test-features
```

Show demo build configuration:
```bash
make verify-demo
```

Output:
```
═══════════════════════════════════════════
  Stratium Demo Build Configuration
═══════════════════════════════════════════

Build Settings:
  Mode:     demo
  Version:  demo-1.0.0
  Features: rate-limiting,short-timeouts

Feature Details:
  ✓ Minimal Logging
    - Only STARTUP messages shown
    - No INFO/DEBUG/WARN logs

  ✓ Rate Limiting
    - key-access-server:  4 requests/minute
    - key-manager-server: 10 requests/minute
    - Other services: default limits

  ✓ Short Timeouts
    - Server: 5s read, 5s write, 30s idle
    - Client: 3s per service call

  ✗ Metrics: DISABLED
  ✗ Observability/Tracing: DISABLED

═══════════════════════════════════════════
```

## Customizing Build

Override build version:
```bash
make build-demo BUILD_VERSION=demo-2.0.0
```

Override demo features:
```bash
make build-demo DEMO_FEATURES=rate-limiting
```

## Comparison: Production vs Demo

### Production Build
```bash
# Build production images (default configuration)
make docker-build

# Run production services
make docker-up
```

Features:
- Full logging (all levels)
- Standard timeouts (30s)
- Metrics and observability available (opt-in)
- Standard rate limits

### Demo Build
```bash
# Build demo images
make build-demo

# Run demo services
make docker-demo-up
```

Features:
- Minimal logging (startup only)
- Short timeouts (5s)
- No metrics or observability
- Strict rate limits (4 req/min for key-access, 10 req/min for key-manager)

## Development Workflow

Typical demo development workflow:

```bash
# 1. Verify demo configuration
make verify-demo

# 2. Run feature flag tests
make test-features

# 3. Build all demo images
make build-demo

# 4. Start demo services
make docker-demo-up

# 5. In another terminal, view logs
make docker-demo-logs

# 6. Test rate limiting
# Run 5 requests to key-access quickly - 5th should fail

# 7. Stop services when done
make docker-demo-down
```

## Troubleshooting

### Demo images not updating
Try building without cache:
```bash
docker build --no-cache \
  --build-arg BUILD_MODE=demo \
  --build-arg BUILD_FEATURES=rate-limiting,short-timeouts \
  -f deployment/Dockerfile .
```

Or use docker-compose:
```bash
docker-compose -f deployment/docker-compose.yml \
  -f deployment/docker-compose.demo.yml \
  up --build --force-recreate
```

### Feature flags not working
Verify feature flags were injected:
```bash
# Check container logs for startup messages
make docker-demo-logs | grep "Build Mode"
```

Should show:
```
STARTUP: Build Mode: demo
STARTUP: Enabled Features: [rate-limiting short-timeouts]
```

### Rate limiting not triggering
Ensure you're making requests to the correct service:
```bash
# Test key-access-server (4 req/min limit)
for i in {1..5}; do
  echo "Request $i:"
  grpcurl -plaintext localhost:50053 list
  sleep 1
done
```

The 5th request should be rate limited.

## See Also

- [Feature Flags Documentation](FEATURE_FLAGS.md) - Complete feature flag reference
- [Demo README](../deployment/README.demo.md) - Docker-specific demo guide
- Main [Makefile](../Makefile) - Full Makefile source
