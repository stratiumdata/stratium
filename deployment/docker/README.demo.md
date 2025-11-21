# Building and Running Demo Images

This guide explains how to build and run Stratium services in demo mode with feature flags. All commands assume you are in `deployment/docker`.

## Quick Start

### Build and Run Demo Services
```bash
cd deployment/docker
docker-compose -f docker-compose.yml -f docker-compose.demo.yml up --build
```

This will build all services with:
- **Minimal logging** (startup messages only)
- **No metrics** collection
- **No observability/tracing**
- **Rate limiting enabled**:
  - key-access-server: 4 requests/minute
  - key-manager-server: 10 requests/minute
- **Short timeouts** (5s server, 3s client)

## Build Individual Demo Service

```bash
docker build \
  --build-arg SERVICE_NAME=key-access-server \
  --build-arg SERVICE_PORT=50053 \
  --build-arg BUILD_MODE=demo \
  --build-arg BUILD_FEATURES="rate-limiting,short-timeouts" \
  --build-arg BUILD_VERSION="demo-1.0.0" \
  -t stratium/key-access:demo \
  -f Dockerfile \
  ..
```

## Build Production Service (Default)

```bash
docker build \
  --build-arg SERVICE_NAME=key-access-server \
  --build-arg SERVICE_PORT=50053 \
  --build-arg BUILD_MODE=production \
  -t stratium/key-access:prod \
  -f Dockerfile \
  ..
```

## Available Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `BUILD_MODE` | `production` | Build mode: `demo`, `production`, `development` |
| `BUILD_FEATURES` | `""` | Comma-separated features (see below) |
| `BUILD_VERSION` | `dev` | Version string for the build |
| `SERVICE_NAME` | required | Service to build (e.g., `key-access-server`) |
| `SERVICE_PORT` | required | Port the service listens on |

## Available Feature Flags

| Feature | Effect when Enabled |
|---------|---------------------|
| `rate-limiting` | Enable strict rate limits per service |
| `short-timeouts` | Use short timeouts (5s server, 3s client) |
| `full-logging` | Enable full logging (default in production) |
| `metrics` | Enable Prometheus metrics collection |
| `observability` | Enable tracing (Jaeger/Zipkin/OTLP) |

## Demo Mode Defaults

When `BUILD_MODE=demo`:
- Logging automatically switches to minimal (startup only)
- Metrics disabled by default
- Observability disabled by default
- Short timeouts if `short-timeouts` feature is enabled

## Testing Rate Limiting

### Test key-access-server (4 req/min limit)

```bash
# This should succeed
grpcurl -plaintext localhost:50053 list

# Run 5 times quickly - the 5th call should be rate limited
for i in {1..5}; do
  echo "Request $i:"
  grpcurl -plaintext localhost:50053 stratium.keyaccess.v1.KeyAccessService/WrapDEK
  sleep 1
done
```

Expected output on 5th request:
```
ERROR:
  Code: ResourceExhausted
  Message: rate limit exceeded. Try again in 14s (at 10:30:45)
```

### Test key-manager-server (10 req/min limit)

```bash
# Run 11 times quickly - the 11th call should be rate limited
for i in {1..11}; do
  echo "Request $i:"
  grpcurl -plaintext localhost:50052 list
  sleep 1
done
```

## Verifying Build Info

Each service logs its build information at startup:

```
STARTUP: =================================================
STARTUP: Service: key-access-server v1.0.0
STARTUP: Build Mode: demo
STARTUP: Build Version: demo-1.0.0
STARTUP: Build Time: 2025-01-15T10:00:00Z
STARTUP: Enabled Features: [rate-limiting short-timeouts]
STARTUP: Full Logging: false
STARTUP: Metrics: false
STARTUP: Observability: false
STARTUP: Rate Limiting: true
STARTUP: Short Timeouts: true
STARTUP: =================================================
STARTUP: Rate limiting: ENABLED - 4 requests/min (burst: 1) for key-access-server
STARTUP: Average time between allowed requests: 15s
```

## Stopping Services

```bash
# Stop and remove containers
docker-compose -f docker-compose.yml -f docker-compose.demo.yml down

# Stop and remove containers + volumes
docker-compose -f docker-compose.yml -f docker-compose.demo.yml down -v
```

## Troubleshooting

### Logs show INFO/DEBUG messages in demo mode
- Check build logs to ensure `BUILD_MODE=demo` was set
- Verify feature flags by checking startup logs
- Rebuild with `--no-cache` if needed

### Rate limiting not working
- Ensure `BUILD_FEATURES` includes `rate-limiting`
- Check startup logs for "Rate limiting: ENABLED"
- Verify requests are coming from same client IP

### Timeouts too short/long
- Demo mode: Controlled by `short-timeouts` feature flag
- Production mode: Uses standard 30s timeouts
- Can override via config files or environment variables
