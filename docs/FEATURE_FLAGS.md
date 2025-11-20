# Feature Flags and Demo Builds

This document describes the feature flag system implemented in Stratium using Go ldflags.

## Overview

Stratium now supports building Docker images with feature flags that can be configured at build time using ldflags. This allows creating minimal "demo" builds with restricted capabilities suitable for demonstrations and local development.

## Feature Flags

The following features can be controlled via build-time flags:

### 1. Logging (`full-logging`)
- **Default (production)**: Full logging with all levels (DEBUG, INFO, WARN, ERROR)
- **Demo mode**: Minimal logging showing only STARTUP messages
- **Purpose**: Reduce log noise in demo environments

### 2. Metrics (`metrics`)
- **Default (production)**: Metrics disabled (explicit opt-in required)
- **Demo mode**: Metrics completely disabled
- **Purpose**: Eliminate metrics collection overhead in demos

### 3. Observability (`observability`)
- **Default (production)**: Tracing disabled (explicit opt-in required)
- **Demo mode**: All observability/tracing disabled
- **Purpose**: Simplify demo deployments

### 4. Rate Limiting (`rate-limiting`)
- **Default (production)**: Standard rate limits (100 req/min)
- **Demo mode**: Service-specific strict limits:
  - **key-access-server**: 4 requests/minute (burst: 1)
  - **key-manager-server**: 10 requests/minute (burst: 2)
  - **Other services**: Feature flag controlled
- **Purpose**: Demonstrate rate limiting behavior and prevent abuse

### 5. Caching (`caching`)
- **Default (all modes)**: NO caching (disabled by default)
- **When enabled**: Full caching capabilities:
  - In-memory caching with configurable TTL
  - Redis-backed distributed caching
  - Configurable cache sizes and eviction policies
- **Purpose**: Proprietary caching optimizations not included in customer distributions

### 6. Short Timeouts (`short-timeouts`)
- **Default (production)**: Standard timeouts (30s read, 30s write, 120s idle)
- **Demo mode**: Short timeouts:
  - Server: 5s read, 5s write, 30s idle, 5s graceful stop
  - Client: 3s per service call
- **Purpose**: Suitable for local/demo environments, not production-ready

## Build Modes

### Production Mode (default)
```bash
docker build \
  --build-arg BUILD_MODE=production \
  --build-arg BUILD_FEATURES="" \
  -t stratium/service:prod .
```

### Demo Mode
```bash
docker build \
  --build-arg BUILD_MODE=demo \
  --build-arg BUILD_FEATURES="rate-limiting,short-timeouts" \
  --build-arg BUILD_VERSION="demo-1.0.0" \
  -t stratium/service:demo .
```

## Using Docker Compose

### Standard Production Build
```bash
docker-compose up --build
```

### Demo Build
```bash
docker-compose -f docker-compose.yml -f docker-compose.demo.yml up --build
```

## Implementation Details

### Feature Flag Package (`go/features/`)
- `features.go`: Core feature flag logic with ldflags injection points
- `features_test.go`: Comprehensive test suite

### Configuration Integration (`go/config/config.go`)
- `applyFeatureFlags()`: Applies feature flag overrides to configuration
- `ApplyServiceSpecificRateLimits()`: Service-specific rate limit configuration

### Logging Package (`go/logging/`)
- `logger.go`: Logging wrapper with feature flag support
- Respects `ShouldEnableFullLogging()` feature flag
- Special `Startup` level always visible

### Rate Limiting Middleware (`go/middleware/`)
- `ratelimit.go`: gRPC interceptor for rate limiting
- Token bucket algorithm using `golang.org/x/time/rate`
- Per-client IP tracking
- Logs when rate limits are exceeded with next available time

## Build Variables

The following variables are injected via ldflags during build:

```go
// In go/features/features.go
var (
    BuildMode     = "production"  // demo, production, development
    BuildFeatures = ""             // comma-separated feature list
    BuildVersion  = "dev"          // version string
    BuildTime     = "unknown"      // build timestamp
)
```

## Dockerfile Integration

The Dockerfile has been updated to accept build arguments and pass them via ldflags:

```dockerfile
ARG BUILD_MODE=production
ARG BUILD_FEATURES=""
ARG BUILD_VERSION=dev

RUN CGO_ENABLED=0 GOOS=linux go build \
    -a -installsuffix cgo \
    -ldflags="-w -s \
    -X 'stratium/features.BuildMode=${BUILD_MODE}' \
    -X 'stratium/features.BuildFeatures=${BUILD_FEATURES}' \
    -X 'stratium/features.BuildVersion=${BUILD_VERSION}' \
    -X 'stratium/features.BuildTime=$(date -u +"%Y-%m-%dT%H:%M:%SZ")'" \
    -o /app/bin/${SERVICE_NAME} \
    ./cmd/${SERVICE_NAME}
```

## Server Updates

Each server's `main.go` has been updated to:

1. Import `stratium/logging` and `stratium/middleware`
2. Initialize feature-aware logger
3. Print build info at startup
4. Apply service-specific rate limits
5. Add rate limiting interceptors to gRPC server
6. Use new logging system throughout

### Example (key-access-server)

```go
func main() {
    logger := logging.GetLogger()
    cfg, err := config.Load(*configFile)

    // Apply service-specific rate limits (4 req/min for key-access)
    config.ApplyServiceSpecificRateLimits(cfg, ServiceName)

    // Print build and feature info
    logger.PrintBuildInfo(ServiceName, ServiceVersion)

    // Create rate limiter
    rateLimiter := middleware.NewRateLimiter(cfg)
    rateLimiter.PrintRateLimitInfo(ServiceName)

    // Create gRPC server with interceptors
    grpcServer := grpc.NewServer(
        grpc.ChainUnaryInterceptor(
            rateLimiter.UnaryServerInterceptor(),
            authInterceptor,
        ),
    )

    // ... rest of server setup
}
```

## Testing

### Unit Tests
```bash
# Test feature flags package
go test ./features/... -v

# Test logging package
go test ./logging/... -v
```

### Integration Test
```bash
# Build and run demo services
docker-compose -f docker-compose.yml -f docker-compose.demo.yml up --build

# Verify rate limiting on key-access-server (should allow 4 req/min)
# Run 5 quick requests - the 5th should fail

# Verify minimal logging - only STARTUP messages should appear
```

## Benefits

1. **Demo Safety**: Rate limits prevent runaway demo scenarios
2. **Resource Efficiency**: Minimal logging and no metrics reduce overhead
3. **Clear Intent**: Build mode explicitly shows deployment purpose
4. **Flexibility**: Can mix and match features as needed
5. **Zero Runtime Overhead**: Feature checks compiled in, no runtime cost

## Future Enhancements

Potential additions to the feature flag system:

- **Authentication modes**: Mock vs real OIDC
- **Storage backends**: In-memory vs persistent
- **API features**: Enable/disable specific endpoints
- **Compliance modes**: Different regulatory requirement sets