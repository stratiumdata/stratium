# Caching Layer - Implementation Guide

## Overview

The Platform Service now includes a comprehensive caching layer for policy decisions, supporting both in-memory and Redis-based distributed caching. This improves performance by reducing database queries and policy evaluation overhead.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    PAP API Service                          │
│  (Policy Administration)                                    │
│                                                             │
│  Create/Update/Delete Policy                                │
│         │                                                   │
│         ├─► Save to PostgreSQL                             │
│         └─► Invalidate Redis Cache                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ Cache Invalidation
                            ▼
                    ┌──────────────┐
                    │    Redis     │
                    │   (Cache)    │
                    └──────────────┘
                            ▲
                            │ Read/Write
                            │
┌─────────────────────────────────────────────────────────────┐
│              Platform Service (PDP)                         │
│                                                             │
│  GetDecision Request                                        │
│         │                                                   │
│         ├─► Check Redis Cache                              │
│         │       └─► Cache Hit: Return cached policy        │
│         │       └─► Cache Miss: Query PostgreSQL           │
│         │                  └─► Store in Redis Cache        │
│         └─► Evaluate Policy                                │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. Cache Interface (`services/platform/cache.go`)

Two cache implementations:

#### InMemoryPolicyCache
- Simple in-memory cache using a Go map
- Thread-safe with RWMutex
- No TTL support (cache lives until process restart)
- Best for single-instance deployments or development

#### RedisPolicyCache
- Distributed cache using Redis
- Supports TTL (configurable via `service.policy_cache_ttl_seconds`, default fallback 1 hour)
- Thread-safe by design (Redis handles concurrency)
- Best for production multi-instance deployments

**Interface:**
```go
type PolicyCache interface {
    Get(ctx context.Context, key string) (*models.Policy, bool)
    Set(ctx context.Context, key string, policy *models.Policy, ttl time.Duration) error
    Invalidate(ctx context.Context, key string) error
    Clear(ctx context.Context) error
}
```

### 2. Cache Invalidator (`pkg/cache/cache.go`)

Used by PAP API to invalidate cache when policies are modified:

#### RedisCacheInvalidator
- Connects to Redis to invalidate cached policies
- Invalidates specific policies by ID
- Can clear all policies in cache

#### NoOpCacheInvalidator
- Does nothing (for in-memory cache or when caching is disabled)

**Interface:**
```go
type CacheInvalidator interface {
    InvalidatePolicy(ctx context.Context, policyID string) error
    InvalidateAllPolicies(ctx context.Context) error
    Close() error
}
```

### 3. Platform Service Integration

**Policy Decision Point** (`services/platform/pdp.go`):
- Accepts a PolicyCache instance
- Currently fetches fresh policy list from DB (can be optimized to cache policy lists)
- Individual policies can be cached by ID

**Cache Constructors:**
```go
// Default: in-memory cache
pdp := platform.NewPolicyDecisionPoint(repo)

// Custom cache (e.g., Redis)
cache := platform.NewRedisPolicyCache(config)
pdp := platform.NewPolicyDecisionPointWithCache(repo, cache)
```

### 4. PAP API Integration

**Cache Invalidation** (`services/pap/policy_handlers.go`):
- Automatically invalidates cache on policy create/update/delete
- Invalidates specific policy by ID
- Also invalidates "all policies" cache to ensure fresh lists

**Server Constructors:**
```go
// Default: no-op cache invalidator
server := pap.NewServer(repo, authService)

// With cache invalidator
server := pap.NewServerWithCacheInvalidator(repo, authService, cacheInvalidator)
```

## Configuration

### Environment Variables

#### Platform Service (PDP)

| Variable | Default | Description |
|----------|---------|-------------|
| CACHE_TYPE | memory | Cache type: `redis` or `memory` |
| REDIS_ADDR | localhost:6379 | Redis server address |
| REDIS_PASSWORD | (empty) | Redis password (if required) |
| REDIS_DB | 0 | Redis database number |
| SERVICE_POLICY_CACHE_TTL_SECONDS | 5 | TTL for PDP in-memory cache and Redis entries |

#### PAP API Service

| Variable | Default | Description |
|----------|---------|-------------|
| CACHE_TYPE | memory | Cache type for invalidation |
| REDIS_ADDR | localhost:6379 | Redis server address |
| REDIS_PASSWORD | (empty) | Redis password (if required) |
| REDIS_DB | 0 | Redis database number |

### Command-Line Flags (Platform Service)

```bash
./platform-server --help

Flags:
  -cache-type string
        Cache type: 'redis' or 'memory' (if empty, uses CACHE_TYPE env var, default: memory)
  -redis-addr string
        Redis address (if empty, uses REDIS_ADDR env var)
```

### Docker Compose

Redis service is automatically configured in `deployment/docker/docker-compose.yml`:

```yaml
redis:
  image: redis:7-alpine
  container_name: stratium-redis
  ports:
    - "6379:6379"
  networks:
    - stratium-network
```

Both Platform and PAP services are configured with Redis environment variables and depend on Redis being healthy.

## Usage

### Development (In-Memory Cache)

```bash
# Platform Service
export CACHE_TYPE=memory
./platform-server

# PAP API
export CACHE_TYPE=memory
./pap-server
```

### Production (Redis Cache)

```bash
# Start Redis
docker-compose up -d redis

# Platform Service
export CACHE_TYPE=redis
export REDIS_ADDR=localhost:6379
./platform-server

# PAP API
export CACHE_TYPE=redis
export REDIS_ADDR=localhost:6379
./pap-server
```

### Docker Compose (Default Configuration)

```bash
# Start all services with Redis caching enabled
docker-compose up -d
```

The default configuration in docker-compose.yml uses Redis caching for both Platform and PAP services.

## Cache Invalidation Flow

1. **Policy Created** via PAP API:
   - Policy saved to PostgreSQL
   - `InvalidateAllPolicies()` called
   - All cached policy lists are cleared
   - Next PDP request will fetch fresh policies

2. **Policy Updated** via PAP API:
   - Policy updated in PostgreSQL
   - `InvalidatePolicy(policyID)` called
   - Specific policy removed from cache
   - `InvalidateAllPolicies()` also called
   - Next PDP request will fetch fresh policy

3. **Policy Deleted** via PAP API:
   - Policy deleted from PostgreSQL
   - `InvalidatePolicy(policyID)` called
   - `InvalidateAllPolicies()` also called
   - Next PDP request will fetch fresh policies

## Performance Optimization

### Current Implementation

- Cache key format: `stratium:policy:{policy-id}`
- Default TTL: 1 hour
- Cache invalidation on policy changes
- No pre-warming or background refresh

### Future Enhancements

1. **Policy List Caching**
   - Cache the list of enabled policies with shorter TTL
   - Reduces database queries on every decision request

2. **Pre-compiled Policies**
   - Pre-compile OPA policies when loaded
   - Store compiled policies in cache

3. **Cache Pre-warming**
   - Load frequently used policies on startup
   - Background task to refresh cache before TTL expires

4. **Metrics & Monitoring**
   - Cache hit/miss ratio
   - Cache size and memory usage
   - Invalidation frequency

5. **Adaptive TTL**
   - Longer TTL for stable policies
   - Shorter TTL for frequently changing policies

## Testing

### Manual Testing

```bash
# Create a policy
TOKEN=$(./scripts/get_token.sh admin456 admin123 | tail -1)
curl -X POST http://localhost:8090/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-cache-policy",
    "language": "opa",
    "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
    "effect": "allow",
    "enabled": true
  }'

# Test decision (first request - cache miss)
grpcurl -plaintext -d '{
  "subject": "admin456",
  "resource": "test-resource",
  "action": "read",
  "context": {"role": "admin"}
}' localhost:50051 platform.PlatformService/GetDecision

# Test decision (second request - cache hit)
grpcurl -plaintext -d '{
  "subject": "admin456",
  "resource": "test-resource",
  "action": "read",
  "context": {"role": "admin"}
}' localhost:50051 platform.PlatformService/GetDecision

# Update the policy (invalidates cache)
curl -X PUT http://localhost:8090/api/v1/policies/{policy-id} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled": false}'

# Test decision (cache miss again after invalidation)
grpcurl -plaintext -d '{
  "subject": "admin456",
  "resource": "test-resource",
  "action": "read",
  "context": {"role": "admin"}
}' localhost:50051 platform.PlatformService/GetDecision
```

### Verify Redis Cache

```bash
# Connect to Redis
docker-compose exec redis redis-cli

# List all policy cache keys
KEYS stratium:policy:*

# Get a specific policy
GET stratium:policy:{policy-id}

# Check TTL
TTL stratium:policy:{policy-id}

# Clear all cache
FLUSHDB
```

## Troubleshooting

### Redis Connection Failed

**Symptom**: "Warning: Failed to initialize Redis cache"

**Causes**:
- Redis not running
- Incorrect Redis address
- Network issues

**Solution**:
```bash
# Check Redis is running
docker-compose ps redis

# Test Redis connection
redis-cli -h localhost -p 6379 ping

# Check Platform logs
docker-compose logs platform | grep "Redis"
```

### Cache Not Invalidating

**Symptom**: Old policy values persist after updates

**Causes**:
- PAP and Platform using different Redis instances
- Cache type mismatch (one using memory, other using Redis)
- Different cache key prefixes

**Solution**:
```bash
# Verify configuration
docker-compose exec platform env | grep CACHE
docker-compose exec pap env | grep CACHE

# Manually clear Redis cache
docker-compose exec redis redis-cli FLUSHDB
```

### High Memory Usage

**Symptom**: Redis using too much memory

**Causes**:
- Large policies being cached
- Too many policies
- TTL too long

**Solution**:
```bash
# Check Redis memory usage
docker-compose exec redis redis-cli INFO memory

# Set memory limit in docker-compose.yml
redis:
  mem_limit: 256m

# Reduce TTL (modify cache.go)
# Default: 1 hour → 15 minutes
```

## Security Considerations

1. **Redis Authentication**
   - Set REDIS_PASSWORD in production
   - Use Redis ACLs for fine-grained access control

2. **Network Security**
   - Keep Redis on internal network only
   - Use TLS for Redis connections in production

3. **Cache Poisoning**
   - Validate data before caching
   - Use signed cache keys
   - Implement cache integrity checks

4. **Data Sensitivity**
   - Policies may contain sensitive rules
   - Consider encrypting cached data
   - Set appropriate TTLs for sensitive policies

## References

- [Platform PDP Integration](./PLATFORM_PDP_INTEGRATION.md)
- [PAP API Guide](./PAP_API_GUIDE.md)
- [Redis Documentation](https://redis.io/documentation)
- [go-redis Client](https://github.com/redis/go-redis)
