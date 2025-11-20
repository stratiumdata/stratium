# Stratium Platform Configuration Guide

This guide explains how to configure Stratium services using YAML files, environment variables, and command-line flags.

## Table of Contents

- [Overview](#overview)
- [Configuration Priority](#configuration-priority)
- [Configuration File Locations](#configuration-file-locations)
- [Configuration Structure](#configuration-structure)
- [Service Configuration](#service-configuration)
- [Environment Variables](#environment-variables)
- [Production Best Practices](#production-best-practices)
- [Examples](#examples)

## Overview

Stratium uses [Viper](https://github.com/spf13/viper) for configuration management, which provides a flexible and powerful way to configure services across different environments.

### Features

- **Multiple Sources**: Configuration can come from YAML files, environment variables, or command-line flags
- **Hot Reloading**: Configuration changes can be detected and applied without restart (when enabled)
- **Validation**: Built-in validation ensures configuration is correct before services start
- **Defaults**: Sensible defaults for all settings reduce configuration overhead
- **Security**: Sensitive values can be provided via environment variables or secret files

## Configuration Priority

Configuration values are resolved in the following order (highest to lowest priority):

1. **Command-line flags** (highest priority)
2. **Environment variables** (prefixed with `STRATIUM_`)
3. **Configuration file** (YAML)
4. **Default values** (lowest priority)

This allows you to:
- Use YAML files for static configuration
- Override with environment variables in containerized environments
- Temporarily override with flags during development

## Configuration File Locations

Stratium searches for configuration files in the following locations (in order):

1. `/etc/stratium/stratium.yaml` (system-wide)
2. `$HOME/.stratium/stratium.yaml` (user-specific)
3. `./config/stratium.yaml` (project config directory)
4. `./stratium.yaml` (current directory)

You can also specify a custom configuration file:

```bash
./pap-server --config /path/to/custom-config.yaml
```

## Configuration Structure

The configuration is organized into logical sections:

```yaml
service:          # Service identification
server:           # Server settings (ports, timeouts, TLS)
database:         # Database connection
cache:            # Caching configuration
encryption:       # Encryption settings
oidc:             # OIDC/OAuth2 authentication
services:         # Service discovery/connections
logging:          # Logging configuration
security:         # Security settings (rate limiting, CORS)
observability:    # Metrics and tracing
```

## Service Configuration

### Service Identity

```yaml
service:
  name: pap-server
  version: 1.0.0
  environment: production  # development, staging, or production
```

### Server Settings

```yaml
server:
  host: 0.0.0.0
  port: 8090
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 300s
  graceful_stop: 60s
  tls:
    enabled: true
    cert_file: /etc/stratium/certs/server.crt
    key_file: /etc/stratium/certs/server.key
    ca_file: /etc/stratium/certs/ca.crt
```

**Settings:**
- `host`: Interface to bind to (use `0.0.0.0` for all interfaces)
- `port`: Port to listen on
- `read_timeout`: Maximum time to read the entire request
- `write_timeout`: Maximum time to write the response
- `idle_timeout`: Maximum time to wait for the next request
- `graceful_stop`: Time allowed for graceful shutdown
- `tls.enabled`: Enable TLS/SSL
- `tls.cert_file`: Path to TLS certificate
- `tls.key_file`: Path to TLS private key
- `tls.ca_file`: Path to CA certificate for client verification

### Database Configuration

```yaml
database:
  driver: postgres
  host: postgres.example.com
  port: 5432
  database: stratium_pap
  user: stratium
  password: ""  # Set via STRATIUM_DATABASE_PASSWORD env var
  sslmode: require
  max_open_conns: 100
  max_idle_conns: 25
  conn_max_lifetime: 30m
  conn_max_idle_time: 10m
```

**Settings:**
- `driver`: Database driver (`postgres` is currently supported)
- `host`: Database server hostname
- `port`: Database server port
- `database`: Database name
- `user`: Database username
- `password`: Database password (prefer environment variable)
- `sslmode`: SSL mode (`disable`, `require`, `verify-ca`, `verify-full`)
- `max_open_conns`: Maximum number of open connections
- `max_idle_conns`: Maximum number of idle connections
- `conn_max_lifetime`: Maximum connection lifetime
- `conn_max_idle_time`: Maximum connection idle time

### Cache Configuration

```yaml
cache:
  type: redis  # memory or redis
  ttl: 10m
  max_size: 10000  # Only used for in-memory cache
  redis:
    address: redis.example.com:6379
    password: ""  # Set via STRATIUM_CACHE_REDIS_PASSWORD env var
    db: 0
    prefix: "stratium:policy:"
```

**Settings:**
- `type`: Cache type (`memory` for development, `redis` for production)
- `ttl`: Time-to-live for cached entries
- `max_size`: Maximum number of entries (in-memory only)
- `redis.address`: Redis server address
- `redis.password`: Redis password
- `redis.db`: Redis database number
- `redis.prefix`: Key prefix for namespacing

### Encryption Configuration

```yaml
encryption:
  algorithm: RSA4096
  key_rotation: true
  admin_key_provider: file  # env, file, or composite
  admin_key_config: /var/run/secrets/stratium/admin-key
  admin_keys:
    - admin
```

**Settings:**
- `algorithm`: Encryption algorithm to use. Available algorithms:

  **Post-Quantum Cryptography (KEM-based):**
  - `KYBER512` - Post-quantum key encapsulation (NIST Level 1)
  - `KYBER768` - Post-quantum key encapsulation (NIST Level 3, recommended)
  - `KYBER1024` - Post-quantum key encapsulation (NIST Level 5)

  **Classical RSA:**
  - `RSA2048` - RSA 2048-bit keys (default, minimum recommended)
  - `RSA3072` - RSA 3072-bit keys
  - `RSA4096` - RSA 4096-bit keys (high security)

  **Elliptic Curve Cryptography:**
  - `P256` - NIST P-256 curve (ECC_P256)
  - `P384` - NIST P-384 curve (ECC_P384)
  - `P521` - NIST P-521 curve (ECC_P521)

- `key_rotation`: Enable automatic key rotation
- `admin_key_provider`: Where to load admin keys from (`env`, `file`, or `composite`)
- `admin_key_config`: Path or configuration for admin key
- `admin_keys`: List of admin key identifiers

### OIDC Configuration

```yaml
oidc:
  enabled: true
  issuer_url: https://auth.example.com/realms/stratium
  client_id: stratium-platform
  client_secret: ""  # Set via STRATIUM_OIDC_CLIENT_SECRET env var
  redirect_url: https://stratium.example.com/callback
  scopes:
    - openid
    - profile
    - email
    - groups
```

**Settings:**
- `enabled`: Enable OIDC authentication
- `issuer_url`: OIDC provider URL
- `client_id`: OAuth2 client ID
- `client_secret`: OAuth2 client secret (prefer environment variable)
- `redirect_url`: OAuth2 redirect URL
- `scopes`: OAuth2 scopes to request

### Service Discovery

```yaml
services:
  platform:
    address: platform.example.com:50051
    timeout: 30s
    tls:
      enabled: true
      ca_file: /etc/stratium/certs/ca.crt
  key_manager:
    address: key-manager.example.com:50052
    timeout: 30s
    tls:
      enabled: true
      ca_file: /etc/stratium/certs/ca.crt
  key_access:
    address: key-access.example.com:50053
    timeout: 30s
    tls:
      enabled: true
      ca_file: /etc/stratium/certs/ca.crt
  pap:
    address: pap.example.com:8090
    timeout: 30s
    tls:
      enabled: true
      ca_file: /etc/stratium/certs/ca.crt
```

### Logging Configuration

```yaml
logging:
  level: info  # debug, info, warn, error
  format: json  # json or text
  output: stdout  # stdout, stderr, or file path
```

**Settings:**
- `level`: Log level (`debug`, `info`, `warn`, `error`)
- `format`: Log format (`json` for production, `text` for development)
- `output`: Where to write logs (`stdout`, `stderr`, or file path)

### Security Configuration

```yaml
security:
  rate_limiting:
    enabled: true
    requests_per_min: 100
    burst: 50
  cors:
    enabled: true
    allowed_origins:
      - https://stratium.example.com
    allowed_methods:
      - GET
      - POST
      - PUT
      - DELETE
      - OPTIONS
    allowed_headers:
      - Authorization
      - Content-Type
    expose_headers:
      - X-Request-ID
      - X-RateLimit-Remaining
    allow_credentials: true
    max_age: 3600s
```

**Settings:**
- `rate_limiting.enabled`: Enable rate limiting
- `rate_limiting.requests_per_min`: Maximum requests per minute per client
- `rate_limiting.burst`: Burst allowance
- `cors.enabled`: Enable CORS
- `cors.allowed_origins`: List of allowed origins for cross-origin requests
- `cors.allowed_methods`: List of allowed HTTP methods
- `cors.allowed_headers`: List of allowed HTTP headers that clients can send
- `cors.expose_headers`: List of headers that are safe to expose to the client (optional)
- `cors.allow_credentials`: Allow credentials (cookies, authorization headers) in CORS requests (default: false)
- `cors.max_age`: Maximum time browsers can cache preflight request results (default: 0s)

### Observability Configuration

```yaml
observability:
  metrics:
    enabled: true
    address: ":9090"
    path: /metrics
  tracing:
    enabled: true
    provider: jaeger  # jaeger, zipkin, or otlp
    endpoint: jaeger-collector.example.com:14268
    service_name: stratium-platform
```

**Settings:**
- `metrics.enabled`: Enable Prometheus metrics export
- `metrics.address`: Metrics server address
- `metrics.path`: Metrics endpoint path
- `tracing.enabled`: Enable distributed tracing
- `tracing.provider`: Tracing backend provider
- `tracing.endpoint`: Tracing backend endpoint
- `tracing.service_name`: Service name for tracing

## Environment Variables

All configuration values can be set via environment variables using the prefix `STRATIUM_` and replacing dots with underscores.

### Examples

| Configuration Key | Environment Variable |
|-------------------|---------------------|
| `server.port` | `STRATIUM_SERVER_PORT` |
| `database.host` | `STRATIUM_DATABASE_HOST` |
| `database.password` | `STRATIUM_DATABASE_PASSWORD` |
| `oidc.client_secret` | `STRATIUM_OIDC_CLIENT_SECRET` |
| `cache.redis.password` | `STRATIUM_CACHE_REDIS_PASSWORD` |
| `logging.level` | `STRATIUM_LOGGING_LEVEL` |

### Setting Environment Variables

```bash
# Bash/Shell
export STRATIUM_SERVER_PORT=8090
export STRATIUM_DATABASE_PASSWORD=my-secure-password
export STRATIUM_LOGGING_LEVEL=debug

# Docker
docker run -e STRATIUM_SERVER_PORT=8090 \
           -e STRATIUM_DATABASE_PASSWORD=my-secure-password \
           stratium/pap-server

# Docker Compose
environment:
  - STRATIUM_SERVER_PORT=8090
  - STRATIUM_DATABASE_PASSWORD=${DB_PASSWORD}

# Kubernetes
env:
  - name: STRATIUM_SERVER_PORT
    value: "8090"
  - name: STRATIUM_DATABASE_PASSWORD
    valueFrom:
      secretKeyRef:
        name: stratium-secrets
        key: database-password
```

## Production Best Practices

### 1. Use Configuration Files for Static Settings

Store non-sensitive, environment-specific settings in YAML files:

```yaml
# /etc/stratium/stratium.yaml
service:
  environment: production

server:
  port: 8090
  tls:
    enabled: true
    cert_file: /etc/stratium/certs/server.crt
    key_file: /etc/stratium/certs/server.key

database:
  host: postgres.example.com
  port: 5432
  database: stratium_pap
  sslmode: require
```

### 2. Use Environment Variables for Secrets

Never commit secrets to configuration files. Use environment variables:

```bash
export STRATIUM_DATABASE_PASSWORD=my-secure-password
export STRATIUM_OIDC_CLIENT_SECRET=oauth-client-secret
export STRATIUM_CACHE_REDIS_PASSWORD=redis-password
```

### 3. Enable TLS in Production

Always enable TLS for production deployments:

```yaml
server:
  tls:
    enabled: true
    cert_file: /etc/stratium/certs/server.crt
    key_file: /etc/stratium/certs/server.key
    ca_file: /etc/stratium/certs/ca.crt
```

### 4. Use Redis for Caching

Use Redis instead of in-memory cache for production:

```yaml
cache:
  type: redis
  redis:
    address: redis.example.com:6379
    password: ""  # Set via STRATIUM_CACHE_REDIS_PASSWORD
```

### 5. Enable Observability

Enable metrics and tracing for production monitoring:

```yaml
observability:
  metrics:
    enabled: true
    address: ":9090"
  tracing:
    enabled: true
    provider: jaeger
    endpoint: jaeger-collector.example.com:14268
```

### 6. Configure Rate Limiting

Protect your services with rate limiting:

```yaml
security:
  rate_limiting:
    enabled: true
    requests_per_min: 100
    burst: 50
```

### 7. Use Structured Logging

Use JSON logging for production:

```yaml
logging:
  level: info
  format: json
  output: stdout
```

### 8. Configure Proper Timeouts

Set appropriate timeouts for your environment:

```yaml
server:
  read_timeout: 30s
  write_timeout: 30s
  idle_timeout: 300s
  graceful_stop: 60s
```

## Examples

### Development Configuration

See [config/examples/stratium-development.yaml](../config/examples/stratium-development.yaml)

```yaml
service:
  environment: development

server:
  port: 50051
  tls:
    enabled: false

database:
  host: localhost
  password: stratium
  sslmode: disable

cache:
  type: memory

logging:
  level: debug
  format: text
```

### Production Configuration

See [config/examples/stratium-production.yaml](../config/examples/stratium-production.yaml)

```yaml
service:
  environment: production

server:
  port: 50051
  tls:
    enabled: true
    cert_file: /etc/stratium/certs/server.crt
    key_file: /etc/stratium/certs/server.key

database:
  host: postgres.example.com
  password: ""  # Set via environment variable
  sslmode: require

cache:
  type: redis
  redis:
    address: redis.example.com:6379

logging:
  level: info
  format: json

observability:
  metrics:
    enabled: true
  tracing:
    enabled: true
```

### Service-Specific Configurations

- **PAP Server**: [config/examples/pap-server.yaml](../config/examples/pap-server.yaml)
- **Key Manager**: [config/examples/key-manager.yaml](../config/examples/key-manager.yaml)

## Configuration Validation

Stratium validates configuration on startup and will fail fast if there are issues:

- Required fields are missing
- Invalid values (e.g., port out of range)
- TLS enabled but certificate files missing
- OIDC enabled but required fields missing

Example validation error:

```
Error: invalid configuration: oidc.issuer_url is required when OIDC is enabled
```

## Migrating from Legacy Configuration

If you're upgrading from an older version that used only environment variables:

1. **Backward Compatible**: The new config system is backward compatible with environment variables
2. **Gradual Migration**: You can gradually move settings to YAML files
3. **Same Environment Variables**: All existing environment variables still work
4. **Enhanced Features**: New features (TLS, caching, observability) are now available

### Example Migration

**Before (environment variables only):**
```bash
export PORT=8090
export DATABASE_URL=postgres://user:pass@localhost/db
export OIDC_ISSUER_URL=http://localhost:8080/realms/stratium
```

**After (YAML + environment variables):**
```yaml
# stratium.yaml
server:
  port: 8090

database:
  host: localhost
  database: stratium_pap
  user: stratium
  # Password from environment variable

oidc:
  enabled: true
  issuer_url: http://localhost:8080/realms/stratium
  # Client secret from environment variable
```

```bash
# Only secrets in environment variables
export STRATIUM_DATABASE_PASSWORD=secure-password
export STRATIUM_OIDC_CLIENT_SECRET=oauth-secret
```

## Getting Help

- See example configurations in `config/examples/`
- Check service logs for configuration validation errors
- Refer to the [Viper documentation](https://github.com/spf13/viper) for advanced features

## License

Copyright © 2025 Stratium Data