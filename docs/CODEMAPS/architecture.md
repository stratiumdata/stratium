<!-- Generated: 2026-03-28 | Service Architecture | Files scanned: 275 Go | Token estimate: ~980 -->

# Stratium Architecture Codemap

**Last Updated:** 2026-03-28

## System Overview

Stratium is a Zero-Trust Data Format (ZTDF) cryptographic key management platform with Attribute-Based Access Control (ABAC). The system uses a distributed microservice architecture with gRPC/mTLS inter-service communication and PostgreSQL as the primary data store.

## Service Boundaries

```
┌──────────────────────────────────────────────────────────────┐
│                      Client SDKs                              │
│         (Go / Java / Python / JavaScript)                     │
└────────────────────┬─────────────────────────────────────────┘
                     │
         ┌───────────┼───────────┬──────────────────┐
         │           │           │                  │
    ┌────▼──────┐ ┌──▼──────┐ ┌─▼─────────┐ ┌─────▼──────┐
    │ Platform  │ │Key Mgr  │ │Key Access │ │PAP Server  │
    │Server     │ │Server   │ │Service    │ │(entitlems) │
    │(gRPC:50051)│ │(gRPC:50052)│(gRPC:50053)│(REST:8080) │
    │           │ │         │ │           │ │            │
    │• GetDecision
    │• Entitlements
    │• ABAC PDP  │ │• KEK Mgmt
    │           │ │• DEK Unwrap
    │           │ │• Key Rotate │• WrapDEK  │ │• Policies  │
    │           │ │         │ │• UnwrapDEK│ │• Entitle.  │
    │           │ │• HSM/Smart
    │           │ │  Card Supp. │• Crypto Op │            │
    └────┬──────┘ └──┬──────┘ └─┬─────────┘ └─────┬──────┘
         │           │         │               │
         └───────────┼─────────┼───────────────┘
                     │
            ┌────────▼──────────┐
            │  PostgreSQL       │
            │  (ZTDF Metadata)  │
            │  (Policies)       │
            │  (Entitlements)   │
            │  (Key Metadata)   │
            └───────────────────┘
```

## Service Details

### Platform Service (`:50051`)
**File**: `/Users/benjaminparrish/Development/stratium/go/services/platform/`

Entry point: `/Users/benjaminparrish/Development/stratium/go/cmd/platform-server/main.go`

Core interfaces:
- `PlatformService.GetDecision()` - Evaluates ABAC policies
- `PlatformService.GetEntitlements()` - Returns subject entitlements

Key components:
- `PolicyDecisionPoint` - Policy evaluation engine (uses OPA/Rego)
- `HierarchyMatcher` - Hierarchical classification matching (NATO/DoD/Commercial)
- `EntitlementManager` - Subject entitlement evaluation

### Key Manager Service (`:50052`)
**File**: `/Users/benjaminparrish/Development/stratium/go/services/key-manager/`

Entry point: `/Users/benjaminparrish/Development/stratium/go/cmd/key-manager-server/main.go`

Core interfaces:
- `KeyManagerService.UnwrapDEK()` - Unwrap Data Encryption Keys
- `KeyManagerService.RegisterClientKey()` - Register user public keys
- `KeyManagerService.RotateKey()` - Key rotation management

Key components:
- `KeyStore` - PostgreSQL-backed encrypted key storage
- `ProviderFactory` - Creates key providers (Software/HSM/SmartCard)
- `DEKUnwrappingService` - Handles DEK decryption
- `KeyRotationManager` - Manages key lifecycle

Crypto algorithms:
- KYBER-512/768/1024 (post-quantum KEM)
- RSA-2048/3072/4096 (classical)
- ECC P-256/P-384/P-521 (elliptic curve)
- AES-256-GCM (symmetric encryption)

### Key Access Service (`:50053`)
**File**: `/Users/benjaminparrish/Development/stratium/go/services/key-access/`

Entry point: `/Users/benjaminparrish/Development/stratium/go/cmd/key-access-server/main.go`

Core interfaces:
- `KeyAccessService.WrapDEK()` - Wrap DEK with ABAC check
- `KeyAccessService.UnwrapDEK()` - Unwrap DEK with ABAC check

Key components:
- `KeyAccessServiceClient` to Key Manager
- ABAC policy evaluation (via Platform Service)
- Client key caching
- Audit logging

### PAP Server (`:8090`)
**File**: `/Users/benjaminparrish/Development/stratium/go/services/pap/`

Entry point: `/Users/benjaminparrish/Development/stratium/go/cmd/pap-server/main.go`

REST endpoints (Gin framework):
- POST/GET/PUT/DELETE `/api/policies` - Policy CRUD
- POST/GET/PUT/DELETE `/api/entitlements` - Entitlement CRUD
- GET `/api/audit-logs` - Audit log viewer
- POST `/validation` - Validate policy JSON

## Data Flow: ZTDF Encryption

```
Client (SDK)
   │
   ├─1. Encrypt plaintext locally → DEK+ciphertext
   │
   ├─2. Call KAS.WrapDEK()
   │   └─> KAS checks ABAC policy (calls Platform.GetDecision)
   │   └─> KAS wraps DEK with KEM public key
   │   └─> Returns wrapped DEK
   │
   └─3. Package wrapped DEK + ciphertext → ZTDF manifest
```

## Data Flow: ZTDF Decryption

```
Client (SDK)
   │
   ├─1. Parse ZTDF manifest
   │
   ├─2. Call KAS.UnwrapDEK()
   │   └─> KAS checks ABAC policy (calls Platform.GetDecision)
   │   └─> KAS calls KeyMgr.UnwrapDEK()
   │   └─> KeyMgr decrypts DEK using KEK
   │   └─> KAS returns plaintext DEK
   │
   └─3. Decrypt ciphertext using DEK
```

## mTLS Communication

Service-to-service authentication via mutual TLS:
- Each service has `/var/run/secrets/stratium/certs/` containing:
  - `service.crt` - Service certificate
  - `service.key` - Service private key
  - `ca.crt` - CA certificate for verification
  - `ca.key` - CA key (for cert rotation)

Configuration: `/Users/benjaminparrish/Development/stratium/go/pkg/security/tlspolicy/`

## Configuration Entry Points

**Config struct**: `/Users/benjaminparrish/Development/stratium/go/config/config.go`

Environment variables (sampled):
- `DATABASE_URL` - PostgreSQL connection
- `PLATFORM_GRPC_PORT` - Platform service port
- `KEY_MANAGER_GRPC_PORT` - Key Manager port
- `KEY_ACCESS_GRPC_PORT` - KAS port
- `KEYCLOAK_URL` - OIDC issuer
- `HSM_ENABLED` - Hardware security module
- `FIPS_ENABLED` - FIPS 140-3 mode

See `/Users/benjaminparrish/Development/stratium/docs/CONFIGURATION.md` for full list.

## Cross-Cutting Concerns

### Licensing
**Package**: `go/pkg/licensing/` — JWT-based offline license validation
**Middleware**: `go/middleware/license.go` — gRPC + Gin interceptors block requests when license invalid
**Config**: `config.LicenseConfig` — enabled flag, public key path, license file path

### Observability
**Package**: `go/observability/observability.go` — OpenTelemetry Provider
- OTLP trace export (gRPC to collector)
- Prometheus metrics endpoint (HTTP)
- Resource attributes: service name, version, environment

### Docker Compose Variants
- `deployment/docker/docker-compose.yml` — Standard development stack
- `deployment/docker/docker-compose.yubikey.yml` — YubiKey-enabled variant with smart card passthrough

### Vendored Dependencies
- `third_party/gin/` — Vendored Gin web framework

### Multi-Provider Agent Authorization

Stratium supports agent authorization across multiple AI providers using two provider-agnostic integration layers:

**MCP Layer** (Desktop agents):
- Binary: `bin/stratium-mcp` — stdio/JSON-RPC MCP server
- Used by: Claude Desktop, ChatGPT Desktop (when MCP ships)
- Source: `go/cmd/stratium-mcp/`, `go/internal/mcp/`, `go/internal/tools/`
- Transport: stdio → gRPC to Agent Gateway (:50054)

**Hooks Layer** (CLI agents):
- Claude Code: `demos/mcp/hooks/pre-tool-use.sh` (Bash, uses grpcurl)
- OpenAI Codex: `demos/codex/hooks/stratium_pre_tool_use.py` (Python, uses `stratium-mcp --mode=check`)
- Config: `.claude/settings.json` (Claude) / `.codex/hooks.json` (Codex)
- Both call Agent Gateway for every tool action via PreToolUse hooks

**Single-Shot Check Mode** (`stratium-mcp --mode=check`):
- Source: `go/internal/mcp/check.go`
- Reads JSON action from stdin, calls Agent Gateway, writes authorization result to stdout
- Used by Codex hook scripts as a subprocess
- Same gRPC client and delegation token model as full MCP mode

**Supported Providers**: `anthropic`, `openai`, `custom` (stored in `agents.provider` column)

See `docs/PRD_OPENAI_AGENT_AUTHORIZATION.md` for full architecture and `docs/TESTING_OPENAI_AGENT_AUTH.md` for testing guide.

## Related Documentation

- **Backend API**: `/docs/CODEMAPS/backend.md`
- **Frontend UI**: `/docs/CODEMAPS/frontend.md`
- **Data Models**: `/docs/CODEMAPS/data.md`
- **SDKs**: `/docs/CODEMAPS/sdks.md`
- **Dependencies**: `/docs/CODEMAPS/dependencies.md`
