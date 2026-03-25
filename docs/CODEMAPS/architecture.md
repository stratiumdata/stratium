<!-- Generated: 2026-03-12 | Service Architecture | Token estimate: ~950 -->

# Stratium Architecture Codemap

**Last Updated:** 2026-03-12

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

### PAP Server (`:8080`)
**File**: `/Users/benjaminparrish/Development/stratium/go/services/pap/`

Entry point: `/Users/benjaminparrish/Development/stratium/go/cmd/pap-server/main.go`

REST endpoints:
- POST `/policies` - Create policy
- GET `/policies/{id}` - Get policy
- POST `/entitlements` - Create entitlement
- GET `/entitlements/{id}` - Get entitlement
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

## Related Documentation

- **Backend API**: `/docs/CODEMAPS/backend.md`
- **Data Models**: `/docs/CODEMAPS/data.md`
- **SDKs**: `/docs/CODEMAPS/sdks.md`
- **Dependencies**: `/docs/CODEMAPS/dependencies.md`
