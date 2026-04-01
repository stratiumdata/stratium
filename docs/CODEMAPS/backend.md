<!-- Generated: 2026-03-28 | gRPC APIs & Service Implementations | Files scanned: 275 Go | Token estimate: ~950 -->

# Backend Services Codemap

**Last Updated:** 2026-03-28

## Service APIs

### Platform Service (`stratium.services.platform.PlatformService`)

**Proto**: `/Users/benjaminparrish/Development/stratium/proto/services/platform/platform.proto`

**Implementation**: `/Users/benjaminparrish/Development/stratium/go/services/platform/server.go`

#### GetDecision RPC

```protobuf
rpc GetDecision(GetDecisionRequest) returns (GetDecisionResponse);

message GetDecisionRequest {
  map<string, google.protobuf.Value> subject_attributes = 1;
  map<string, string> resource_attributes = 2;
  string action = 3;
  map<string, string> context = 4;
  string policy_id = 5;  // Optional
}

message GetDecisionResponse {
  Decision decision = 1;          // ALLOW/DENY/CONDITIONAL
  string reason = 2;
  map<string, string> details = 3;
  google.protobuf.Timestamp timestamp = 4;
  string evaluated_policy = 5;
}

enum Decision {
  DECISION_UNSPECIFIED = 0;
  DECISION_ALLOW = 1;
  DECISION_DENY = 2;
  DECISION_CONDITIONAL = 3;
}
```

**Function signature**:
```go
func (s *Server) GetDecision(ctx context.Context, req *GetDecisionRequest) (*GetDecisionResponse, error)
```

**Logic flow**:
1. Validate action is not empty
2. Use PolicyDecisionPoint (if configured) OR fall back to legacy evaluation
3. Return Decision with timestamp and evaluated policy ID

**Testing**: `/Users/benjaminparrish/Development/stratium/go/services/platform/server_test.go`

#### GetEntitlements RPC

```protobuf
rpc GetEntitlements(GetEntitlementsRequest) returns (GetEntitlementsResponse);

message GetEntitlementsRequest {
  map<string, google.protobuf.Value> subject = 1;
  string resource_filter = 2;
  string action_filter = 3;
  map<string, string> context = 4;
  string page_token = 5;
  int32 page_size = 6;
}

message GetEntitlementsResponse {
  repeated Entitlement entitlements = 1;
  string next_page_token = 2;
  int64 total_count = 3;
  google.protobuf.Timestamp timestamp = 4;
}
```

### Key Manager Service (`stratium.services.key_manager.KeyManagerService`)

**Proto**: `/Users/benjaminparrish/Development/stratium/proto/services/key-manager/key-manager.proto`

**Implementation**: `/Users/benjaminparrish/Development/stratium/go/services/key-manager/server.go`

**Key operations**:

```protobuf
rpc CreateKey(CreateKeyRequest) returns (CreateKeyResponse);
rpc UnwrapDEK(UnwrapDEKRequest) returns (UnwrapDEKResponse);
rpc RewrapClientDEK(RewrapClientDEKRequest) returns (RewrapClientDEKResponse);
rpc RegisterClientKey(RegisterClientKeyRequest) returns (RegisterClientKeyResponse);
rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);
```

**Key types**:
```protobuf
enum KeyType {
  KEY_TYPE_RSA_2048 = 1;
  KEY_TYPE_RSA_3072 = 2;
  KEY_TYPE_RSA_4096 = 3;
  KEY_TYPE_ECC_P256 = 4;
  KEY_TYPE_ECC_P384 = 5;
  KEY_TYPE_ECC_P521 = 6;
  KEY_TYPE_KYBER_512 = 7;
  KEY_TYPE_KYBER_768 = 8;
  KEY_TYPE_KYBER_1024 = 9;
}
```

**Key status tracking**:
```protobuf
enum KeyStatus {
  KEY_STATUS_ACTIVE = 1;
  KEY_STATUS_INACTIVE = 2;
  KEY_STATUS_PENDING_ROTATION = 3;
  KEY_STATUS_DEPRECATED = 4;
  KEY_STATUS_COMPROMISED = 5;
  KEY_STATUS_REVOKED = 6;
}
```

**Implementation details**:
- `NewServer()` - Initializes PostgreSQL key store + optional HSM
- `UnwrapDEK()` - Decrypts DEK using current KEK
- `RegisterClientKey()` - Stores client public key for wrapping
- `RotateKey()` - Performs key rotation with status tracking

**Testing**: `/Users/benjaminparrish/Development/stratium/go/services/key-manager/server_test.go`

### Key Access Service (`stratium.services.key_access.KeyAccessService`)

**Proto**: `/Users/benjaminparrish/Development/stratium/proto/services/key-access/key-access.proto`

**Implementation**: `/Users/benjaminparrish/Development/stratium/go/services/key-access/server.go`

**Operations**:

```protobuf
rpc WrapDEK(WrapDEKRequest) returns (WrapDEKResponse);
rpc UnwrapDEK(UnwrapDEKRequest) returns (UnwrapDEKResponse);

message WrapDEKRequest {
  string resource = 1;
  bytes dek = 2;
  string key_id = 3;
  string action = 4;
  map<string, string> context = 5;
  string policy = 6;  // Base64 ZTDF policy
  string client_key_id = 7;
}

message UnwrapDEKRequest {
  string resource = 1;
  bytes wrapped_dek = 2;
  string key_id = 3;
  string client_key_id = 4;
  string action = 5;
  map<string, string> context = 6;
}
```

**Function signatures**:
```go
func (s *Server) WrapDEK(ctx context.Context, req *WrapDEKRequest) (*WrapDEKResponse, error)
func (s *Server) UnwrapDEK(ctx context.Context, req *UnwrapDEKRequest) (*UnwrapDEKResponse, error)
```

**ABAC evaluation**:
- Extracts subject from OIDC token in Authorization header
- Calls Platform.GetDecision() to verify access
- Returns AccessDecision with applied rules

**Testing**: `/Users/benjaminparrish/Development/stratium/go/services/key-access/server_test.go`

### PAP REST API

**Implementation**: `/Users/benjaminparrish/Development/stratium/go/services/pap/server.go`

**REST endpoints**:

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| POST | `/policies` | CreatePolicy | Create new policy |
| GET | `/policies/{id}` | GetPolicy | Retrieve policy |
| GET | `/policies` | ListPolicies | List all policies |
| POST | `/entitlements` | CreateEntitlement | Create entitlement |
| GET | `/entitlements/{id}` | GetEntitlement | Retrieve entitlement |
| GET | `/entitlements` | ListEntitlements | List entitlements |
| PUT | `/policies/{id}` | UpdatePolicy | Update policy |
| DELETE | `/policies/{id}` | DeletePolicy | Delete policy |
| PUT | `/entitlements/{id}` | UpdateEntitlement | Update entitlement |
| DELETE | `/entitlements/{id}` | DeleteEntitlement | Delete entitlement |
| GET | `/audit-logs` | ListAuditLogs | List audit logs |
| GET | `/audit-logs/{id}` | GetAuditLog | Get audit entry |
| POST | `/validation` | ValidatePolicy | Validate policy JSON |

**Framework**: Gin web framework (vendored at `third_party/gin/`, see `/go/services/pap/server.go`)

## Core Packages

### Policy Decision Point

**Package**: `/Users/benjaminparrish/Development/stratium/go/pkg/policy_engine/`

Main types:
```go
type PolicyDecisionPoint struct {
  policyCache PolicyCache
  engine      PolicyEvaluationEngine
  logger      Logger
}

type PolicyEvaluationEngine interface {
  Evaluate(ctx context.Context, req *GetDecisionRequest) (*DecisionResult, error)
}
```

Implementations:
- OPA/Rego policy engine (production)
- JSON policy language (simplified)

### ZTDF Validators

**Package**: `/Users/benjaminparrish/Development/stratium/go/pkg/validators/`

Key functions:
- `ValidateManifest()` - ZTDF manifest schema validation
- `ValidateAssertion()` - Assertion validation
- `HierarchyMatcher.MatchesHierarchical()` - Hierarchical attribute matching
- `ExtractAttributes()` - Extract attributes from manifest

**Hierarchies supported**:
- NATO/DoD (TOP-SECRET > SECRET > CONFIDENTIAL > RESTRICTED > UNCLASSIFIED)
- Commercial (HIGHLY-CONFIDENTIAL > RESTRICTED > CONFIDENTIAL > INTERNAL > PUBLIC)

**File**: `/Users/benjaminparrish/Development/stratium/go/pkg/validators/ztdf.go`

### Authentication & Authorization

**Package**: `/Users/benjaminparrish/Development/stratium/go/pkg/auth/`

Components:
- `AuthService` - Token validation & extraction
- `AuthProvider` - OIDC token provider
- `OIDCVerifier` - JWT signature verification (Keycloak)

**Token usage**:
```go
// Interceptor extracts OIDC token from gRPC metadata
metadata.FromIncomingContext(ctx) → "authorization" header
tokenString := strings.TrimPrefix(auth_header, "Bearer ")
claims := verify(tokenString)  // Via OIDC provider
```

## Database Schema

**Connection**: PostgreSQL (configured in `/go/config/config.go`)

**Key tables** (inferred from code):
- `keys` - KEK/DEK metadata with encryption status
- `policies` - ABAC policies (JSON)
- `entitlements` - Subject entitlements
- `audit_logs` - All access decisions

**Encrypted columns**:
- `keys.private_key` - Encrypted with admin key
- `keys.public_key` - Plaintext (but can be rotated)

See `/Users/benjaminparrish/Development/stratium/go/services/key-manager/server.go:initializePostgresKeyStore()` for initialization.

## Middleware

### Rate Limiting
**Package**: `go/middleware/ratelimit.go`
- Per-client IP rate limiting (token bucket via `golang.org/x/time/rate`)
- gRPC unary + stream interceptors
- Config: `RATE_LIMIT_REQUESTS_PER_MIN`, `RATE_LIMIT_BURST`

### License Enforcement
**Package**: `go/middleware/license.go`
- `LicenseEnforcer` wraps `licensing.Manager`
- gRPC interceptor: returns `codes.PermissionDenied` when license invalid
- Gin middleware: returns HTTP 403
- Auto-refresh: checks license file every 5 minutes

### Licensing Manager
**Package**: `go/pkg/licensing/`
- `Manager` — loads JWT-signed license files, validates RS256 signatures
- `Claims` — custom JWT claims: service features, expiry, seat count
- `State` — tracks loaded license validity + last error
- License file path + public key path from `config.LicenseConfig`

### Observability
**Package**: `go/observability/observability.go`
- `Provider` struct wires tracerProvider + meterProvider
- `Init()` — configures OTLP trace exporter + Prometheus metrics HTTP server
- Integrated into all service `main.go` entry points

## Related Documentation

- **Architecture**: `/docs/CODEMAPS/architecture.md`
- **Frontend**: `/docs/CODEMAPS/frontend.md`
- **Data Models**: `/docs/CODEMAPS/data.md`
- **Configuration**: `/docs/CONFIGURATION.md`
