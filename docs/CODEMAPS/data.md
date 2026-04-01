<!-- Generated: 2026-03-28 | Data Models & Protobuf Types | Files scanned: 275 Go | Token estimate: ~950 -->

# Data Models Codemap

**Last Updated:** 2026-03-28

## Core Domain Models

### Entitlement

**Go type**: `/Users/benjaminparrish/Development/stratium/go/pkg/models/entitlement.go`

```go
type Entitlement struct {
  ID                 uuid.UUID
  Name               string
  Description        string
  SubjectAttributes  map[string]interface{}  // e.g., {"role": "admin", "dept": "eng"}
  ResourceAttributes map[string]interface{}  // e.g., {"classification": "secret"}
  Actions            []string                // e.g., ["read", "write"]
  Conditions         map[string]interface{}  // e.g., {"time_before": "2025-12-31"}
  Enabled            bool
  CreatedAt          time.Time
  UpdatedAt          time.Time
  CreatedBy          sql.NullString
  UpdatedBy          sql.NullString
  ExpiresAt          *time.Time              // Optional expiration
}
```

**Proto equivalence**: `platform.Entitlement` message

**Semantics**:
- Multiple entitlements can match a subject → combined as OR rules
- Conditions use temporal logic (valid_before, valid_after)
- Database backed (PostgreSQL)

### Policy

**Go type**: `/Users/benjaminparrish/Development/stratium/go/services/platform/server.go`

```go
type Policy struct {
  ID          string
  Name        string
  Description string
  Rules       []PolicyRule
}

type PolicyRule struct {
  Resource  string  // Resource name/pattern
  Action    string  // read, write, delete, etc.
  Subject   string  // Subject pattern
  Condition string  // Condition expression
  Effect    string  // "allow" or "deny"
}
```

**Evaluation model**:
- Policies are evaluated in priority order
- Early ALLOW/DENY stops evaluation
- Returns CONDITIONAL if no explicit match

### ZTDF Manifest

**Proto**: `/Users/benjaminparrish/Development/stratium/proto/models/ztdf.proto`

**Go type**: `/Users/benjaminparrish/Development/stratium/go/pkg/models/manifest.go`

Key fields:
```go
type Manifest struct {
  ID             string
  Version        string            // "1.0"
  Type           string            // "ztdf"
  Assertions     []*Assertion      // Access control rules
  EncryptionInfo EncryptionInfo    // Algorithm, key info
  Payload        []byte            // Encrypted data
  CreatedAt      time.Time
  ExpiresAt      *time.Time
}

type Assertion struct {
  ID        string
  Scope     string                // "data" or "manifest"
  Attributes map[string]string   // e.g., {"classification": "secret"}
  Statement *AssertionStatement  // Assertion type/value
}

type EncryptionInfo struct {
  Algorithm      string  // "AES-256-GCM"
  WrappedKey    []byte  // DEK wrapped with KEM public key
  KeyID         string  // Reference to KEK used
  InitVector    []byte  // IV for AES-GCM
}
```

### Decision Result

**Proto**: `platform.GetDecisionResponse`

**Go type**: `/Users/benjaminparrish/Development/stratium/go/services/platform/server.go`

```go
type DecisionResult struct {
  Decision       Decision             // ALLOW/DENY/CONDITIONAL
  Reason         string               // Human-readable explanation
  Details        map[string]string    // Additional metadata
  Timestamp      *timestamppb.Timestamp
  EvaluatedPolicy string              // Policy ID that matched
}
```

## Key Material Models

### Key Metadata

**Proto**: `key_manager.Key`

```protobuf
message Key {
  string key_id = 1;
  string client_id = 2;
  KeyType type = 3;           // RSA-2048, KYBER-512, etc.
  KeyStatus status = 4;       // ACTIVE, DEPRECATED, etc.
  RotationPolicy rotation = 5;
  google.protobuf.Timestamp created_at = 6;
  google.protobuf.Timestamp expires_at = 7;
  int32 rotation_interval_days = 8;
}
```

**Database storage**:
- `keys.private_key` - Encrypted with admin key (PostgreSQL BYTEA)
- `keys.public_key` - Plaintext PEM format
- `keys.metadata` - JSON with algorithm, status, etc.

### KEK (Key Encryption Key)

**Purpose**: Master key that wraps DEKs

**Storage**:
- PostgreSQL (encrypted at rest via admin key)
- Optional: HSM (Hardware Security Module)
- Optional: Smart Card / YubiKey

**Algorithm support**:
- RSA-2048/3072/4096 (classical)
- ECC P-256/P-384/P-521 (elliptic curve)
- KYBER-512/768/1024 (post-quantum)

**Provider interface**: `/Users/benjaminparrish/Development/stratium/go/services/key-manager/server.go`

```go
type KeyProvider interface {
  GetPublicKey() (crypto.PublicKey, error)
  Decrypt(ciphertext []byte) ([]byte, error)
  Sign(data []byte) ([]byte, error)
}
```

### DEK (Data Encryption Key)

**Purpose**: Encrypts/decrypts user data

**Generation**: Random 256-bit AES key

**Wrapping flow**:
1. Client generates DEK locally
2. Client wraps DEK with KAS public key
3. Server stores wrapped DEK with ZTDF manifest
4. On decryption: Server calls KeyMgr to unwrap DEK using KEK

**FIPS mode behavior**:
- FIPS on: DEK sent plaintext over TLS (no RSA wrapping)
- FIPS off: DEK wrapped with RSA PKCS#1 v1.5

## Attribute Models

### Subject Attributes

**Standard attributes** (from OIDC token):
```json
{
  "sub": "user@example.com",
  "email": "user@example.com",
  "name": "Alice Smith",
  "role": "admin",
  "department": "engineering",
  "clearance": "SECRET",
  "groups": ["team-a", "admins"]
}
```

### Resource Attributes

**Standard attributes**:
```json
{
  "name": "financial-report.pdf",
  "type": "document",
  "classification": "CONFIDENTIAL",
  "department": "finance",
  "sensitivity": "high"
}
```

### Hierarchy Classification

**Format**: `urn:ztdf:<domain>:<type>:<value>`

**NATO/DoD hierarchy**:
- `urn:ztdf:nato:classification:top-secret` (level 4)
- `urn:ztdf:nato:classification:secret` (level 3)
- `urn:ztdf:nato:classification:confidential` (level 2)
- `urn:ztdf:nato:classification:restricted` (level 1)
- `urn:ztdf:nato:classification:unclassified` (level 0)

**Hierarchical matching logic** (in `/go/pkg/validators/ztdf.go`):
```
Subject clearance ≥ Resource classification → ALLOW
e.g., SECRET clearance can access CONFIDENTIAL documents
```

## Context Models

### Request Context

Passed through ABAC evaluation:
```json
{
  "ip_address": "192.168.1.100",
  "timestamp": "2026-03-12T10:30:00Z",
  "environment": "production",
  "user_agent": "StratiumSDK/1.0"
}
```

## Audit Models

### Audit Log Entry

**Go type**: `go/pkg/models/audit.go`
**DB table**: `audit_logs` (see `deployment/postgres/02-init.sql`)

```go
type AuditLog struct {
  ID         uuid.UUID
  EntityType string  // "policy" | "entitlement"
  EntityID   uuid.UUID
  Action     string  // "create" | "update" | "delete" | "evaluate" | "test"
  Actor      string
  Changes    map[string]interface{}  // JSONB
  Result     map[string]interface{}  // JSONB
  Timestamp  time.Time
  IPAddress  string
  UserAgent  string
}
```

**Indexes**: entity (type+id), timestamp DESC, actor

## License Models

### License Claims

**Go type**: `go/pkg/licensing/claims.go`

```go
type Claims struct {
  jwt.RegisteredClaims
  // Service feature flags, seat count, tier
}
```

**License State**: `go/pkg/licensing/manager.go:State` — tracks validity, loaded timestamp, last error

## Protobuf Message Hierarchy

### Platform Service Messages

```
GetDecisionRequest/Response
├── subject_attributes (map<string, Value>)
├── resource_attributes (map<string, string>)
├── action (string)
├── context (map<string, string>)
└── Decision enum (ALLOW/DENY/CONDITIONAL)

GetEntitlementsRequest/Response
├── subject (map<string, Value>)
├── resource_filter (string)
├── action_filter (string)
└── Entitlement[] (repeated)
```

### Key Manager Messages

```
CreateKeyRequest
├── key_type (KeyType enum)
├── client_id (string)
└── rotation_policy (RotationPolicy enum)

UnwrapDEKRequest/Response
├── wrapped_dek (bytes)
├── key_id (string)
└── unwrapped_dek (bytes)

RegisterClientKeyRequest
├── client_id (string)
├── public_key (bytes)
└── algorithm (string)
```

### Key Access Messages

```
WrapDEKRequest
├── resource (string)
├── dek (bytes)
├── action (string)
├── policy (string - base64 encoded ZTDF policy)
└── client_key_id (string)

UnwrapDEKRequest
├── wrapped_dek (bytes)
├── key_id (string)
├── client_key_id (string)
└── action (string)
```

## Related Documentation

- **Backend**: `/docs/CODEMAPS/backend.md`
- **Validators**: `/go/pkg/validators/`
- **ZTDF spec**: `https://spec.ztdf.dev`
- **STANAG 4774**: `/proto/models/stanag4774.proto`
