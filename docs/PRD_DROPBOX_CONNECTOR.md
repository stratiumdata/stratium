# PRD: Stratium Dropbox Connector

**Status:** Draft
**Author:** Benjamin Parrish
**Date:** 2026-03-28
**Feature Flag:** `dropbox-connector`

---

## Design Decisions

Key architectural decisions made during PRD development:

| Decision | Choice | Alternatives Considered |
|----------|--------|------------------------|
| Primary use case | Transparent encryption + policy-gated sharing + classification-based DLP | Individual features only |
| Target users | Both admins and end users | Admin-only, developer-only, end-user-only |
| Deployment model | Desktop client + browser extension | Background sync service, server-side middleware, desktop-only |
| Encryption trigger | Hybrid: folder defaults + per-file overrides | Folder-only auto-encrypt, manual tagging only, policy-driven admin rules |
| Sharing model | Allow sharing, gate decryption (zero-trust) | Block sharing, transparent re-wrap, notify + approve workflow |
| Browser extension scope | Full standalone capability | Lightweight companion, view + decrypt only, admin dashboard only |
| Dropbox auth flow | Hybrid: team admin token + per-user OAuth2 consent | Per-user PKCE only, team admin only, service account |
| Classification source | User-prompted on first encrypt | Inherit folder, content-based ML, file type mapping |
| Hierarchy support | Both NATO/DoD and Commercial (tenant-configurable) | Commercial only, NATO only, custom hierarchies |
| Migration strategy | Phased migration with admin-defined priority rules | Bulk retroactive, encrypt-on-access, no retroactive |
| File format | .ztdf extension (e.g., report.pdf.ztdf) | Original extension, hidden sidecar, configurable per-tenant |
| Offline mode | No offline decryption (strict zero-trust) | Cached DEKs, read-only cache, full offline with deferred sync |
| Service architecture | Standalone service with its own database | New microservice on :50055, KAS extension, sidecar |
| Event processing | Cursor-based polling + webhooks (Dropbox recommended pattern) | Synchronous processing, queue-based async, periodic polling only |
| Agent authorization | Out of scope for this integration | Design now, Phase 2, timeline-dependent |
| Desktop UI | System tray / menu bar app + settings window | Full windowed app, CLI-only |
| Browser targets | Chrome + Firefox + Safari | Chrome only, Chromium-based only |
| Secret storage | OS keychain + optional YubiKey PIV binding | Encrypted local file, server-side token vault, OS keychain only |
| Rate limiting | Pre-configured throttle (admin-set max ops/sec) | Adaptive, token bucket, Dropbox plan-aware (roadmap) |
| Change detection | Dual hash: Dropbox content_hash + plaintext hash in ZTDF metadata | Dropbox hash only, always re-process, revision tracking only |
| Tamper handling | Detect and quarantine | Restore from version history, alert only, integrity check on access |
| MVP scope | Desktop client + browser extension (core encrypt/decrypt) | Desktop only, full stack minus DLP |
| Dropbox app permissions | Scoped to App Folder (/Apps/Stratium) | Full Dropbox access, granular scopes, team + individual scopes |
| SDK strategy | New service with direct gRPC to Stratium services | Existing Go SDK, Python SDK, multi-language |
| Testing strategy | Unit + integration + E2E + contract + chaos testing | Standard three-tier, integration-heavy, contract-focused |
| Rollout strategy | MVP → GA (2 phases) | Alpha → Beta → GA, feature-flagged progressive, design partner co-dev |
| Compliance | All applicable, tenant-configurable (FIPS 140-3, SOC 2, GDPR, ITAR/EAR) | Single framework focus |
| Product name | Stratium Dropbox Connector | Stratium for Dropbox, Stratium Vault for Dropbox |

---

## 1. Problem Statement

Organizations using Dropbox for file storage and collaboration have no mechanism to enforce cryptographic access controls on their files at rest. Dropbox provides encryption-at-rest using its own keys, but the platform operator (Dropbox) retains access to plaintext content. For organizations handling classified, regulated, or sensitive data, this creates an unacceptable trust dependency.

**The gap:** There is no way to ensure that files stored in Dropbox are:
- Encrypted with keys the organization controls (not Dropbox)
- Subject to Attribute-Based Access Control (ABAC) policies that persist regardless of how the file is shared
- Classified according to organizational or regulatory hierarchies (NATO/DoD, Commercial)
- Auditable at the cryptographic level — who accessed what, when, and under what policy

**The risk:** Without client-controlled encryption, a Dropbox breach, insider threat, or misconfigured sharing link exposes plaintext content. Compliance frameworks (FedRAMP, ITAR/EAR, GDPR) may prohibit storing certain data classes in cloud storage without additional encryption controls.

### Core Principle

> Files stored in Dropbox via the Stratium Dropbox Connector are ZTDF-encrypted with organization-controlled keys and governed by ABAC policies. Dropbox never holds plaintext for protected files. Sharing a file does not grant access — the recipient must satisfy the ZTDF policy.

---

## 2. Goals

1. **Transparent ZTDF encryption** — files placed in the Stratium-managed Dropbox folder are automatically encrypted using ZTDF format with organization-controlled keys (KEK/DEK via Stratium Key Manager).
2. **Policy-gated sharing** — Dropbox sharing propagates the encrypted blob, but decryption requires the recipient to satisfy the ABAC policy embedded in the ZTDF manifest. Sharing ≠ access.
3. **Classification-based DLP** — files are classified at encryption time (user-prompted) using tenant-configurable hierarchies (NATO/DoD or Commercial). Classification governs who can decrypt.
4. **Dual-surface client** — a desktop tray application and a standalone browser extension provide the same core encrypt/decrypt capability across different workflows.
5. **Strict zero-trust posture** — no offline decryption, no cached plaintext, every access requires a live ABAC policy evaluation against Stratium services.
6. **Phased migration** — existing Dropbox files can be retroactively encrypted via admin-configured priority rules and background processing.
7. **Tamper detection** — unauthorized modification of `.ztdf` files is detected and quarantined automatically.
8. **Multi-framework compliance** — FIPS 140-3, SOC 2, GDPR, and ITAR/EAR compliance, configurable per-tenant.

### Non-Goals (V1)

- AI agent authorization for Dropbox file access (see PRD_AGENT_AUTHORIZATION.md for the broader agent auth initiative).
- Content-based automatic classification (ML/NLP scanning of file contents).
- Real-time co-editing of encrypted files (collaborative editing requires plaintext; out of scope).
- Dropbox Paper or Dropbox-native document encryption (only file-based ZTDF).
- Mobile clients (iOS/Android) — desktop and browser only for V1.

---

## 3. Architecture Overview

### 3.1 System Topology

```
┌──────────────────────────────────────────────────────────────────────────┐
│                          User Devices                                     │
│                                                                          │
│  ┌─────────────────────────┐    ┌──────────────────────────────────┐     │
│  │  Desktop Client         │    │  Browser Extension               │     │
│  │  (macOS / Windows /     │    │  (Chrome / Firefox / Safari)     │     │
│  │   Linux)                │    │                                  │     │
│  │                         │    │  • Encrypt / Decrypt             │     │
│  │  • System Tray App      │    │  • Classification prompts       │     │
│  │  • Settings Window      │    │  • Policy status overlay        │     │
│  │  • Classification UI    │    │  • Inline .ztdf handling        │     │
│  │  • OS Keychain + YubiKey│    │  • Web Crypto API               │     │
│  └────────┬────────────────┘    └──────────┬───────────────────────┘     │
│           │                                │                             │
└───────────┼────────────────────────────────┼─────────────────────────────┘
            │                                │
            │  gRPC/TLS                      │  HTTPS/TLS
            │                                │
   ┌────────▼────────────────────────────────▼───────────┐
   │           Stratium Dropbox Connector                 │
   │           (Standalone Service)                       │
   │                                                      │
   │  • Dropbox OAuth2 token management                   │
   │  • Webhook receiver + cursor-based change detection  │
   │  • File encryption orchestration                     │
   │  • Migration job scheduler                           │
   │  • Tamper detection + quarantine                     │
   │  • Dual hash tracking (content_hash + plaintext)     │
   │  • Dropbox API client (scoped to /Apps/Stratium)     │
   │                                                      │
   │  Own Database (PostgreSQL):                          │
   │  • File sync state + hash mappings                   │
   │  • Migration job queue + progress                    │
   │  • Dropbox OAuth tokens (encrypted)                  │
   │  • User ↔ tenant ↔ folder mappings                   │
   │  • Quarantine records                                │
   └──────┬──────────┬──────────┬─────────────────────────┘
          │          │          │
          │ mTLS     │ mTLS     │ mTLS
          │          │          │
   ┌──────▼───┐  ┌───▼──────┐  ┌▼───────────┐
   │ Platform │  │ Key Mgr  │  │ Key Access │
   │ :50051   │  │ :50052   │  │ :50053     │
   │          │  │          │  │            │
   │ • ABAC   │  │ • KEK/DEK│  │ • WrapDEK  │
   │ • Policy │  │ • Rotate │  │ • UnwrapDEK│
   └──────────┘  └──────────┘  └────────────┘
                                      │
                              ┌───────▼────────┐
                              │  Dropbox API   │
                              │  (v2)          │
                              │                │
                              │  App Folder:   │
                              │  /Apps/Stratium│
                              └────────────────┘
```

### 3.2 Data Flow: Encrypt and Upload

```
User (Desktop Client or Browser Extension)
   │
   ├─1. User places file in /Apps/Stratium/ folder
   │    (or explicitly encrypts via right-click / extension UI)
   │
   ├─2. Client prompts for classification
   │    (User selects: e.g., CONFIDENTIAL in Commercial hierarchy)
   │
   ├─3. Client authenticates to Stratium (OIDC → Keycloak)
   │    └─ User OIDC token + Stratium client credentials
   │
   ├─4. Client calls Dropbox Connector → Encrypt RPC
   │    └─ Sends: plaintext bytes, classification, resource attributes
   │
   │    Connector internally:
   │    ├─4a. Generate random 256-bit DEK
   │    ├─4b. Encrypt plaintext with AES-256-GCM(DEK)
   │    ├─4c. Call KAS.WrapDEK() with ABAC policy
   │    │     └─ KAS calls Platform.GetDecision() to verify user can encrypt at this classification
   │    ├─4d. Package: manifest + wrapped-DEK + ciphertext → .ztdf blob
   │    ├─4e. Compute plaintext hash (SHA-256) → store in ZTDF manifest metadata
   │    └─4f. Upload .ztdf blob to Dropbox /Apps/Stratium/ via Dropbox API
   │
   ├─5. Connector records in its database:
   │    ├─ Dropbox file_id, rev, content_hash (of .ztdf blob)
   │    ├─ Plaintext hash (from ZTDF manifest metadata)
   │    ├─ Classification, policy_id, key_id
   │    └─ Original filename, timestamp, user_id
   │
   └─6. Client confirms encryption complete
        └─ File appears as "filename.ext.ztdf" in Dropbox
```

### 3.3 Data Flow: Download and Decrypt

```
User (Desktop Client or Browser Extension)
   │
   ├─1. User selects .ztdf file in /Apps/Stratium/ folder
   │    (via Dropbox client sync, web UI, or extension overlay)
   │
   ├─2. Client authenticates to Stratium (OIDC → Keycloak)
   │
   ├─3. Client calls Dropbox Connector → Decrypt RPC
   │    └─ Sends: Dropbox file_id or path, user OIDC token
   │
   │    Connector internally:
   │    ├─3a. Download .ztdf blob from Dropbox API
   │    ├─3b. Verify ZTDF manifest integrity (structure, signatures)
   │    ├─3c. Call KAS.UnwrapDEK() with user's OIDC token
   │    │     └─ KAS calls Platform.GetDecision()
   │    │     └─ Evaluates: user clearance ≥ resource classification?
   │    │     └─ If DENY → return AccessDenied with reason
   │    ├─3d. Decrypt ciphertext with AES-256-GCM(DEK)
   │    ├─3e. Verify plaintext hash matches ZTDF manifest metadata
   │    └─3f. Return plaintext to client (streamed, never persisted on connector)
   │
   ├─4. Client presents decrypted file to user
   │    └─ Desktop: opens in default application (temp file, auto-deleted)
   │    └─ Browser: in-memory display or download prompt
   │
   └─5. Audit log entry created:
        └─ event_type: DECRYPT, user, file, classification, decision, timestamp
```

### 3.4 Data Flow: Sharing (Zero-Trust Model)

```
User A (file owner, SECRET clearance)
   │
   ├─1. Shares .ztdf file via Dropbox native sharing
   │    (shared link, folder invite, etc.)
   │
   ├─2. Dropbox delivers the encrypted .ztdf blob to User B
   │    └─ User B now has the ciphertext — but NOT the DEK
   │
User B (recipient, CONFIDENTIAL clearance)
   │
   ├─3. Attempts to decrypt via Desktop Client or Browser Extension
   │
   ├─4. Client calls Dropbox Connector → Decrypt RPC
   │    └─ Connector calls KAS.UnwrapDEK() with User B's token
   │    └─ KAS calls Platform.GetDecision():
   │        subject: User B (clearance: CONFIDENTIAL)
   │        resource: file (classification: SECRET)
   │        action: "decrypt"
   │
   ├─5a. If User B's clearance ≥ file classification → ALLOW
   │     └─ DEK unwrapped, file decrypted, User B can access
   │
   └─5b. If User B's clearance < file classification → DENY
         └─ "Access denied: insufficient clearance for SECRET resource"
         └─ User B has the .ztdf blob but cannot read it
```

### 3.5 Dual Hash Change Detection

```
┌─────────────────────────────────────────────────────────────┐
│                    Dual Hash Strategy                         │
│                                                              │
│  Dropbox content_hash          ZTDF Manifest plaintext_hash  │
│  (SHA-256 of .ztdf blob)       (SHA-256 of original file)   │
│                                                              │
│  ┌──────────────────┐          ┌──────────────────┐         │
│  │ Detects:         │          │ Detects:         │         │
│  │ • .ztdf blob was │          │ • Content changed│         │
│  │   modified on    │          │   vs. same content│        │
│  │   Dropbox        │          │   re-encrypted   │         │
│  │ • Unauthorized   │          │ • Key rotation   │         │
│  │   tampering      │          │   (new ciphertext,│        │
│  │ • Upload of new  │          │    same plaintext)│         │
│  │   encrypted      │          │ • Deduplication  │         │
│  │   version        │          │   across files   │         │
│  └──────────────────┘          └──────────────────┘         │
│                                                              │
│  Sync Logic:                                                 │
│  1. Webhook fires → fetch cursor changes                     │
│  2. Compare Dropbox content_hash with stored hash            │
│  3. If match → skip (no change)                              │
│  4. If mismatch → download .ztdf, parse manifest             │
│     4a. If manifest valid → update stored hashes             │
│     4b. If manifest invalid → QUARANTINE (tamper detected)   │
└─────────────────────────────────────────────────────────────┘
```

### 3.6 Webhook + Cursor-Based Event Processing

```
Dropbox                   Connector Webhook Handler          Worker
  │                              │                             │
  ├─1. POST /webhook ───────────►│                             │
  │    (accounts changed)        │                             │
  │                              ├─2. Respond 200 (< 10s) ────►
  │                              │                             │
  │                              ├─3. For each account:        │
  │                              │    Load stored cursor        │
  │                              │    Call /list_folder/continue│
  │◄─────────────────────────────┤                             │
  │  4. Return changed entries   │                             │
  │──────────────────────────────►                             │
  │                              │                             │
  │                              ├─5. For each changed file:   │
  │                              │    ├─ New .ztdf → validate  │
  │                              │    ├─ Modified → check hash │
  │                              │    ├─ Deleted → clean up DB │
  │                              │    └─ Non-.ztdf in protected│
  │                              │       folder → prompt encrypt│
  │                              │                             │
  │                              ├─6. Store updated cursor     │
  │                              │                             │
```

---

## 4. Data Models

### 4.1 Dropbox File Mapping

```go
type DropboxFileMapping struct {
    ID                uuid.UUID
    TenantID          string
    UserID            string              // Stratium user ID
    DropboxAccountID  string              // Dropbox account ID
    DropboxFileID     string              // Dropbox file ID (stable across renames)
    DropboxPath       string              // Current path in /Apps/Stratium/
    DropboxRev        string              // Dropbox revision
    DropboxContentHash string             // SHA-256 of the .ztdf blob (Dropbox's content_hash)
    PlaintextHash     string              // SHA-256 of original plaintext (stored in ZTDF manifest)
    OriginalFilename  string              // Original filename before .ztdf extension
    OriginalSize      int64               // Original plaintext file size in bytes
    ZtdfSize          int64               // Encrypted .ztdf blob size in bytes
    Classification    string              // e.g., "CONFIDENTIAL", "SECRET"
    HierarchyDomain   string              // e.g., "nato", "commercial"
    PolicyID          string              // ABAC policy ID governing this file
    KeyID             string              // KEK ID used for wrapping
    ManifestID        string              // ZTDF manifest ID
    Status            FileMappingStatus   // ACTIVE, QUARANTINED, PENDING_ENCRYPT, MIGRATING
    QuarantineReason  *string             // Reason for quarantine (if applicable)
    EncryptedAt       time.Time
    LastAccessedAt    *time.Time
    LastSyncedAt      time.Time
    CreatedAt         time.Time
    UpdatedAt         time.Time
}

type FileMappingStatus int

const (
    FileMappingStatusActive         FileMappingStatus = 0
    FileMappingStatusQuarantined    FileMappingStatus = 1
    FileMappingStatusPendingEncrypt FileMappingStatus = 2
    FileMappingStatusMigrating      FileMappingStatus = 3
    FileMappingStatusDeleted        FileMappingStatus = 4
)
```

### 4.2 Dropbox User Binding

```go
type DropboxUserBinding struct {
    ID                  uuid.UUID
    TenantID            string
    StratiumUserID      string            // Stratium OIDC subject
    DropboxAccountID    string            // Dropbox account ID
    DropboxTeamMemberID *string           // Dropbox Business team member ID (if applicable)
    DropboxEmail        string            // Dropbox account email
    OAuthRefreshToken   string            // Encrypted Dropbox OAuth2 refresh token
    OAuthTokenExpiry    time.Time         // Current access token expiry
    SyncCursor          string            // Dropbox /list_folder cursor for this user
    ConsentGrantedAt    time.Time         // When user authorized the integration
    LastSyncAt          *time.Time
    Enabled             bool
    CreatedAt           time.Time
    UpdatedAt           time.Time
}
```

### 4.3 Tenant Dropbox Configuration

```go
type TenantDropboxConfig struct {
    ID                    uuid.UUID
    TenantID              string
    DropboxTeamToken      string           // Encrypted Dropbox Business team token
    DropboxAppKey         string           // Dropbox App key
    DropboxAppSecret      string           // Encrypted Dropbox App secret
    HierarchyDomain       string           // "nato" or "commercial" (tenant default)
    DefaultClassification string           // Default classification for new files
    RateLimitMaxOpsPerSec int              // Admin-configured throttle
    WebhookSecret         string           // For verifying Dropbox webhook signatures
    WebhookURL            string           // Registered webhook endpoint
    ProtectedFolderPath   string           // Default: "/Apps/Stratium"
    Enabled               bool
    CreatedAt             time.Time
    UpdatedAt             time.Time
}
```

### 4.4 Migration Job

```go
type MigrationJob struct {
    ID              uuid.UUID
    TenantID        string
    CreatedBy       string              // Admin who initiated
    SourcePath      string              // Dropbox path to migrate (e.g., "/Finance")
    Classification  string              // Classification to apply
    HierarchyDomain string             // Hierarchy for classification
    Priority        int                 // Lower = higher priority
    Status          MigrationJobStatus
    TotalFiles      int64               // Total files discovered
    ProcessedFiles  int64               // Files encrypted so far
    FailedFiles     int64               // Files that failed encryption
    ErrorLog        []string            // Recent errors
    StartedAt       *time.Time
    CompletedAt     *time.Time
    CreatedAt       time.Time
    UpdatedAt       time.Time
}

type MigrationJobStatus int

const (
    MigrationJobStatusPending    MigrationJobStatus = 0
    MigrationJobStatusRunning    MigrationJobStatus = 1
    MigrationJobStatusPaused     MigrationJobStatus = 2
    MigrationJobStatusCompleted  MigrationJobStatus = 3
    MigrationJobStatusFailed     MigrationJobStatus = 4
    MigrationJobStatusCancelled  MigrationJobStatus = 5
)
```

### 4.5 Quarantine Record

```go
type QuarantineRecord struct {
    ID                uuid.UUID
    TenantID          string
    FileMappingID     uuid.UUID           // Reference to DropboxFileMapping
    DropboxFileID     string
    DropboxPath       string
    Reason            QuarantineReason
    DetectedAt        time.Time
    ExpectedHash      string              // Expected Dropbox content_hash
    ActualHash        string              // Actual content_hash found
    QuarantinePath    string              // Where the file was moved (e.g., /Apps/Stratium/.quarantine/)
    ResolvedAt        *time.Time
    ResolvedBy        *string
    Resolution        *string             // "restored", "deleted", "re-encrypted"
    CreatedAt         time.Time
}

type QuarantineReason int

const (
    QuarantineReasonTamperDetected     QuarantineReason = 0  // content_hash mismatch
    QuarantineReasonManifestCorrupted  QuarantineReason = 1  // ZTDF manifest parse failure
    QuarantineReasonIntegrityFailure   QuarantineReason = 2  // HMAC/signature verification failed
    QuarantineReasonUnauthorizedModify QuarantineReason = 3  // File modified outside Stratium
)
```

---

## 5. gRPC Service Definition

### 5.1 Dropbox Connector Service

```protobuf
syntax = "proto3";
package stratium.services.dropbox_connector;

service DropboxConnectorService {
  // File operations
  rpc EncryptAndUpload(EncryptAndUploadRequest) returns (EncryptAndUploadResponse);
  rpc DownloadAndDecrypt(DownloadAndDecryptRequest) returns (DownloadAndDecryptResponse);
  rpc ReEncrypt(ReEncryptRequest) returns (ReEncryptResponse);

  // Folder management
  rpc ConfigureProtectedFolder(ConfigureProtectedFolderRequest) returns (ConfigureProtectedFolderResponse);
  rpc ListProtectedFolders(ListProtectedFoldersRequest) returns (ListProtectedFoldersResponse);

  // File status
  rpc GetFileStatus(GetFileStatusRequest) returns (GetFileStatusResponse);
  rpc ListFiles(ListFilesRequest) returns (ListFilesResponse);

  // Migration
  rpc StartMigration(StartMigrationRequest) returns (StartMigrationResponse);
  rpc GetMigrationStatus(GetMigrationStatusRequest) returns (GetMigrationStatusResponse);
  rpc PauseMigration(PauseMigrationRequest) returns (PauseMigrationResponse);
  rpc CancelMigration(CancelMigrationRequest) returns (CancelMigrationResponse);

  // Quarantine
  rpc ListQuarantinedFiles(ListQuarantinedFilesRequest) returns (ListQuarantinedFilesResponse);
  rpc ResolveQuarantine(ResolveQuarantineRequest) returns (ResolveQuarantineResponse);

  // User binding
  rpc BindDropboxAccount(BindDropboxAccountRequest) returns (BindDropboxAccountResponse);
  rpc UnbindDropboxAccount(UnbindDropboxAccountRequest) returns (UnbindDropboxAccountResponse);
  rpc GetBindingStatus(GetBindingStatusRequest) returns (GetBindingStatusResponse);

  // Admin
  rpc ConfigureTenant(ConfigureTenantRequest) returns (ConfigureTenantResponse);
  rpc GetTenantConfig(GetTenantConfigRequest) returns (GetTenantConfigResponse);
  rpc GetSyncStatus(GetSyncStatusRequest) returns (GetSyncStatusResponse);
}
```

### 5.2 Key Messages

```protobuf
message EncryptAndUploadRequest {
  bytes plaintext = 1;
  string filename = 2;
  string classification = 3;           // e.g., "CONFIDENTIAL"
  string hierarchy_domain = 4;         // e.g., "commercial"
  string destination_path = 5;         // Path within /Apps/Stratium/
  map<string, string> resource_attributes = 6;  // Additional ABAC attributes
}

message EncryptAndUploadResponse {
  string dropbox_file_id = 1;
  string dropbox_path = 2;
  string manifest_id = 3;
  string key_id = 4;
  string content_hash = 5;            // Dropbox content_hash of .ztdf blob
  string plaintext_hash = 6;          // SHA-256 of original plaintext
  int64 encrypted_size = 7;
}

message DownloadAndDecryptRequest {
  string dropbox_file_id = 1;         // Dropbox file ID (preferred)
  string dropbox_path = 2;            // OR path-based lookup
}

message DownloadAndDecryptResponse {
  bytes plaintext = 1;
  string original_filename = 2;
  string classification = 3;
  string hierarchy_domain = 4;
  string policy_id = 5;
  AccessDecision decision = 6;        // The ABAC decision that allowed decryption
}

message AccessDecision {
  string decision = 1;                // "ALLOW"
  string reason = 2;
  string evaluated_policy = 3;
  map<string, string> details = 4;
}

message StartMigrationRequest {
  string source_path = 1;             // Dropbox path to migrate
  string classification = 2;
  string hierarchy_domain = 3;
  int32 priority = 4;                 // Lower = higher priority
}

message ResolveQuarantineRequest {
  string quarantine_id = 1;
  string resolution = 2;              // "restore", "delete", "re-encrypt"
}
```

---

## 6. Desktop Client

### 6.1 Architecture

```
┌───────────────────────────────────────────────────────┐
│                  Desktop Client                        │
│                                                        │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │ System Tray  │  │ Settings     │  │ Classification│ │
│  │ / Menu Bar   │  │ Window       │  │ Prompt Dialog │ │
│  │              │  │              │  │              │ │
│  │ • Sync status│  │ • Account    │  │ • Hierarchy  │ │
│  │ • Recent     │  │ • Folders    │  │   selector   │ │
│  │   activity   │  │ • YubiKey    │  │ • Level      │ │
│  │ • Quick      │  │ • Rate limit │  │   picker     │ │
│  │   actions    │  │ • Tenant     │  │ • Resource   │ │
│  │              │  │   config     │  │   attributes │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘ │
│         │                 │                 │          │
│  ┌──────▼─────────────────▼─────────────────▼───────┐ │
│  │              Core Engine                          │ │
│  │                                                   │ │
│  │  • Dropbox folder watcher (filesystem events)     │ │
│  │  • ZTDF encrypt/decrypt orchestration             │ │
│  │  • gRPC client → Dropbox Connector service        │ │
│  │  • OIDC authentication (Keycloak)                 │ │
│  │  • Dropbox OAuth2 PKCE flow                       │ │
│  └──────┬───────────────────────────────────────────┘ │
│         │                                              │
│  ┌──────▼───────────────────────────────────────────┐ │
│  │              Secret Store                         │ │
│  │                                                   │ │
│  │  • OS Keychain (macOS Keychain / Win Credential   │ │
│  │    Manager / Linux libsecret)                     │ │
│  │  • Optional: YubiKey PIV slot binding             │ │
│  │  • Stores: Dropbox refresh token, Stratium OIDC   │ │
│  │    credentials, device key                        │ │
│  └───────────────────────────────────────────────────┘ │
└───────────────────────────────────────────────────────┘
```

### 6.2 Platform Support

| Platform | UI Framework | Tray Integration | Keychain | YubiKey |
|----------|-------------|------------------|----------|---------|
| macOS | Native (AppKit or SwiftUI) | NSStatusItem | Keychain Services | PIV via CryptoTokenKit |
| Windows | WPF or WinUI 3 | NotifyIcon | Credential Manager | PIV via Windows Smart Card |
| Linux | GTK4 or Qt | AppIndicator / StatusNotifierItem | libsecret (GNOME Keyring) | PIV via pcsclite |

### 6.3 Folder Watching

The desktop client monitors the local Dropbox sync folder for changes in protected paths:

1. **File added** to `/Apps/Stratium/` → if not `.ztdf`, prompt user for classification → encrypt → upload encrypted version → delete plaintext local copy.
2. **File modified** (`.ztdf` file) → compare content_hash → if mismatch from expected, trigger tamper check.
3. **File deleted** → update file mapping status, retain audit record.
4. **File renamed/moved** → update Dropbox path in file mapping (Dropbox file_id remains stable).

### 6.4 Classification Prompt

When a new file is placed in a protected folder, the desktop client presents a modal dialog:

```
┌─────────────────────────────────────────┐
│  Classify: quarterly-report.xlsx        │
│                                         │
│  Hierarchy: [Commercial ▼]             │
│                                         │
│  Classification:                        │
│    ○ PUBLIC                             │
│    ○ INTERNAL                           │
│    ● CONFIDENTIAL                       │
│    ○ RESTRICTED                         │
│    ○ HIGHLY-CONFIDENTIAL                │
│                                         │
│  [Advanced: Resource Attributes ▼]      │
│                                         │
│  [ Cancel ]              [ Encrypt ]    │
└─────────────────────────────────────────┘
```

The hierarchy dropdown shows the tenant's configured hierarchy. If the folder has a default classification, it is pre-selected.

---

## 7. Browser Extension

### 7.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Browser Extension                         │
│                                                              │
│  ┌────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ Content Script  │  │ Background   │  │ Popup UI       │  │
│  │ (injected into  │  │ Service      │  │                │  │
│  │  dropbox.com)   │  │ Worker       │  │ • Auth status  │  │
│  │                 │  │              │  │ • Recent files │  │
│  │ • Overlay .ztdf │  │ • gRPC-Web   │  │ • Quick actions│  │
│  │   file icons    │  │   client     │  │ • Settings     │  │
│  │ • Inject        │  │ • OAuth flow │  │               │  │
│  │   classification│  │   handler    │  │               │  │
│  │   badges        │  │ • Web Crypto │  │               │  │
│  │ • Intercept     │  │   operations │  │               │  │
│  │   download      │  │ • Token mgmt │  │               │  │
│  │   clicks        │  │              │  │               │  │
│  └────────┬────────┘  └──────┬───────┘  └───────┬───────┘  │
│           │                  │                   │           │
│           └──────────────────┼───────────────────┘           │
│                              │                               │
└──────────────────────────────┼───────────────────────────────┘
                               │ gRPC-Web / HTTPS
                               │
                    ┌──────────▼──────────┐
                    │ Dropbox Connector   │
                    │ Service             │
                    └─────────────────────┘
```

### 7.2 Browser Support Matrix

| Browser | Extension API | Crypto API | Build Target |
|---------|-------------|-----------|-------------|
| Chrome | Manifest V3 | `crypto.subtle` | Chrome Web Store |
| Firefox | WebExtensions (MV3-compatible) | `crypto.subtle` | Firefox Add-ons |
| Safari | Safari Web Extensions (Xcode) | `crypto.subtle` | Mac App Store |

### 7.3 Content Script Behavior

The content script modifies the Dropbox web UI to:

1. **Classification badges** — show a colored badge on `.ztdf` files indicating their classification level (e.g., 🔴 SECRET, 🟡 CONFIDENTIAL, 🟢 PUBLIC).
2. **Download intercept** — when a user clicks to download a `.ztdf` file, intercept the download, decrypt via the Connector service, and deliver plaintext to the browser.
3. **Upload encryption** — when a user uploads a file to a protected folder via the Dropbox web UI, intercept the upload, prompt for classification, encrypt, and upload the `.ztdf` version.
4. **Sharing warnings** — when sharing a `.ztdf` file, display a notice: "This file is ZTDF-encrypted. Recipients will need Stratium authorization to decrypt."
5. **Policy status** — hovering over a `.ztdf` file shows a tooltip with classification, policy, last accessed, and encryption timestamp.

### 7.4 Crypto in Browser

The browser extension uses the Web Crypto API (`crypto.subtle`) for:
- AES-256-GCM decryption of file content (DEK provided by Connector service)
- SHA-256 hashing for content verification

The extension does NOT perform:
- Key generation or DEK wrapping (delegated to Connector → KAS)
- ABAC policy evaluation (delegated to Connector → Platform Service)
- Private key storage (all keys managed server-side)

---

## 8. Authentication

### 8.1 Dual Authentication Flow

Users authenticate with both Stratium and Dropbox:

```
User
  │
  ├─1. Authenticate with Stratium (OIDC / Keycloak)
  │    └─ Standard OAuth2 flow → access token + refresh token
  │    └─ Token contains: sub, email, role, department, clearance, groups
  │
  ├─2. Admin deploys Dropbox Business team token (one-time)
  │    └─ Team admin authorizes Stratium Dropbox Connector app
  │    └─ Team token stored encrypted in TenantDropboxConfig
  │
  └─3. Per-user Dropbox consent (OAuth2 PKCE)
       └─ User authorizes the Connector to access their /Apps/Stratium folder
       └─ Scoped to: files.content.read, files.content.write within App Folder
       └─ Refresh token stored encrypted in DropboxUserBinding
       └─ Access tokens auto-refreshed (short-lived)
```

### 8.2 Token Management

| Token | Storage | TTL | Refresh |
|-------|---------|-----|---------|
| Stratium OIDC access token | In-memory (client) | ~5 min | Via Keycloak refresh token |
| Stratium OIDC refresh token | OS Keychain | ~24 hours | Re-authenticate |
| Dropbox team token | Connector DB (encrypted) | Long-lived | Admin re-authorizes |
| Dropbox user access token | Connector DB (encrypted) | ~4 hours | Via refresh token |
| Dropbox user refresh token | Connector DB (encrypted) | Long-lived | User re-consents |

### 8.3 YubiKey Integration

For high-security deployments, the Stratium client credentials can be bound to a YubiKey PIV slot:

1. User's Stratium client key is generated on the YubiKey (slot 9a or 9d).
2. The desktop client uses the YubiKey for authentication to Stratium services.
3. Touch policy can be enforced (user must physically touch YubiKey for each decrypt operation).
4. This leverages Stratium's existing YubiKey support (`ClientKeyProvider: "yubikey"` in SDK config).

---

## 9. Dropbox App Configuration

### 9.1 App Registration

The Stratium Dropbox Connector requires a Dropbox App with the following configuration:

| Setting | Value |
|---------|-------|
| **App type** | Scoped access |
| **Access type** | App folder (creates /Apps/Stratium) |
| **Individual scopes** | `files.content.read`, `files.content.write`, `account_info.read` |
| **Team scopes** (Business) | `team_data.member`, `team_info.read`, `members.read` |
| **Webhook URI** | `https://<connector-host>/webhooks/dropbox` |
| **PKCE** | Required (no client_secret on desktop/browser clients) |

### 9.2 App Folder Structure

```
/Apps/Stratium/                      # Root App Folder (Dropbox-managed)
├── Finance/                          # User-created subfolder
│   ├── quarterly-report.xlsx.ztdf   # Encrypted file
│   └── budget-2026.xlsx.ztdf
├── Legal/
│   └── contract-draft.docx.ztdf
├── .stratium/                        # Hidden metadata folder
│   ├── config.json                  # Local sync configuration
│   └── .quarantine/                 # Quarantined files
│       └── tampered-file.pdf.ztdf
└── Personal/
    └── notes.md.ztdf
```

---

## 10. Tamper Detection and Quarantine

### 10.1 Detection Flow

On every sync cycle (triggered by webhook + cursor):

1. Fetch changed files via `/files/list_folder/continue`.
2. For each changed `.ztdf` file:
   a. Compare Dropbox `content_hash` with stored hash in the Connector DB.
   b. If hash matches → no change, skip.
   c. If hash differs → download and attempt to parse ZTDF manifest.
   d. If manifest parses successfully → legitimate update (e.g., re-encryption after key rotation). Update stored hashes.
   e. If manifest parse fails → **tamper detected**.

### 10.2 Quarantine Process

When tamper is detected:

1. Move the corrupted file to `/Apps/Stratium/.stratium/.quarantine/`.
2. Create a `QuarantineRecord` in the Connector database.
3. Notify the file owner via desktop notification and/or email.
4. Notify the tenant admin via the admin dashboard.
5. Log an audit event: `event_type: TAMPER_DETECTED`.

### 10.3 Resolution Options

Admins can resolve quarantined files via:

- **Restore** — move the quarantined file back to its original location (if admin determines it was a false positive).
- **Delete** — permanently remove the corrupted file.
- **Re-encrypt** — if the original plaintext is available (e.g., from backup or version history), re-encrypt and replace.

---

## 11. Migration

### 11.1 Phased Migration Flow

```
Admin
  │
  ├─1. Create migration job via API or admin dashboard
  │    └─ Specifies: source Dropbox path, classification, hierarchy, priority
  │
  ├─2. Connector scans source path via Dropbox API
  │    └─ /files/list_folder (recursive) → discover all files
  │    └─ Record total file count in MigrationJob.TotalFiles
  │
  ├─3. Worker processes files in priority order
  │    └─ For each file:
  │        ├─ Download from current Dropbox location
  │        ├─ Encrypt as .ztdf with specified classification
  │        ├─ Upload to /Apps/Stratium/<mirrored-path>/
  │        ├─ (Optional) Delete or archive original in source path
  │        └─ Update MigrationJob.ProcessedFiles counter
  │
  ├─4. Rate throttling applied per TenantDropboxConfig.RateLimitMaxOpsPerSec
  │
  └─5. Job completes → admin notified → summary report generated
```

### 11.2 Migration Constraints

- Files are processed at the admin-configured rate limit (max ops/sec).
- Multiple migration jobs can run concurrently but share the same rate limit.
- Failed files are retried 3 times with exponential backoff, then logged as failures.
- Migration can be paused and resumed without data loss.
- Large files (>150MB) use Dropbox upload sessions (chunked upload).

---

## 12. Compliance

### 12.1 Supported Frameworks (Tenant-Configurable)

| Framework | Key Requirements | How Stratium Dropbox Connector Addresses |
|-----------|-----------------|----------------------------------------|
| **FIPS 140-3** | FIPS-validated cryptographic modules | Leverages Stratium's existing FIPS mode. When `FIPS_ENABLED=true`, all crypto operations use FIPS-approved algorithms only. KYBER disabled. DEK sent plaintext over TLS (server-side RSA wrapping). |
| **SOC 2 Type II** | Audit trail, access controls, encryption | Full audit logging of every encrypt/decrypt/access-denied event. ABAC policy enforcement. Encryption at rest with organization-controlled keys. |
| **GDPR** | Data residency, right to erasure, data minimization | Connector service can be deployed in-region. Right to erasure: revoke user's keys → all their .ztdf files become permanently unreadable. No plaintext cached or stored by the Connector. |
| **ITAR/EAR** | Export-controlled data must remain under US jurisdiction/control | ZTDF encryption ensures Dropbox (even if hosted outside US) never has access to plaintext. Key material stays in Stratium services under organization control. Classification hierarchy enforces export control markings. |

### 12.2 Audit Trail

Every operation generates an audit log entry:

| Event Type | Captured Data |
|------------|--------------|
| `FILE_ENCRYPTED` | user, file, classification, hierarchy, policy_id, key_id, timestamp |
| `FILE_DECRYPTED` | user, file, classification, decision (ALLOW/DENY), policy_id, timestamp |
| `ACCESS_DENIED` | user, file, classification, decision (DENY), reason, timestamp |
| `TAMPER_DETECTED` | file, expected_hash, actual_hash, quarantine_action, timestamp |
| `MIGRATION_STARTED` | admin, source_path, classification, total_files, timestamp |
| `MIGRATION_COMPLETED` | job_id, processed, failed, duration, timestamp |
| `USER_BOUND` | user, dropbox_account, tenant, timestamp |
| `USER_UNBOUND` | user, dropbox_account, reason, timestamp |
| `QUARANTINE_RESOLVED` | admin, file, resolution, timestamp |

---

## 13. Security Considerations

### 13.1 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Dropbox breach exposes file contents | Files are ZTDF-encrypted; Dropbox only stores ciphertext. DEKs are wrapped with Stratium-controlled KEKs. |
| Dropbox insider accesses files | Same as above — no plaintext accessible without Stratium ABAC authorization. |
| Man-in-the-middle on Dropbox API | All Dropbox API calls over TLS. All Stratium service calls over mTLS. |
| Stolen Dropbox OAuth token | Scoped to App Folder only. Cannot access files outside /Apps/Stratium. Token rotation via short-lived access tokens. |
| Stolen Stratium OIDC token | Short-lived tokens (5 min). YubiKey binding requires physical presence. No offline decryption. |
| .ztdf file tampering | Dual hash detection + ZTDF manifest integrity verification + automatic quarantine. |
| Desktop client compromise | No plaintext cached on disk. Secrets in OS Keychain (hardware-backed on macOS). Temp files auto-deleted after viewing. |
| Browser extension compromise | No private keys in extension. All crypto orchestrated server-side. Extension only receives plaintext transiently for display. |
| Rate limit abuse during migration | Pre-configured throttle prevents exceeding Dropbox rate limits. |
| Unauthorized classification downgrade | Classification can only be set at encrypt time. Re-classification requires decrypt (ABAC check) + re-encrypt at new level. |

### 13.2 Secret Storage Summary

| Secret | Storage Location | Encryption |
|--------|-----------------|-----------|
| Dropbox team token | Connector DB | AES-256-GCM (admin key) |
| Dropbox user refresh token | Connector DB | AES-256-GCM (admin key) |
| Dropbox App secret | Connector DB | AES-256-GCM (admin key) |
| Stratium OIDC client credentials | OS Keychain (desktop) / Extension storage (browser) | OS-level encryption |
| Stratium user OIDC refresh token | OS Keychain (desktop) | OS-level encryption + optional YubiKey |
| Webhook verification secret | Connector DB | AES-256-GCM (admin key) |

---

## 14. Testing Strategy

### 14.1 Test Pyramid

| Layer | Focus | Tools | Coverage Target |
|-------|-------|-------|----------------|
| **Unit** | Crypto operations, hash computation, manifest parsing, classification logic | Go `testing`, table-driven tests | 90%+ for crypto/security paths |
| **Integration** | Connector ↔ Stratium services (KAS, Platform, Key Manager), Connector ↔ Dropbox API | Testcontainers (PostgreSQL), Dropbox API sandbox, gRPC test clients | 80%+ for service interactions |
| **Contract** | Verify Connector's expectations of Dropbox API v2 and Stratium gRPC APIs remain valid | Pact (consumer-driven contract tests) | All external API calls covered |
| **E2E** | Full workflows: encrypt → upload → share → decrypt, migration, tamper detection | Playwright (browser extension), desktop client test harness | Critical paths: encrypt, decrypt, share, quarantine |
| **Chaos** | Dropbox API failures, Stratium service outages, network partitions, webhook delivery failures | Custom chaos framework, toxiproxy for network simulation | Resilience of all sync and migration flows |

### 14.2 Chaos Test Scenarios

| Scenario | Expected Behavior |
|----------|------------------|
| Dropbox API returns 429 (rate limited) | Connector respects Retry-After, pauses operations, resumes automatically |
| Stratium KAS unreachable during decrypt | Client receives clear error: "Decryption unavailable — Stratium services unreachable" |
| Webhook delivery fails (Dropbox retries) | Connector handles duplicate webhook notifications idempotently |
| Dropbox API returns 5xx during migration | Migration job pauses, retries with exponential backoff, resumes |
| Network partition between Connector and Key Manager | In-flight encrypt operations fail cleanly, no partial .ztdf files uploaded |
| PostgreSQL (Connector DB) crash | Connector enters read-only mode, existing encrypted files remain accessible via Dropbox, sync pauses |
| Large file upload interrupted mid-stream | Dropbox upload session resumed (chunked upload checkpointing) |

---

## 15. MVP vs. GA Scope

### 15.1 MVP (Phase 1)

| Feature | Description |
|---------|------------|
| Desktop client (tray app) | macOS + Windows + Linux. System tray, settings window, classification prompt dialog. |
| Browser extension | Chrome + Firefox + Safari. Full encrypt/decrypt, classification badges, download intercept. |
| Core encrypt/decrypt | ZTDF encryption with AES-256-GCM, ABAC policy enforcement via KAS/Platform, .ztdf file format. |
| Protected folder (App Folder) | Files in /Apps/Stratium/ are encrypted. Hybrid: folder defaults + per-file classification override. |
| Zero-trust sharing | Dropbox sharing works for .ztdf blobs; decryption gated by ABAC policy. |
| Dual authentication | Stratium OIDC + Dropbox OAuth2 PKCE with team admin + per-user consent. |
| OS Keychain + YubiKey | Secret storage via OS keychain with optional YubiKey PIV binding. |
| Tamper detection + quarantine | Dual hash monitoring, automatic quarantine of corrupted files. |
| Webhook + cursor sync | Real-time change detection via Dropbox webhooks + cursor-based polling. |
| Pre-configured rate throttle | Admin-set max ops/sec for Dropbox API calls. |
| Connector service + database | Standalone gRPC service with own PostgreSQL database. mTLS to Stratium services. |
| Audit logging | All encrypt/decrypt/deny/tamper events logged. |
| Tenant-configurable hierarchy | NATO/DoD or Commercial classification hierarchies per tenant. |
| FIPS 140-3 support | Leverage Stratium's existing FIPS mode for all crypto operations. |

### 15.2 GA (Phase 2)

| Feature | Description |
|---------|------------|
| Phased migration tool | Admin-initiated, priority-based retroactive encryption of existing Dropbox files. |
| Admin dashboard | Web UI for encryption coverage, policy violations, quarantine management, migration status, audit logs. |
| Classification-based DLP rules | Admin-defined rules for auto-classification by path, file type, or metadata patterns. |
| Dropbox plan-aware throttling | Query Dropbox team plan limits, set migration throughput as percentage of monthly allowance, alert on approaching limits. |
| Advanced sharing controls | Sharing notifications, recipient authorization status, revocation of shared file access. |
| Bulk re-encryption (key rotation) | When Stratium keys rotate, automatically re-encrypt affected .ztdf files in Dropbox. |
| Mobile client (iOS/Android) | Encrypt/decrypt on mobile Dropbox apps. |
| Content-based auto-classification | ML/NLP scanning of file contents to suggest classification levels. |
| Multi-cloud expansion | Extensible architecture for Google Drive, OneDrive, Box connectors. |

---

## 16. Roadmap Items (Beyond GA)

| Item | Description |
|------|------------|
| Adaptive rate limiting | Replace pre-configured throttle with dynamic rate adjustment based on Dropbox 429 responses and Retry-After headers. |
| Dropbox plan-aware throttling | Integrate with `/team/features/get_values` for data transport limit awareness. |
| Real-time co-editing | Explore integration with Dropbox's file locking APIs for conflict resolution on encrypted files. |
| Dropbox Paper support | Investigate ZTDF encryption for Dropbox Paper documents (requires export → encrypt → re-import). |
| Agent authorization integration | When Stratium Agent Authorization (PRD_AGENT_AUTHORIZATION.md) ships, extend the Dropbox Connector to support delegation tokens for AI agent access to Dropbox files. |
| Cross-cloud ZTDF portability | Enable a file encrypted via the Dropbox Connector to be decrypted via a future Google Drive or OneDrive connector, maintaining the same ZTDF manifest and policies. |

---

## 17. Open Questions

| # | Question | Impact | Status |
|---|----------|--------|--------|
| 1 | Should the Connector service expose a REST API in addition to gRPC (for browser extension compatibility via gRPC-Web)? | Browser extension architecture | Open |
| 2 | How should file previews work for .ztdf files in Dropbox web UI — generate encrypted thumbnail, or rely entirely on the browser extension overlay? | UX for non-extension users | Open |
| 3 | What is the maximum file size the Connector should support for single-request encrypt/decrypt before requiring streaming? | Performance, memory | Open |
| 4 | Should the Connector support Dropbox Namespaces (team folders vs. personal folders) in the App Folder model? | Enterprise deployment | Open |
| 5 | How should the integration handle Dropbox's 30-day file recovery (deleted files)? Should we purge ZTDF metadata when Dropbox permanently deletes? | Data retention compliance | Open |
| 6 | Should classification downgrades (e.g., SECRET → CONFIDENTIAL) require admin approval, or should any authorized user be able to re-classify? | Policy governance | Open |
| 7 | What happens when a tenant's Stratium subscription expires — do .ztdf files in Dropbox become permanently unreadable? | Business continuity | Open |
