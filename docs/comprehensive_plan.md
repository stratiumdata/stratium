# Comprehensive Plan: ZTDF File Decryption in Web Client

## Overview
This document outlines the plan for implementing ZTDF (Zero Trust Data Format) file decryption in the `samples/ztdf/ui` web application, porting the Go ZTDF client functionality to TypeScript while using WebCrypto APIs for secure, non-extractable key management.

## Architecture

### 1. Backend: Envoy Proxy + gRPC-Web
- **Envoy Proxy Configuration** (`deployment/envoy.yaml`)
  - Add route for Key Access Service (`/key_access.KeyAccessService`)
  - Configure CORS for web client access
  - Enable gRPC-Web filter for protocol translation. Utilize connectrpc library to enable grpc-web.

### 2. TypeScript ZTDF Client
Port Go ZTDF client (`go/pkg/ztdf/client.go`) to TypeScript with the following key differences:
- Use WebCrypto API instead of Go crypto
- Use ECDH P-256 for client key pairs (non-extractable, immutable)
- Use gRPC-Web instead of standard gRPC
- Store keys in IndexedDB (non-extractable key handles only)
- No file caching - decrypt on demand

### 3. Client Key Management
- **WebCrypto-based Keys**
  - Algorithm: ECDH P-256 (Elliptic Curve Diffie-Hellman)
  - Properties: non-extractable, immutable
  - Storage: IndexedDB (store CryptoKey handles, not raw keys)
  - Registration: Short expiration time (configurable, e.g., 24 hours)

- **Key Registration Flow**
  1. Generate ECDH P-256 key pair using WebCrypto
  2. Export public key (JWK format)
  3. Register with Key Manager Service via gRPC-Web
  4. Store key ID and expiration in IndexedDB
  5. Periodic cleanup job removes expired keys from database

### 4. ZTDF Decryption Flow
```
1. User uploads .ztdf file
2. Parse ZIP (manifest.json + 0.payload)
3. Extract wrapped DEK from manifest
4. Call KeyAccessService.UnwrapDEK via gRPC-Web:
   - Send: wrapped_dek, key_id, client_key_id, policy
   - Auth: Keycloak JWT in Authorization header
   - ABAC evaluation on server
   - Receive: DEK encrypted with client's public key
5. Decrypt DEK using client's private key (WebCrypto)
6. Verify policy binding (REQUIRED)
7. Decrypt payload using DEK (AES-256-GCM)
8. Verify payload integrity (REQUIRED)
9. Display decrypted content
10. NO CACHING - discard decrypted data when done
```

## Implementation Tasks

### Phase 1: Envoy Proxy Configuration
**File:** `deployment/envoy.yaml`

#### 1.1 Add Key Access Service Route
- Add route matcher for `/key_access.KeyAccessService`
- Point to `key_access_service` cluster
- Configure timeout and CORS

#### 1.2 Add Service Cluster
- Define `key_access_service` cluster
- Configure health checks and load balancing

### Phase 2: gRPC-Web Client Generation
**Directory:** `samples/ztdf/ui/src/proto`

#### 2.1 Install Dependencies
```bash
npm install --save-dev @protobuf-ts/plugin
npm install @protobuf-ts/runtime @protobuf-ts/runtime-rpc grpc-web
```

#### 2.2 Generate TypeScript gRPC-Web Clients
- Copy proto files to `samples/ztdf/ui/proto/`
- Utilize connectrpc for gRPC-Web
- Generate client code:
  - `key-access.client.ts`

#### 2.3 Create gRPC-Web Transport
**File:** `samples/ztdf/ui/src/lib/grpc-transport.ts`
- Configure gRPC-Web transport
- Add authentication interceptor (Keycloak JWT)
- Error handling

### Phase 3: WebCrypto Key Management
**Directory:** `samples/ztdf/ui/src/lib/crypto`

#### 3.1 Key Generation Service
**File:** `key-generation.ts`
```typescript
// Generate ECDH P-256 key pair
async function generateClientKeyPair(): Promise<CryptoKeyPair>
// Export public key as JWK
async function exportPublicKey(key: CryptoKey): Promise<JsonWebKey>
```

#### 3.2 Key Storage Service
**File:** `key-storage.ts`
```typescript
// Store key pair in IndexedDB (non-extractable handles)
async function storeKeyPair(keyPair: CryptoKeyPair, metadata: KeyMetadata)
// Retrieve key pair from IndexedDB
async function getKeyPair(keyId: string): Promise<CryptoKeyPair | null>
// Delete expired keys
async function cleanupExpiredKeys()
```

#### 3.3 Key Registration Service
**File:** `key-registration.ts`
```typescript
// Register public key with Key Manager Service
async function registerClientKey(
  publicKey: JsonWebKey,
  expiresIn: number // milliseconds
): Promise<{ keyId: string, expiresAt: Date }>
```

#### 3.4 DEK Decryption Service
**File:** `dek-decryption.ts`
```typescript
// Decrypt DEK using client's private key (ECIES)
async function decryptDEK(
  encryptedDEK: Uint8Array,
  privateKey: CryptoKey
): Promise<Uint8Array>
```

### Phase 4: TypeScript ZTDF Client
**Directory:** `samples/ztdf/ui/src/lib/ztdf`

#### 4.1 ZTDF Parser
**File:** `parser.ts`
```typescript
interface ZtdfFile {
  manifest: Manifest
  payload: Uint8Array
}

// Parse .ztdf file (ZIP)
async function parseZtdfFile(file: File): Promise<ZtdfFile>
```

#### 4.2 Crypto Operations
**File:** `crypto.ts`
```typescript
// Decrypt payload with DEK (AES-256-GCM)
async function decryptPayload(
  encryptedPayload: Uint8Array,
  dek: Uint8Array,
  iv: Uint8Array
): Promise<Uint8Array>

// Verify policy binding
function verifyPolicyBinding(
  dek: Uint8Array,
  policy: string,
  expectedHash: string
): boolean

// Verify payload integrity
function verifyPayloadHash(
  encryptedPayload: Uint8Array,
  expectedHash: Uint8Array
): boolean
```

#### 4.3 ZTDF Client
**File:** `client.ts`
```typescript
class ZtdfClient {
  constructor(
    keyAccessClient: KeyAccessServiceClient,
    keyManagerClient: KeyManagerServiceClient,
    authProvider: AuthProvider
  )

  // Initialize client (generate/load keys)
  async initialize(): Promise<void>

  // Decrypt ZTDF file
  async unwrap(
    ztdfFile: File,
    options?: UnwrapOptions
  ): Promise<Uint8Array>
}
```

### Phase 5: Web UI Integration
**Directory:** `samples/ztdf/ui/src`

#### 5.1 ZTDF Context
**File:** `contexts/ZtdfContext.tsx`
```typescript
interface ZtdfContextValue {
  client: ZtdfClient | null
  isInitialized: boolean
  initialize: () => Promise<void>
  decryptFile: (file: File) => Promise<DecryptedFile>
}
```

#### 5.2 File Upload & Decrypt Component
**File:** `components/ZtdfDecryptor.tsx`
- File upload dropzone
- Progress indicator
- Error handling
- Display decrypted content
- Download decrypted file
- NO caching of decrypted data

#### 5.3 Viewer Page Integration
**File:** `pages/Viewer.tsx`
- Integrate ZtdfDecryptor component
- Handle authentication
- Display file metadata
- Show ABAC policy info
- Display access logs

### Phase 6: Database Schema & Cleanup
**Location:** Backend (Key Manager Service)

#### 6.1 Client Key Schema
```sql
CREATE TABLE client_keys (
  key_id UUID PRIMARY KEY,
  subject VARCHAR(255) NOT NULL,
  public_key JSONB NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  last_used_at TIMESTAMP
);

CREATE INDEX idx_client_keys_subject ON client_keys(subject);
CREATE INDEX idx_client_keys_expires_at ON client_keys(expires_at);
```

#### 6.2 Cleanup Job
**Implementation:** Database cron job or scheduled task
- Run periodically (e.g., hourly)
- Delete keys where `expires_at < NOW()`
- Only delete expired keys (not revoked keys)
- Log cleanup operations

**Note:** Short expiration (24 hours) prevents database bloat while maintaining security. Keys are NOT revoked, just expired and cleaned up.

### Phase 7: Configuration & Environment
**Directory:** `samples/ztdf/ui`

#### 7.1 Environment Variables
**File:** `.env`
```bash
VITE_KEY_ACCESS_URL=http://localhost:8081
VITE_KEY_MANAGER_URL=http://localhost:8081
VITE_KEYCLOAK_URL=http://localhost:8080
VITE_KEYCLOAK_REALM=stratium
VITE_KEYCLOAK_CLIENT_ID=ztdf-viewer
VITE_CLIENT_KEY_EXPIRATION_MS=86400000 # 24 hours
```

#### 7.2 Config Service
**File:** `src/config/ztdf.ts`
```typescript
export const ztdfConfig = {
  keyAccessUrl: import.meta.env.VITE_KEY_ACCESS_URL,
  keyManagerUrl: import.meta.env.VITE_KEY_MANAGER_URL,
  clientKeyExpirationMs: parseInt(
    import.meta.env.VITE_CLIENT_KEY_EXPIRATION_MS || '86400000'
  ),
}
```

## Security Considerations

### 1. Key Security
- **WebCrypto non-extractable keys:** Private keys cannot be exported or read
- **IndexedDB storage:** Only store CryptoKey handles, not raw key material
- **Key expiration:** Automatic cleanup prevents key accumulation
- **No caching:** Decrypted ZTDF files are never persisted

### 2. End-to-End Encryption
- DEK is encrypted end-to-end from KAS to client
- Server never sees plaintext DEK
- Server encrypts DEK with client's public key
- Only client's private key can decrypt

### 3. Access Control
- ABAC policy evaluation on server
- Keycloak JWT authentication
- Policy binding verification
- Integrity verification

### 4. Data Protection
- No decrypted file caching
- Decrypted data discarded after use
- Secure memory handling (as much as possible in browser)

## Testing Strategy

### Unit Tests
- WebCrypto key generation
- DEK encryption/decryption
- ZTDF parsing
- Policy binding verification
- Integrity verification

### Integration Tests
- gRPC-Web client communication
- Key registration flow
- Full decryption flow
- Error handling

### End-to-End Tests
- Upload ZTDF file
- Authenticate with Keycloak
- Decrypt file
- Verify content
- Key expiration and cleanup

## Deployment Considerations

### 1. Envoy Proxy
- Update deployment/envoy.yaml
- Restart Envoy service
- Verify routing

### 2. Database Migration
- Create client_keys table
- Set up cleanup job
- Configure expiration time

### 3. Web Client
- Build production bundle
- Configure environment variables
- Deploy to hosting platform

## Future Enhancements

### Optional Features (Not in Initial Implementation)
1. **Key Rotation:** Automatically rotate client keys before expiration
2. **Offline Support:** Cache encrypted files only (not decrypted)
3. **Streaming Decryption:** For large files
4. **Multi-key Support:** Handle multiple client keys per user
5. **Audit Logging:** Client-side access logs

## Migration Path

### From Go Client to TypeScript
1. Port crypto operations to WebCrypto
2. Translate gRPC to gRPC-Web
3. Adapt key management for browser environment
4. Implement IndexedDB storage
5. Remove file-based operations (use File API)

## Dependencies

### NPM Packages
```json
{
  "dependencies": {
    "@protobuf-ts/runtime": "^2.9.0",
    "@protobuf-ts/runtime-rpc": "^2.9.0",
    "grpc-web": "^1.4.2",
    "jszip": "^3.10.1"
  },
  "devDependencies": {
    "@protobuf-ts/plugin": "^2.9.0"
  }
}
```

### Proto Files
- `proto/services/key-access/key-access.proto`
- `proto/services/key-manager/key-manager.proto`
- `proto/models/ztdf.proto` (if exists)

## Success Criteria

1.  User can upload .ztdf file
2.  Client generates and registers WebCrypto keys
3.  Client successfully decrypts ZTDF files
4.  ABAC policy enforcement works
5.  No decrypted data is cached
6.  Expired keys are automatically cleaned up
7.  All operations work via gRPC-Web through Envoy
8.  Keys are non-extractable and immutable
9.  End-to-end encryption maintained
10.  UI is responsive and user-friendly

## Timeline Estimate

- **Phase 1:** Envoy Configuration - 2 hours
- **Phase 2:** gRPC-Web Setup - 4 hours
- **Phase 3:** WebCrypto Key Management - 8 hours
- **Phase 4:** ZTDF Client - 12 hours
- **Phase 5:** UI Integration - 8 hours
- **Phase 6:** Database & Cleanup - 4 hours
- **Phase 7:** Configuration - 2 hours
- **Testing & Debugging:** 8 hours

**Total:** ~48 hours (6 days)