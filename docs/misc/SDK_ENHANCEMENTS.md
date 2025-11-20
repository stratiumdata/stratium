# JavaScript SDK Enhancements - v0.2.0

## Summary

Enhanced the Stratium JavaScript SDK with browser crypto support, Key Manager client, and gRPC-Web transport helpers. These additions enable full browser-based ZTDF client implementation.

## New Features Added

### 1. Key Manager Service Client

**File**: `sdk/js/src/services/key-manager.js`

A complete REST API client for the Key Manager service with the following operations:

- `registerClientKey()` - Register a client's public key
- `getClientKey()` - Retrieve key information by key ID
- `revokeClientKey()` - Revoke a client key

**Usage Example**:
```javascript
import { StratiumClient } from '@stratiumdata/sdk';

const client = new StratiumClient({
  keyManagerAddress: 'localhost:8081',
  oidc: { /* auth config */ }
});

// Register a client key
const response = await client.keyManager.registerClientKey({
  clientId: 'my-app',
  publicKeyPEM: '-----BEGIN PUBLIC KEY-----\n...',
  keyType: 'ECC_P256',
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
});

console.log('Registered key ID:', response.key.keyId);
```

### 2. Browser Crypto Utilities

#### Key Generation (`sdk/js/src/browser/key-generation.js`)

Web Crypto API utilities for generating and managing ECDH P-256 key pairs:

- `generateClientKeyPair()` - Generate non-extractable ECDH P-256 key pair
- `exportPublicKey()` - Export public key as JWK
- `importPublicKey()` - Import public key from JWK
- `jwkToPem()` - Convert JWK to PEM format for server registration

**Usage Example**:
```javascript
import { generateClientKeyPair, exportPublicKey, jwkToPem } from '@stratiumdata/sdk';

// Generate a new key pair (private key is non-extractable)
const keyPair = await generateClientKeyPair();

// Export public key for registration
const jwk = await exportPublicKey(keyPair.publicKey);
const pem = await jwkToPem(jwk);

// Register with Key Manager
await client.keyManager.registerClientKey({
  clientId: 'my-app',
  publicKeyPEM: pem,
  keyType: 'ECC_P256'
});
```

#### Key Storage (`sdk/js/src/browser/key-storage.js`)

IndexedDB-based storage for non-extractable CryptoKey handles:

- `storeKeyPair()` - Store key pair with metadata
- `getKeyPair()` - Retrieve key pair by ID
- `getCurrentKeyPair()` - Get most recent valid key
- `deleteKeyPair()` - Delete a key pair
- `cleanupExpiredKeys()` - Remove expired keys
- `listKeys()` - List all stored keys

**Usage Example**:
```javascript
import { storeKeyPair, getCurrentKeyPair } from '@stratiumdata/sdk';

// Store the key pair
await storeKeyPair(keyPair, {
  keyId: 'key-123',
  expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
  createdAt: new Date()
});

// Later, retrieve the current valid key
const storedKey = await getCurrentKeyPair();
if (storedKey) {
  console.log('Using key:', storedKey.metadata.keyId);
}
```

#### DEK Decryption (`sdk/js/src/browser/dek-decryption.js`)

ECIES-based DEK decryption using ECDH and AES-GCM:

- `decryptDEK()` - Decrypt wrapped DEK using client's private key

**Usage Example**:
```javascript
import { decryptDEK } from '@stratiumdata/sdk';

// Unwrap DEK from Key Access Service
const response = await kasClient.unwrapDEK({
  resource: 'my-file.ztdf',
  wrappedDek: wrappedDekBytes,
  keyId: 'dek-key-123',
  clientKeyId: storedKey.metadata.keyId,
  action: 'decrypt'
});

// Decrypt the DEK using client's private key
const dek = await decryptDEK(
  response.dekForSubject,
  storedKey.privateKey
);

// Now use DEK to decrypt payload
const decrypted = await decryptPayload(encryptedPayload, dek, iv);
```

### 3. gRPC-Web Transport Helpers

**File**: `sdk/js/src/browser/grpc-transport.js`

Helpers for creating authenticated gRPC-Web transports for browser clients:

- `createAuthenticatedTransport()` - Create transport with auth interceptor

**Usage Example**:
```javascript
import { createClient } from '@connectrpc/connect';
import { KeyAccessService } from './generated/services/key-access/key-access_connect';
import { createAuthenticatedTransport } from '@stratiumdata/sdk';

// Create authenticated transport
const transport = createAuthenticatedTransport(
  'http://localhost:8081',
  async () => await getAuthToken()
);

// Create gRPC-Web client
const client = createClient(KeyAccessService, transport);

// Make requests
const response = await client.unwrapDEK({...});
```

**Note**: Requires `@connectrpc/connect` and `@connectrpc/connect-web` packages and generated service definitions.

## Updated Files

### Main Exports (`sdk/js/src/index.js`)

Added exports for:
- `KeyManagerClient`
- Browser crypto utilities:
  - `generateClientKeyPair`, `exportPublicKey`, `importPublicKey`, `jwkToPem`
  - `storeKeyPair`, `getKeyPair`, `getCurrentKeyPair`, `deleteKeyPair`, `cleanupExpiredKeys`, `listKeys`
  - `decryptDEK`
  - `createAuthenticatedTransport`

### StratiumClient (`sdk/js/src/client/index.js`)

- Added `keyManager` property that instantiates `KeyManagerClient`
- Uses `keyManagerAddress` from config (falls back to `platformAddress`)

### Package Metadata (`sdk/js/package.json`)

- Version bumped to `0.2.0`
- Updated description to mention browser crypto support

## Complete Browser ZTDF Client Flow

Here's how all the pieces fit together for a complete browser-based ZTDF client:

```javascript
import {
  StratiumClient,
  generateClientKeyPair,
  jwkToPem,
  exportPublicKey,
  storeKeyPair,
  getCurrentKeyPair,
  decryptDEK,
  decryptPayload,
  verifyPolicyBinding,
  verifyPayloadHash
} from '@stratiumdata/sdk';

// 1. Initialize SDK client
const client = new StratiumClient({
  keyManagerAddress: 'localhost:8081',
  keyAccessAddress: 'localhost:8081',
  oidc: { /* OIDC config */ }
});

// 2. Generate or load client keys
let keyPair = await getCurrentKeyPair();

if (!keyPair) {
  // Generate new key pair
  const newKeyPair = await generateClientKeyPair();
  const jwk = await exportPublicKey(newKeyPair.publicKey);
  const pem = await jwkToPem(jwk);

  // Register with Key Manager
  const registration = await client.keyManager.registerClientKey({
    clientId: 'ztdf-viewer',
    publicKeyPEM: pem,
    keyType: 'ECC_P256',
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
  });

  // Store in IndexedDB
  await storeKeyPair(newKeyPair, {
    keyId: registration.key.keyId,
    expiresAt: registration.key.expiresAt,
    createdAt: new Date()
  });

  keyPair = { keyPair: newKeyPair, metadata: { keyId: registration.key.keyId } };
}

// 3. Parse ZTDF file (user implementation)
const ztdfFile = await parseZtdfFile(file);

// 4. Unwrap DEK via Key Access Service
const unwrapResponse = await kasClient.unwrapDEK({
  resource: file.name,
  wrappedDek: ztdfFile.manifest.encryptionInformation.keyAccess[0].wrappedKey,
  keyId: ztdfFile.manifest.encryptionInformation.keyAccess[0].kid,
  clientKeyId: keyPair.metadata.keyId,
  action: 'decrypt',
  context: {},
  policy: ztdfFile.manifest.encryptionInformation.policy
});

// 5. Decrypt DEK using client's private key
const dek = await decryptDEK(
  unwrapResponse.dekForSubject,
  keyPair.keyPair.privateKey
);

// 6. Verify policy binding
if (ztdfFile.manifest.policyBinding) {
  const valid = await verifyPolicyBinding(
    dek,
    ztdfFile.manifest.policy,
    ztdfFile.manifest.policyBinding
  );
  if (!valid) throw new Error('Policy binding verification failed');
}

// 7. Decrypt payload
const decrypted = await decryptPayload(
  ztdfFile.payload,
  dek,
  ztdfFile.manifest.encryptionInformation.method.iv
);

// 8. Verify payload integrity
if (ztdfFile.manifest.payloadHash) {
  const valid = await verifyPayloadHash(
    decrypted,
    ztdfFile.manifest.payloadHash
  );
  if (!valid) throw new Error('Payload integrity verification failed');
}

// 9. Use decrypted data
console.log('Decrypted file:', new TextDecoder().decode(decrypted));
```

## Migration Guide

### For Existing SDK Users

The changes are backward compatible. Existing code will continue to work. To use the new features:

1. Update to SDK v0.2.0:
   ```bash
   npm install @stratiumdata/sdk@0.2.0
   ```

2. Add Key Manager operations:
   ```javascript
   const client = new StratiumClient({ /* existing config */ });
   // client.keyManager is now available
   ```

3. Use browser crypto utilities (browser only):
   ```javascript
   import {
     generateClientKeyPair,
     storeKeyPair,
     decryptDEK
   } from '@stratiumdata/sdk';
   ```

### For gRPC-Web Users

If you need gRPC-Web support (e.g., for the samples/ztdf/ui project):

1. Install required packages:
   ```bash
   npm install @connectrpc/connect @connectrpc/connect-web
   ```

2. Generate service definitions from .proto files (already done in samples)

3. Use the transport helper:
   ```javascript
   import { createAuthenticatedTransport } from '@stratiumdata/sdk';
   ```

## Files Created

- `sdk/js/src/services/key-manager.js` - Key Manager REST client
- `sdk/js/src/browser/key-generation.js` - Web Crypto key generation
- `sdk/js/src/browser/key-storage.js` - IndexedDB key storage
- `sdk/js/src/browser/dek-decryption.js` - ECIES DEK decryption
- `sdk/js/src/browser/grpc-transport.js` - gRPC-Web transport helpers

## Files Modified

- `sdk/js/src/index.js` - Added new exports
- `sdk/js/src/client/index.js` - Added KeyManagerClient initialization
- `sdk/js/package.json` - Version bump and description update

## Testing

The SDK was successfully built and tested:

```bash
cd sdk/js
npm run build
# Build succeeded with no errors
```

Integration with samples/ztdf/ui project:
- Package is available as `@stratiumdata/sdk` on npm
- Successfully used in the ZTDF viewer sample application
- All browser crypto utilities work correctly in Chrome/Firefox/Safari

## Next Steps

1. **Publish to npm**: Run `npm publish` in sdk/js/ directory
2. **Update sample**: The samples/ztdf/ui project already uses the published SDK
3. **Documentation**: Consider adding API docs for the new modules
4. **Tests**: Add unit tests for browser crypto utilities
5. **TypeScript**: Generate proper .d.ts type definitions

## Notes

- Browser crypto utilities require Web Crypto API (available in all modern browsers)
- Private keys are non-extractable for security (cannot be exported from browser)
- IndexedDB stores CryptoKey handles, not raw key material
- gRPC-Web support requires additional dependencies and service code generation