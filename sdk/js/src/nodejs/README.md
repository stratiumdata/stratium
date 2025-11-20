# Stratium SDK - Node.js Module

Node.js-specific implementation of the Stratium SDK for server-side applications.

## Features

- **Node.js Web Crypto API**: Uses `crypto.webcrypto` for cryptographic operations
- **File-based key storage**: Stores keys in `.ztdf-keys` directory (configurable)
- **Standard gRPC**: Uses `@connectrpc/connect-node` for gRPC communication
- **Full ZTDF support**: Encrypt and decrypt ZTDF files

## Installation

```bash
npm install @stratiumdata/sdk @connectrpc/connect-node
```

## Quick Start

### Initialize Client

```javascript
import { ZtdfClient } from '@stratiumdata/sdk/nodejs';

const client = new ZtdfClient({
  keyAccessUrl: 'http://localhost:8081',
  keyManagerUrl: 'http://localhost:8081',
  clientId: 'my-server-app',
  clientKeyExpirationMs: 24 * 60 * 60 * 1000, // 24 hours
  getToken: async () => await getMyAuthToken(),
  debug: true
});

// Initialize (generates/loads keys)
await client.initialize();
```

### Encrypt Data (Wrap)

```javascript
import { readFile, writeFile } from 'fs/promises';

// Read plaintext file
const plaintext = await readFile('/path/to/document.pdf');

// Encrypt to ZTDF
const ztdfBuffer = await client.wrap(plaintext, {
  filename: 'document.pdf',
  contentType: 'application/pdf',
  resource: 'financial-reports',
  resourceAttributes: {
    classification: 'confidential',
    department: 'finance'
  },
  integrityCheck: true
});

// Save ZTDF file
await writeFile('/path/to/document.pdf.ztdf', ztdfBuffer);
```

### Decrypt Data (Unwrap)

```javascript
// Decrypt from file path
const result = await client.unwrap('/path/to/document.pdf.ztdf');

console.log('Filename:', result.filename);
console.log('Content type:', result.contentType);
console.log('Content length:', result.content.length);

// Save decrypted content
await writeFile('/path/to/decrypted.pdf', result.content);

// Or decrypt from Buffer
const ztdfBuffer = await readFile('/path/to/file.ztdf');
const result2 = await client.unwrap(ztdfBuffer);
```

## Configuration

### Key Storage Directory

By default, keys are stored in `./.ztdf-keys`. You can configure this:

```javascript
import { setStorageDirectory } from '@stratiumdata/sdk/nodejs';

// Set custom key storage directory
setStorageDirectory('/var/app/secrets/ztdf-keys');
```

### Key Management

```javascript
import {
  listKeys,
  getKeyPair,
  deleteKeyPair,
  cleanupExpiredKeys
} from '@stratiumdata/sdk/nodejs';

// List all keys
const keys = await listKeys();
keys.forEach(k => console.log(k.keyId, k.expiresAt));

// Get specific key
const keyPair = await getKeyPair('key-id-123');

// Clean up expired keys
const deleted = await cleanupExpiredKeys();
console.log(`Deleted ${deleted} expired keys`);
```

## Advanced Usage

### Manual Key Generation

```javascript
import {
  generateClientKeyPair,
  exportPublicKey,
  exportPrivateKey
} from '@stratiumdata/sdk/nodejs';

// Generate key pair
const keyPair = await generateClientKeyPair();

// Export keys
const publicKeyJwk = await exportPublicKey(keyPair.publicKey);
const privateKeyJwk = await exportPrivateKey(keyPair.privateKey);

// Save to file
await writeFile('public-key.json', JSON.stringify(publicKeyJwk));
await writeFile('private-key.json', JSON.stringify(privateKeyJwk));
```

### Direct Crypto Operations

```javascript
import {
  generateDEK,
  encryptPayload,
  decryptPayload,
  calculatePayloadHash
} from '@stratiumdata/sdk/nodejs';

// Generate DEK
const dek = generateDEK();

// Encrypt data
const plaintext = Buffer.from('Hello, World!');
const { ciphertext, iv } = await encryptPayload(plaintext, dek);

// Calculate hash
const hash = await calculatePayloadHash(plaintext);

// Decrypt
const decrypted = await decryptPayload(ciphertext, dek, iv);
```

## Differences from Browser SDK

| Feature | Node.js | Browser |
|---------|---------|---------|
| Key Storage | File system | IndexedDB |
| Crypto API | `crypto.webcrypto` | `window.crypto` |
| gRPC Transport | `connect-node` | `connect-web` |
| Keys Exportable | ✅ Yes | ❌ No (non-extractable) |
| File Operations | Native `fs` | File API / Blobs |

## TypeScript Support

The SDK includes TypeScript definitions:

```typescript
import { ZtdfClient } from '@stratiumdata/sdk/nodejs';

const client: ZtdfClient = new ZtdfClient({
  keyAccessUrl: 'http://localhost:8081',
  keyManagerUrl: 'http://localhost:8081',
  clientId: 'my-app',
});

await client.initialize();
const buffer: Buffer = await client.wrap(plaintext, options);
```

## Error Handling

```javascript
try {
  await client.initialize();
} catch (error) {
  if (error.message.includes('gRPC')) {
    console.error('gRPC connection failed:', error);
  } else if (error.message.includes('auth')) {
    console.error('Authentication failed:', error);
  }
}
```

## Environment Requirements

- **Node.js**: v15.0.0 or higher (for `crypto.webcrypto`)
- **Recommended**: Node.js v19+ (has global `crypto` object)

## License

Apache-2.0