# Stratium JavaScript SDK

Official JavaScript SDK for Stratium - Zero Trust Data Platform

## Features

- **Authorization Decisions**: Make policy-based access control decisions
- **Data Encryption Keys**: Request and unwrap DEKs for data encryption
- **ZTDF Support**: Built-in cryptographic utilities for Zero Trust Data Format
- **OIDC Authentication**: Automatic token management with refresh
- **TypeScript Ready**: Full TypeScript type definitions included
- **Modern JavaScript**: ES6+ with async/await support
- **Browser & Node.js**: Works in both environments

## Installation

```bash
npm install @stratium/sdk
```

## Quick Start

### Basic Authorization

```javascript
import { StratiumClient, DECISION_ALLOW } from '@stratium/sdk';

const client = new StratiumClient({
  platformAddress: 'platform.example.com:50051',
  oidc: {
    issuerURL: 'https://keycloak.example.com/realms/stratium',
    clientID: 'my-app',
    clientSecret: 'secret'
  }
});

// Check if user can access a resource
const allowed = await client.platform.checkAccess({
  subjectAttributes: {
    sub: 'user123',
    department: 'engineering'
  },
  resourceAttributes: {
    name: 'document-service',
    type: 'service'
  },
  action: 'read'
});

if (allowed) {
  console.log('Access granted!');
}
```

### Policy Management

```javascript
// Create a new policy
const policy = await client.pap.createPolicy({
  name: 'engineering-access',
  description: 'Engineering department access policy',
  rules: {
    subject: { department: 'engineering' },
    resource: { type: 'service' },
    actions: ['read', 'write']
  },
  active: true
});

// Create an entitlement
const entitlement = await client.pap.createEntitlement({
  subject: 'user123',
  resource: 'document-service',
  actions: ['read', 'write'],
  active: true
});

// List all policies
const policies = await client.pap.listPolicies();
```

### Data Encryption (ZTDF)

```javascript
import { generateDEK, encryptPayload } from '@stratium/sdk';

// Generate a data encryption key
const dek = generateDEK();

// Encrypt data
const plaintext = new TextEncoder().encode('Secret data');
const { ciphertext, iv } = await encryptPayload(plaintext, dek);

// Request wrapped DEK from Key Access service
const { wrappedDEK, keyID } = await client.keyAccess.requestDEK({
  clientID: 'my-app',
  resourceAttributes: { name: 'my-document' },
  purpose: 'encryption'
});
```

## Configuration

### StratiumClient Options

```javascript
const client = new StratiumClient({
  // Service addresses
  platformAddress: 'platform.example.com:50051',    // Platform service
  keyAccessAddress: 'key-access.example.com:50053',  // Key Access service

  // OIDC authentication (optional)
  oidc: {
    issuerURL: 'https://keycloak.example.com/realms/stratium',
    clientID: 'my-app',
    clientSecret: 'secret',
    scopes: ['openid', 'profile', 'email']  // Optional
  },

  // Connection options
  timeout: 30000,        // Request timeout in milliseconds (default: 30000)
  retryAttempts: 3,      // Number of retry attempts (default: 3)
  useTLS: false          // Use TLS for connections (default: false)
});
```

## API Reference

### Platform Client

#### getDecision(request)

Make an authorization decision.

```javascript
const decision = await client.platform.getDecision({
  subjectAttributes: {
    sub: 'user123',
    email: 'user@example.com',
    department: 'engineering'
  },
  resourceAttributes: {
    name: 'document-service',
    type: 'service'
  },
  action: 'read',
  context: {
    ip_address: '192.168.1.100',
    time: new Date().toISOString()
  }
});

console.log(decision.decision);      // 0=deny, 1=allow, 2=conditional
console.log(decision.reason);        // Reason for the decision
console.log(decision.evaluatedPolicy); // Policy that made the decision
```

#### checkAccess(request)

Convenience method that returns `true` if access is allowed.

```javascript
const allowed = await client.platform.checkAccess({
  subjectAttributes: { sub: 'user123' },
  resourceAttributes: { name: 'document-service' },
  action: 'read'
});
```

#### getEntitlements(subjectAttributes)

Get all entitlements for a subject.

```javascript
const entitlements = await client.platform.getEntitlements({
  sub: 'user123'
});
```

### Key Access Client

#### requestDEK(request)

Request a wrapped DEK for encryption.

```javascript
const { wrappedDEK, keyID } = await client.keyAccess.requestDEK({
  clientID: 'my-app',
  resourceAttributes: {
    name: 'my-document',
    type: 'document'
  },
  purpose: 'encryption',
  context: {}
});
```

#### unwrapDEK(clientID, wrappedDEK)

Unwrap a DEK for decryption.

```javascript
const dek = await client.keyAccess.unwrapDEK('my-app', wrappedDEK);
```

## ZTDF Cryptographic Utilities

### Key Generation

```javascript
import { generateDEK, generateIV } from '@stratium/sdk';

const dek = generateDEK();  // 32-byte AES-256 key
const iv = generateIV();    // 12-byte IV for GCM
```

### Encryption/Decryption

```javascript
import { encryptPayload, decryptPayload } from '@stratium/sdk';

// Encrypt
const plaintext = new TextEncoder().encode('Secret data');
const { ciphertext, iv } = await encryptPayload(plaintext, dek);

// Decrypt
const decrypted = await decryptPayload(ciphertext, dek, iv);
const text = new TextDecoder().decode(decrypted);
```

### Policy Binding

```javascript
import { calculatePolicyBinding, verifyPolicyBinding } from '@stratium/sdk';

// Calculate binding
const binding = await calculatePolicyBinding(dek, policyBase64);

// Verify binding
const valid = await verifyPolicyBinding(dek, policyBase64, expectedBinding);
```

## Error Handling

The SDK provides typed errors for better error handling:

```javascript
import {
  StratiumError,
  ValidationError,
  AuthenticationError,
  APIError,
  EncryptionError
} from '@stratium/sdk';

try {
  await client.platform.checkAccess(request);
} catch (error) {
  if (error instanceof ValidationError) {
    console.log('Validation failed:', error.field, error.message);
  } else if (error instanceof AuthenticationError) {
    console.log('Auth failed:', error.message);
  } else if (error instanceof APIError) {
    console.log('API error:', error.statusCode, error.message);
  }
}
```

## Browser Usage

The SDK works in modern browsers with Web Crypto API support:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Stratium SDK Example</title>
</head>
<body>
  <script type="module">
    import { StratiumClient } from './node_modules/@stratium/sdk/dist/index.esm.js';

    const client = new StratiumClient({
      platformAddress: 'platform.example.com:50051',
      oidc: {
        issuerURL: 'https://keycloak.example.com/realms/stratium',
        clientID: 'browser-app',
        clientSecret: 'secret'
      }
    });

    async function checkAccess() {
      const allowed = await client.platform.checkAccess({
        subjectAttributes: { sub: 'user123' },
        resourceAttributes: { name: 'document' },
        action: 'read'
      });

      document.getElementById('result').textContent =
        allowed ? 'Access Granted' : 'Access Denied';
    }

    document.getElementById('checkBtn').addEventListener('click', checkAccess);
  </script>

  <button id="checkBtn">Check Access</button>
  <div id="result"></div>
</body>
</html>
```

## Examples

See the `examples/` directory for complete examples:

- `examples/basic/authorization.js` - Authorization decisions
- `examples/basic/policy-management.js` - Policy and entitlement management
- `examples/web/` - Browser-based examples

## Development

### Build

```bash
npm install
npm run build
```

### Test

```bash
npm test
```

### Lint

```bash
npm run lint
```

## License

Apache-2.0

## Support

For issues and feature requests, please visit:
https://github.com/stratiumdata/sdk/issues