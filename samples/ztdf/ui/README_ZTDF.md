# ZTDF Web Client Implementation

This directory contains a complete implementation of the ZTDF (Zero Trust Data Format) web client for decrypting encrypted files using WebCrypto APIs and gRPC-Web.

## Overview

The ZTDF web client enables users to decrypt `.ztdf` files in a web browser with end-to-end encryption, WebCrypto-based key management, and ABAC policy enforcement.

## Architecture

### Key Components

1. **WebCrypto Key Management** (`src/lib/crypto/`)
   - ECDH P-256 key pair generation (non-extractable)
   - IndexedDB storage for key metadata
   - Key registration with Key Manager Service
   - DEK decryption using ECIES

2. **ZTDF Client** (`src/lib/ztdf/`)
   - ZIP file parsing (manifest.json + payload)
   - DEK unwrapping via Key Access Service
   - AES-256-GCM payload decryption
   - Policy binding and integrity verification

3. **gRPC-Web Transport** (`src/lib/grpc-transport.ts`)
   - ConnectRPC client generation
   - Authenticated transport with JWT tokens
   - Key Access and Key Manager service clients

4. **React Components** (`src/components/`, `src/contexts/`)
   - ZtdfContext for application-wide client state
   - ZtdfDecryptor component for file upload and decryption UI

## File Structure

```
src/
├── lib/
│   ├── crypto/
│   │   ├── key-generation.ts      # WebCrypto ECDH P-256 key generation
│   │   ├── key-storage.ts         # IndexedDB key storage
│   │   ├── key-registration.ts    # Key Manager registration
│   │   └── dek-decryption.ts      # ECIES DEK decryption
│   ├── ztdf/
│   │   ├── parser.ts              # ZTDF file parsing
│   │   ├── crypto.ts              # Payload decryption and verification
│   │   └── client.ts              # Main ZTDF client class
│   └── grpc-transport.ts          # gRPC-Web client setup
├── generated/                     # Auto-generated protobuf code
├── contexts/
│   └── ZtdfContext.tsx           # React context for ZTDF client
├── components/
│   └── ZtdfDecryptor.tsx         # File decryption UI component
└── config/
    └── ztdf.ts                   # Configuration

```

## Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Edit `.env`:
```
VITE_KEY_ACCESS_URL=http://localhost:8081
VITE_KEY_MANAGER_URL=http://localhost:8081
VITE_CLIENT_KEY_EXPIRATION_MS=86400000  # 24 hours
```

### 3. Generate Protobuf Code

```bash
npm run proto:gen
```

This generates TypeScript clients from proto files and fixes import compatibility issues.

### 4. Run Development Server

```bash
npm run dev
```

## Usage

### Integrating ZTDF into Your App

1. **Wrap your app with ZtdfProvider**:

```typescript
import { ZtdfProvider } from './contexts/ZtdfContext';

function App() {
  return (
    <ZtdfProvider>
      {/* Your app components */}
    </ZtdfProvider>
  );
}
```

2. **Use the ZtdfDecryptor component**:

```typescript
import { ZtdfDecryptor } from './components/ZtdfDecryptor';

function MyPage() {
  return (
    <div>
      <h1>Decrypt ZTDF Files</h1>
      <ZtdfDecryptor />
    </div>
  );
}
```

3. **Or use the ZTDF client directly**:

```typescript
import { useZtdf } from './contexts/ZtdfContext';

function MyComponent() {
  const { isInitialized, initialize, decryptFile } = useZtdf();

  const handleDecrypt = async (file: File) => {
    if (!isInitialized) {
      await initialize();
    }
    
    const decrypted = await decryptFile(file);
    console.log('Decrypted:', decrypted.content);
    
    // Download decrypted file
    const blob = new Blob([decrypted.content], { 
      type: decrypted.contentType 
    });
    // ... download logic
  };

  return <div>{/* Your UI */}</div>;
}
```

## Security Features

### 1. Non-Extractable Keys
- Private keys are generated as non-extractable
- Keys cannot be exported or read from JavaScript
- Only CryptoKey handles are stored in IndexedDB

### 2. End-to-End Encryption
- DEK is encrypted end-to-end from KAS to client
- Server encrypts DEK with client's public key
- Only client's private key can decrypt

### 3. No Caching
- Decrypted files are never persisted
- Data is only in memory during decryption
- Cleared after download or page close

### 4. Policy Binding & Integrity
- HMAC-based policy binding verification
- SHA-256 payload hash verification
- ABAC policy enforcement on server

### 5. Key Expiration
- Client keys expire after 24 hours (configurable)
- Automatic cleanup of expired keys
- Keys regenerated on next use

## API Reference

### ZtdfClient

```typescript
class ZtdfClient {
  constructor(config?: ZtdfClientConfig)
  
  // Initialize client (generate/load keys)
  async initialize(): Promise<void>
  
  // Decrypt ZTDF file
  async unwrap(file: File, options?: UnwrapOptions): Promise<DecryptedFile>
  
  // Get current key metadata
  getKeyMetadata(): KeyMetadata | null
  
  // Check initialization status
  isInitialized(): boolean
}
```

### useZtdf Hook

```typescript
const {
  client,           // ZtdfClient instance
  isInitialized,    // Initialization status
  isInitializing,   // Initialization in progress
  error,            // Initialization error
  keyMetadata,      // Current key metadata
  initialize,       // Initialize client function
  decryptFile,      // Decrypt file function
} = useZtdf();
```

## Development

### Scripts

- `npm run dev` - Start development server
- `npm run build` - Build for production
- `npm run proto:gen` - Generate protobuf TypeScript code
- `npm run lint` - Run ESLint

### Generated Code

Protobuf code is generated with:
- `@bufbuild/protoc-gen-es` v2.10.0 for message types
- `@connectrpc/protoc-gen-connect-es` v1.7.0 for service clients

A post-generation script (`scripts/fix-proto-imports.cjs`) fixes import compatibility between these versions.

## Testing

To test the ZTDF decryption flow:

1. Ensure backend services are running (Key Access Service, Key Manager Service)
2. Have a valid `.ztdf` file
3. Navigate to the decryptor page
4. Upload the `.ztdf` file
5. Click "Decrypt File"
6. Download the decrypted content

## Troubleshooting

### "Client not initialized" error
Call `initialize()` before `decryptFile()`, or let the component handle initialization automatically.

### "Access denied" error
Check that:
- Your authentication token is valid
- ABAC policies allow access to the resource
- The correct policy is embedded in the ZTDF file

### Import errors with generated code
Run `npm run proto:gen` to regenerate and fix proto code.

### IndexedDB errors
Check browser console for IndexedDB permissions and quota issues.

## Production Considerations

1. **Environment Variables**: Use proper environment variables for production endpoints
2. **Error Handling**: Add comprehensive error handling and user feedback
3. **Logging**: Remove console.log statements or use proper logging
4. **Performance**: Consider streaming decryption for large files
5. **Browser Support**: Test on target browsers (requires modern browser with WebCrypto)

## Implementation Notes

This implementation follows the comprehensive plan in `/docs/comprehensive_plan.md` with:
- ✅ ConnectRPC for gRPC-Web (instead of @protobuf-ts)
- ✅ WebCrypto ECDH P-256 for client keys
- ✅ IndexedDB for key storage
- ✅ Full ZTDF decryption flow
- ✅ Policy binding and integrity verification
- ✅ No file caching
- ✅ React integration with Context API

## License

This code is part of the Stratium project.
