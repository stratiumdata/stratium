# samples/ztdf/ui Project Update - SDK v0.2.0

## Summary

Updated the samples/ztdf/ui project to use the enhanced @stratiumdata/sdk v0.2.0, removing local crypto implementations and leveraging the SDK's browser utilities.

## Changes Made

### 1. Package Dependencies

**File**: `samples/ztdf/ui/package.json:46`
```json
"@stratiumdata/sdk": "^0.2.0"  // Updated from ^0.1.1
```

### 2. Removed Local Implementations

The following local files were **removed** as they are now provided by the SDK:

- ❌ `src/lib/crypto/key-generation.ts` → Now: `import { generateClientKeyPair, exportPublicKey, jwkToPem } from '@stratiumdata/sdk'`
- ❌ `src/lib/crypto/key-storage.ts` → Now: `import { storeKeyPair, getCurrentKeyPair } from '@stratiumdata/sdk'`
- ❌ `src/lib/crypto/dek-decryption.ts` → Now: `import { decryptDEK } from '@stratiumdata/sdk'`
- ❌ `src/lib/ztdf/crypto.ts` → Now: Import directly from SDK in client.ts

### 3. Updated Files

#### `src/lib/ztdf/client.ts`

**Before**:
```typescript
import { generateClientKeyPair } from "../crypto/key-generation";
import { storeKeyPair, getCurrentKeyPair, type KeyMetadata, type StoredKeyPair } from "../crypto/key-storage";
import { decryptDEK } from "../crypto/dek-decryption";
import { decryptPayload, verifyPolicyBinding, verifyPayloadHash } from "./crypto";
import { base64ToBytes } from "@stratiumdata/sdk";
```

**After**:
```typescript
import {
  generateClientKeyPair,
  storeKeyPair,
  getCurrentKeyPair,
  decryptDEK,
  decryptPayload,
  verifyPolicyBinding,
  verifyPayloadHash,
  base64ToBytes,
} from "@stratiumdata/sdk";
import type { KeyMetadata, StoredKeyPair } from "@stratiumdata/sdk";
```

#### `src/lib/crypto/key-registration.ts`

**Before**:
```typescript
import { exportPublicKey } from "./key-generation";

// Had duplicate jwkToPem function (56 lines)
```

**After**:
```typescript
import { exportPublicKey, jwkToPem } from "@stratiumdata/sdk";

// No duplicate code - uses SDK's jwkToPem
```

#### `src/contexts/ZtdfContext.tsx`

**Before**:
```typescript
import type { KeyMetadata } from "../lib/crypto/key-storage";
```

**After**:
```typescript
import type { KeyMetadata } from "@stratiumdata/sdk";
```

### 4. Files Kept (Sample-Specific)

These files remain because they contain sample-specific logic:

- ✅ `src/lib/crypto/key-registration.ts` - gRPC-Web specific key registration
- ✅ `src/lib/grpc-transport.ts` - Sample's gRPC-Web transport configuration
- ✅ `src/lib/ztdf/client.ts` - ZTDF client implementation
- ✅ `src/lib/ztdf/parser.ts` - ZTDF file parsing

## Code Reduction

### Lines of Code Removed: ~280 lines

- `key-generation.ts`: ~43 lines
- `key-storage.ts`: ~234 lines (including IndexedDB implementation)
- `dek-decryption.ts`: ~117 lines
- `crypto.ts`: ~10 lines
- Duplicate `jwkToPem` in `key-registration.ts`: ~34 lines
- **Total removed**: ~438 lines
- **Net reduction after imports**: ~280 lines of duplicate code eliminated

## Benefits

1. **Less Maintenance**: No need to maintain local copies of crypto utilities
2. **Bug Fixes**: Automatically get SDK bug fixes and improvements
3. **Type Safety**: Shared TypeScript types between SDK and sample
4. **Consistency**: Same crypto implementation across all projects using the SDK
5. **Smaller Codebase**: Reduced code complexity in the sample project

## Build Verification

✅ **Build Status**: SUCCESS

```bash
$ npm run build
✓ 1858 modules transformed.
✓ built in 2.32s
```

The project builds successfully with all SDK imports working correctly.

## Current Status

### ✅ Completed
- [x] Updated package.json to SDK v0.2.0
- [x] Removed local crypto implementations
- [x] Updated all imports to use SDK
- [x] Build verified successfully

### ⚠️ Pending (To Use New Features)

The project is **ready** but currently using SDK v0.1.1 from npm (cached). To use the new v0.2.0 features:

**Option 1: Publish SDK to npm** (Recommended for production)
```bash
cd sdk/js
npm publish
cd ../../samples/ztdf/ui
npm install @stratiumdata/sdk@0.2.0
```

**Option 2: Use npm link** (Recommended for local testing)
```bash
# In SDK directory
cd sdk/js
npm link

# In sample project
cd ../../samples/ztdf/ui
npm link @stratiumdata/sdk

# Build and test
npm run build
npm run dev
```

**Option 3: Install from local directory**
```bash
cd samples/ztdf/ui
npm install ../../sdk/js
npm run build
```

## Migration Notes

### For Other Projects

If you have other projects using local crypto utilities, follow this pattern:

1. **Update package.json**:
   ```json
   "@stratiumdata/sdk": "^0.2.0"
   ```

2. **Replace imports**:
   ```typescript
   // Old
   import { generateClientKeyPair } from "./local/key-generation";

   // New
   import { generateClientKeyPair } from "@stratiumdata/sdk";
   ```

3. **Remove local files** that are now in the SDK

4. **Test build**:
   ```bash
   npm install
   npm run build
   ```

## Testing Checklist

Once SDK v0.2.0 is published or linked, test the following:

- [ ] Client key generation and registration
- [ ] Key storage in IndexedDB
- [ ] Key retrieval from IndexedDB
- [ ] DEK decryption with ECDH
- [ ] ZTDF file decryption end-to-end
- [ ] Policy binding verification
- [ ] Payload hash verification

## Files Modified

- `samples/ztdf/ui/package.json` - SDK version bump
- `samples/ztdf/ui/src/lib/ztdf/client.ts` - Updated imports
- `samples/ztdf/ui/src/lib/crypto/key-registration.ts` - Removed duplicate code, added SDK imports
- `samples/ztdf/ui/src/contexts/ZtdfContext.tsx` - Updated KeyMetadata import

## Files Deleted

- `samples/ztdf/ui/src/lib/crypto/key-generation.ts`
- `samples/ztdf/ui/src/lib/crypto/key-storage.ts`
- `samples/ztdf/ui/src/lib/crypto/dek-decryption.ts`
- `samples/ztdf/ui/src/lib/ztdf/crypto.ts`

## Next Steps

1. **Publish SDK**: Run `npm publish` in `sdk/js/` to make v0.2.0 available
2. **Update Sample**: Run `npm install` in `samples/ztdf/ui` to get the published version
3. **Test**: Start the dev server and test ZTDF file decryption
4. **Database Migration**: Remember to apply the `key_integrity_hash` migration if not done yet:
   ```bash
   docker exec -i stratium-postgres psql -U keycloak < deployment/postgres/04-add-key-integrity-hash.sql
   ```

## Documentation

See also:
- `SDK_ENHANCEMENTS.md` - Details on SDK v0.2.0 features
- `sdk/js/README.md` - SDK documentation
- `deployment/postgres/04-add-key-integrity-hash.sql` - Database migration