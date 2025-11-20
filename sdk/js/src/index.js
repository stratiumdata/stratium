/**
 * @fileoverview Stratium JavaScript SDK
 * @module @stratiumdata/sdk
 * @version 0.5.0
 */

// Main client
export { StratiumClient } from './client/index.js';

// Configuration
export { Config } from './client/config.js';

// Service clients
export { PlatformClient, DECISION_DENY, DECISION_ALLOW, DECISION_CONDITIONAL } from './services/platform.js';
export { KeyAccessClient } from './services/key-access.js';
export { KeyManagerClient } from './services/key-manager.js';

// Error classes
export {
  StratiumError,
  ValidationError,
  AuthenticationError,
  APIError,
  EncryptionError,
  ErrClientIDRequired,
  ErrResourceAttributesRequired,
  ErrActionRequired,
  ErrSubjectAttributesRequired,
  ErrRequestNil,
} from './utils/errors.js';

// Constants
export * from './utils/constants.js';

// ZTDF Crypto utilities
export {
  generateDEK,
  generateIV,
  encryptPayload,
  decryptPayload,
  calculatePayloadHash,
  verifyPayloadHash,
  calculatePolicyBinding,
  verifyPolicyBinding,
} from './ztdf/crypto.js';

// ZTDF Client and Parser (browser only)
export { ZtdfClient } from './ztdf/client.js';
export { parseZtdfFile } from './ztdf/parser.js';

// Utility helpers
export {
  validateSubjectIdentifier,
  createAuthHeaders,
  formatString,
  sleep,
  retryWithBackoff,
  base64ToBytes,
  bytesToBase64,
} from './utils/helpers.js';

// Browser-specific exports (Web Crypto API)
// These are only available in browser environments
export {
  generateClientKeyPair,
  exportPublicKey,
  importPublicKey,
  jwkToPem,
} from './browser/key-generation.js';

export {
  storeKeyPair,
  getKeyPair,
  getCurrentKeyPair,
  deleteKeyPair,
  cleanupExpiredKeys,
  listKeys,
} from './browser/key-storage.js';

// Re-export types via JSDoc (TypeScript will include these in .d.ts)
/**
 * @typedef {import('./browser/key-storage.js').KeyMetadata} KeyMetadata
 */

/**
 * @typedef {import('./browser/key-storage.js').StoredKeyPair} StoredKeyPair
 */

export {
  registerClientKey,
} from './browser/key-registration.js';

export {
  decryptDEK,
} from './browser/dek-decryption.js';

export {
  createAuthenticatedTransport,
} from './browser/grpc-transport.js';

// gRPC-Web clients (browser only - includes generated protobuf code)
export {
  createKeyAccessGrpcClient,
  KeyAccessGrpcClient,
} from './grpc/key-access-grpc.js';

export {
  createKeyManagerGrpcClient,
  KeyManagerGrpcClient,
} from './grpc/key-manager-grpc.js';

export {
  createPlatformGrpcClient,
  PlatformGrpcClient,
} from './grpc/platform-grpc.js';

// Generated protobuf types (for advanced users)
// Users can import these directly if needed:
// import { UnwrapDEKRequest } from '@stratiumdata/sdk/generated/services/key-access/key-access_pb';

// Default export
export { StratiumClient as default } from './client/index.js';