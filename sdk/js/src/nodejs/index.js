/**
 * @fileoverview Node.js-specific exports for Stratium SDK
 * @module nodejs
 *
 * This module provides Node.js-compatible implementations using:
 * - Node.js Web Crypto API (crypto.webcrypto)
 * - File-based key storage
 * - Standard gRPC transport
 */

// Node.js ZTDF Client
export { ZtdfClient } from './ztdf-client.js';

// Node.js Key Management
export {
  generateClientKeyPair,
  exportPublicKey,
  exportPrivateKey,
  importPublicKey,
  importPrivateKey,
  jwkToPem,
} from './key-generation.js';

export {
  storeKeyPair,
  getKeyPair,
  getCurrentKeyPair,
  deleteKeyPair,
  cleanupExpiredKeys,
  listKeys,
  setStorageDirectory,
  getStorageDirectory,
} from './key-storage.js';

export {
  registerClientKey,
} from './key-registration.js';

export {
  decryptDEK,
} from './dek-decryption.js';

export {
  createAuthenticatedTransport,
} from './grpc-transport.js';

// Re-export shared modules
export { parseZtdfFile } from '../ztdf/parser.js';
export * from '../ztdf/crypto.js';
export * from '../utils/helpers.js';
export * from '../utils/constants.js';
export * from '../utils/errors.js';

// gRPC clients (same for both browser and Node.js)
export {
  createKeyAccessGrpcClient,
  KeyAccessGrpcClient,
} from '../grpc/key-access-grpc.js';

export {
  createKeyManagerGrpcClient,
  KeyManagerGrpcClient,
} from '../grpc/key-manager-grpc.js';

export {
  createPlatformGrpcClient,
  PlatformGrpcClient,
} from '../grpc/platform-grpc.js';