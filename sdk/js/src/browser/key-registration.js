/**
 * @fileoverview Client Key Registration Helpers (gRPC-Web)
 * @module browser/key-registration
 *
 * Browser-specific helpers for registering client keys with the Key Manager Service using gRPC-Web.
 */

import { exportPublicKey, jwkToPem } from './key-generation.js';
import { Timestamp } from '@bufbuild/protobuf';
import { KeyType } from '../generated/services/key-manager/key-manager_pb.js';
import { createKeyManagerGrpcClient } from '../grpc/key-manager-grpc.js';
import { createAuthenticatedTransport } from './grpc-transport.js';

/**
 * Register client's public key with the Key Manager Service using gRPC-Web
 *
 * @param {string} clientId - Client identifier
 * @param {CryptoKey} publicKey - Client's public key (from Web Crypto API)
 * @param {string} baseUrl - Base URL for Key Manager service
 * @param {number} [expiresIn=86400000] - Key expiration time in milliseconds (default 24 hours)
 * @param {Function} [getToken] - Optional function that returns an auth token
 * @returns {Promise<{keyId: string, expiresAt: Date}>} Registration result
 * @throws {Error} If registration fails or parameters are invalid
 *
 * @example
 * import { generateClientKeyPair, registerClientKey } from '@stratiumdata/sdk';
 *
 * const keyPair = await generateClientKeyPair();
 * const registration = await registerClientKey(
 *   'my-client-id',
 *   keyPair.publicKey,
 *   'http://localhost:8081',
 *   24 * 60 * 60 * 1000, // 24 hours
 *   async () => 'my-auth-token'
 * );
 * console.log('Key registered:', registration.keyId);
 */
export async function registerClientKey(
  clientId,
  publicKey,
  baseUrl,
  expiresIn = 24 * 60 * 60 * 1000,
  getToken
) {
  if (!clientId || clientId.trim() === '') {
    throw new Error('client ID cannot be empty');
  }

  // Export public key as JWK first
  const jwk = await exportPublicKey(publicKey);

  // Convert JWK to PEM format
  const pem = await jwkToPem(jwk);

  // Create Key Manager gRPC client
  const transport = createAuthenticatedTransport(baseUrl, getToken);
  const client = createKeyManagerGrpcClient(transport);

  // Calculate expiration time
  const expiresAt = new Date(Date.now() + expiresIn);
  const expiresAtTimestamp = Timestamp.fromDate(expiresAt);

  // Determine key type from JWK
  const keyType = inferKeyTypeFromJwk(jwk);

  // Register key
  const response = await client.registerClientKey({
    clientId: clientId,
    publicKeyPem: pem,
    keyType: keyType,
    expiresAt: expiresAtTimestamp,
  });

  if (!response.success || !response.key) {
    throw new Error(response.errorMessage || 'Failed to register client key');
  }

  const responseExpiresAt = response.key.expiresAt
    ? response.key.expiresAt.toDate()
    : expiresAt;

  return {
    keyId: response.key.keyId,
    expiresAt: responseExpiresAt,
  };
}

function inferKeyTypeFromJwk(jwk) {
  if (jwk.kty === 'EC' && jwk.crv === 'P-256') {
    return KeyType.ECC_P256;
  }
  if (jwk.kty === 'EC' && jwk.crv === 'P-384') {
    return KeyType.ECC_P384;
  }
  if (jwk.kty === 'RSA') {
    const modulusBytes = base64UrlToUint8Array(jwk.n);
    const bits = modulusBytes.length * 8;
    switch (bits) {
      case 2048:
        return KeyType.RSA_2048;
      case 3072:
        return KeyType.RSA_3072;
      case 4096:
        return KeyType.RSA_4096;
      default:
        throw new Error(`Unsupported RSA key size: ${bits}`);
    }
  }
  throw new Error(`Unsupported key type: ${jwk.kty} ${jwk.crv || ''}`);
}

function base64UrlToUint8Array(base64url) {
  const padding = '='.repeat((4 - (base64url.length % 4)) % 4);
  const base64 = (base64url + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    output[i] = raw.charCodeAt(i);
  }
  return output;
}
