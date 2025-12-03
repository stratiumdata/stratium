/**
 * @fileoverview Client Key Registration Helpers (gRPC for Node.js)
 * @module nodejs/key-registration
 *
 * Node.js-specific helpers for registering client keys with the Key Manager Service using gRPC.
 */

import { Timestamp } from '@bufbuild/protobuf';
import { KeyType } from '../generated/services/key-manager/key-manager_pb.js';
import { createKeyManagerGrpcClient } from '../grpc/key-manager-grpc.js';
import { createAuthenticatedTransport } from './grpc-transport.js';

/**
 * Register client's public key with the Key Manager Service using gRPC
 *
 * @param {string} clientId - Client identifier
 * @param {CryptoKey} publicKey - Client's public key (from Node.js Web Crypto API)
 * @param {string} baseUrl - Base URL for Key Manager service
 * @param {number} [expiresIn=86400000] - Key expiration time in milliseconds (default 24 hours)
 * @param {Function} [getToken] - Optional function that returns an auth token
 * @returns {Promise<{keyId: string, expiresAt: Date}>} Registration result
 * @throws {Error} If registration fails or parameters are invalid
 *
 * @example
 * import { generateClientKeyPair, registerClientKey } from '@stratiumdata/sdk/nodejs';
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
  publicKeyPem,
  baseUrl,
  expiresIn = 24 * 60 * 60 * 1000,
  getToken
) {
  if (!clientId || clientId.trim() === '') {
    throw new Error('client ID cannot be empty');
  }

  // Create Key Manager gRPC client
  const transport = createAuthenticatedTransport(baseUrl, getToken);
  const client = createKeyManagerGrpcClient(transport);

  // Calculate expiration time
  const expiresAt = new Date(Date.now() + expiresIn);
  const expiresAtTimestamp = Timestamp.fromDate(expiresAt);

  // Register key
  const response = await client.registerClientKey({
    clientId: clientId,
    publicKeyPem,
    keyType: KeyType.RSA_2048,
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
