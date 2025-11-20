/**
 * @fileoverview gRPC-Web client for Key Manager Service
 * @module grpc/key-manager-grpc
 */

import { createClient } from '@connectrpc/connect';
import { KeyManagerService } from '../generated/services/key-manager/key-manager_connect.js';

/**
 * Create a gRPC-Web Key Manager client
 *
 * @param {Object} transport - gRPC-Web transport (from createAuthenticatedTransport)
 * @returns {Object} Key Manager client
 *
 * @example
 * import { createAuthenticatedTransport } from '@stratiumdata/sdk/browser/grpc-transport';
 * import { createKeyManagerGrpcClient } from '@stratiumdata/sdk/grpc/key-manager-grpc';
 *
 * const transport = createAuthenticatedTransport(
 *   'http://localhost:8081',
 *   async () => await getToken()
 * );
 *
 * const client = createKeyManagerGrpcClient(transport);
 *
 * // Register a client key
 * const response = await client.registerClientKey({
 *   clientId: 'my-app',
 *   publicKeyPem: '-----BEGIN PUBLIC KEY-----\n...',
 *   keyType: 4, // ECC_P256
 *   expiresAt: expirationTimestamp
 * });
 */
export function createKeyManagerGrpcClient(transport) {
  return createClient(KeyManagerService, transport);
}

/**
 * Key Manager gRPC client class (for advanced usage)
 *
 * @example
 * import { KeyManagerGrpcClient } from '@stratiumdata/sdk/grpc/key-manager-grpc';
 *
 * const client = new KeyManagerGrpcClient(
 *   'http://localhost:8081',
 *   async () => await getToken()
 * );
 *
 * const response = await client.registerClientKey({...});
 */
export class KeyManagerGrpcClient {
  /**
   * @param {string} baseUrl - Base URL for the Key Manager service
   * @param {Function} [getToken] - Optional function that returns an auth token
   */
  constructor(baseUrl, getToken) {
    // Lazy load to avoid errors in non-browser environments
    let createAuthenticatedTransport;
    try {
      createAuthenticatedTransport = require('../browser/grpc-transport.js').createAuthenticatedTransport;
    } catch (e) {
      throw new Error(
        'gRPC-Web clients require browser environment and @connectrpc packages. ' +
        'Use the REST client instead for Node.js environments.'
      );
    }

    const transport = createAuthenticatedTransport(baseUrl, getToken);
    this.client = createKeyManagerGrpcClient(transport);
  }

  /**
   * Register a client public key
   * @param {Object} request - Register client key request
   * @returns {Promise<Object>} Register client key response
   */
  async registerClientKey(request) {
    return await this.client.registerClientKey(request);
  }

  /**
   * Get client key information
   * @param {Object} request - Get client key request
   * @returns {Promise<Object>} Get client key response
   */
  async getClientKey(request) {
    return await this.client.getClientKey(request);
  }

  /**
   * Revoke a client key
   * @param {Object} request - Revoke client key request
   * @returns {Promise<Object>} Revoke client key response
   */
  async revokeClientKey(request) {
    return await this.client.revokeClientKey(request);
  }

  /**
   * List client keys
   * @param {Object} request - List client keys request
   * @returns {Promise<Object>} List client keys response
   */
  async listClientKeys(request) {
    return await this.client.listClientKeys(request);
  }
}
