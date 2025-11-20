/**
 * @fileoverview gRPC-Web client for Key Access Service
 * @module grpc/key-access-grpc
 */

import { createClient } from '@connectrpc/connect';
import { KeyAccessService } from '../generated/services/key-access/key-access_connect.js';

/**
 * Create a gRPC-Web Key Access client
 *
 * @param {Object} transport - gRPC-Web transport (from createAuthenticatedTransport)
 * @returns {Object} Key Access client
 *
 * @example
 * import { createAuthenticatedTransport } from '@stratiumdata/sdk/browser/grpc-transport';
 * import { createKeyAccessGrpcClient } from '@stratiumdata/sdk/grpc/key-access-grpc';
 *
 * const transport = createAuthenticatedTransport(
 *   'http://localhost:8081',
 *   async () => await getToken()
 * );
 *
 * const client = createKeyAccessGrpcClient(transport);
 *
 * // Unwrap a DEK
 * const response = await client.unwrapDEK({
 *   resource: 'my-file.ztdf',
 *   wrappedDek: wrappedDekBytes,
 *   keyId: 'dek-key-123',
 *   clientKeyId: 'client-key-456',
 *   action: 'decrypt',
 *   context: {},
 *   policy: ''
 * });
 */
export function createKeyAccessGrpcClient(transport) {
  return createClient(KeyAccessService, transport);
}

/**
 * Key Access gRPC client class (for advanced usage)
 *
 * @example
 * import { KeyAccessGrpcClient } from '@stratiumdata/sdk/grpc/key-access-grpc';
 *
 * const client = new KeyAccessGrpcClient(
 *   'http://localhost:8081',
 *   async () => await getToken()
 * );
 *
 * const response = await client.unwrapDEK({...});
 */
export class KeyAccessGrpcClient {
  /**
   * @param {string} baseUrl - Base URL for the Key Access service
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
    this.client = createKeyAccessGrpcClient(transport);
  }

  /**
   * Unwrap a DEK for decryption
   * @param {Object} request - Unwrap DEK request
   * @returns {Promise<Object>} Unwrap DEK response
   */
  async unwrapDEK(request) {
    return await this.client.unwrapDEK(request);
  }

  /**
   * Request a new DEK for encryption
   * @param {Object} request - Request DEK request
   * @returns {Promise<Object>} Request DEK response
   */
  async requestDEK(request) {
    return await this.client.requestDEK(request);
  }
}
