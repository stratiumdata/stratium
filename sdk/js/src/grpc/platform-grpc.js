/**
 * @fileoverview gRPC-Web client for Platform Service
 * @module grpc/platform-grpc
 */

import { createClient } from '@connectrpc/connect';
import { PlatformService } from '../generated/services/platform/platform_connect.js';

/**
 * Create a gRPC-Web Platform client
 *
 * @param {Object} transport - gRPC-Web transport (from createAuthenticatedTransport)
 * @returns {Object} Platform client
 *
 * @example
 * import { createAuthenticatedTransport } from '@stratiumdata/sdk/browser/grpc-transport';
 * import { createPlatformGrpcClient } from '@stratiumdata/sdk/grpc/platform-grpc';
 *
 * const transport = createAuthenticatedTransport(
 *   'http://localhost:8081',
 *   async () => await getToken()
 * );
 *
 * const client = createPlatformGrpcClient(transport);
 *
 * // Check access
 * const response = await client.checkAccess({
 *   subjectAttributes: { sub: 'user123' },
 *   resourceAttributes: { name: 'document' },
 *   action: 'read'
 * });
 */
export function createPlatformGrpcClient(transport) {
  return createClient(PlatformService, transport);
}

/**
 * Platform gRPC client class (for advanced usage)
 *
 * @example
 * import { PlatformGrpcClient } from '@stratiumdata/sdk/grpc/platform-grpc';
 *
 * const client = new PlatformGrpcClient(
 *   'http://localhost:8081',
 *   async () => await getToken()
 * );
 *
 * const response = await client.checkAccess({...});
 */
export class PlatformGrpcClient {
  /**
   * @param {string} baseUrl - Base URL for the Platform service
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
    this.client = createPlatformGrpcClient(transport);
  }

  /**
   * Check access for a subject to perform an action on a resource
   * @param {Object} request - Check access request
   * @returns {Promise<Object>} Check access response
   */
  async checkAccess(request) {
    return await this.client.checkAccess(request);
  }

  /**
   * Evaluate a policy
   * @param {Object} request - Evaluate policy request
   * @returns {Promise<Object>} Evaluate policy response
   */
  async evaluatePolicy(request) {
    return await this.client.evaluatePolicy(request);
  }
}
