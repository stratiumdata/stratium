/**
 * @fileoverview gRPC Transport Helpers for Node.js
 * @module nodejs/grpc-transport
 *
 * Provides helpers for creating authenticated gRPC transports and clients.
 * This is for Node.js applications that need to connect to gRPC services.
 *
 * Note: Requires @connectrpc/connect and @connectrpc/connect-node packages to be installed.
 */
import { createRequire } from 'module';

const require = createRequire(import.meta.url);

/**
 * Create an authenticated gRPC transport for Node.js
 *
 * @param {string} baseUrl - Base URL for the gRPC service
 * @param {Function} [getToken] - Optional function that returns an auth token
 * @returns {Object} gRPC transport
 * @throws {Error} If required dependencies are not available
 *
 * @example
 * import { createClient } from '@connectrpc/connect';
 * import { KeyAccessService } from './generated/services/key-access/key-access_connect';
 *
 * const transport = createAuthenticatedTransport(
 *   'http://localhost:8081',
 *   async () => 'my-auth-token'
 * );
 * const client = createClient(KeyAccessService, transport);
 */
export function createAuthenticatedTransport(baseUrl, getToken) {
  // Check if required packages are available
  let createGrpcTransport;
  try {
    // Synchronous require for Node.js gRPC transport
    const { createGrpcTransport: grpcTransportFn } = require('@connectrpc/connect-node');
    createGrpcTransport = grpcTransportFn;
  } catch (e) {
    throw new Error(
      'gRPC support requires @connectrpc/connect and @connectrpc/connect-node packages. ' +
      'Install them with: npm install @connectrpc/connect @connectrpc/connect-node'
    );
  }

  const finalUrl = (baseUrl && typeof baseUrl === 'string' && baseUrl.trim()) || 'http://localhost:8081';

  return createGrpcTransport({
    baseUrl: finalUrl,
    httpVersion: '2',
    interceptors: getToken ? [
      (next) => async (req) => {
        const token = await getToken();
        if (token) {
          req.header.set('authorization', `Bearer ${token}`);
        }
        return next(req);
      }
    ] : [],
  });
}
