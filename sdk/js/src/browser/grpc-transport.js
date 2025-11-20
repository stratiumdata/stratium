/**
 * @fileoverview gRPC-Web Transport Helpers
 * @module browser/grpc-transport
 *
 * Provides helpers for creating authenticated gRPC-Web transports and clients.
 * This is useful for browser-based applications that need to connect to gRPC services.
 *
 * Note: Requires @connectrpc/connect and @connectrpc/connect-web packages to be installed.
 */

/**
 * Create an authenticated gRPC-Web transport
 *
 * @param {string} baseUrl - Base URL for the gRPC-Web service
 * @param {Function} [getToken] - Optional function that returns an auth token
 * @returns {Object} gRPC-Web transport
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
  if (typeof window === 'undefined') {
    throw new Error('gRPC-Web transport is only available in browsers');
  }

  // Check if required packages are available
  let createGrpcWebTransport;
  try {
    // Try to import dynamically if available
    const connectWeb = require('@connectrpc/connect-web');
    createGrpcWebTransport = connectWeb.createGrpcWebTransport;
  } catch (e) {
    throw new Error(
      'gRPC-Web support requires @connectrpc/connect and @connectrpc/connect-web packages. ' +
      'Install them with: npm install @connectrpc/connect @connectrpc/connect-web'
    );
  }

  const finalUrl = (baseUrl && typeof baseUrl === 'string' && baseUrl.trim()) || 'http://localhost:8081';

  return createGrpcWebTransport({
    baseUrl: finalUrl,
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
