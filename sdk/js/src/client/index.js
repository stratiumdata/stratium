/**
 * @fileoverview Main Stratium SDK client
 * @module client
 */

import { Config } from './config.js';
import { AuthManager } from './auth.js';
import { PlatformClient } from '../services/platform.js';
import { KeyAccessClient } from '../services/key-access.js';
import { KeyManagerClient } from '../services/key-manager.js';

/**
 * Main Stratium SDK client
 *
 * @example
 * import { StratiumClient } from '@stratium/sdk';
 *
 * const client = new StratiumClient({
 *   platformAddress: 'platform.example.com:50051',
 *   keyAccessAddress: 'key-access.example.com:50053',
 *   oidc: {
 *     issuerURL: 'https://keycloak.example.com/realms/stratium',
 *     clientID: 'my-app',
 *     clientSecret: 'secret'
 *   }
 * });
 *
 * // Check authorization
 * const allowed = await client.platform.checkAccess({
 *   subjectAttributes: { sub: 'user123' },
 *   resourceAttributes: { name: 'document-service' },
 *   action: 'read'
 * });
 */
export class StratiumClient {
  /**
   * Create a new Stratium client
   * @param {Object} options - Configuration options (see Config class)
   * @throws {Error} If configuration is invalid
   */
  constructor(options) {
    // Create and validate config
    this.config = new Config(options);
    this.config.validate();

    // Initialize authentication if OIDC is configured
    this.authManager = this.config.oidc ? new AuthManager(this.config.oidc) : null;

    // Initialize service clients
    this.platform = this.config.platformAddress
      ? new PlatformClient(this.config, this.authManager)
      : null;

    this.keyAccess = this.config.keyAccessAddress
      ? new KeyAccessClient(this.config, this.authManager)
      : null;

    this.keyManager = this.config.keyManagerAddress || this.config.platformAddress
      ? new KeyManagerClient(this.config, this.authManager)
      : null;
  }

  /**
   * Get the current authentication token
   * @returns {Promise<string|null>} Access token or null if not authenticated
   */
  async getToken() {
    if (!this.authManager) {
      return null;
    }
    return this.authManager.getToken();
  }

  /**
   * Force a token refresh
   * @returns {Promise<void>}
   * @throws {AuthenticationError} If authentication fails
   */
  async refreshToken() {
    if (!this.authManager) {
      throw new Error('Authentication not configured');
    }
    return this.authManager.refreshToken();
  }

  /**
   * Clear stored authentication tokens
   */
  clearTokens() {
    if (this.authManager) {
      this.authManager.clearTokens();
    }
  }

  /**
   * Get the client configuration
   * @returns {Config} Configuration object
   */
  getConfig() {
    return this.config;
  }
}