/**
 * @fileoverview Configuration for the Stratium SDK client
 * @module client/config
 */

import { DEFAULT_TIMEOUT, DEFAULT_RETRY_ATTEMPTS, DEFAULT_OIDC_SCOPES } from '../utils/constants.js';

/**
 * OIDC configuration for authentication
 * @typedef {Object} OIDCConfig
 * @property {string} issuerURL - OIDC issuer URL (e.g., 'https://keycloak.example.com/realms/stratium')
 * @property {string} clientID - OIDC client ID
 * @property {string} clientSecret - OIDC client secret
 * @property {string[]} [scopes] - OIDC scopes (default: ['openid', 'profile', 'email'])
 */

/**
 * Configuration for the Stratium SDK client
 */
export class Config {
  /**
   * @param {Object} options - Configuration options
   * @param {string} [options.platformAddress] - Platform service gRPC address
   * @param {string} [options.keyManagerAddress] - Key Manager service gRPC address
   * @param {string} [options.keyAccessAddress] - Key Access service gRPC address
   * @param {OIDCConfig} [options.oidc] - OIDC configuration
   * @param {number} [options.timeout] - Default timeout for requests in milliseconds
   * @param {number} [options.retryAttempts] - Number of retry attempts on failure
   * @param {boolean} [options.useTLS] - Use TLS for connections
   */
  constructor(options = {}) {
    this.platformAddress = options.platformAddress || '';
    this.keyManagerAddress = options.keyManagerAddress || '';
    this.keyAccessAddress = options.keyAccessAddress || '';
    this.oidc = options.oidc || null;
    this.timeout = options.timeout || DEFAULT_TIMEOUT;
    this.retryAttempts = options.retryAttempts || DEFAULT_RETRY_ATTEMPTS;
    this.useTLS = options.useTLS || false;

    // Set default OIDC scopes if OIDC is configured
    if (this.oidc && (!this.oidc.scopes || this.oidc.scopes.length === 0)) {
      this.oidc.scopes = DEFAULT_OIDC_SCOPES;
    }
  }

  /**
   * Validate the configuration
   * @throws {Error} If configuration is invalid
   */
  validate() {
    if (!this.platformAddress && !this.keyManagerAddress && !this.keyAccessAddress) {
      throw new Error('At least one service address must be configured');
    }

    if (this.oidc) {
      if (!this.oidc.issuerURL) {
        throw new Error('OIDC issuer URL is required');
      }
      if (!this.oidc.clientID) {
        throw new Error('OIDC client ID is required');
      }
      if (!this.oidc.clientSecret) {
        throw new Error('OIDC client secret is required');
      }
    }
  }

  /**
   * Get the protocol prefix based on TLS setting
   * @returns {string} Protocol prefix ('https://' or 'http://')
   */
  getProtocol() {
    return this.useTLS ? 'https://' : 'http://';
  }

  /**
   * Get full URL for a service address
   * @param {string} address - Service address
   * @returns {string} Full URL
   */
  getFullURL(address) {
    if (!address) return '';
    if (address.startsWith('http://') || address.startsWith('https://')) {
      return address;
    }
    return this.getProtocol() + address;
  }
}