/**
 * @fileoverview Authentication manager for OIDC token management
 * @module client/auth
 */

import axios from 'axios';
import {
  OIDC_TOKEN_PATH,
  GRANT_TYPE_CLIENT_CREDENTIALS,
  GRANT_TYPE_REFRESH_TOKEN,
  CONTENT_TYPE_FORM_URLENCODED,
} from '../utils/constants.js';
import { AuthenticationError } from '../utils/errors.js';

/**
 * Authentication manager for handling OIDC tokens
 */
export class AuthManager {
  /**
   * @param {import('./config.js').OIDCConfig} oidcConfig - OIDC configuration
   */
  constructor(oidcConfig) {
    this.config = oidcConfig;
    this.token = null;
    this.refreshToken = null;
    this.expiresAt = null;
    this.tokenLock = Promise.resolve();
  }

  /**
   * Get a valid access token (refreshes if needed)
   * @returns {Promise<string>} Access token
   * @throws {AuthenticationError} If authentication fails
   */
  async getToken() {
    // Check if we have a valid token
    if (this.token && this.expiresAt && Date.now() < this.expiresAt - 30000) {
      return this.token;
    }

    // Ensure only one token refresh happens at a time
    return this.tokenLock = this.tokenLock.then(() => this._refreshToken());
  }

  /**
   * Force a token refresh
   * @returns {Promise<void>}
   * @throws {AuthenticationError} If authentication fails
   */
  async refreshToken() {
    this.tokenLock = this.tokenLock.then(() => this._refreshToken());
    await this.tokenLock;
  }

  /**
   * Internal method to refresh the token
   * @private
   * @returns {Promise<string>} New access token
   * @throws {AuthenticationError} If authentication fails
   */
  async _refreshToken() {
    try {
      const tokenURL = `${this.config.issuerURL}${OIDC_TOKEN_PATH}`;

      // Prepare request body
      const params = new URLSearchParams();

      if (this.refreshToken) {
        params.append('grant_type', GRANT_TYPE_REFRESH_TOKEN);
        params.append('refresh_token', this.refreshToken);
        params.append('client_id', this.config.clientID);
        params.append('client_secret', this.config.clientSecret);
      } else {
        params.append('grant_type', GRANT_TYPE_CLIENT_CREDENTIALS);
        params.append('client_id', this.config.clientID);
        params.append('client_secret', this.config.clientSecret);
        if (this.config.scopes && this.config.scopes.length > 0) {
          params.append('scope', this.config.scopes.join(' '));
        }
      }

      const response = await axios.post(tokenURL, params.toString(), {
        headers: {
          'Content-Type': CONTENT_TYPE_FORM_URLENCODED,
        },
      });

      this.token = response.data.access_token;
      this.refreshToken = response.data.refresh_token || this.refreshToken;

      // Set expiration time (subtract 30 seconds for buffer)
      if (response.data.expires_in) {
        this.expiresAt = Date.now() + (response.data.expires_in * 1000);
      }

      return this.token;
    } catch (error) {
      throw new AuthenticationError('Failed to obtain access token', error);
    }
  }

  /**
   * Clear stored tokens
   */
  clearTokens() {
    this.token = null;
    this.refreshToken = null;
    this.expiresAt = null;
  }
}