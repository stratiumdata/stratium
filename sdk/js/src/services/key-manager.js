/**
 * @fileoverview Key Manager service client for client key registration
 * @module services/key-manager
 */

import axios from 'axios';
import { CONTENT_TYPE_JSON } from '../utils/constants.js';
import { ValidationError, APIError, ErrRequestNil } from '../utils/errors.js';
import { createAuthHeaders } from '../utils/helpers.js';

/**
 * Client key registration request
 * @typedef {Object} RegisterKeyRequest
 * @property {string} clientId - Client identifier
 * @property {string} publicKeyPEM - Public key in PEM format
 * @property {string} keyType - Key type (e.g., 'ECC_P256', 'RSA_2048')
 * @property {Date} [expiresAt] - Key expiration time
 * @property {Object<string, string>} [metadata] - Additional metadata
 */

/**
 * Client key registration response
 * @typedef {Object} RegisterKeyResponse
 * @property {boolean} success - Registration success indicator
 * @property {Object} key - Registered key information
 * @property {string} key.keyId - Unique key identifier
 * @property {string} key.status - Key status
 * @property {Date} key.expiresAt - Key expiration time
 * @property {string} [errorMessage] - Error message if registration failed
 */

/**
 * Key Manager client for client key registration and management
 */
export class KeyManagerClient {
  /**
   * @param {import('../client/config.js').Config} config - SDK configuration
   * @param {import('../client/auth.js').AuthManager} authManager - Authentication manager
   */
  constructor(config, authManager) {
    this.config = config;
    this.authManager = authManager;
    this.baseURL = config.getFullURL(config.keyManagerAddress || config.platformAddress);
  }

  /**
   * Register a client public key with the Key Manager
   * @param {RegisterKeyRequest} request - Registration request
   * @returns {Promise<RegisterKeyResponse>} Registration response
   * @throws {ValidationError} If request is invalid
   * @throws {APIError} If API call fails
   *
   * @example
   * const response = await client.keyManager.registerClientKey({
   *   clientId: 'my-app',
   *   publicKeyPEM: '-----BEGIN PUBLIC KEY-----\n...',
   *   keyType: 'ECC_P256',
   *   expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
   * });
   */
  async registerClientKey(request) {
    // Validate request
    if (!request) {
      throw ErrRequestNil;
    }
    if (!request.clientId) {
      throw new ValidationError('clientId', 'is required');
    }
    if (!request.publicKeyPEM) {
      throw new ValidationError('publicKeyPEM', 'is required');
    }
    if (!request.keyType) {
      throw new ValidationError('keyType', 'is required');
    }

    try {
      // Get auth token
      const token = this.authManager ? await this.authManager.getToken() : null;

      // Prepare request body
      const body = {
        client_id: request.clientId,
        public_key_pem: request.publicKeyPEM,
        key_type: request.keyType,
      };

      // Add optional fields
      if (request.expiresAt) {
        body.expires_at = request.expiresAt.toISOString();
      }
      if (request.metadata) {
        body.metadata = request.metadata;
      }

      // Make request
      const response = await axios.post(
        `${this.baseURL}/v1/keys/register`,
        body,
        {
          headers: {
            'Content-Type': CONTENT_TYPE_JSON,
            ...createAuthHeaders(token),
          },
          timeout: this.config.timeout,
        }
      );

      return {
        success: response.data.success || false,
        key: {
          keyId: response.data.key?.key_id || '',
          status: response.data.key?.status || '',
          expiresAt: response.data.key?.expires_at ? new Date(response.data.key.expires_at) : new Date(),
        },
        errorMessage: response.data.error_message,
      };
    } catch (error) {
      if (error.response) {
        throw new APIError(
          error.response.status,
          `Failed to register client key: ${error.response.data?.error_message || error.response.data?.message || error.message}`,
          error
        );
      }
      throw error;
    }
  }

  /**
   * Get client key information
   * @param {string} keyId - Key identifier
   * @returns {Promise<Object>} Key information
   * @throws {ValidationError} If keyId is missing
   * @throws {APIError} If API call fails
   *
   * @example
   * const keyInfo = await client.keyManager.getClientKey('key-123');
   */
  async getClientKey(keyId) {
    if (!keyId) {
      throw new ValidationError('keyId', 'is required');
    }

    try {
      const token = this.authManager ? await this.authManager.getToken() : null;

      const response = await axios.get(
        `${this.baseURL}/v1/keys/${keyId}`,
        {
          headers: {
            ...createAuthHeaders(token),
          },
          timeout: this.config.timeout,
        }
      );

      return {
        keyId: response.data.key_id,
        clientId: response.data.client_id,
        keyType: response.data.key_type,
        status: response.data.status,
        createdAt: new Date(response.data.created_at),
        expiresAt: response.data.expires_at ? new Date(response.data.expires_at) : null,
        metadata: response.data.metadata || {},
      };
    } catch (error) {
      if (error.response) {
        throw new APIError(error.response.status, `Failed to get client key: ${error.response.data?.message || error.message}`, error);
      }
      throw error;
    }
  }

  /**
   * Revoke a client key
   * @param {string} keyId - Key identifier
   * @returns {Promise<{success: boolean}>} Revocation result
   * @throws {ValidationError} If keyId is missing
   * @throws {APIError} If API call fails
   *
   * @example
   * await client.keyManager.revokeClientKey('key-123');
   */
  async revokeClientKey(keyId) {
    if (!keyId) {
      throw new ValidationError('keyId', 'is required');
    }

    try {
      const token = this.authManager ? await this.authManager.getToken() : null;

      const response = await axios.post(
        `${this.baseURL}/v1/keys/${keyId}/revoke`,
        {},
        {
          headers: {
            'Content-Type': CONTENT_TYPE_JSON,
            ...createAuthHeaders(token),
          },
          timeout: this.config.timeout,
        }
      );

      return {
        success: response.data.success || false,
      };
    } catch (error) {
      if (error.response) {
        throw new APIError(error.response.status, `Failed to revoke client key: ${error.response.data?.message || error.message}`, error);
      }
      throw error;
    }
  }
}