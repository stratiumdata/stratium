/**
 * @fileoverview Key Access service client for DEK operations
 * @module services/key-access
 */

import axios from 'axios';
import { CONTENT_TYPE_JSON } from '../utils/constants.js';
import { ValidationError, APIError, ErrRequestNil, ErrClientIDRequired, ErrResourceAttributesRequired } from '../utils/errors.js';
import { createAuthHeaders, bytesToBase64, base64ToBytes } from '../utils/helpers.js';

/**
 * DEK request parameters
 * @typedef {Object} DEKRequest
 * @property {string} clientID - Client identifier
 * @property {Object<string, string>} resourceAttributes - Resource attributes
 * @property {string} [purpose] - Purpose of the DEK (e.g., 'encryption', 'decryption')
 * @property {Object<string, string>} [context] - Additional context
 */

/**
 * DEK response
 * @typedef {Object} DEKResponse
 * @property {Uint8Array} wrappedDEK - Wrapped data encryption key
 * @property {string} keyID - Key identifier
 */

/**
 * Key Access client for requesting and unwrapping DEKs
 */
export class KeyAccessClient {
  /**
   * @param {import('../client/config.js').Config} config - SDK configuration
   * @param {import('../client/auth.js').AuthManager} authManager - Authentication manager
   */
  constructor(config, authManager) {
    this.config = config;
    this.authManager = authManager;
    this.baseURL = config.getFullURL(config.keyAccessAddress);
  }

  /**
   * Request a DEK for encryption
   * @param {DEKRequest} request - DEK request
   * @returns {Promise<DEKResponse>} DEK response
   * @throws {ValidationError} If request is invalid
   * @throws {APIError} If API call fails
   *
   * @example
   * const dekResponse = await client.keyAccess.requestDEK({
   *   clientID: 'my-app',
   *   resourceAttributes: {
   *     name: 'my-document',
   *     type: 'document'
   *   },
   *   purpose: 'encryption'
   * });
   */
  async requestDEK(request) {
    // Validate request
    if (!request) {
      throw ErrRequestNil;
    }
    if (!request.clientID) {
      throw ErrClientIDRequired;
    }
    if (!request.resourceAttributes || Object.keys(request.resourceAttributes).length === 0) {
      throw ErrResourceAttributesRequired;
    }

    try {
      // Get auth token
      const token = this.authManager ? await this.authManager.getToken() : null;

      // Make request
      const response = await axios.post(
        `${this.baseURL}/v1/dek/request`,
        {
          client_id: request.clientID,
          resource_attributes: request.resourceAttributes,
          purpose: request.purpose || 'encryption',
          context: request.context || {},
        },
        {
          headers: {
            'Content-Type': CONTENT_TYPE_JSON,
            ...createAuthHeaders(token),
          },
          timeout: this.config.timeout,
        }
      );

      return {
        wrappedDEK: base64ToBytes(response.data.wrapped_dek),
        keyID: response.data.key_id || '',
      };
    } catch (error) {
      if (error.response) {
        throw new APIError(error.response.status, `Failed to request DEK: ${error.response.data?.message || error.message}`, error);
      }
      throw error;
    }
  }

  /**
   * Unwrap a DEK for decryption
   * @param {string} clientID - Client identifier
   * @param {Uint8Array} wrappedDEK - Wrapped DEK bytes
   * @returns {Promise<Uint8Array>} Unwrapped DEK
   * @throws {ValidationError} If request is invalid
   * @throws {APIError} If API call fails
   *
   * @example
   * const dek = await client.keyAccess.unwrapDEK('my-app', wrappedDEKBytes);
   */
  async unwrapDEK(clientID, wrappedDEK) {
    // Validate request
    if (!clientID) {
      throw ErrClientIDRequired;
    }
    if (!wrappedDEK || wrappedDEK.length === 0) {
      throw new ValidationError('wrapped_dek', 'is required');
    }

    try {
      // Get auth token
      const token = this.authManager ? await this.authManager.getToken() : null;

      // Make request
      const response = await axios.post(
        `${this.baseURL}/v1/dek/unwrap`,
        {
          client_id: clientID,
          wrapped_dek: bytesToBase64(wrappedDEK),
        },
        {
          headers: {
            'Content-Type': CONTENT_TYPE_JSON,
            ...createAuthHeaders(token),
          },
          timeout: this.config.timeout,
        }
      );

      return base64ToBytes(response.data.dek);
    } catch (error) {
      if (error.response) {
        throw new APIError(error.response.status, `Failed to unwrap DEK: ${error.response.data?.message || error.message}`, error);
      }
      throw error;
    }
  }
}