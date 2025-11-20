/**
 * @fileoverview Platform service client for authorization decisions
 * @module services/platform
 */

import axios from 'axios';
import { CONTENT_TYPE_JSON, DECISION_DENY, DECISION_ALLOW, DECISION_CONDITIONAL } from '../utils/constants.js';
import { ValidationError, APIError, ErrRequestNil, ErrActionRequired, ErrSubjectAttributesRequired } from '../utils/errors.js';
import { validateSubjectIdentifier, createAuthHeaders } from '../utils/helpers.js';

/**
 * Authorization request parameters
 * @typedef {Object} AuthorizationRequest
 * @property {Object<string, string>} subjectAttributes - Subject attributes (user/client making the request)
 * @property {Object<string, string>} [resourceAttributes] - Resource attributes (what is being accessed)
 * @property {string} action - Action being performed (e.g., 'read', 'write', 'delete')
 * @property {Object<string, string>} [context] - Additional context for the decision
 */

/**
 * Authorization response
 * @typedef {Object} AuthorizationResponse
 * @property {number} decision - Authorization decision (0=deny, 1=allow, 2=conditional)
 * @property {string} reason - Explanation for the decision
 * @property {string} evaluatedPolicy - Policy that made the decision
 * @property {Object<string, string>} details - Additional details
 * @property {string} timestamp - When the decision was made
 */

/**
 * Platform client for making authorization decisions
 */
export class PlatformClient {
  /**
   * @param {import('../client/config.js').Config} config - SDK configuration
   * @param {import('../client/auth.js').AuthManager} authManager - Authentication manager
   */
  constructor(config, authManager) {
    this.config = config;
    this.authManager = authManager;
    this.baseURL = config.getFullURL(config.platformAddress);
  }

  /**
   * Make an authorization decision for the given request
   * @param {AuthorizationRequest} request - Authorization request
   * @returns {Promise<AuthorizationResponse>} Authorization response
   * @throws {ValidationError} If request is invalid
   * @throws {APIError} If API call fails
   *
   * @example
   * const decision = await client.platform.getDecision({
   *   subjectAttributes: {
   *     sub: 'user123',
   *     email: 'user@example.com',
   *     department: 'engineering'
   *   },
   *   resourceAttributes: {
   *     name: 'document-service',
   *     type: 'service'
   *   },
   *   action: 'read',
   *   context: {
   *     ip_address: '192.168.1.100'
   *   }
   * });
   *
   * if (decision.decision === DECISION_ALLOW) {
   *   // Grant access
   * }
   */
  async getDecision(request) {
    // Validate request
    if (!request) {
      throw ErrRequestNil;
    }
    if (!request.action) {
      throw ErrActionRequired;
    }
    if (!request.subjectAttributes || Object.keys(request.subjectAttributes).length === 0) {
      throw ErrSubjectAttributesRequired;
    }

    // Validate subject has an identifier
    validateSubjectIdentifier(request.subjectAttributes);

    try {
      // Get auth token
      const token = this.authManager ? await this.authManager.getToken() : null;

      // Make request
      const response = await axios.post(
        `${this.baseURL}/v1/decisions`,
        {
          subject_attributes: request.subjectAttributes,
          resource_attributes: request.resourceAttributes || {},
          action: request.action,
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
        decision: response.data.decision || DECISION_DENY,
        reason: response.data.reason || '',
        evaluatedPolicy: response.data.evaluated_policy || '',
        details: response.data.details || {},
        timestamp: response.data.timestamp || new Date().toISOString(),
      };
    } catch (error) {
      if (error.response) {
        throw new APIError(error.response.status, `Failed to get decision: ${error.response.data?.message || error.message}`, error);
      }
      throw error;
    }
  }

  /**
   * Check if access is allowed (convenience method)
   * @param {AuthorizationRequest} request - Authorization request
   * @returns {Promise<boolean>} True if access is allowed
   *
   * @example
   * const allowed = await client.platform.checkAccess({
   *   subjectAttributes: { sub: 'user123' },
   *   resourceAttributes: { name: 'document-service' },
   *   action: 'read'
   * });
   *
   * if (allowed) {
   *   // Grant access
   * }
   */
  async checkAccess(request) {
    const decision = await this.getDecision(request);
    return decision.decision === DECISION_ALLOW;
  }

  /**
   * Get entitlements for a subject
   * @param {Object<string, string>} subjectAttributes - Subject attributes
   * @returns {Promise<Array<Object>>} List of entitlements
   * @throws {ValidationError} If request is invalid
   * @throws {APIError} If API call fails
   *
   * @example
   * const entitlements = await client.platform.getEntitlements({
   *   sub: 'user123'
   * });
   */
  async getEntitlements(subjectAttributes) {
    // Validate request
    if (!subjectAttributes || Object.keys(subjectAttributes).length === 0) {
      throw ErrSubjectAttributesRequired;
    }

    // Validate subject has an identifier
    validateSubjectIdentifier(subjectAttributes);

    try {
      // Get auth token
      const token = this.authManager ? await this.authManager.getToken() : null;

      // Make request
      const response = await axios.post(
        `${this.baseURL}/v1/entitlements`,
        {
          subject_attributes: subjectAttributes,
        },
        {
          headers: {
            'Content-Type': CONTENT_TYPE_JSON,
            ...createAuthHeaders(token),
          },
          timeout: this.config.timeout,
        }
      );

      return response.data.entitlements || [];
    } catch (error) {
      if (error.response) {
        throw new APIError(error.response.status, `Failed to get entitlements: ${error.response.data?.message || error.message}`, error);
      }
      throw error;
    }
  }
}

// Export decision constants
export { DECISION_DENY, DECISION_ALLOW, DECISION_CONDITIONAL };