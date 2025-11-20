/**
 * @fileoverview Error classes for the Stratium SDK
 * @module utils/errors
 */

import {
  ERR_MSG_CLIENT_ID_REQUIRED,
  ERR_MSG_RESOURCE_ATTRIBUTES_REQUIRED,
  ERR_MSG_ACTION_REQUIRED,
  ERR_MSG_SUBJECT_ATTRIBUTES_REQUIRED,
  ERR_MSG_REQUEST_NIL,
} from './constants.js';

/**
 * Base error class for Stratium SDK errors
 */
export class StratiumError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StratiumError';
  }
}

/**
 * Validation error for missing or invalid fields
 */
export class ValidationError extends StratiumError {
  /**
   * @param {string} field - The field that failed validation
   * @param {string} message - Error message
   */
  constructor(field, message) {
    super(`${field}: ${message}`);
    this.name = 'ValidationError';
    this.field = field;
  }
}

/**
 * Authentication error for auth failures
 */
export class AuthenticationError extends StratiumError {
  /**
   * @param {string} message - Error message
   * @param {Error} [cause] - Original error
   */
  constructor(message, cause) {
    super(message);
    this.name = 'AuthenticationError';
    this.cause = cause;
  }
}

/**
 * API error for HTTP API errors with status codes
 */
export class APIError extends StratiumError {
  /**
   * @param {number} statusCode - HTTP status code
   * @param {string} message - Error message
   * @param {Error} [cause] - Original error
   */
  constructor(statusCode, message, cause) {
    super(message);
    this.name = 'APIError';
    this.statusCode = statusCode;
    this.cause = cause;
  }
}

/**
 * Encryption error for crypto operations
 */
export class EncryptionError extends StratiumError {
  /**
   * @param {string} operation - Operation that failed (e.g., 'encrypt', 'decrypt')
   * @param {string} message - Error message
   * @param {Error} [cause] - Original error
   */
  constructor(operation, message, cause) {
    super(`${operation}: ${message}`);
    this.name = 'EncryptionError';
    this.operation = operation;
    this.cause = cause;
  }
}

// Pre-defined error instances
export const ErrClientIDRequired = new ValidationError('client_id', ERR_MSG_CLIENT_ID_REQUIRED);
export const ErrResourceAttributesRequired = new ValidationError('resource_attributes', ERR_MSG_RESOURCE_ATTRIBUTES_REQUIRED);
export const ErrActionRequired = new ValidationError('action', ERR_MSG_ACTION_REQUIRED);
export const ErrSubjectAttributesRequired = new ValidationError('subject_attributes', ERR_MSG_SUBJECT_ATTRIBUTES_REQUIRED);
export const ErrRequestNil = new ValidationError('request', ERR_MSG_REQUEST_NIL);