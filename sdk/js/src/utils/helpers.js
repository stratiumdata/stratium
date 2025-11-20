/**
 * @fileoverview Helper utilities for the Stratium SDK
 * @module utils/helpers
 */

import { AUTH_HEADER_PREFIX, SUBJECT_ATTR_SUB, SUBJECT_ATTR_USER_ID, SUBJECT_ATTR_ID, ERR_MSG_SUBJECT_IDENTIFIER_REQUIRED } from './constants.js';
import { ValidationError } from './errors.js';

/**
 * Validate that subject attributes contain a valid identifier
 * @param {Object} subjectAttributes - Subject attributes to validate
 * @throws {ValidationError} If no valid identifier is found
 */
export function validateSubjectIdentifier(subjectAttributes) {
  if (!subjectAttributes) {
    throw new ValidationError('subject_attributes', 'cannot be null or undefined');
  }

  const hasSub = subjectAttributes.hasOwnProperty(SUBJECT_ATTR_SUB);
  const hasUserID = subjectAttributes.hasOwnProperty(SUBJECT_ATTR_USER_ID);
  const hasID = subjectAttributes.hasOwnProperty(SUBJECT_ATTR_ID);

  if (!hasSub && !hasUserID && !hasID) {
    throw new ValidationError('subject_attributes', ERR_MSG_SUBJECT_IDENTIFIER_REQUIRED);
  }
}

/**
 * Create authorization headers for HTTP requests
 * @param {string} token - Access token
 * @returns {Object} Headers object
 */
export function createAuthHeaders(token) {
  if (!token) return {};
  return {
    Authorization: AUTH_HEADER_PREFIX + token,
  };
}

/**
 * Format a string template with values
 * @param {string} template - Template string with %s placeholders
 * @param {...string} values - Values to insert
 * @returns {string} Formatted string
 */
export function formatString(template, ...values) {
  let result = template;
  for (const value of values) {
    result = result.replace('%s', value);
  }
  return result;
}

/**
 * Sleep for a specified duration
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
export function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Retry a function with exponential backoff
 * @param {Function} fn - Function to retry
 * @param {number} maxAttempts - Maximum number of attempts
 * @param {number} baseDelay - Base delay in milliseconds
 * @returns {Promise<*>} Result of the function
 */
export async function retryWithBackoff(fn, maxAttempts = 3, baseDelay = 1000) {
  let lastError;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < maxAttempts - 1) {
        const delay = baseDelay * Math.pow(2, attempt);
        await sleep(delay);
      }
    }
  }

  throw lastError;
}

/**
 * Convert a base64 string to Uint8Array
 * @param {string} base64 - Base64 encoded string
 * @returns {Uint8Array} Decoded bytes
 */
export function base64ToBytes(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

/**
 * Convert Uint8Array to base64 string
 * @param {Uint8Array} bytes - Bytes to encode
 * @returns {string} Base64 encoded string
 */
export function bytesToBase64(bytes) {
  let binaryString = '';
  for (let i = 0; i < bytes.length; i++) {
    binaryString += String.fromCharCode(bytes[i]);
  }
  return btoa(binaryString);
}