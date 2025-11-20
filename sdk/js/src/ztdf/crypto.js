/**
 * @fileoverview Cryptographic utilities for ZTDF
 * @module ztdf/crypto
 *
 * Works in both browser and Node.js environments.
 */

import { AES_KEY_SIZE, AES_IV_SIZE } from '../utils/constants.js';
import { EncryptionError } from '../utils/errors.js';

// Polyfill for Node.js and browser compatibility
function getCrypto() {
  if (typeof window !== 'undefined' && window.crypto) {
    // Browser environment
    return window.crypto;
  } else if (typeof global !== 'undefined' && global.crypto) {
    // Node.js 19+ with global crypto
    return global.crypto;
  } else {
    // Try to import Node.js webcrypto
    try {
      // eslint-disable-next-line no-undef
      const { webcrypto } = require('crypto');
      return webcrypto;
    } catch (e) {
      throw new Error('Web Crypto API is not available in this environment');
    }
  }
}

const crypto = getCrypto();

/**
 * Generate a random Data Encryption Key (DEK)
 * @returns {Uint8Array} 32-byte AES-256 key
 */
export function generateDEK() {
  const dek = new Uint8Array(AES_KEY_SIZE);
  crypto.getRandomValues(dek);
  return dek;
}

/**
 * Generate a random initialization vector (IV)
 * @returns {Uint8Array} 12-byte IV for AES-GCM
 */
export function generateIV() {
  const iv = new Uint8Array(AES_IV_SIZE);
  crypto.getRandomValues(iv);
  return iv;
}

/**
 * Encrypt payload with AES-256-GCM
 * @param {Uint8Array} plaintext - Data to encrypt
 * @param {Uint8Array} dek - Data encryption key
 * @param {Uint8Array} [iv] - Initialization vector (generated if not provided)
 * @returns {Promise<{ciphertext: Uint8Array, iv: Uint8Array}>} Encrypted data and IV
 * @throws {EncryptionError} If encryption fails
 */
export async function encryptPayload(plaintext, dek, iv = null) {
  try {
    if (!iv) {
      iv = generateIV();
    }

    // Import the DEK
    const key = await crypto.subtle.importKey(
      'raw',
      dek,
      { name: 'AES-GCM' },
      false,
      ['encrypt']
    );

    // Encrypt the data
    const ciphertext = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      plaintext
    );

    return {
      ciphertext: new Uint8Array(ciphertext),
      iv: iv,
    };
  } catch (error) {
    throw new EncryptionError('encrypt', 'Failed to encrypt payload', error);
  }
}

/**
 * Decrypt payload with AES-256-GCM
 * @param {Uint8Array} ciphertext - Encrypted data
 * @param {Uint8Array} dek - Data encryption key
 * @param {Uint8Array} iv - Initialization vector
 * @returns {Promise<Uint8Array>} Decrypted data
 * @throws {EncryptionError} If decryption fails
 */
export async function decryptPayload(ciphertext, dek, iv) {
  try {
    // Import the DEK
    const key = await crypto.subtle.importKey(
      'raw',
      dek,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Decrypt the data
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv,
      },
      key,
      ciphertext
    );

    return new Uint8Array(plaintext);
  } catch (error) {
    throw new EncryptionError('decrypt', 'Failed to decrypt payload', error);
  }
}

/**
 * Calculate SHA-256 hash
 * @param {Uint8Array} data - Data to hash
 * @returns {Promise<Uint8Array>} Hash
 */
export async function sha256(data) {
  const hash = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(hash);
}

/**
 * Calculate payload hash for integrity verification
 * @param {Uint8Array} payload - Payload data
 * @returns {Promise<Uint8Array>} SHA-256 hash
 */
export async function calculatePayloadHash(payload) {
  return sha256(payload);
}

/**
 * Verify payload hash
 * @param {Uint8Array} payload - Payload data
 * @param {Uint8Array} expectedHash - Expected hash
 * @returns {Promise<boolean>} True if hash matches
 */
export async function verifyPayloadHash(payload, expectedHash) {
  const actualHash = await calculatePayloadHash(payload);

  // Constant-time comparison
  if (actualHash.length !== expectedHash.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < actualHash.length; i++) {
    result |= actualHash[i] ^ expectedHash[i];
  }

  return result === 0;
}

/**
 * Calculate HMAC-SHA256
 * @param {Uint8Array} key - HMAC key
 * @param {Uint8Array} data - Data to sign
 * @returns {Promise<Uint8Array>} HMAC signature
 */
export async function hmacSHA256(key, data) {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(signature);
}

/**
 * Calculate policy binding hash
 * @param {Uint8Array} dek - Data encryption key
 * @param {string} policyBase64 - Base64-encoded policy
 * @returns {Promise<string>} Base64-encoded policy binding hash
 */
export async function calculatePolicyBinding(dek, policyBase64) {
  const policyBytes = new TextEncoder().encode(policyBase64);
  const hmac = await hmacSHA256(dek, policyBytes);

  // Convert to base64 (works in both browser and Node.js)
  if (typeof btoa !== 'undefined') {
    // Browser
    let binary = '';
    for (let i = 0; i < hmac.length; i++) {
      binary += String.fromCharCode(hmac[i]);
    }
    return btoa(binary);
  } else {
    // Node.js
    return Buffer.from(hmac).toString('base64');
  }
}

/**
 * Verify policy binding
 * @param {Uint8Array} dek - Data encryption key
 * @param {string} policyBase64 - Base64-encoded policy
 * @param {string} expectedBindingBase64 - Expected policy binding hash (base64)
 * @returns {Promise<boolean>} True if binding is valid
 */
export async function verifyPolicyBinding(dek, policyBase64, expectedBindingBase64) {
  const actualBinding = await calculatePolicyBinding(dek, policyBase64);
  return actualBinding === expectedBindingBase64;
}