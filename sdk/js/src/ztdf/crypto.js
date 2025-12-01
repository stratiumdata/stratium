/**
 * @fileoverview Cryptographic utilities for ZTDF
 * @module ztdf/crypto
 *
 * Works in both browser and Node.js environments.
 */

import { AES_KEY_SIZE, AES_IV_SIZE } from '../utils/constants.js';
import { base64ToBytes } from '../utils/helpers.js';
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
 * Decrypt a segmented payload produced by the streaming encryptor.
 * Each segment is sealed independently using AES-GCM with a derived nonce.
 *
 * @param {Uint8Array} payload - Concatenated ciphertext segments
 * @param {Uint8Array} dek - Data encryption key
 * @param {Uint8Array} baseNonce - Base nonce from the manifest
 * @param {Array} segments - IntegrityInformation segments describing each chunk
 * @param {string} [expectedRootHashBase64] - Optional root hash (base64) to verify
 * @returns {Promise<Uint8Array>} Decrypted plaintext
 */
export async function decryptSegmentedPayload(payload, dek, baseNonce, segments, expectedRootHashBase64) {
  if (!segments || segments.length === 0) {
    throw new EncryptionError('decrypt', 'Missing integrity segments for segmented payload');
  }
  if (!baseNonce || baseNonce.length < 4) {
    throw new EncryptionError('decrypt', 'Invalid base nonce for segmented payload');
  }

  const key = await crypto.subtle.importKey(
    'raw',
    dek,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const plaintextChunks = [];
  let offset = 0;

  for (let i = 0; i < segments.length; i++) {
    const segment = segments[i];
    const encryptedSize = Number(segment?.encryptedSegmentSize ?? segment?.segmentSize ?? 0);
    if (!Number.isFinite(encryptedSize) || encryptedSize <= 0) {
      throw new EncryptionError('decrypt', `Invalid segment size for chunk ${i}`);
    }
    if (offset + encryptedSize > payload.length) {
      throw new EncryptionError('decrypt', 'Encrypted payload length mismatch');
    }

    const chunkCipher = payload.slice(offset, offset + encryptedSize);
    offset += encryptedSize;

    if (segment?.hash) {
      const chunkHash = await sha256(chunkCipher);
      const expectedHash = base64ToBytes(segment.hash);
      if (!buffersEqual(chunkHash, expectedHash)) {
        throw new EncryptionError('decrypt', `Segment hash mismatch for chunk ${i}`);
      }
    }

    const nonce = deriveChunkNonce(baseNonce, i);
    let chunkPlaintext;
    try {
      chunkPlaintext = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: nonce,
        },
        key,
        chunkCipher
      );
    } catch (error) {
      throw new EncryptionError('decrypt', `Failed to decrypt payload segment ${i}`, error);
    }

    plaintextChunks.push(new Uint8Array(chunkPlaintext));
  }

  if (offset !== payload.length) {
    throw new EncryptionError('decrypt', 'Encrypted payload contains extra data beyond declared segments');
  }

  if (expectedRootHashBase64) {
    const expectedRoot = base64ToBytes(expectedRootHashBase64);
    const actualRoot = await sha256(payload);
    if (!buffersEqual(actualRoot, expectedRoot)) {
      throw new EncryptionError('decrypt', 'Payload integrity verification failed');
    }
  }

  return concatUint8Arrays(plaintextChunks);
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

function deriveChunkNonce(baseNonce, chunkIndex) {
  const nonce = new Uint8Array(baseNonce);
  if (nonce.length < 4) {
    return nonce;
  }
  const view = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  const counterOffset = nonce.length - 4;
  view.setUint32(counterOffset, chunkIndex >>> 0, false);
  return nonce;
}

function buffersEqual(a, b) {
  if (!a || !b || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

function concatUint8Arrays(chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}
