/**
 * @fileoverview DEK Decryption using ECIES (Node.js)
 * @module nodejs/dek-decryption
 *
 * Decrypts Data Encryption Keys (DEKs) using ECIES with the client's private key.
 * Uses Node.js Web Crypto API for ECDH key agreement, HKDF, and AES-GCM.
 */

import { webcrypto } from 'crypto';
import { base64ToBytes } from '../utils/helpers.js';

const { subtle } = webcrypto;

/**
 * Decrypt a wrapped DEK using ECIES
 *
 * The wrappedKey format is:
 * [ephemeral public key length (1 byte)][ephemeral public key][nonce (12 bytes)][ciphertext]
 *
 * Algorithm:
 * 1. Extract ephemeral public key from wrapped DEK
 * 2. Perform ECDH with client's private key to get shared secret
 * 3. Derive AES key using HKDF-SHA256
 * 4. Decrypt ciphertext using AES-256-GCM
 *
 * @param {CryptoKey} privateKey - Client's ECDH private key
 * @param {string} wrappedKeyBase64 - Base64-encoded wrapped DEK
 * @returns {Promise<Uint8Array>} Decrypted DEK
 * @throws {Error} If decryption fails
 *
 * @example
 * const dek = await decryptDEK(privateKey, wrappedKeyBase64);
 * console.log('Decrypted DEK:', dek);
 */
export async function decryptDEK(privateKey, wrappedKeyBase64) {
  const wrappedKey = base64ToBytes(wrappedKeyBase64);

  // Parse wrapped DEK format
  if (wrappedKey.length < 1) {
    throw new Error('Wrapped DEK too short');
  }

  // Extract ephemeral public key
  const ephemeralPublicKeyLen = wrappedKey[0];
  if (wrappedKey.length < 1 + ephemeralPublicKeyLen + 12) {
    throw new Error('Wrapped DEK format invalid');
  }

  const ephemeralPublicKeyBytes = wrappedKey.slice(1, 1 + ephemeralPublicKeyLen);
  const nonceStart = 1 + ephemeralPublicKeyLen;
  const nonce = wrappedKey.slice(nonceStart, nonceStart + 12);
  const ciphertext = wrappedKey.slice(nonceStart + 12);

  // Import ephemeral public key
  const ephemeralPublicKey = await subtle.importKey(
    'raw',
    ephemeralPublicKeyBytes,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    false,
    []
  );

  // Perform ECDH to get shared secret
  const sharedSecretBits = await subtle.deriveBits(
    {
      name: 'ECDH',
      public: ephemeralPublicKey,
    },
    privateKey,
    256 // 256 bits
  );

  const sharedSecret = new Uint8Array(sharedSecretBits);

  // Derive AES key using HKDF-SHA256
  const hkdfKey = await subtle.importKey(
    'raw',
    sharedSecret,
    {
      name: 'HKDF',
    },
    false,
    ['deriveBits', 'deriveKey']
  );

  const aesKey = await subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('ztdf-ecies-v1'),
    },
    hkdfKey,
    {
      name: 'AES-GCM',
      length: 256,
    },
    false,
    ['decrypt']
  );

  // Decrypt DEK
  const dekBuffer = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
    },
    aesKey,
    ciphertext
  );

  return new Uint8Array(dekBuffer);
}