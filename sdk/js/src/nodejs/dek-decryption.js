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

function base64UrlEncode(bytes) {
  return Buffer.from(bytes)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

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

  const coordSize = 32; // P-256
  const headerSize = coordSize * 2;
  if (wrappedKey.length <= headerSize + 12) {
    throw new Error('Wrapped DEK format invalid');
  }

  const ephemeralBytes = wrappedKey.slice(0, headerSize);
  const ephemeralX = ephemeralBytes.slice(0, coordSize);
  const ephemeralY = ephemeralBytes.slice(coordSize, headerSize);

  const ephemeralKeyJwk = {
    kty: 'EC',
    crv: 'P-256',
    x: base64UrlEncode(ephemeralX),
    y: base64UrlEncode(ephemeralY),
  };

  const ephemeralPublicKey = await subtle.importKey(
    'jwk',
    ephemeralKeyJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const sharedSecretBits = await subtle.deriveBits(
    {
      name: 'ECDH',
      public: ephemeralPublicKey,
    },
    privateKey,
    256
  );

  const hkdfKey = await subtle.importKey(
    'raw',
    new Uint8Array(sharedSecretBits),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  );

  const derivedKeyMaterial = await subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new Uint8Array(0),
      info: new TextEncoder().encode('key-manager-ecc-dek'),
    },
    hkdfKey,
    256
  );

  const aesKey = await subtle.importKey(
    'raw',
    derivedKeyMaterial,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );

  const ciphertextWithNonce = wrappedKey.slice(headerSize);
  const nonce = ciphertextWithNonce.slice(0, 12);
  const ciphertext = ciphertextWithNonce.slice(12);

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
