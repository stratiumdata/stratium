/**
 * @fileoverview Node.js Crypto Key Generation for ZTDF Client
 * @module nodejs/key-generation
 *
 * Generates ECDH P-256 key pairs for secure key exchange in Node.js.
 * These utilities use the Node.js Web Crypto API (crypto.webcrypto).
 */

import { webcrypto } from 'crypto';

const { subtle } = webcrypto;

/**
 * Generate an ECDH P-256 key pair for client use
 * Keys are extractable in Node.js (can be saved to file)
 *
 * @returns {Promise<CryptoKeyPair>} Generated key pair
 * @throws {Error} If key generation fails
 *
 * @example
 * const keyPair = await generateClientKeyPair();
 * console.log('Generated key pair:', keyPair.publicKey, keyPair.privateKey);
 */
export async function generateClientKeyPair() {
  return await subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true, // extractable (can export private key for file storage)
    ['deriveBits', 'deriveKey']
  );
}

/**
 * Export public key as JWK format for server registration
 *
 * @param {CryptoKey} key - Public key to export
 * @returns {Promise<JsonWebKey>} Exported key in JWK format
 * @throws {Error} If key export fails
 *
 * @example
 * const jwk = await exportPublicKey(keyPair.publicKey);
 * console.log('Public key JWK:', jwk);
 */
export async function exportPublicKey(key) {
  return await subtle.exportKey('jwk', key);
}

/**
 * Export private key as JWK format for file storage
 *
 * @param {CryptoKey} key - Private key to export
 * @returns {Promise<JsonWebKey>} Exported key in JWK format
 * @throws {Error} If key export fails
 *
 * @example
 * const jwk = await exportPrivateKey(keyPair.privateKey);
 * // Save jwk to file
 */
export async function exportPrivateKey(key) {
  return await subtle.exportKey('jwk', key);
}

/**
 * Import public key from JWK format
 *
 * @param {JsonWebKey} jwk - Public key in JWK format
 * @returns {Promise<CryptoKey>} Imported public key
 * @throws {Error} If key import fails
 *
 * @example
 * const publicKey = await importPublicKey(jwk);
 */
export async function importPublicKey(jwk) {
  return await subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    []
  );
}

/**
 * Import private key from JWK format
 *
 * @param {JsonWebKey} jwk - Private key in JWK format
 * @returns {Promise<CryptoKey>} Imported private key
 * @throws {Error} If key import fails
 *
 * @example
 * const privateKey = await importPrivateKey(jwk);
 */
export async function importPrivateKey(jwk) {
  return await subtle.importKey(
    'jwk',
    jwk,
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    true,
    ['deriveBits', 'deriveKey']
  );
}

/**
 * Convert JWK to PEM format (for compatibility with backend)
 *
 * @param {JsonWebKey} jwk - Key in JWK format
 * @returns {string} PEM-formatted key
 *
 * @example
 * const pem = jwkToPem(jwk);
 */
export function jwkToPem(jwk) {
  const keyData = JSON.stringify(jwk);
  const base64 = Buffer.from(keyData).toString('base64');
  const pem = base64.match(/.{1,64}/g).join('\n');
  const type = jwk.d ? 'PRIVATE KEY' : 'PUBLIC KEY';
  return `-----BEGIN ${type}-----\n${pem}\n-----END ${type}-----`;
}