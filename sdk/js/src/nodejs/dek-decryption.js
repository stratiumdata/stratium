/**
 * @fileoverview DEK Decryption using RSA (Node.js)
 * @module nodejs/dek-decryption
 *
 * Decrypts Data Encryption Keys (DEKs) using ECIES with the client's private key.
 * Uses Node.js Web Crypto API for ECDH key agreement, HKDF, and AES-GCM.
 */

import crypto from 'crypto';

/**
 * Decrypt a wrapped DEK using RSA-OAEP
 *
 * @param {string} privateKeyPem - Client's RSA private key PEM
 * @param {string} wrappedKeyBase64 - Base64-encoded wrapped DEK
 * @returns {Promise<Uint8Array>} Decrypted DEK
 * @throws {Error} If decryption fails
 *
 * @example
 * const dek = await decryptDEK(privateKey, wrappedKeyBase64);
 * console.log('Decrypted DEK:', dek);
 */
export async function decryptDEK(privateKeyPem, wrappedKeyBase64) {
  const wrapped = Buffer.from(wrappedKeyBase64, 'base64');
  const decrypted = crypto.privateDecrypt(
    {
      key: privateKeyPem,
      padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    wrapped
  );
  return new Uint8Array(decrypted);
}
