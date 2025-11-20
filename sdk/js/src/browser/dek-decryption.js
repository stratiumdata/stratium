/**
 * @fileoverview DEK Decryption using ECIES (Elliptic Curve Integrated Encryption Scheme)
 * @module browser/dek-decryption
 *
 * Decrypts DEK that was encrypted with client's public key using ECIES.
 * This module uses the Web Crypto API for ECDH key derivation and AES-GCM decryption.
 */

/**
 * Base64URL encode a byte array (without padding)
 * @private
 * @param {Uint8Array} bytes - Bytes to encode
 * @returns {string} Base64URL encoded string
 */
function base64UrlEncode(bytes) {
  const base64 = btoa(String.fromCharCode(...bytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decrypt DEK using client's private key via ECDH key derivation
 *
 * The encrypted DEK format from server (ECIES):
 * - ephemeralPublicKey (64 bytes: 32 bytes X + 32 bytes Y for P-256)
 * - nonce (12 bytes)
 * - ciphertext (encrypted DEK)
 * - authTag (16 bytes, included in ciphertext for AES-GCM)
 *
 * @param {Uint8Array} encryptedDEK - Encrypted DEK bytes
 * @param {CryptoKey} privateKey - Client's private key
 * @returns {Promise<Uint8Array>} Decrypted DEK
 * @throws {Error} If decryption fails
 *
 * @example
 * const dek = await decryptDEK(encryptedDEKBytes, clientPrivateKey);
 * console.log('Decrypted DEK length:', dek.length);
 */
export async function decryptDEK(encryptedDEK, privateKey) {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API is not available. This function only works in browsers.');
  }

  try {
    console.log('DEK decryption - Encrypted DEK length:', encryptedDEK.length);

    // Parse encrypted DEK structure
    // Format: ephemeralPublicKey (64 bytes) + nonce (12 bytes) + ciphertext + authTag (16 bytes)

    // Extract ephemeral public key (raw 64 bytes for P-256: 32 bytes X + 32 bytes Y)
    const ephemeralPubKeyBytes = encryptedDEK.slice(0, 64);
    const ephemeralX = ephemeralPubKeyBytes.slice(0, 32);
    const ephemeralY = ephemeralPubKeyBytes.slice(32, 64);

    console.log('Ephemeral key X length:', ephemeralX.length);
    console.log('Ephemeral key Y length:', ephemeralY.length);

    // Convert to JWK format for import
    const ephemeralKeyJWK = {
      kty: 'EC',
      crv: 'P-256',
      x: base64UrlEncode(ephemeralX),
      y: base64UrlEncode(ephemeralY),
    };

    // Import ephemeral public key
    const ephemeralPublicKey = await window.crypto.subtle.importKey(
      'jwk',
      ephemeralKeyJWK,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      []
    );

    // Derive shared secret using ECDH
    const sharedSecret = await window.crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: ephemeralPublicKey,
      },
      privateKey,
      256 // 256 bits for AES-256
    );

    // Derive AES key from shared secret using HKDF with same context as server
    const hkdfKey = await window.crypto.subtle.importKey(
      'raw',
      sharedSecret,
      { name: 'HKDF' },
      false,
      ['deriveBits']
    );

    const derivedKeyMaterial = await window.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode('key-manager-dek-wrap'),
      },
      hkdfKey,
      256 // 256 bits for AES-256
    );

    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      derivedKeyMaterial,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );

    // Extract ciphertext (starts after 64-byte ephemeral key)
    // The ciphertext contains: nonce (12 bytes) + encrypted data + auth tag (16 bytes)
    const ciphertextWithNonce = encryptedDEK.slice(64);
    const nonce = ciphertextWithNonce.slice(0, 12);
    const ciphertext = ciphertextWithNonce.slice(12);

    // Decrypt DEK
    const decryptedDEK = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce,
      },
      aesKey,
      ciphertext
    );

    return new Uint8Array(decryptedDEK);
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : 'Unknown error';
    throw new Error(`Failed to decrypt DEK: ${errorMsg}`);
  }
}