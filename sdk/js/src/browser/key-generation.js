/**
 * @fileoverview WebCrypto Key Generation for ZTDF Client
 * @module browser/key-generation
 *
 * Generates ECDH P-256 key pairs for secure key exchange in the browser.
 * These utilities use the Web Crypto API which is available in modern browsers.
 */

/**
 * Generate an ECDH P-256 key pair for client use
 * Keys are non-extractable for security (private key cannot be exported)
 *
 * @returns {Promise<CryptoKeyPair>} Generated key pair
 * @throws {Error} If key generation fails
 *
 * @example
 * const keyPair = await generateClientKeyPair();
 * console.log('Generated key pair:', keyPair.publicKey, keyPair.privateKey);
 */
export async function generateClientKeyPair() {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API is not available. This function only works in browsers.');
  }

  return await window.crypto.subtle.generateKey(
    {
      name: 'ECDH',
      namedCurve: 'P-256',
    },
    false, // non-extractable (cannot export private key)
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
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API is not available. This function only works in browsers.');
  }

  return await window.crypto.subtle.exportKey('jwk', key);
}

/**
 * Import a public key from JWK format
 *
 * @param {JsonWebKey} jwk - Public key in JWK format
 * @returns {Promise<CryptoKey>} Imported public key
 * @throws {Error} If key import fails
 *
 * @example
 * const publicKey = await importPublicKey(jwk);
 */
export async function importPublicKey(jwk) {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API is not available. This function only works in browsers.');
  }

  return await window.crypto.subtle.importKey(
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
 * Convert JWK to PEM format
 * Handles both RSA and EC keys
 *
 * @param {JsonWebKey} jwk - Key in JWK format
 * @returns {Promise<string>} Key in PEM format
 * @throws {Error} If conversion fails or key type is unsupported
 *
 * @example
 * const pem = await jwkToPem(jwk);
 * console.log('PEM format:', pem);
 */
export async function jwkToPem(jwk) {
  if (typeof window === 'undefined' || !window.crypto || !window.crypto.subtle) {
    throw new Error('Web Crypto API is not available. This function only works in browsers.');
  }

  // Determine key type and import accordingly
  let key;

  if (jwk.kty === 'EC') {
    // Import EC key
    key = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDH', namedCurve: jwk.crv || 'P-256' },
      true,
      []
    );
  } else if (jwk.kty === 'RSA') {
    // Import RSA key
    key = await window.crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
  } else {
    throw new Error(`Unsupported key type: ${jwk.kty}`);
  }

  // Export as SPKI (SubjectPublicKeyInfo) format
  const exported = await window.crypto.subtle.exportKey('spki', key);

  // Convert to PEM format
  const exportedAsString = String.fromCharCode.apply(null, new Uint8Array(exported));
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;

  return pemExported;
}