/**
 * @fileoverview File-based Storage for Client Keys (Node.js)
 * @module nodejs/key-storage
 *
 * Stores PEM-encoded RSA key pairs and metadata on disk for reuse.
 * This allows keys to persist across Node.js application restarts.
 */

import fs from 'fs/promises';
import path from 'path';

/**
 * Key metadata
 * @typedef {Object} KeyMetadata
 * @property {string} keyId - Unique key identifier
 * @property {string} expiresAt - Key expiration time (ISO string)
 * @property {string} createdAt - Key creation time (ISO string)
 */

/**
 * Stored key pair with metadata
 * @typedef {Object} StoredKeyPair
 * @property {string} keyId - Key identifier
 * @property {KeyMetadata} metadata - Key metadata
 * @property {CryptoKey} publicKey - Public key handle
 * @property {CryptoKey} privateKey - Private key handle
 */

/**
 * Key storage directory (default: ./.ztdf-keys)
 */
let STORAGE_DIR = path.join(process.cwd(), '.ztdf-keys');

/**
 * Set the storage directory for keys
 *
 * @param {string} dir - Directory path for key storage
 *
 * @example
 * setStorageDirectory('/var/app/keys');
 */
export function setStorageDirectory(dir) {
  STORAGE_DIR = dir;
}

/**
 * Get the current storage directory
 *
 * @returns {string} Current storage directory
 */
export function getStorageDirectory() {
  return STORAGE_DIR;
}

/**
 * Ensure storage directory exists
 * @private
 */
async function ensureStorageDir() {
  try {
    await fs.mkdir(STORAGE_DIR, { recursive: true, mode: 0o700 });
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw new Error(`Failed to create storage directory: ${err.message}`);
    }
  }
}

/**
 * Get file path for a key
 * @private
 */
function getKeyPath(keyId) {
  return path.join(STORAGE_DIR, `${keyId}.json`);
}

/**
 * Store a key pair with metadata
 *
 * @param {CryptoKeyPair} keyPair - Key pair to store
 * @param {KeyMetadata} metadata - Key metadata
 * @returns {Promise<void>}
 * @throws {Error} If storage fails
 *
 * @example
 * await storeKeyPair(keyPair, {
 *   keyId: 'key-123',
 *   expiresAt: new Date(Date.now() + 86400000).toISOString(),
 *   createdAt: new Date().toISOString()
 * });
 */
export async function storeKeyPair(keyPair, metadata) {
  await ensureStorageDir();

  const data = {
    keyId: metadata.keyId,
    metadata: metadata,
    publicKeyPem: keyPair.publicKey,
    privateKeyPem: keyPair.privateKey,
  };

  const filePath = getKeyPath(metadata.keyId);
  await fs.writeFile(filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
}

/**
 * Get a specific key pair by ID
 *
 * @param {string} keyId - Key identifier
 * @returns {Promise<StoredKeyPair|null>} Stored key pair or null if not found
 *
 * @example
 * const keyPair = await getKeyPair('key-123');
 * if (keyPair) {
 *   console.log('Found key:', keyPair.metadata);
 * }
 */
export async function getKeyPair(keyId) {
  try {
    const filePath = getKeyPath(keyId);
    const content = await fs.readFile(filePath, 'utf8');
    const data = JSON.parse(content);

    return {
      keyId: data.keyId,
      metadata: data.metadata,
      publicKey: data.publicKeyPem,
      privateKey: data.privateKeyPem,
    };
  } catch (err) {
    if (err.code === 'ENOENT') {
      return null;
    }
    throw new Error(`Failed to load key pair: ${err.message}`);
  }
}

/**
 * Get the current (non-expired) key pair
 *
 * @returns {Promise<StoredKeyPair|null>} Current key pair or null if none available
 *
 * @example
 * const currentKey = await getCurrentKeyPair();
 * if (!currentKey) {
 *   // Need to generate new key
 * }
 */
export async function getCurrentKeyPair() {
  const keys = await listKeys();
  const now = new Date();

  // Find non-expired keys, sorted by creation date (newest first)
  const validKeys = keys
    .filter((k) => new Date(k.expiresAt) > now)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

  if (validKeys.length === 0) {
    return null;
  }

  return await getKeyPair(validKeys[0].keyId);
}

/**
 * Delete a key pair
 *
 * @param {string} keyId - Key identifier
 * @returns {Promise<void>}
 *
 * @example
 * await deleteKeyPair('key-123');
 */
export async function deleteKeyPair(keyId) {
  try {
    const filePath = getKeyPath(keyId);
    await fs.unlink(filePath);
  } catch (err) {
    if (err.code !== 'ENOENT') {
      throw new Error(`Failed to delete key pair: ${err.message}`);
    }
  }
}

/**
 * Clean up expired keys
 *
 * @returns {Promise<number>} Number of keys deleted
 *
 * @example
 * const deleted = await cleanupExpiredKeys();
 * console.log(`Cleaned up ${deleted} expired keys`);
 */
export async function cleanupExpiredKeys() {
  const keys = await listKeys();
  const now = new Date();
  let deleted = 0;

  for (const key of keys) {
    if (new Date(key.expiresAt) <= now) {
      await deleteKeyPair(key.keyId);
      deleted++;
    }
  }

  return deleted;
}

/**
 * List all stored keys (metadata only)
 *
 * @returns {Promise<KeyMetadata[]>} Array of key metadata
 *
 * @example
 * const keys = await listKeys();
 * keys.forEach(k => console.log(k.keyId, k.expiresAt));
 */
export async function listKeys() {
  try {
    await ensureStorageDir();
    const files = await fs.readdir(STORAGE_DIR);
    const keyFiles = files.filter((f) => f.endsWith('.json'));

    const keys = [];
    for (const file of keyFiles) {
      try {
        const filePath = path.join(STORAGE_DIR, file);
        const content = await fs.readFile(filePath, 'utf8');
        const data = JSON.parse(content);
        keys.push(data.metadata);
      } catch (err) {
        // Skip invalid files
        console.warn(`Skipping invalid key file ${file}:`, err.message);
      }
    }

    return keys;
  } catch (err) {
    if (err.code === 'ENOENT') {
      return [];
    }
    throw err;
  }
}
