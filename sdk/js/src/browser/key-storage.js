/**
 * @fileoverview IndexedDB Storage for Client Keys
 * @module browser/key-storage
 *
 * Stores non-extractable CryptoKey handles and metadata in IndexedDB.
 * This allows keys to persist across browser sessions without being exportable.
 */

const DB_NAME = 'ztdf-client-keys';
const DB_VERSION = 2;
const STORE_NAME = 'keys';

/**
 * Key metadata
 * @typedef {Object} KeyMetadata
 * @property {string} keyId - Unique key identifier
 * @property {Date} expiresAt - Key expiration time
 * @property {Date} createdAt - Key creation time
 */

/**
 * Stored key pair with metadata
 * @typedef {Object} StoredKeyPair
 * @property {string} keyId - Key identifier (duplicate at root for IndexedDB keyPath)
 * @property {KeyMetadata} metadata - Key metadata
 * @property {CryptoKey} publicKey - Public key handle
 * @property {CryptoKey} privateKey - Private key handle (non-extractable)
 */

/**
 * Open IndexedDB connection
 * @private
 * @returns {Promise<IDBDatabase>} Database connection
 */
function openDB() {
  if (typeof window === 'undefined' || !window.indexedDB) {
    throw new Error('IndexedDB is not available. This function only works in browsers.');
  }

  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      const oldVersion = event.oldVersion;

      // Delete old store if upgrading from version 1
      if (oldVersion < 2 && db.objectStoreNames.contains(STORE_NAME)) {
        db.deleteObjectStore(STORE_NAME);
      }

      // Create new store with updated keyPath
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        const store = db.createObjectStore(STORE_NAME, { keyPath: 'keyId' });
        store.createIndex('expiresAt', 'metadata.expiresAt', { unique: false });
      }
    };
  });
}

/**
 * Store key pair with metadata in IndexedDB
 *
 * @param {CryptoKeyPair} keyPair - Key pair to store
 * @param {KeyMetadata} metadata - Key metadata
 * @returns {Promise<void>}
 * @throws {Error} If storage fails
 *
 * @example
 * await storeKeyPair(keyPair, {
 *   keyId: 'key-123',
 *   expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
 *   createdAt: new Date()
 * });
 */
export async function storeKeyPair(keyPair, metadata) {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);

    const data = {
      keyId: metadata.keyId,
      metadata,
      publicKey: keyPair.publicKey,
      privateKey: keyPair.privateKey,
    };

    const request = store.put(data);

    request.onsuccess = () => {
      db.close();
      resolve();
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/**
 * Retrieve key pair from IndexedDB by key ID
 *
 * @param {string} keyId - Key identifier
 * @returns {Promise<StoredKeyPair|null>} Stored key pair or null if not found/expired
 * @throws {Error} If retrieval fails
 *
 * @example
 * const keyPair = await getKeyPair('key-123');
 * if (keyPair) {
 *   console.log('Found key:', keyPair.metadata);
 * }
 */
export async function getKeyPair(keyId) {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.get(keyId);

    request.onsuccess = () => {
      db.close();
      const result = request.result;

      // Check if key is expired
      if (result && new Date(result.metadata.expiresAt) < new Date()) {
        // Key is expired, delete it
        deleteKeyPair(keyId).catch(console.error);
        resolve(null);
      } else {
        resolve(result || null);
      }
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/**
 * Get the most recent valid key pair
 *
 * @returns {Promise<StoredKeyPair|null>} Most recent valid key pair or null
 * @throws {Error} If retrieval fails
 *
 * @example
 * const currentKey = await getCurrentKeyPair();
 * if (currentKey) {
 *   console.log('Current key ID:', currentKey.metadata.keyId);
 * }
 */
export async function getCurrentKeyPair() {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('expiresAt');

    // Get all keys ordered by expiration (most recent first)
    const request = index.openCursor(null, 'prev');

    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) {
        const keyPair = cursor.value;
        // Check if not expired
        if (new Date(keyPair.metadata.expiresAt) > new Date()) {
          db.close();
          resolve(keyPair);
        } else {
          // Try next key
          cursor.continue();
        }
      } else {
        // No valid keys found
        db.close();
        resolve(null);
      }
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/**
 * Delete a key pair from IndexedDB
 *
 * @param {string} keyId - Key identifier
 * @returns {Promise<void>}
 * @throws {Error} If deletion fails
 *
 * @example
 * await deleteKeyPair('key-123');
 */
export async function deleteKeyPair(keyId) {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.delete(keyId);

    request.onsuccess = () => {
      db.close();
      resolve();
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/**
 * Delete all expired keys from IndexedDB
 *
 * @returns {Promise<number>} Number of keys deleted
 * @throws {Error} If cleanup fails
 *
 * @example
 * const deletedCount = await cleanupExpiredKeys();
 * console.log(`Deleted ${deletedCount} expired keys`);
 */
export async function cleanupExpiredKeys() {
  const db = await openDB();
  const now = new Date();
  let deletedCount = 0;

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const index = store.index('expiresAt');

    // Get all keys with expiration before now
    const range = IDBKeyRange.upperBound(now);
    const request = index.openCursor(range);

    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor) {
        cursor.delete();
        deletedCount++;
        cursor.continue();
      } else {
        db.close();
        resolve(deletedCount);
      }
    };

    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}

/**
 * List all stored key pairs
 *
 * @returns {Promise<KeyMetadata[]>} Array of key metadata
 * @throws {Error} If listing fails
 *
 * @example
 * const keys = await listKeys();
 * keys.forEach(key => console.log('Key:', key.keyId, 'Expires:', key.expiresAt));
 */
export async function listKeys() {
  const db = await openDB();

  return new Promise((resolve, reject) => {
    const transaction = db.transaction([STORE_NAME], 'readonly');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.getAll();

    request.onsuccess = () => {
      db.close();
      const keys = request.result.map(k => k.metadata);
      resolve(keys);
    };
    request.onerror = () => {
      db.close();
      reject(request.error);
    };
  });
}