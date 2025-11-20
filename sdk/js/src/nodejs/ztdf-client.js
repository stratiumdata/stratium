/**
 * @fileoverview ZTDF Client for Node.js-based ZTDF file encryption/decryption
 * @module nodejs/ztdf-client
 *
 * Main client for encrypting and decrypting ZTDF files using Node.js crypto and gRPC.
 * Handles complete workflow: key generation, registration, file storage, and file encryption/decryption.
 */

import JSZip from 'jszip';
import { createKeyAccessGrpcClient } from '../grpc/key-access-grpc.js';
import { createAuthenticatedTransport } from './grpc-transport.js';
import { generateClientKeyPair } from './key-generation.js';
import { storeKeyPair, getCurrentKeyPair } from './key-storage.js';
import { registerClientKey } from './key-registration.js';
import { decryptDEK } from './dek-decryption.js';
import {
  generateDEK,
  generateIV,
  encryptPayload,
  decryptPayload,
  calculatePayloadHash,
  calculatePolicyBinding,
  verifyPolicyBinding,
  verifyPayloadHash,
} from '../ztdf/crypto.js';
import { bytesToBase64, base64ToBytes } from '../utils/helpers.js';
import { parseZtdfFile } from '../ztdf/parser.js';
import { Manifest } from '../generated/models/ztdf_pb.js';
import { readFile } from 'fs/promises';

/**
 * ZTDF Client for Node.js-based file encryption/decryption
 *
 * @example
 * import { ZtdfClient } from '@stratiumdata/sdk/nodejs';
 *
 * const client = new ZtdfClient({
 *   keyAccessUrl: 'http://localhost:8081',
 *   keyManagerUrl: 'http://localhost:8081',
 *   clientId: 'my-app',
 *   clientKeyExpirationMs: 24 * 60 * 60 * 1000,
 *   getToken: async () => await getMyToken(),
 *   debug: true
 * });
 *
 * await client.initialize();
 *
 * // Encrypt
 * const ztdfBlob = await client.wrap(plaintext, {
 *   filename: 'document.pdf',
 *   contentType: 'application/pdf'
 * });
 *
 * // Decrypt
 * const result = await client.unwrap('/path/to/file.ztdf');
 * console.log('Decrypted:', result.content);
 */
export class ZtdfClient {
  /**
   * @param {Object} config - Client configuration
   * @param {string} config.keyAccessUrl - Key Access Service URL
   * @param {string} config.keyManagerUrl - Key Manager Service URL
   * @param {string} config.clientId - Client identifier for key registration
   * @param {number} [config.clientKeyExpirationMs=86400000] - Client key expiration in milliseconds (default 24 hours)
   * @param {Function} [config.getToken] - Optional function that returns an auth token
   * @param {boolean} [config.debug=false] - Enable debug logging
   */
  constructor(config) {
    if (!config.keyAccessUrl) {
      throw new Error('keyAccessUrl is required');
    }
    if (!config.keyManagerUrl) {
      throw new Error('keyManagerUrl is required');
    }
    if (!config.clientId) {
      throw new Error('clientId is required');
    }

    this.config = {
      keyAccessUrl: config.keyAccessUrl,
      keyManagerUrl: config.keyManagerUrl,
      clientId: config.clientId,
      clientKeyExpirationMs: config.clientKeyExpirationMs || 24 * 60 * 60 * 1000,
      getToken: config.getToken,
      debug: config.debug || false,
    };

    // Create gRPC clients
    const kasTransport = createAuthenticatedTransport(this.config.keyAccessUrl, this.config.getToken);
    this.kasClient = createKeyAccessGrpcClient(kasTransport);

    this.currentKeyPair = null;
  }

  /**
   * Log debug message if debug mode is enabled
   * @private
   */
  _log(...args) {
    if (this.config.debug) {
      console.log('[ZtdfClient]', ...args);
    }
  }

  /**
   * Initialize the client
   * Loads existing key or generates and registers a new one
   *
   * @returns {Promise<void>}
   * @throws {Error} If initialization fails
   *
   * @example
   * await client.initialize();
   */
  async initialize() {
    this._log('Initializing ZTDF client...');

    // Try to load existing key
    const existingKey = await getCurrentKeyPair();

    if (existingKey) {
      this._log('Found existing key pair:', existingKey.metadata.keyId);
      this.currentKeyPair = existingKey;
      return;
    }

    // Generate new key pair
    this._log('Generating new key pair...');
    const keyPair = await generateClientKeyPair();

    // Register with Key Manager
    this._log('Registering key with Key Manager...');
    const registration = await registerClientKey(
      this.config.clientId,
      keyPair.publicKey,
      this.config.keyManagerUrl,
      this.config.clientKeyExpirationMs,
      this.config.getToken
    );

    // Store key pair with metadata
    const metadata = {
      keyId: registration.keyId,
      expiresAt: registration.expiresAt.toISOString(),
      createdAt: new Date().toISOString(),
    };

    await storeKeyPair(keyPair, metadata);

    this.currentKeyPair = {
      ...keyPair,
      metadata,
    };

    this._log('Client initialized successfully with key:', registration.keyId);
  }

  /**
   * Get current key metadata
   *
   * @returns {Object|null} Key metadata or null if not initialized
   *
   * @example
   * const metadata = client.getKeyMetadata();
   * console.log('Key ID:', metadata.keyId);
   */
  getKeyMetadata() {
    return this.currentKeyPair?.metadata || null;
  }

  /**
   * Encrypt data into ZTDF format
   *
   * @param {Buffer|Uint8Array} plaintext - Data to encrypt
   * @param {Object} options - Encryption options
   * @param {string} [options.filename='file'] - Original filename
   * @param {string} [options.contentType='application/octet-stream'] - MIME type
   * @param {string} [options.resource] - Resource identifier for policy
   * @param {Object} [options.resourceAttributes={}] - Resource attributes for ABAC
   * @param {string} [options.policy=''] - Custom policy (optional)
   * @param {boolean} [options.integrityCheck=true] - Include payload hash for integrity
   * @param {Object} [options.context={}] - Additional context for key access
   * @returns {Promise<Buffer>} ZTDF file as Buffer
   * @throws {Error} If encryption fails
   *
   * @example
   * const plaintext = Buffer.from('Hello, World!');
   * const ztdfBuffer = await client.wrap(plaintext, {
   *   filename: 'hello.txt',
   *   contentType: 'text/plain',
   *   resource: 'my-document',
   *   resourceAttributes: { classification: 'confidential' }
   * });
   */
  async wrap(plaintext, options = {}) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized. Call initialize() first.');
    }

    const plaintextArray = plaintext instanceof Buffer ? new Uint8Array(plaintext) : plaintext;

    const resource = options.resource || 'encrypted-file';
    const resourceAttributes = options.resourceAttributes || {};
    const filename = options.filename || 'file';
    const contentType = options.contentType || 'application/octet-stream';
    const integrityCheck = options.integrityCheck !== false;
    const context = options.context || {};

    this._log(`Encrypting file: ${filename} (${plaintextArray.length} bytes)`);

    // Step 1: Generate DEK and IV
    const dek = generateDEK();
    const iv = generateIV();

    // Step 2: Encrypt payload
    const { ciphertext } = await encryptPayload(plaintextArray, dek, iv);

    // Step 3: Calculate payload hash (if integrity check enabled)
    let payloadHash = null;
    if (integrityCheck) {
      payloadHash = await calculatePayloadHash(plaintextArray);
    }

    // Step 4: Request wrapped DEK from Key Access Service
    const wrapResult = await this._requestWrappedDEK(
      dek, resource, resourceAttributes, options.policy, context
    );

    // Step 5: Calculate policy binding
    let policyBinding = null;
    if (wrapResult.policy) {
      policyBinding = await calculatePolicyBinding(dek, wrapResult.policy);
    }

    // Step 6: Create manifest
    const manifest = this._createManifest({
      filename, contentType, payloadSize: plaintextArray.length,
      encryptedSize: ciphertext.length, iv: bytesToBase64(iv),
      keyId: wrapResult.keyId, wrappedKey: bytesToBase64(wrapResult.wrappedDek),
      policy: wrapResult.policy, policyBinding,
      payloadHash: payloadHash ? bytesToBase64(payloadHash) : null,
    });

    // Step 7: Package into ZIP format
    const ztdfBuffer = await this._packageZTDF(manifest, ciphertext);

    this._log(`File encrypted successfully (${ztdfBuffer.length} bytes)`);
    return ztdfBuffer;
  }

  /**
   * Decrypt a ZTDF file
   *
   * @param {string|Buffer|Uint8Array} ztdfFile - Path to ZTDF file, Buffer, or Uint8Array
   * @param {Object} [options={}] - Decryption options
   * @returns {Promise<Object>} Decrypted file data with metadata
   * @throws {Error} If decryption fails
   *
   * @example
   * const result = await client.unwrap('/path/to/file.ztdf');
   * console.log('Decrypted:', result.content);
   * console.log('Filename:', result.filename);
   */
  async unwrap(ztdfFile, options = {}) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized. Call initialize() first.');
    }

    // Load ZTDF file
    let ztdfData;
    if (typeof ztdfFile === 'string') {
      // File path
      ztdfData = await readFile(ztdfFile);
    } else if (ztdfFile instanceof Buffer) {
      ztdfData = ztdfFile;
    } else {
      ztdfData = Buffer.from(ztdfFile);
    }

    this._log(`Decrypting ZTDF file (${ztdfData.length} bytes)`);

    // Parse ZTDF file
    const { manifest, payload } = await parseZtdfFile(ztdfData);

    // Extract encryption info
    const encInfo = manifest.encryptionInformation;
    const keyAccess = encInfo.keyAccess[0];
    const wrappedKey = keyAccess.wrappedKey;

    // Decrypt DEK
    const dek = await decryptDEK(this.currentKeyPair.privateKey, wrappedKey);

    // Decrypt payload
    const iv = base64ToBytes(encInfo.method.iv);
    const plaintext = await decryptPayload(payload, dek, iv);

    // Verify integrity if provided
    if (encInfo.integrityInformation && options.verifyIntegrity !== false) {
      const payloadHash = base64ToBytes(manifest.payloadHash);
      const isValid = await verifyPayloadHash(plaintext, payloadHash);
      if (!isValid) {
        throw new Error('Payload integrity check failed');
      }
      this._log('Payload integrity verified');
    }

    // Verify policy binding if provided
    if (keyAccess.policyBinding && options.verifyPolicy !== false) {
      const isValid = await verifyPolicyBinding(dek, encInfo.policy, keyAccess.policyBinding);
      if (!isValid) {
        throw new Error('Policy binding verification failed');
      }
      this._log('Policy binding verified');
    }

    this._log(`File decrypted successfully (${plaintext.length} bytes)`);

    return {
      content: plaintext,
      filename: manifest.filename,
      contentType: manifest.contentType,
      accessGranted: true,
      accessReason: 'Key access granted',
      appliedRules: [],
      timestamp: new Date(),
    };
  }

  /**
   * Request wrapped DEK from Key Access Service
   * @private
   */
  async _requestWrappedDEK(dek, resource, resourceAttributes, policy, context) {
    const response = await this.kasClient.requestDEK({
      resource,
      dek,
      policy: policy || '',
      resourceAttributes,
      context,
      clientKeyId: this.currentKeyPair.metadata.keyId,
    });

    return {
      wrappedDek: response.dekForSubject,
      keyId: response.keyId || 'default-key',
      policy: response.policy || policy || '',
    };
  }

  /**
   * Create ZTDF manifest
   * @private
   */
  _createManifest(opts) {
    const manifest = new Manifest({
      filename: opts.filename,
      contentType: opts.contentType,
      encryptionInformation: {
        type: 'split',
        keyAccess: [{
          type: 'wrapped',
          kid: opts.keyId,
          wrappedKey: opts.wrappedKey,
          policyBinding: opts.policyBinding || '',
          url: this.config.keyAccessUrl,
          protocol: 'kas',
        }],
        method: {
          algorithm: 'AES-256-GCM',
          iv: opts.iv,
          isStreamable: false,
        },
        integrityInformation: opts.payloadHash ? {
          rootSignature: {
            algorithm: 'SHA-256',
            value: opts.payloadHash,
          },
          segmentHashAlg: 'SHA-256',
          segments: [{
            hash: opts.payloadHash,
            segmentSize: opts.payloadSize.toString(),
          }],
        } : undefined,
        policy: opts.policy || '',
      },
      payloadHash: opts.payloadHash || '',
    });

    return manifest;
  }

  /**
   * Package manifest and payload into ZTDF ZIP format
   * @private
   */
  async _packageZTDF(manifest, ciphertext) {
    const zip = new JSZip();
    zip.file('manifest.json', manifest.toJsonString());
    zip.file('0.payload', ciphertext);

    const buffer = await zip.generateAsync({
      type: 'nodebuffer',
      compression: 'DEFLATE',
      compressionOptions: { level: 6 },
    });

    return buffer;
  }
}