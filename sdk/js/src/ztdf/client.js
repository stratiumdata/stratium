/**
 * @fileoverview ZTDF Client for browser-based ZTDF file decryption
 * @module ztdf/client
 *
 * Main client for decrypting ZTDF files using WebCrypto and gRPC-Web.
 * Handles complete workflow: key generation, registration, storage, and file decryption.
 */

import JSZip from 'jszip';
import { createKeyAccessGrpcClient } from '../grpc/key-access-grpc.js';
import { createAuthenticatedTransport } from '../browser/grpc-transport.js';
import { generateClientKeyPair } from '../browser/key-generation.js';
import { storeKeyPair, getCurrentKeyPair } from '../browser/key-storage.js';
import { registerClientKey } from '../browser/key-registration.js';
import { decryptDEK } from '../browser/dek-decryption.js';
import {
  generateDEK,
  generateIV,
  encryptPayload,
  decryptPayload,
  decryptSegmentedPayload,
  calculatePayloadHash,
  calculatePolicyBinding,
  verifyPolicyBinding,
  verifyPayloadHash,
} from './crypto.js';
import { base64ToBytes, bytesToBase64 } from '../utils/helpers.js';
import { parseZtdfFile } from './parser.js';
import { Manifest } from '../generated/models/ztdf_pb.js';

/**
 * ZTDF Client for browser-based file decryption
 *
 * @example
 * import { ZtdfClient } from '@stratiumdata/sdk';
 *
 * const client = new ZtdfClient({
 *   keyAccessUrl: 'http://localhost:8081',
 *   keyManagerUrl: 'http://localhost:8081',
 *   clientId: 'my-app',
 *   clientKeyExpirationMs: 24 * 60 * 60 * 1000,
 *   getToken: async () => await keycloak.token,
 *   debug: true
 * });
 *
 * await client.initialize();
 *
 * const result = await client.unwrap(ztdfFile, {
 *   resource: 'document.pdf',
 *   action: 'read',
 *   context: { department: 'engineering' }
 * });
 *
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
   * Initialize the client by generating or loading client keys
   * @returns {Promise<void>}
   * @throws {Error} If initialization fails
   */
  async initialize() {
    this._log('Initializing ZTDF client...');

    // Try to get existing valid key
    const existingKey = await getCurrentKeyPair();

    if (existingKey) {
      this._log('Using existing client key:', existingKey.metadata.keyId);
      this.currentKeyPair = {
        keyPair: {
          publicKey: existingKey.publicKey,
          privateKey: existingKey.privateKey,
        },
        metadata: existingKey.metadata,
      };
      return;
    }

    // Generate new key pair
    this._log('Generating new client key pair...');
    const keyPair = await generateClientKeyPair();

    // Register with Key Manager
    const registration = await registerClientKey(
      this.config.clientId,
      keyPair.publicKey,
      this.config.keyManagerUrl,
      this.config.clientKeyExpirationMs,
      this.config.getToken
    );

    this._log('Registered new client key:', registration.keyId);

    // Store in IndexedDB
    const metadata = {
      keyId: registration.keyId,
      expiresAt: registration.expiresAt,
      createdAt: new Date(),
    };

    await storeKeyPair(keyPair, metadata);

    this.currentKeyPair = {
      keyPair,
      metadata,
    };
  }

  /**
   * Decrypt a ZTDF file
   *
   * @param {File|Blob} ztdfFile - ZTDF file to decrypt
   * @param {Object} [options] - Unwrap options
   * @param {string} [options.resource] - Resource identifier (defaults to filename)
   * @param {string} [options.action='decrypt'] - Action being performed
   * @param {Object<string,string>} [options.context={}] - Additional context attributes
   * @returns {Promise<Object>} Decrypted file information
   * @returns {Uint8Array} return.content - Decrypted file content
   * @returns {string} [return.filename] - Original filename
   * @returns {string} [return.contentType] - Content type
   * @returns {boolean} return.accessGranted - Whether access was granted
   * @returns {string} return.accessReason - Reason for access decision
   * @returns {string[]} return.appliedRules - Applied policy rules
   * @returns {Date} return.timestamp - Unwrap timestamp
   * @throws {Error} If client is not initialized or decryption fails
   */
  async unwrap(ztdfFile, options = {}) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized. Call initialize() first.');
    }

    this._log('Parsing ZTDF file...');
    const parsed = await parseZtdfFile(ztdfFile);

    const fileName = ztdfFile.name || 'file.ztdf';
    const resource = options.resource || fileName;
    const action = options.action || 'decrypt';
    const context = options.context || {};

    this._log('Unwrapping DEK...');
    let unwrapResult;
    try {
      unwrapResult = await this._unwrapDEK(parsed, resource, action, context);
    } catch (err) {
      this._log('Failed to unwrap DEK:', err);
      throw err;
    }

    if (!unwrapResult.accessGranted) {
      throw new Error(`Access denied: ${unwrapResult.accessReason}`);
    }

    this._log('DEK unwrapped successfully');
    this._log('Decrypted DEK length:', unwrapResult.dek.length);

    // Verify policy binding if present
    if (parsed.manifest.policyBinding && parsed.manifest.policyBinding.length > 0) {
      this._log('Verifying policy binding...');
      const policyValid = await verifyPolicyBinding(
        unwrapResult.dek,
        parsed.manifest.policy || '',
        parsed.manifest.policyBinding
      );

      if (!policyValid) {
        throw new Error('Policy binding verification failed');
      }
      this._log('Policy binding verified');
    }

    // Prepare encryption metadata
    const encInfo = parsed.manifest.encryptionInformation;
    const method = encInfo?.method;
    if (!method?.iv) {
      throw new Error('Missing IV in ZTDF manifest (encryptionInformation.method.iv)');
    }

    let baseNonce;
    if (typeof method.iv === 'string') {
      baseNonce = base64ToBytes(method.iv);
    } else if (method.iv instanceof Uint8Array) {
      baseNonce = method.iv;
    } else {
      throw new Error(`Unexpected IV type: ${typeof method.iv}`);
    }

    const integrityInfo = encInfo?.integrityInformation;
    const segments = Array.isArray(integrityInfo?.segments) ? integrityInfo.segments : [];
    const hasMultipleSegments = segments.length > 1;
    const isSegmented = Boolean(method?.isStreamable && hasMultipleSegments);

    this._log('Decrypting payload...');
    let decrypted;
    if (isSegmented && segments.length > 0) {
      this._log('Segmented payload detected; decrypting per segment');
      decrypted = await decryptSegmentedPayload(
        parsed.payload,
        unwrapResult.dek,
        baseNonce,
        segments,
        integrityInfo?.rootSignature?.sig
      );
    } else {
      this._log('Single-segment payload detected; decrypting directly');
      decrypted = await decryptPayload(parsed.payload, unwrapResult.dek, baseNonce);

      if (parsed.manifest.payloadHash && parsed.manifest.payloadHash.length > 0) {
        this._log('Verifying payload integrity...');
        const payloadHashBytes = base64ToBytes(parsed.manifest.payloadHash);
        const hashValid = await verifyPayloadHash(decrypted, payloadHashBytes);
        if (!hashValid) {
          throw new Error('Payload integrity verification failed');
        }
        this._log('Payload integrity verified');
      }
    }

    this._log('ZTDF file decrypted successfully');

    return {
      content: decrypted,
      filename: parsed.manifest.filename || fileName.replace('.ztdf', ''),
      contentType: parsed.manifest.contentType || 'application/octet-stream',
      accessGranted: unwrapResult.accessGranted,
      accessReason: unwrapResult.accessReason,
      appliedRules: unwrapResult.appliedRules,
      timestamp: unwrapResult.timestamp,
    };
  }

  /**
   * Encrypt data into ZTDF format
   *
   * @param {Uint8Array} plaintext - Data to encrypt
   * @param {Object} [options] - Wrap options
   * @param {string} [options.resource] - Resource identifier
   * @param {Object<string,string>} [options.resourceAttributes] - Resource attributes for policy
   * @param {string} [options.policy] - Base64-encoded policy (optional)
   * @param {string} [options.filename] - Original filename
   * @param {string} [options.contentType='application/octet-stream'] - Content type
   * @param {boolean} [options.integrityCheck=true] - Include payload integrity check
   * @param {Object<string,string>} [options.context={}] - Additional context
   * @returns {Promise<Blob>} ZTDF file as a Blob (ZIP format)
   * @throws {Error} If client is not initialized or encryption fails
   *
   * @example
   * const plaintext = new TextEncoder().encode('sensitive data');
   * const ztdfBlob = await client.wrap(plaintext, {
   *   resource: 'document.pdf',
   *   resourceAttributes: { classification: 'confidential' },
   *   filename: 'document.pdf',
   *   contentType: 'application/pdf'
   * });
   *
   * // Save as file
   * const url = URL.createObjectURL(ztdfBlob);
   * const a = document.createElement('a');
   * a.href = url;
   * a.download = 'document.pdf.ztdf';
   * a.click();
   */
  async wrap(plaintext, options = {}) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized. Call initialize() first.');
    }

    const resource = options.resource || 'encrypted-file';
    const resourceAttributes = options.resourceAttributes || {};
    const filename = options.filename || 'file';
    const contentType = options.contentType || 'application/octet-stream';
    const integrityCheck = options.integrityCheck !== false;
    const context = options.context || {};

    this._log('Encrypting data into ZTDF format...');
    this._log('Resource:', resource);
    this._log('Plaintext size:', plaintext.length);

    // Step 1: Generate DEK and IV
    this._log('Generating DEK and IV...');
    const dek = generateDEK();
    const iv = generateIV();

    // Step 2: Encrypt payload
    this._log('Encrypting payload...');
    const { ciphertext } = await encryptPayload(plaintext, dek, iv);

    // Step 3: Calculate payload hash (if integrity check enabled)
    let payloadHash = null;
    if (integrityCheck) {
      this._log('Calculating payload hash...');
      payloadHash = calculatePayloadHash(plaintext);
    }

    // Step 4: Request wrapped DEK from Key Access Service
    this._log('Requesting wrapped DEK from KAS...');
    const wrapResult = await this._requestWrappedDEK(
      dek,
      resource,
      resourceAttributes,
      options.policy,
      context
    );

    // Step 5: Calculate policy binding
    let policyBinding = null;
    if (wrapResult.policy) {
      this._log('Calculating policy binding...');
      policyBinding = calculatePolicyBinding(dek, wrapResult.policy);
    }

    // Step 6: Create manifest
    this._log('Creating manifest...');
    const manifest = this._createManifest({
      filename,
      contentType,
      payloadSize: plaintext.length,
      encryptedSize: ciphertext.length,
      iv: bytesToBase64(iv),
      keyId: wrapResult.keyId,
      wrappedKey: bytesToBase64(wrapResult.wrappedDek),
      policy: wrapResult.policy,
      policyBinding,
      payloadHash: payloadHash ? bytesToBase64(payloadHash) : null,
    });

    // Step 7: Package into ZIP format
    this._log('Packaging ZTDF file...');
    const ztdfBlob = await this._packageZTDF(manifest, ciphertext);

    this._log('ZTDF file created successfully');
    return ztdfBlob;
  }

  /**
   * Unwrap DEK using Key Access Service
   * @private
   */
  async _unwrapDEK(ztdfFile, resource, action, context) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized');
    }

    // Extract keyId and wrappedKey from encryptionInformation.keyAccess[0]
    const keyAccess = ztdfFile.manifest.encryptionInformation?.keyAccess?.[0];
    if (!keyAccess) {
      throw new Error('Invalid ZTDF: missing keyAccess information');
    }

    // Decode base64 wrappedKey to Uint8Array
    const wrappedKeyBase64 = keyAccess.wrappedKey || '';
    const wrappedDek = base64ToBytes(wrappedKeyBase64);

    const response = await this.kasClient.unwrapDEK({
      resource,
      wrappedDek,
      keyId: keyAccess.kid || '',
      clientKeyId: this.currentKeyPair.metadata.keyId,
      action,
      context,
      policy: ztdfFile.manifest.encryptionInformation?.policy || '',
    });

    if (!response.accessGranted) {
      throw new Error(`Access denied: ${response.accessReason}`);
    }

    // Decrypt DEK using client's private key
    const dek = await decryptDEK(
      response.dekForSubject,
      this.currentKeyPair.keyPair.privateKey
    );

    const timestamp = response.timestamp
      ? response.timestamp.toDate()
      : new Date();

    return {
      dek,
      accessGranted: response.accessGranted,
      accessReason: response.accessReason,
      appliedRules: response.appliedRules,
      timestamp,
    };
  }

  /**
   * Get current client key metadata
   * @returns {Object|null} Key metadata or null if not initialized
   */
  getKeyMetadata() {
    return this.currentKeyPair?.metadata || null;
  }

  /**
   * Check if client is initialized
   * @returns {boolean} True if client is initialized
   */
  isInitialized() {
    return this.currentKeyPair !== null;
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
        keyAccess: [
          {
            type: 'wrapped',
            kid: opts.keyId,
            wrappedKey: opts.wrappedKey,
            policyBinding: opts.policyBinding || '',
            url: this.config.keyAccessUrl,
            protocol: 'kas',
          },
        ],
        method: {
          algorithm: 'AES-256-GCM',
          iv: opts.iv,
          isStreamable: false,
        },
        integrityInformation: opts.payloadHash
          ? {
              rootSignature: {
                algorithm: 'HS256',
                sig: '',
              },
              segmentSizeDefault: 0,
              encryptedSegmentSizeDefault: 0,
              segments: [],
            }
          : undefined,
        policy: opts.policy || '',
      },
      payloadHash: opts.payloadHash || '',
    });

    return manifest;
  }

  /**
   * Package manifest and payload into ZIP format
   * @private
   */
  async _packageZTDF(manifest, ciphertext) {
    const zip = new JSZip();

    // Add manifest.json
    const manifestJson = manifest.toJsonString();
    zip.file('manifest.json', manifestJson);

    // Add encrypted payload
    zip.file('0.payload', ciphertext);

    // Generate ZIP blob
    const blob = await zip.generateAsync({
      type: 'blob',
      compression: 'DEFLATE',
      compressionOptions: { level: 6 },
    });

    return blob;
  }
}
