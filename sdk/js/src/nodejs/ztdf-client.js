/**
 * @fileoverview ZTDF Client for Node.js-based ZTDF file encryption/decryption
 * @module nodejs/ztdf-client
 *
 * Main client for encrypting and decrypting ZTDF files using Node.js crypto and gRPC.
 * Handles complete workflow: key generation, registration, file storage, and file encryption/decryption.
 */

import path from 'path';
import JSZip from 'jszip';
import Yazl from 'yazl';
import yauzl from 'yauzl';
import { PassThrough } from 'stream';
import { finished } from 'stream/promises';
import { createReadStream, createWriteStream } from 'fs';
import { readFile, stat as statFile } from 'fs/promises';
import { createHash, createCipheriv, createDecipheriv, privateEncrypt, constants as cryptoConstants } from 'crypto';
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
  decryptSegmentedPayload,
  calculatePayloadHash,
  calculatePolicyBinding,
  verifyPolicyBinding,
  verifyPayloadHash,
} from '../ztdf/crypto.js';
import { bytesToBase64, base64ToBytes } from '../utils/helpers.js';
import { parseZtdfFile } from '../ztdf/parser.js';
import {
  Manifest,
  EncryptionInformation_KeyAccessObject_KeyAccessObjectType,
  EncryptionInformation_KeyAccessObject_KeyAccessObjectProtocol,
  EncryptionInformation_EncryptionInformationType,
} from '../generated/models/ztdf_pb.js';

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
const STREAM_CHUNK_SIZE = 64 * 1024 * 1024; // 64MB
const GCM_AUTH_TAG_LENGTH = 16;
const POLICY_BINDING_ALG = 'HS256';

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
   * Stream a file into ZTDF format and write directly to disk.
   *
   * @param {string} inputPath - Path to the plaintext file
   * @param {string} outputPath - Path where the ZTDF file should be written
   * @param {Object} options - Encryption options (same as wrap)
   * @returns {Promise<{outputPath: string, plaintextSize: number, encryptedSize: number}>}
   */
  async wrapFile(inputPath, outputPath, options = {}) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized. Call initialize() first.');
    }

    const stats = await statFile(inputPath);
    const resource = options.resource || 'encrypted-file';
    const resourceAttributes = options.resourceAttributes || {};
    const filename = options.filename || path.basename(inputPath);
    const contentType = options.contentType || 'application/octet-stream';
    const integrityCheck = options.integrityCheck !== false;
    const context = options.context || {};

    const dek = generateDEK();
    const iv = generateIV();

    const zip = new Yazl.ZipFile();
    const output = createWriteStream(outputPath);
    const zipDone = finished(zip.outputStream.pipe(output));
    let zipClosed = false;
    const closeZip = () => {
      if (!zipClosed) {
        zip.end();
        zipClosed = true;
      }
    };

    const payloadStream = new PassThrough();
    zip.addReadStream(payloadStream, '0.payload', { compress: false });

    let ciphertextSize;
    let payloadHash;
    try {
      const streamResult = await this._encryptFileToStream({
        inputPath,
        payloadStream,
        dek,
        iv,
        integrityCheck,
      });
      ciphertextSize = streamResult.ciphertextSize;
      payloadHash = streamResult.payloadHash;
    } catch (error) {
      payloadStream.destroy(error);
      closeZip();
      output.destroy();
      throw error;
    }

    const wrapResult = await this._requestWrappedDEK(
      dek, resource, resourceAttributes, options.policy, context
    );

    let policyBinding = null;
    if (wrapResult.policy) {
      policyBinding = await calculatePolicyBinding(dek, wrapResult.policy);
    }

    const integrityInfo = payloadHash ? this._buildIntegrityInfo(
      bytesToBase64(payloadHash),
      stats.size,
      ciphertextSize
    ) : undefined;

    const manifest = this._createManifest({
      filename,
      contentType,
      payloadSize: stats.size,
      encryptedSize: ciphertextSize,
      iv: bytesToBase64(iv),
      keyId: wrapResult.keyId,
      wrappedKey: bytesToBase64(wrapResult.wrappedDek),
      policy: wrapResult.policy,
      policyBinding,
      payloadHash: payloadHash ? bytesToBase64(payloadHash) : null,
      integrityInfo,
      isStreamable: true,
    });

    zip.addBuffer(Buffer.from(manifest.toJsonString()), 'manifest.json', { compress: true });
    closeZip();
    await zipDone;

    this._log(`File encrypted successfully (${ciphertextSize} bytes written)`);
    return {
      outputPath,
      plaintextSize: stats.size,
      encryptedSize: ciphertextSize,
    };
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
    const context = options.context || {};

    const encryptedForSubjectBase64 = await this._unwrapDekFromKas({
      resource: manifest.filename || options.resource || 'encrypted-file',
      wrappedKeyBase64: keyAccess.wrappedKey,
      keyId: keyAccess.kid || '',
      policy: encInfo.policy || '',
      context,
    });

    const dek = await decryptDEK(this.currentKeyPair.privateKey, encryptedForSubjectBase64);

    const method = encInfo.method;
    const integrityInfo = encInfo.integrityInformation;
    const segments = Array.isArray(integrityInfo?.segments) ? integrityInfo.segments : [];
    const isSegmented = Boolean(method?.isStreamable && segments.length > 0);

    let plaintext;
    if (isSegmented && segments.length > 0) {
      const baseNonce = base64ToBytes(method.iv);
      plaintext = await decryptSegmentedPayload(
        payload,
        dek,
        baseNonce,
        segments,
        integrityInfo?.rootSignature?.sig
      );
    } else {
      const iv = base64ToBytes(method.iv);
      plaintext = await decryptPayload(payload, dek, iv);

      if (integrityInfo && options.verifyIntegrity !== false && manifest.payloadHash) {
        const payloadHash = base64ToBytes(manifest.payloadHash);
        const isValid = await verifyPayloadHash(plaintext, payloadHash);
        if (!isValid) {
          throw new Error('Payload integrity check failed');
        }
        this._log('Payload integrity verified');
      }
    }

    // Verify policy binding if provided
    const policyBindingValue = keyAccess.policyBinding
      ? (typeof keyAccess.policyBinding === 'string'
        ? keyAccess.policyBinding
        : keyAccess.policyBinding.hash)
      : null;
    if (policyBindingValue && options.verifyPolicy !== false) {
      const isValid = await verifyPolicyBinding(dek, encInfo.policy, policyBindingValue);
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
   * Stream a ZTDF file to disk without loading it into memory.
   *
   * @param {string} ztdfPath - Path to the ZTDF file
   * @param {string} outputPath - Path to write decrypted plaintext
   * @param {Object} [options={}] - Decryption options
   * @returns {Promise<{outputPath: string, filename: string, contentType: string}>}
   */
  async unwrapFile(ztdfPath, outputPath, options = {}) {
    if (!this.currentKeyPair) {
      throw new Error('Client not initialized. Call initialize() first.');
    }

    const manifestBuffer = await this._readZipEntryBuffer(ztdfPath, 'manifest.json');
    const manifest = Manifest.fromJsonString(manifestBuffer.toString('utf8'));
    const encInfo = manifest.encryptionInformation;
    const keyAccess = encInfo.keyAccess[0];

    const wrappedKey = keyAccess.wrappedKey;
    const dek = await decryptDEK(this.currentKeyPair.privateKey, wrappedKey);

    if (keyAccess.policyBinding && options.verifyPolicy !== false && encInfo.policy) {
      const isValid = await verifyPolicyBinding(dek, encInfo.policy, keyAccess.policyBinding);
      if (!isValid) {
        throw new Error('Policy binding verification failed');
      }
      this._log('Policy binding verified');
    }

    const payloadStream = await this._openZipEntryStream(ztdfPath, '0.payload');
    const verifyIntegrity = options.verifyIntegrity !== false && encInfo.integrityInformation;
    const expectedHash = verifyIntegrity && !encInfo.method?.isStreamable && manifest.payloadHash
      ? base64ToBytes(manifest.payloadHash)
      : null;

    await this._decryptPayloadStream({
      payloadStream,
      dek,
      iv: base64ToBytes(encInfo.method.iv),
      outputPath,
      expectedHash,
    });

    this._log(`File decrypted successfully to ${outputPath}`);

    return {
      outputPath,
      filename: manifest.filename,
      contentType: manifest.contentType,
    };
  }

  /**
   * Request wrapped DEK from Key Access Service
   * @private
   */
  async _requestWrappedDEK(dek, resource, resourceAttributes, policy, context) {
    const combinedContext = {
      ...normalizeStringMap(resourceAttributes),
      ...normalizeStringMap(context),
    };

    const clientWrappedDek = wrapDekWithPrivateKey(this.currentKeyPair.privateKey, dek);
    const response = await this.kasClient.wrapDEK({
      resource,
      dek: clientWrappedDek,
      action: 'encrypt',
      context: combinedContext,
      policy: policy || '',
      clientKeyId: this.currentKeyPair.metadata.keyId,
    });

    if (!response.accessGranted) {
      throw new Error(`Key Access denied: ${response.accessReason || 'wrap denied'}`);
    }

    return {
      wrappedDek: response.wrappedDek,
      keyId: response.keyId || 'default-key',
      policy: policy || '',
    };
  }

  async _unwrapDekFromKas({ resource, wrappedKeyBase64, keyId, policy, context }) {
    const response = await this.kasClient.unwrapDEK({
      resource,
      wrappedDek: base64ToBytes(wrappedKeyBase64),
      keyId: keyId || '',
      clientKeyId: this.currentKeyPair.metadata.keyId,
      action: 'decrypt',
      context: normalizeStringMap(context),
      policy: policy || '',
    });

    if (!response.accessGranted) {
      throw new Error(`Key Access denied: ${response.accessReason || 'unwrap denied'}`);
    }

    return bytesToBase64(response.dekForSubject);
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
        type: EncryptionInformation_EncryptionInformationType.SPLIT,
        keyAccess: [{
          type: EncryptionInformation_KeyAccessObject_KeyAccessObjectType.WRAPPED,
          kid: opts.keyId,
          wrappedKey: opts.wrappedKey,
          policyBinding: opts.policyBinding
            ? { alg: POLICY_BINDING_ALG, hash: opts.policyBinding }
            : undefined,
          url: this.config.keyAccessUrl,
          protocol: EncryptionInformation_KeyAccessObject_KeyAccessObjectProtocol.KAS,
        }],
        method: {
          algorithm: 'AES-256-GCM',
          iv: opts.iv,
          isStreamable: Boolean(opts.isStreamable),
        },
        integrityInformation: opts.integrityInfo || (opts.payloadHash ? this._buildIntegrityInfo(
          opts.payloadHash,
          opts.payloadSize,
          opts.encryptedSize
        ) : undefined),
        policy: opts.policy || '',
      },
      payloadHash: opts.payloadHash || '',
    });

    return manifest;
  }

  _buildIntegrityInfo(payloadHashBase64, payloadSize, encryptedSize) {
    if (!payloadHashBase64) {
      return undefined;
    }
    return {
      rootSignature: {
        alg: 'SHA256',
        sig: payloadHashBase64,
      },
      segmentHashAlg: 'SHA256',
      segments: [{
        hash: payloadHashBase64,
        segmentSize: payloadSize != null ? Number(payloadSize) : 0,
        encryptedSegmentSize: encryptedSize != null ? Number(encryptedSize) : undefined,
      }],
    };
  }

  async _encryptFileToStream({ inputPath, payloadStream, dek, iv, integrityCheck }) {
    const dekBuffer = Buffer.from(dek);
    const ivBuffer = Buffer.from(iv);
    const cipher = createCipheriv('aes-256-gcm', dekBuffer, ivBuffer);
    const readStream = createReadStream(inputPath, { highWaterMark: STREAM_CHUNK_SIZE });
    const hash = integrityCheck ? createHash('sha256') : null;

    return new Promise((resolve, reject) => {
      let ciphertextSize = 0;
      const handleError = (err) => {
        readStream.destroy();
        cipher.destroy();
        payloadStream.destroy();
        reject(err);
      };

      cipher.on('data', (chunk) => {
        ciphertextSize += chunk.length;
        if (!payloadStream.write(chunk)) {
          cipher.pause();
          payloadStream.once('drain', () => cipher.resume());
        }
      });

      cipher.on('end', () => {
        const authTag = cipher.getAuthTag();
        ciphertextSize += authTag.length;
        payloadStream.end(authTag);
      });

      cipher.on('error', handleError);
      payloadStream.on('error', handleError);

      readStream.on('data', (chunk) => {
        if (hash) {
          hash.update(chunk);
        }
        if (!cipher.write(chunk)) {
          readStream.pause();
          cipher.once('drain', () => readStream.resume());
        }
      });

      readStream.on('end', () => {
        cipher.end();
      });

      readStream.on('error', handleError);

      payloadStream.on('finish', () => {
        resolve({
          ciphertextSize,
          payloadHash: hash ? hash.digest() : null,
        });
      });
    });
  }

  async _readZipEntryBuffer(zipPath, entryName) {
    return new Promise((resolve, reject) => {
      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          return reject(err);
        }
        let settled = false;
        const finish = (error, buffer) => {
          if (!settled) {
            settled = true;
            zipfile.close();
            if (error) {
              reject(error);
            } else {
              resolve(buffer);
            }
          }
        };
        zipfile.on('entry', (entry) => {
          if (entry.fileName === entryName) {
            zipfile.openReadStream(entry, (streamErr, stream) => {
              if (streamErr) {
                return finish(streamErr);
              }
              streamToBuffer(stream)
                .then((buffer) => finish(null, buffer))
                .catch((streamError) => finish(streamError));
            });
          } else {
            zipfile.readEntry();
          }
        });
        zipfile.on('error', (error) => finish(error));
        zipfile.on('end', () => finish(new Error(`${entryName} not found in ZTDF file`)));
        zipfile.readEntry();
      });
    });
  }

  async _openZipEntryStream(zipPath, entryName) {
    return new Promise((resolve, reject) => {
      yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
        if (err) {
          return reject(err);
        }
        let settled = false;
        const fail = (error) => {
          if (!settled) {
            settled = true;
            zipfile.close();
            reject(error);
          }
        };
        zipfile.on('entry', (entry) => {
          if (entry.fileName === entryName) {
            zipfile.openReadStream(entry, (streamErr, stream) => {
              if (streamErr) {
                return fail(streamErr);
              }
              settled = true;
              stream.on('end', () => zipfile.close());
              stream.on('error', () => zipfile.close());
              resolve(stream);
            });
          } else {
            zipfile.readEntry();
          }
        });
        zipfile.on('error', (error) => fail(error));
        zipfile.on('end', () => fail(new Error(`${entryName} not found in ZTDF file`)));
        zipfile.readEntry();
      });
    });
  }

  async _decryptPayloadStream({ payloadStream, dek, iv, outputPath, expectedHash }) {
    const dekBuffer = Buffer.from(dek);
    const ivBuffer = Buffer.from(iv);
    const decipher = createDecipheriv('aes-256-gcm', dekBuffer, ivBuffer);
    const output = createWriteStream(outputPath);
    const hash = expectedHash ? createHash('sha256') : null;

    return new Promise((resolve, reject) => {
      let tail = Buffer.alloc(0);
      const handleError = (err) => {
        payloadStream.destroy();
        decipher.destroy();
        output.destroy();
        reject(err);
      };

      payloadStream.on('data', (chunk) => {
        const combined = Buffer.concat([tail, chunk]);
        if (combined.length <= GCM_AUTH_TAG_LENGTH) {
          tail = combined;
          return;
        }
        const dataLen = combined.length - GCM_AUTH_TAG_LENGTH;
        const data = combined.slice(0, dataLen);
        tail = combined.slice(dataLen);
        if (!decipher.write(data)) {
          payloadStream.pause();
          decipher.once('drain', () => payloadStream.resume());
        }
      });

      payloadStream.on('end', () => {
        if (tail.length !== GCM_AUTH_TAG_LENGTH) {
          handleError(new Error('Invalid payload: missing authentication tag'));
          return;
        }
        try {
          decipher.setAuthTag(tail);
        } catch (err) {
          handleError(err);
          return;
        }
        decipher.end();
      });

      payloadStream.on('error', handleError);

      decipher.on('data', (chunk) => {
        if (hash) {
          hash.update(chunk);
        }
        if (!output.write(chunk)) {
          decipher.pause();
          output.once('drain', () => decipher.resume());
        }
      });

      decipher.on('end', () => {
        output.end();
      });

      decipher.on('error', handleError);
      output.on('error', handleError);

      output.on('finish', () => {
        if (expectedHash) {
          const actual = hash.digest();
          const expectedBuffer = Buffer.from(expectedHash);
          if (!actual.equals(expectedBuffer)) {
            return reject(new Error('Payload integrity check failed'));
          }
        }
        resolve();
      });
    });
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

function normalizeStringMap(source) {
  if (!source || typeof source !== 'object') {
    return {};
  }
  const result = {};
  for (const [key, value] of Object.entries(source)) {
    if (value === undefined || value === null) {
      continue;
    }
    result[key] = String(value);
  }
  return result;
}

async function streamToBuffer(stream) {
  const chunks = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => chunks.push(chunk));
    stream.on('error', reject);
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
}
function wrapDekWithPrivateKey(privateKeyPem, dek) {
  const buffer = Buffer.isBuffer(dek) ? dek : Buffer.from(dek);
  const wrapped = privateEncrypt(
    {
      key: privateKeyPem,
      padding: cryptoConstants.RSA_PKCS1_PADDING,
    },
    buffer
  );
  return new Uint8Array(wrapped);
}
