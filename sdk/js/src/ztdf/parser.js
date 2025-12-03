/**
 * @fileoverview ZTDF File Parser
 * @module ztdf/parser
 *
 * Parses .ztdf files (ZIP format with manifest.json and encrypted payload)
 */

import JSZip from 'jszip';
import { Manifest } from '../generated/models/ztdf_pb.js';

/**
 * Parse a ZTDF file from a File or Blob object
 *
 * @param {File|Blob} file - ZTDF file to parse
 * @returns {Promise<{manifest: Manifest, payload: Uint8Array}>} Parsed ZTDF content
 * @throws {Error} If file is invalid or parsing fails
 *
 * @example
 * import { parseZtdfFile } from '@stratiumdata/sdk';
 *
 * const ztdfFile = await parseZtdfFile(fileInput.files[0]);
 * console.log('Manifest:', ztdfFile.manifest);
 * console.log('Payload size:', ztdfFile.payload.length);
 */
export async function parseZtdfFile(file) {
  try {
    // Load ZIP file
    const zip = await JSZip.loadAsync(file);

    // Extract manifest.json
    const manifestFile = zip.file('manifest.json');
    if (!manifestFile) {
      throw new Error('Invalid ZTDF file: missing manifest.json');
    }

    const manifestText = await manifestFile.async('text');

    // Convert JSON to Manifest proto
    const manifest = Manifest.fromJsonString(manifestText, {
      ignoreUnknownFields: true,
    });

    // Extract payload
    const payloadFile = zip.file('0.payload');
    if (!payloadFile) {
      throw new Error('Invalid ZTDF file: missing 0.payload');
    }

    const payload = await payloadFile.async('uint8array');

    return {
      manifest,
      payload,
    };
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : 'Unknown error';
    throw new Error(`Failed to parse ZTDF file: ${errorMsg}`);
  }
}
