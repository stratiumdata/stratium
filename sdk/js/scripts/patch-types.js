#!/usr/bin/env node
/**
 * Post-build script to add missing type exports to index.d.ts
 * This ensures TypeScript users can import types like KeyMetadata
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexDtsPath = path.join(__dirname, '../dist/index.d.ts');

// Read the generated index.d.ts file
let content = fs.readFileSync(indexDtsPath, 'utf-8');

// Check if types are already exported (to avoid duplicate exports)
if (!content.includes('export type { KeyMetadata')) {
  // Find the line that exports from browser/key-storage
  const storageExportLine = content.match(/export \{ [^}]+ \} from "\.\/browser\/key-storage\.js";/);

  if (storageExportLine) {
    // Replace it to include the types
    const oldLine = storageExportLine[0];
    const newLine = oldLine.replace(
      /export \{ ([^}]+) \}/,
      'export { $1, type KeyMetadata, type StoredKeyPair }'
    );

    content = content.replace(oldLine, newLine);

    // Write back
    fs.writeFileSync(indexDtsPath, content, 'utf-8');
    console.log('✓ Added KeyMetadata and StoredKeyPair type exports to index.d.ts');
  } else {
    console.warn('⚠ Could not find browser/key-storage export line to patch');
  }
} else {
  console.log('✓ Type exports already present in index.d.ts');
}