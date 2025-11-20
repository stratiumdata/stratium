#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

const generatedDir = path.join(__dirname, '../src/generated');

function fixConnectFile(filePath) {
  let content = fs.readFileSync(filePath, 'utf8');
  let modified = false;

  // Fix imports from _pb files to use Schema suffix
  const importRegex = /import\s*{([^}]+)}\s*from\s*"(\.\/[^"]+_pb\.js)"/g;

  content = content.replace(importRegex, (match, imports, from) => {
    const importList = imports.split(',').map(i => i.trim());
    const transformedImports = importList.map(imp => {
      if (imp === 'MethodKind') {
        return imp;
      }
      return `${imp}Schema as ${imp}`;
    });
    modified = true;
    return `import { ${transformedImports.join(', ')} } from "${from}"`;
  });

  // Remove MethodKind import line entirely
  if (content.includes('import { MethodKind } from "@bufbuild/protobuf"')) {
    content = content.replace(/import\s*{\s*MethodKind\s*}\s*from\s*"@bufbuild\/protobuf";\s*\n/g, '');
    modified = true;
  }

  // Replace MethodKind.Unary with string literal "unary"
  if (content.includes('MethodKind.Unary')) {
    content = content.replace(/MethodKind\.Unary/g, '"unary"');
    modified = true;
  }

  // Replace other MethodKind values if they exist
  if (content.includes('MethodKind.ServerStreaming')) {
    content = content.replace(/MethodKind\.ServerStreaming/g, '"server_streaming"');
    modified = true;
  }

  if (content.includes('MethodKind.ClientStreaming')) {
    content = content.replace(/MethodKind\.ClientStreaming/g, '"client_streaming"');
    modified = true;
  }

  if (content.includes('MethodKind.BiDiStreaming')) {
    content = content.replace(/MethodKind\.BiDiStreaming/g, '"bidi_streaming"');
    modified = true;
  }

  if (modified) {
    fs.writeFileSync(filePath, content, 'utf8');
    console.log(`Fixed: ${path.relative(generatedDir, filePath)}`);
  }
}

function walkDir(dir) {
  const files = fs.readdirSync(dir);
  for (const file of files) {
    const filePath = path.join(dir, file);
    const stat = fs.statSync(filePath);
    if (stat.isDirectory()) {
      walkDir(filePath);
    } else if (file.endsWith('_connect.ts')) {
      fixConnectFile(filePath);
    }
  }
}

console.log('Fixing generated Connect files...');
walkDir(generatedDir);
console.log('Done!');
