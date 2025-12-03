#!/usr/bin/env node

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { ZtdfClient } from '../src/nodejs/ztdf-client.js';
import { setStorageDirectory } from '../src/nodejs/key-storage.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  const mode = process.argv[2];
  if (!mode || !['encrypt', 'decrypt'].includes(mode)) {
    console.error('Usage: node cross-sdk-tool.mjs <encrypt|decrypt>');
    process.exit(1);
  }

  const rawInput = await readStdin();
  if (!rawInput) {
    throw new Error('Missing JSON payload on stdin');
  }

  let request;
  try {
    request = JSON.parse(rawInput);
  } catch (err) {
    throw new Error(`Failed to parse JSON request: ${err.message}`);
  }

  const env = loadEnv();
  await ensureDir(env.keyDir);
  const client = new ZtdfClient({
    keyAccessUrl: env.keyAccessUrl,
    keyManagerUrl: env.keyManagerUrl,
    clientId: env.clientId,
    getToken: () => fetchToken(env),
    debug: env.debug,
  });

  setStorageDirectory(env.keyDir);
  await client.initialize();

  if (mode === 'encrypt') {
    const resp = await handleEncrypt(client, env, request);
    writeResponse(resp);
  } else {
    const resp = await handleDecrypt(client, env, request);
    writeResponse(resp);
  }
}

async function handleEncrypt(client, env, request) {
  const plaintext = decodeField(request.plaintext, 'plaintext');
  const options = {
    filename: request.filename || env.defaultFilename,
    contentType: request.contentType || env.defaultContentType,
    resource: request.resource || env.defaultResource,
    policy: request.policyBase64 || env.policyBase64,
  };
  if (!options.policy) {
    throw new Error('policyBase64 must be provided');
  }

  const ztdfBuffer = await client.wrap(Buffer.from(plaintext), options);
  return { ztdf: ztdfBuffer.toString('base64') };
}

async function handleDecrypt(client, env, request) {
  const ztdfBytes = decodeField(request.ztdf, 'ztdf');
  const result = await client.unwrap(Buffer.from(ztdfBytes), {
    resource: request.resource || env.defaultResource,
  });
  return { plaintext: Buffer.from(result.content).toString('base64') };
}

function decodeField(value, fieldName) {
  if (!value || typeof value !== 'string') {
    throw new Error(`Missing ${fieldName} field`);
  }
  try {
    return Buffer.from(value, 'base64');
  } catch (err) {
    throw new Error(`Invalid base64 in ${fieldName}: ${err.message}`);
  }
}

function writeResponse(obj) {
  process.stdout.write(`${JSON.stringify(obj)}\n`);
}

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data.trim()));
    process.stdin.on('error', reject);
  });
}

function loadEnv() {
  const required = (key) => {
    const value = process.env[key];
    if (!value) {
      throw new Error(`Environment variable ${key} is required`);
    }
    return value;
  };

  const repoRoot = path.resolve(__dirname, '..', '..', '..');
  const keyDir = process.env.STRATIUM_JS_KEY_DIR
    || path.join(repoRoot, 'artifacts', 'client-keys', 'js');

  const keyAccessUrl = resolveUrl(
    process.env.STRATIUM_KEY_ACCESS_URI,
    process.env.STRATIUM_KEY_ACCESS_URL,
    process.env.STRATIUM_KEY_ACCESS_ADDR
  );
  const keyManagerUrl = resolveUrl(
    process.env.STRATIUM_KEY_MANAGER_URI,
    process.env.STRATIUM_KEY_MANAGER_URL,
    process.env.STRATIUM_KEY_MANAGER_ADDR
  );

  return {
    keyAccessUrl,
    keyManagerUrl,
    clientId: required('STRATIUM_CLIENT_ID'),
    keycloakUrl: required('STRATIUM_KEYCLOAK_URL'),
    realm: required('STRATIUM_KEYCLOAK_REALM'),
    clientSecret: process.env.STRATIUM_CLIENT_SECRET || '',
    username: process.env.STRATIUM_USERNAME || '',
    password: process.env.STRATIUM_PASSWORD || '',
    bearerToken: process.env.STRATIUM_BEARER_TOKEN || '',
    policyBase64: process.env.STRATIUM_POLICY_BASE64 || '',
    defaultResource: process.env.STRATIUM_RESOURCE || 'integration-resource',
    defaultFilename: process.env.STRATIUM_FILENAME || 'interop.txt',
    defaultContentType: process.env.STRATIUM_CONTENT_TYPE || 'text/plain',
    keyDir,
    debug: process.env.STRATIUM_SDK_DEBUG === '1',
  };
}

async function ensureDir(dir) {
  try {
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  } catch (err) {
    if (err.code !== 'EEXIST') {
      throw err;
    }
  }
}

function resolveUrl(...candidates) {
  for (const value of candidates) {
    if (!value) continue;
    if (value.startsWith('http://') || value.startsWith('https://')) {
      return value;
    }
    // No scheme, try to prepend http://
    if (/^[-\w.]+:\d+$/.test(value) || value.startsWith('localhost')) {
      return `http://${value}`;
    }
    return value;
  }
  throw new Error('Missing required URL/URI value');
}

async function fetchToken(env) {
  if (env.bearerToken) {
    return env.bearerToken;
  }

  const tokenUrl = `${env.keycloakUrl}/realms/${env.realm}/protocol/openid-connect/token`;
  const params = new URLSearchParams();
  params.set('client_id', env.clientId);
  if (env.clientSecret) {
    params.set('client_secret', env.clientSecret);
  }

  if (env.username && env.password) {
    params.set('grant_type', 'password');
    params.set('username', env.username);
    params.set('password', env.password);
  } else {
    params.set('grant_type', 'client_credentials');
  }

  const res = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  if (!res.ok) {
    throw new Error(`Token request failed: ${res.status} ${res.statusText}`);
  }
  const data = await res.json();
  if (!data.access_token) {
    throw new Error('Token response missing access_token');
  }
  return data.access_token;
}

main().catch((err) => {
  const message = err?.message || String(err);
  console.error(message);
  process.exit(1);
});
