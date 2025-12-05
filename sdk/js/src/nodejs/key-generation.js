import crypto from 'crypto';

const SUPPORTED_RSA_SIZES = [2048, 3072, 4096];
const DEFAULT_RSA_BITS = 2048;

function resolveRsaSize() {
  const override = process.env.STRATIUM_JS_RSA_BITS || process.env.STRATIUM_RSA_BITS;
  if (!override) {
    return DEFAULT_RSA_BITS;
  }
  const parsed = Number.parseInt(override, 10);
  if (Number.isNaN(parsed) || !SUPPORTED_RSA_SIZES.includes(parsed)) {
    throw new Error(
      `Invalid STRATIUM_JS_RSA_BITS value "${override}". Supported sizes: ${SUPPORTED_RSA_SIZES.join(', ')}`
    );
  }
  return parsed;
}

export async function generateClientKeyPair() {
  const modulusLength = resolveRsaSize();
  return await new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      },
      (err, publicKey, privateKey) => {
        if (err) {
          reject(err);
          return;
        }
        resolve({
          publicKey,
          privateKey,
        });
      }
    );
  });
}

export async function exportPublicKey(key) {
  return key;
}

export async function exportPrivateKey(key) {
  return key;
}

export async function importPublicKey(pem) {
  return pem;
}

export async function importPrivateKey(pem) {
  return pem;
}

export function jwkToPem() {
  throw new Error('jwkToPem is not supported for RSA key generation.');
}
