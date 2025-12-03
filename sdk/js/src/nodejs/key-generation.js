import crypto from 'crypto';

const DEFAULT_RSA_BITS = 2048;

export async function generateClientKeyPair() {
  return await new Promise((resolve, reject) => {
    crypto.generateKeyPair(
      'rsa',
      {
        modulusLength: DEFAULT_RSA_BITS,
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
