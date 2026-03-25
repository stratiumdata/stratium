const CREDENTIAL_STORAGE_KEY = "stratium_yubikey_webauthn_credential_id";
const DB_NAME = "stratium-yubikey-sample-db";
const DB_VERSION = 1;
const KEY_STORE = "keys";
const MASTER_KEY_NAME = "master-kek-v1";
const TDF_VERSION = "4.0.0";

function byId(id) {
  return document.getElementById(id);
}

const els = {
  status: byId("status"),
  result: byId("result"),
  registerBtn: byId("registerBtn"),
  touchBtn: byId("touchBtn"),
  wrapBtn: byId("wrapBtn"),
  unwrapBtn: byId("unwrapBtn"),
  rpId: byId("rpId"),
  userDisplayName: byId("userDisplayName"),
  resource: byId("resource"),
  wrapText: byId("wrapText"),
  outputName: byId("outputName"),
  inputFile: byId("inputFile"),
  wrappedInput: byId("wrappedInput"),
  unwrapText: byId("unwrapText"),
};

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let j = 0; j < 8; j++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    table[i] = c >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let c = 0xffffffff;
  for (const b of bytes) {
    c = CRC32_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function concatBytes(chunks) {
  const total = chunks.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of chunks) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function base64urlEncode(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let str = "";
  for (const value of bytes) {
    str += String.fromCharCode(value);
  }
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(str) {
  const normalized = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const raw = atob(padded);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

function base64Encode(data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  let str = "";
  for (const value of bytes) {
    str += String.fromCharCode(value);
  }
  return btoa(str);
}

function base64Decode(str) {
  const normalized = str.replace(/\s+/g, "");
  const raw = atob(normalized);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

function utf8Encode(text) {
  return new TextEncoder().encode(text);
}

function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function randomID() {
  return base64urlEncode(randomBytes(16));
}

async function sha256(data) {
  const hash = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(hash);
}

function ensureWebAuthnAvailable() {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    throw new Error("WebAuthn is not available in this browser.");
  }
}

function logResult(title, details) {
  const lines = [title, ""];
  for (const [key, value] of Object.entries(details)) {
    lines.push(`${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`);
  }
  els.result.textContent = lines.join("\n");
}

function setStatus(text) {
  els.status.textContent = text;
}

function setBusy(isBusy, statusText) {
  els.registerBtn.disabled = isBusy;
  els.touchBtn.disabled = isBusy;
  els.wrapBtn.disabled = isBusy;
  els.unwrapBtn.disabled = isBusy;
  setStatus(statusText);
}

function currentRPID() {
  const explicit = els.rpId.value.trim();
  return explicit || window.location.hostname;
}

function storedCredentialId() {
  return localStorage.getItem(CREDENTIAL_STORAGE_KEY) || "";
}

function requireCredentialId() {
  const credentialId = storedCredentialId();
  if (!credentialId) {
    throw new Error("No registered credential. Run registration first.");
  }
  return credentialId;
}

async function registerCredential() {
  ensureWebAuthnAvailable();
  const rpID = currentRPID();
  const displayName = els.userDisplayName.value.trim() || "Stratium User";

  const publicKey = {
    challenge: randomBytes(32),
    rp: {
      id: rpID,
      name: "Stratium YubiKey Browser Sample",
    },
    user: {
      id: randomBytes(16),
      name: "stratium-user@local",
      displayName,
    },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },
      { type: "public-key", alg: -257 },
    ],
    authenticatorSelection: {
      authenticatorAttachment: "cross-platform",
      residentKey: "preferred",
      userVerification: "required",
    },
    timeout: 60000,
    attestation: "none",
  };

  const credential = await navigator.credentials.create({ publicKey });
  if (!credential || !credential.rawId) {
    throw new Error("Credential registration failed.");
  }
  const credentialId = base64urlEncode(new Uint8Array(credential.rawId));
  localStorage.setItem(CREDENTIAL_STORAGE_KEY, credentialId);

  logResult("Registration Complete", {
    credentialId,
    rpId: rpID,
    note: "Credential ID saved in localStorage for subsequent touch assertions.",
  });
}

async function performTouchAssertion() {
  ensureWebAuthnAvailable();
  const credentialId = requireCredentialId();

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      allowCredentials: [
        {
          id: base64urlDecode(credentialId),
          type: "public-key",
          transports: ["usb", "nfc", "ble"],
        },
      ],
      userVerification: "required",
      timeout: 60000,
    },
  });

  if (!assertion) {
    throw new Error("Touch assertion failed.");
  }

  const signature = assertion.response?.signature
    ? base64urlEncode(new Uint8Array(assertion.response.signature))
    : "n/a";

  logResult("Touch Assertion Succeeded", {
    credentialId,
    authenticatorDataBytes: assertion.response?.authenticatorData?.byteLength || 0,
    signaturePreview: `${signature.slice(0, 24)}...`,
  });

  return assertion;
}

function openDB() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(KEY_STORE)) {
        db.createObjectStore(KEY_STORE);
      }
    };
    req.onerror = () => reject(req.error || new Error("Failed to open IndexedDB."));
    req.onsuccess = () => resolve(req.result);
  });
}

function dbGet(db, key) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readonly");
    const store = tx.objectStore(KEY_STORE);
    const req = store.get(key);
    req.onerror = () => reject(req.error || new Error("IndexedDB get failed."));
    req.onsuccess = () => resolve(req.result);
  });
}

function dbPut(db, key, value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE, "readwrite");
    const store = tx.objectStore(KEY_STORE);
    const req = store.put(value, key);
    req.onerror = () => reject(req.error || new Error("IndexedDB put failed."));
    req.onsuccess = () => resolve();
  });
}

async function getOrCreateMasterKey() {
  const db = await openDB();
  const existing = await dbGet(db, MASTER_KEY_NAME);
  if (existing) {
    return existing;
  }
  const key = await crypto.subtle.generateKey(
    { name: "AES-KW", length: 256 },
    false,
    ["wrapKey", "unwrapKey"],
  );
  await dbPut(db, MASTER_KEY_NAME, key);
  return key;
}

function downloadBinaryFile(filename, bytes) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function createZip(entries) {
  const localChunks = [];
  const centralChunks = [];
  let offset = 0;
  let centralSize = 0;

  for (const entry of entries) {
    const nameBytes = utf8Encode(entry.name);
    const data = entry.data instanceof Uint8Array ? entry.data : new Uint8Array(entry.data);
    const crc = crc32(data);

    const localHeader = new Uint8Array(30 + nameBytes.length);
    const l = new DataView(localHeader.buffer);
    l.setUint32(0, 0x04034b50, true);
    l.setUint16(4, 20, true);
    l.setUint16(6, 0, true);
    l.setUint16(8, 0, true);
    l.setUint16(10, 0, true);
    l.setUint16(12, 0, true);
    l.setUint32(14, crc, true);
    l.setUint32(18, data.length, true);
    l.setUint32(22, data.length, true);
    l.setUint16(26, nameBytes.length, true);
    l.setUint16(28, 0, true);
    localHeader.set(nameBytes, 30);

    localChunks.push(localHeader, data);

    const centralHeader = new Uint8Array(46 + nameBytes.length);
    const c = new DataView(centralHeader.buffer);
    c.setUint32(0, 0x02014b50, true);
    c.setUint16(4, 20, true);
    c.setUint16(6, 20, true);
    c.setUint16(8, 0, true);
    c.setUint16(10, 0, true);
    c.setUint16(12, 0, true);
    c.setUint16(14, 0, true);
    c.setUint32(16, crc, true);
    c.setUint32(20, data.length, true);
    c.setUint32(24, data.length, true);
    c.setUint16(28, nameBytes.length, true);
    c.setUint16(30, 0, true);
    c.setUint16(32, 0, true);
    c.setUint16(34, 0, true);
    c.setUint16(36, 0, true);
    c.setUint32(38, 0, true);
    c.setUint32(42, offset, true);
    centralHeader.set(nameBytes, 46);

    centralChunks.push(centralHeader);
    centralSize += centralHeader.length;
    offset += localHeader.length + data.length;
  }

  const eocd = new Uint8Array(22);
  const e = new DataView(eocd.buffer);
  e.setUint32(0, 0x06054b50, true);
  e.setUint16(4, 0, true);
  e.setUint16(6, 0, true);
  e.setUint16(8, entries.length, true);
  e.setUint16(10, entries.length, true);
  e.setUint32(12, centralSize, true);
  e.setUint32(16, offset, true);
  e.setUint16(20, 0, true);

  return concatBytes([...localChunks, ...centralChunks, eocd]);
}

function findEOCD(bytes) {
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 65557); i--) {
    if (
      bytes[i] === 0x50 &&
      bytes[i + 1] === 0x4b &&
      bytes[i + 2] === 0x05 &&
      bytes[i + 3] === 0x06
    ) {
      return i;
    }
  }
  return -1;
}

async function inflateRaw(compressed) {
  if (!window.DecompressionStream) {
    throw new Error("This browser cannot read deflated ZIP entries.");
  }
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Blob([compressed]).stream().pipeThrough(ds);
  const out = await new Response(stream).arrayBuffer();
  return new Uint8Array(out);
}

async function parseZip(bytes) {
  const data = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  const eocdOffset = findEOCD(data);
  if (eocdOffset < 0) {
    throw new Error("Invalid ZIP: EOCD marker not found.");
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const totalEntries = view.getUint16(eocdOffset + 10, true);
  const centralOffset = view.getUint32(eocdOffset + 16, true);
  let ptr = centralOffset;
  const files = {};

  for (let i = 0; i < totalEntries; i++) {
    if (view.getUint32(ptr, true) !== 0x02014b50) {
      throw new Error("Invalid ZIP: central directory record missing.");
    }
    const method = view.getUint16(ptr + 10, true);
    const compressedSize = view.getUint32(ptr + 20, true);
    const nameLen = view.getUint16(ptr + 28, true);
    const extraLen = view.getUint16(ptr + 30, true);
    const commentLen = view.getUint16(ptr + 32, true);
    const localOffset = view.getUint32(ptr + 42, true);
    const name = utf8Decode(data.slice(ptr + 46, ptr + 46 + nameLen));

    if (view.getUint32(localOffset, true) !== 0x04034b50) {
      throw new Error(`Invalid ZIP: local header missing for ${name}.`);
    }
    const localNameLen = view.getUint16(localOffset + 26, true);
    const localExtraLen = view.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const compressed = data.slice(dataStart, dataStart + compressedSize);

    if (method === 0) {
      files[name] = compressed;
    } else if (method === 8) {
      files[name] = await inflateRaw(compressed);
    } else {
      throw new Error(`Unsupported ZIP compression method (${method}) for ${name}.`);
    }

    ptr += 46 + nameLen + extraLen + commentLen;
  }

  return files;
}

async function createZtdfPackage(plaintext, resource) {
  await performTouchAssertion();

  const dek = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
  const rawDEK = await crypto.subtle.exportKey("raw", dek);
  const iv = randomBytes(12);
  const ciphertextBuffer = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    dek,
    utf8Encode(plaintext),
  );
  const ciphertext = new Uint8Array(ciphertextBuffer);

  const master = await getOrCreateMasterKey();
  const wrappedDEK = new Uint8Array(await crypto.subtle.wrapKey("raw", dek, master, "AES-KW"));

  const policy = {
    body: {
      dataAttributes: [
        { attribute: "resource", value: resource || "document-service" },
      ],
    },
    tdfSpecVersion: TDF_VERSION,
  };
  const policyBase64 = base64Encode(utf8Encode(JSON.stringify(policy)));

  const hmacKey = await crypto.subtle.importKey(
    "raw",
    rawDEK,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const policyBinding = new Uint8Array(
    await crypto.subtle.sign("HMAC", hmacKey, utf8Encode(policyBase64)),
  );
  const payloadHash = await sha256(ciphertext);
  const credentialId = requireCredentialId();

  const manifest = {
    assertions: [],
    encryptionInformation: {
      type: "SPLIT",
      keyAccess: [
        {
          type: "WRAPPED",
          url: "browser://local-kas",
          protocol: "KAS",
          wrappedKey: base64Encode(wrappedDEK),
          sid: randomID(),
          kid: "browser-webauthn-demo",
          policyBinding: {
            alg: "HS256",
            hash: base64Encode(policyBinding),
          },
          metadata: {
            client_key_provider: "webauthn",
            yubikey_touch_required: "true",
            credential_id: credentialId,
          },
          tdfSpecVersion: TDF_VERSION,
        },
      ],
      method: {
        algorithm: "AES-256-GCM",
        isStreamable: false,
        iv: base64Encode(iv),
      },
      integrityInformation: {
        rootSignature: {
          alg: "HS256",
          sig: base64Encode(payloadHash),
        },
        segmentHashAlg: "HS256",
      },
      policy: policyBase64,
    },
    payload: {
      type: "reference",
      url: "0.payload",
      protocol: "zip",
      isEncrypted: true,
      mimeType: "application/octet-stream",
      tdfSpecVersion: TDF_VERSION,
    },
  };

  const zipBytes = createZip([
    { name: "manifest.json", data: utf8Encode(JSON.stringify(manifest, null, 2)) },
    { name: "0.payload", data: ciphertext },
  ]);

  return {
    zipBytes,
    manifest,
    ciphertextBytes: ciphertext.length,
  };
}

async function wrapClientSide() {
  const plaintext = els.wrapText.value;
  if (!plaintext) {
    throw new Error("Plaintext is required.");
  }

  const resource = els.resource.value.trim() || "document-service";
  const { zipBytes, manifest, ciphertextBytes } = await createZtdfPackage(plaintext, resource);
  const filename = (els.outputName.value.trim() || "yubikey-client-demo.ztdf")
    .replace(/\.json$/i, "")
    .replace(/\s+/g, "-");

  downloadBinaryFile(filename, zipBytes);
  els.wrappedInput.value = base64Encode(zipBytes);

  logResult("Wrap Complete", {
    file: filename,
    container: ".ztdf zip (manifest.json + 0.payload)",
    plaintextBytes: utf8Encode(plaintext).byteLength,
    ciphertextBytes,
    wrappedKeyBytes: base64Decode(manifest.encryptionInformation.keyAccess[0].wrappedKey).length,
    note: "Unwrap requires YubiKey touch and the same browser profile (IndexedDB master key).",
  });
}

async function readWrappedBytes() {
  const file = els.inputFile.files?.[0];
  if (file) {
    return new Uint8Array(await file.arrayBuffer());
  }
  const pasted = els.wrappedInput.value.trim();
  if (!pasted) {
    throw new Error("Provide a .ztdf file upload or Base64 content.");
  }
  return base64Decode(pasted);
}

async function parseWrappedPackage(bytes) {
  const files = await parseZip(bytes);
  const manifestBytes = files["manifest.json"];
  const payloadBytes = files["0.payload"];
  if (!manifestBytes || !payloadBytes) {
    throw new Error("ZTDF package missing manifest.json or 0.payload.");
  }
  const manifest = JSON.parse(utf8Decode(manifestBytes));
  return { manifest, payloadBytes };
}

async function unwrapClientSide() {
  const packageBytes = await readWrappedBytes();
  const { manifest, payloadBytes } = await parseWrappedPackage(packageBytes);

  const keyAccess = manifest.encryptionInformation?.keyAccess?.[0];
  const wrappedDEKB64 = keyAccess?.wrappedKey;
  const ivB64 = manifest.encryptionInformation?.method?.iv;
  if (!wrappedDEKB64 || !ivB64) {
    throw new Error("Manifest missing wrapped DEK or IV.");
  }

  const expectedCredential = keyAccess?.metadata?.credential_id;
  const localCredential = requireCredentialId();
  if (expectedCredential && expectedCredential !== localCredential) {
    throw new Error("ZTDF was wrapped with a different WebAuthn credential ID.");
  }

  await performTouchAssertion();

  const integritySig = manifest.encryptionInformation?.integrityInformation?.rootSignature?.sig;
  if (integritySig) {
    const hash = await sha256(payloadBytes);
    if (base64Encode(hash) !== integritySig) {
      throw new Error("Payload integrity check failed.");
    }
  }

  const master = await getOrCreateMasterKey();
  const dek = await crypto.subtle.unwrapKey(
    "raw",
    base64Decode(wrappedDEKB64),
    master,
    "AES-KW",
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  const plaintextBytes = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64Decode(ivB64) },
    dek,
    payloadBytes,
  );
  const plaintext = utf8Decode(new Uint8Array(plaintextBytes));
  els.unwrapText.value = plaintext;

  logResult("Unwrap Complete", {
    plaintextBytes: new Uint8Array(plaintextBytes).length,
    resource: els.resource.value.trim() || "document-service",
    container: ".ztdf zip",
    note: "Touch assertion and local key unwrap both succeeded.",
  });
}

els.registerBtn.addEventListener("click", async () => {
  setBusy(true, "Waiting for registration touch...");
  try {
    await registerCredential();
    setStatus("Credential registered.");
  } catch (error) {
    setStatus("Registration failed.");
    logResult("Registration Error", { error: String(error) });
  } finally {
    setBusy(false, els.status.textContent);
  }
});

els.touchBtn.addEventListener("click", async () => {
  setBusy(true, "Waiting for touch assertion...");
  try {
    await performTouchAssertion();
    setStatus("Touch assertion passed.");
  } catch (error) {
    setStatus("Touch assertion failed.");
    logResult("Touch Assertion Error", { error: String(error) });
  } finally {
    setBusy(false, els.status.textContent);
  }
});

els.wrapBtn.addEventListener("click", async () => {
  setBusy(true, "Wrap in progress, touch YubiKey...");
  try {
    await wrapClientSide();
    setStatus("Wrap succeeded.");
  } catch (error) {
    setStatus("Wrap failed.");
    logResult("Wrap Error", { error: String(error) });
  } finally {
    setBusy(false, els.status.textContent);
  }
});

els.unwrapBtn.addEventListener("click", async () => {
  setBusy(true, "Unwrap in progress, touch YubiKey...");
  try {
    await unwrapClientSide();
    setStatus("Unwrap succeeded.");
  } catch (error) {
    setStatus("Unwrap failed.");
    logResult("Unwrap Error", { error: String(error) });
  } finally {
    setBusy(false, els.status.textContent);
  }
});
