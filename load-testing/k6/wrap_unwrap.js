import grpc from 'k6/net/grpc';
import http from 'k6/http';
import { check, sleep } from 'k6';
import { randomBytes } from 'k6/crypto';
import encoding from 'k6/encoding';

const grpcClient = new grpc.Client();
grpcClient.load(['proto'], 'services/key-access/key-access.proto');

const keyManagerClient = new grpc.Client();
keyManagerClient.load(['proto'], 'services/key-manager/key-manager.proto');

const kasTarget = __ENV.KAS_TARGET || 'localhost:50053';
const useTLS = (__ENV.KAS_TLS || 'false').toLowerCase() === 'true';
const keyManagerTarget = __ENV.KM_TARGET || 'localhost:50052';
const keyManagerUseTLS = (__ENV.KM_TLS || __ENV.KAS_TLS || 'false').toLowerCase() === 'true';

const resourceName = __ENV.RESOURCE_NAME || 'loadtest-resource';
const policyB64 =
  __ENV.POLICY_B64 ||
  'eyJhcnRpZmFjdHMiOlt7Im5hbWUiOiJjbGFzc2lmaWNhdGlvbiIsInZhbHVlIjoiY29uZmlkZW50aWFsIn1dfQ==';
const shouldRegisterClientKey = (__ENV.REGISTER_CLIENT_KEY || __ENV.REGISTER_CLIENT_KEYS || 'false').toLowerCase() === 'true';
const staticClientKeyId = parseClientKeyEnv(shouldRegisterClientKey);
const clientRegistrationId = __ENV.CLIENT_KEY_CLIENT_ID || __ENV.LOADTEST_USERNAME || 'loadtest-user';
const clientKeyNamePrefix = __ENV.CLIENT_KEY_PREFIX || 'loadtest-client-key';
const shouldCreateServiceKeys = (__ENV.CREATE_SERVICE_KEYS || (__ENV.KEY_IDS ? 'false' : 'true')).toLowerCase() === 'true';
const serviceKeyCount = Number(__ENV.SERVICE_KEY_COUNT || 5);
const staticServiceKeyIds = parseServiceKeyEnv();
const serviceKeyNamePrefix = __ENV.SERVICE_KEY_PREFIX || 'loadtest-service-key';
const KEY_TYPE_RSA_2048 = 1;
const KEY_PROVIDER_TYPE_SOFTWARE = 1;
const ROTATION_POLICY_MANUAL = 1;
const defaultClientPublicKeyPem = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2M6Tly0inD/2a9llQgeH
rsCCPNXRXQ8Wn6AZ6FlSw6VJ1Yo4eCIklwLVeBdXqcjL9fYS/bLzI1K8JrMg+mHG
LKQLHMXjfQ+fbSuQHn1wPSkYZTUZe4agwJnV97EHqYzLnP1nJb9C1SMGhlHDkaJF
j/WWwDoO0olpOLb5R3qBe0NbnlMuLPY6Mjf+vGbu0jMJp6D7+KRSZ3FrLC9xBb9Q
NyjYjS23FzBiYh9c9szElbxb4GVCFue+JKw+YXg9gvRVQSQCzuHVUFXaFz4eOcWy
rLBsk8EtKRdL06km40hkdT9jTyFS3Z8a/gPYFtR3UlfcZHM7dsOBxZrfTc3WOKOv
ZwIDAQAB
-----END PUBLIC KEY-----`;
const clientPublicKeyPem = (__ENV.CLIENT_PUBLIC_KEY_PEM || defaultClientPublicKeyPem).replace(/\\n/g, '\n');
const baseContext = {
  scenario: 'wrap_unwrap_loadtest',
  target: kasTarget,
};

let cachedClientKeyId = staticClientKeyId;
let cachedServiceKeyIds = staticServiceKeyIds.slice();

const keycloakBaseUrl = (__ENV.KEYCLOAK_BASE_URL || 'http://localhost:8080').replace(/\/$/, '');
const keycloakRealm = __ENV.KEYCLOAK_REALM || 'stratium';
const tokenUrl = `${keycloakBaseUrl}/realms/${keycloakRealm}/protocol/openid-connect/token`;
const clientId = __ENV.LOADTEST_CLIENT_ID || 'stratium-load-test';
const clientSecret = __ENV.LOADTEST_CLIENT_SECRET || 'stratium-load-test-secret';
const username = __ENV.LOADTEST_USERNAME || '';
const password = __ENV.LOADTEST_PASSWORD || '';
const userScope = __ENV.LOADTEST_SCOPE || 'openid profile';
const tokenRefreshBufferSeconds = Number(__ENV.TOKEN_REFRESH_BUFFER || 30);
const startRate = Number(__ENV.START_RPS || 100);
const preAllocatedVUs = Number(__ENV.PRE_ALLOCATED_VUS || 150);
const maxVUs = Number(__ENV.MAX_VUS || 500);

export const options = {
  discardResponseBodies: false,
  scenarios: {
    wrapAndUnwrap: {
      executor: 'ramping-arrival-rate',
      startRate,
      timeUnit: '1s',
      preAllocatedVUs,
      maxVUs,
      stages: rateStages(),
      gracefulStop: __ENV.GRACEFUL_STOP || '30s',
    },
  },
  thresholds: {
    grpc_req_duration: ['p(95)<500'],
    'checks{type:wrap}': ['rate>0.99'],
    'checks{type:unwrap}': ['rate>0.99'],
  },
};

if ((username && !password) || (!username && password)) {
  throw new Error('Both LOADTEST_USERNAME and LOADTEST_PASSWORD must be set for password grant.');
}

let cachedToken = '';
let tokenExpiresAt = 0;
let clientConnected = false;
let keyManagerConnected = false;

function rateStages() {
  if (__ENV.RATE_STAGES) {
    try {
      return JSON.parse(__ENV.RATE_STAGES);
    } catch (err) {
      throw new Error(`Invalid RATE_STAGES JSON: ${err.message}`);
    }
  }

  return [
    { target: 250, duration: '2m' },
    { target: 500, duration: '2m' },
    { target: 750, duration: '2m' },
    { target: 1000, duration: '4m' },
  ];
}

function ensureGrpcConnection() {
  if (!clientConnected) {
    grpcClient.connect(kasTarget, { plaintext: !useTLS });
    clientConnected = true;
  }
}

function ensureKeyManagerConnection() {
  if (!keyManagerConnected) {
    keyManagerClient.connect(keyManagerTarget, { plaintext: !keyManagerUseTLS });
    keyManagerConnected = true;
  }
}

function buildTokenPayload() {
  const parts = [`client_id=${encodeURIComponent(clientId)}`];
  if (clientSecret) {
    parts.push(`client_secret=${encodeURIComponent(clientSecret)}`);
  }

  if (username && password) {
    parts.push('grant_type=password');
    parts.push(`username=${encodeURIComponent(username)}`);
    parts.push(`password=${encodeURIComponent(password)}`);
    if (userScope) {
      parts.push(`scope=${encodeURIComponent(userScope)}`);
    }
  } else {
    parts.push('grant_type=client_credentials');
  }

  return parts.join('&');
}

function fetchAccessToken() {
  const payload = buildTokenPayload();

  const res = http.post(tokenUrl, payload, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    tags: { endpoint: 'keycloak_token' },
  });

  if (!res || res.status !== 200 || !res.body) {
    throw new Error(
      `Keycloak token request failed (status=${res && res.status}) body=${res && res.body}`,
    );
  }

  let body;
  try {
    body = res.json();
  } catch (err) {
    throw new Error(`Keycloak token response was not JSON: ${err} body=${res.body}`);
  }

  if (!body.access_token) {
    throw new Error(`Keycloak token response missing access_token: ${res.body}`);
  }

  cachedToken = body.access_token;
  const expiresInMs = (body.expires_in || 60) * 1000;
  tokenExpiresAt = Date.now() + expiresInMs - tokenRefreshBufferSeconds * 1000;
  return cachedToken;
}

function getAccessToken() {
  if (!cachedToken || Date.now() >= tokenExpiresAt) {
    return fetchAccessToken();
  }
  return cachedToken;
}

function parseClientKeyEnv(registrationEnabled) {
  const fromList = (__ENV.CLIENT_KEY_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);

  if (fromList.length > 1) {
    throw new Error('Only one CLIENT_KEY_ID/CLIENT_KEY_IDS value is supported.');
  }

  if (fromList.length === 1) {
    return fromList[0];
  }

  if (__ENV.CLIENT_KEY_ID && __ENV.CLIENT_KEY_ID.trim().length > 0) {
    return __ENV.CLIENT_KEY_ID.trim();
  }

  if (!registrationEnabled) {
    return 'loadtest-client-key';
  }

  return null;
}

function parseServiceKeyEnv() {
  const fromList = (__ENV.KEY_IDS || '')
    .split(',')
    .map((id) => id.trim())
    .filter(Boolean);

  return fromList;
}

function selectServiceKeyId(pool) {
  const source = pool && pool.length > 0 ? pool : cachedServiceKeyIds;
  if (!source.length) {
    throw new Error('No service key IDs available. Provide KEY_IDS or enable CREATE_SERVICE_KEYS.');
  }
  const idx = Math.floor(Math.random() * source.length);
  return source[idx];
}

function registerClientKey() {
  ensureKeyManagerConnection();
  const metadata = { metadata: { authorization: `Bearer ${cachedToken || getAccessToken()}` } };
  const keyLabel = `${clientKeyNamePrefix}-${Date.now()}-${encoding.b64encode(randomBytes(2), 'std')}`;
  const request = {
    client_id: clientRegistrationId,
    public_key_pem: clientPublicKeyPem,
    key_type: KEY_TYPE_RSA_2048,
    metadata: {
      client_key_name: keyLabel,
      environment: __ENV.LOADTEST_ENVIRONMENT || 'load-test',
    },
  };

  const response = keyManagerClient.invoke(
    'key_manager.KeyManagerService/RegisterClientKey',
    request,
    metadata,
  );

  const ok = response && response.status === grpc.StatusOK && response.message && response.message.success;
  check(response, {
    'client key registered': () => ok,
  });

  if (!ok) {
    const errorMsg = response?.message?.errorMessage || 'unknown error';
    throw new Error(`RegisterClientKey failed: ${errorMsg}`);
  }

  return response.message.key.keyId;
}

function createServiceKeys(count) {
  ensureKeyManagerConnection();
  const metadata = { metadata: { authorization: `Bearer ${getAccessToken()}` } };
  const created = [];

  for (let i = 0; i < count; i += 1) {
    const keyLabel = `${serviceKeyNamePrefix}-${Date.now()}-${i + 1}-${encoding.b64encode(randomBytes(2), 'std')}`;
    const request = {
      name: keyLabel,
      key_type: KEY_TYPE_RSA_2048,
      provider_type: KEY_PROVIDER_TYPE_SOFTWARE,
      rotation_policy: ROTATION_POLICY_MANUAL,
      rotation_interval_days: Number(__ENV.SERVICE_KEY_ROTATION_DAYS || 90),
      metadata: {
        environment: __ENV.LOADTEST_ENVIRONMENT || 'load-test',
        service_key_name: keyLabel,
      },
      authorized_subjects: [clientRegistrationId],
      authorized_resources: [resourceName],
    };

    const response = keyManagerClient.invoke(
      'key_manager.KeyManagerService/CreateKey',
      request,
      metadata,
    );

    const ok = response && response.status === grpc.StatusOK && response.message && response.message.key;
    check(response, {
      'service key created': () => ok,
    });

    if (!ok) {
      const errorMsg = response?.message?.errorMessage || 'unknown error';
      throw new Error(`CreateKey failed: ${errorMsg}`);
    }

    created.push(response.message.key.keyId);
  }

  return created;
}

function randomDek() {
  return encoding.b64encode(randomBytes(32), 'std');
}

function wrapWithNewDek(serviceKeyId, metadata) {
  const req = {
    resource: resourceName,
    key_id: serviceKeyId,
    action: 'wrap_dek',
    dek: randomDek(),
    policy: policyB64,
    context: {
      ...baseContext,
      vu: String(__VU),
      iter: String(__ITER),
      event: 'wrap',
    },
  };

  const response = grpcClient.invoke('key_access.KeyAccessService/WrapDEK', req, metadata);
  check(response, {
    'wrap rpc ok': (res) => res && res.status === grpc.StatusOK,
    'wrap granted': (res) => res && res.message && res.message.accessGranted,
  }, { type: 'wrap' });

  if (response.message && !response.message.accessGranted) {
    console.error(`Wrap denied: reason="${response.message.accessReason || 'unknown'}" rules=${JSON.stringify(response.message.appliedRules || [])}`);
  }

  if (response.status !== grpc.StatusOK) {
    throw new Error(`WrapDEK failed: ${JSON.stringify(response)}`);
  }

  return {
    wrappedDek: response.message.wrappedDek,
    keyId: response.message.keyId,
  };
}

function unwrapWrappedDek(wrappedDek, keyId, clientKeyId, metadata) {
  const req = {
    resource: resourceName,
    wrapped_dek: wrappedDek,
    key_id: keyId,
    client_key_id: clientKeyId,
    action: 'unwrap_dek',
    policy: policyB64,
    context: {
      ...baseContext,
      vu: String(__VU),
      iter: String(__ITER),
      event: 'unwrap',
    },
  };

  const response = grpcClient.invoke('key_access.KeyAccessService/UnwrapDEK', req, metadata);
  check(response, {
    'unwrap rpc ok': (res) => res && res.status === grpc.StatusOK,
    'unwrap granted': (res) => res && res.message && res.message.accessGranted,
  }, { type: 'unwrap' });

  if (response.message && !response.message.accessGranted) {
    console.error(`Unwrap denied: reason="${response.message.accessReason || 'unknown'}" rules=${JSON.stringify(response.message.appliedRules || [])}`);
  }

  if (response.status !== grpc.StatusOK) {
    throw new Error(`UnwrapDEK failed: ${JSON.stringify(response)}`);
  }
}

export function setup() {
  let clientKeyId = cachedClientKeyId;
  let serviceKeyIds = cachedServiceKeyIds;

  if (shouldCreateServiceKeys) {
    serviceKeyIds = createServiceKeys(serviceKeyCount);
  }

  if (shouldRegisterClientKey) {
    clientKeyId = registerClientKey();
  }

  if (!serviceKeyIds.length) {
    serviceKeyIds = staticServiceKeyIds;
  }

  if (clientKeyId) {
    cachedClientKeyId = clientKeyId;
  }
  if (serviceKeyIds.length) {
    cachedServiceKeyIds = serviceKeyIds;
  }

  return {
    clientKeyId: cachedClientKeyId,
    serviceKeyIds: cachedServiceKeyIds,
  };
}

export default function (data) {
  ensureGrpcConnection();
  const serviceKeyPool =
    data && Array.isArray(data.serviceKeyIds) && data.serviceKeyIds.length > 0
      ? data.serviceKeyIds
      : cachedServiceKeyIds;
  const clientKeyId = data && data.clientKeyId ? data.clientKeyId : cachedClientKeyId;
  if (!clientKeyId) {
    throw new Error('Client key ID unavailable. Provide CLIENT_KEY_ID or enable REGISTER_CLIENT_KEY.');
  }
  const serviceKeyId = selectServiceKeyId(serviceKeyPool);
  const callOptions = { metadata: { authorization: `Bearer ${getAccessToken()}` } };

  const wrapResult = wrapWithNewDek(serviceKeyId, callOptions);
  unwrapWrappedDek(wrapResult.wrappedDek, wrapResult.keyId, clientKeyId, callOptions);

  const pause = Number(__ENV.THINK_TIME_MS || 0);
  if (pause > 0) {
    sleep(pause / 1000);
  }
}

export function teardown() {
  grpcClient.close();
  if (keyManagerConnected) {
    keyManagerClient.close();
  }
}
