/**
 * grpc-client.js
 *
 * Thin wrapper around `grpcurl` and `curl` subprocesses for communicating
 * with Stratium's Agent Gateway (gRPC) and PAP REST API.
 *
 * Zero npm dependencies — shells out to grpcurl (gRPC) and curl (REST).
 * Both tools must be available on PATH or specified via config.
 */

'use strict';

const { execFileSync } = require('child_process');
const fs               = require('fs');
const path             = require('path');

/**
 * @typedef {object} GrpcCallOptions
 * @property {string}   gateway      - host:port of Agent Gateway
 * @property {string}   [cacert]     - Path to CA cert for TLS verification
 * @property {boolean}  [plaintext]  - Use -plaintext flag (for local dev without TLS)
 * @property {number}   [timeoutMs]  - Request timeout in ms (default: 5000)
 */

/**
 * @typedef {object} RestCallOptions
 * @property {string}  baseUrl      - Base URL of PAP REST API
 * @property {string}  [token]      - Bearer token for Authorization header
 * @property {string}  [cacert]     - Path to CA cert for TLS verification
 * @property {number}  [timeoutMs]  - Request timeout in ms (default: 5000)
 */

const DEFAULT_TIMEOUT_MS = 5000;

/**
 * Build the common grpcurl argument array for a call.
 *
 * @param {GrpcCallOptions} opts
 * @param {string} service - gRPC method in format Package.Service/Method
 * @param {object} payload - Request body (will be JSON-encoded)
 * @param {Record<string,string>} [metadata] - gRPC metadata headers (e.g. Authorization)
 * @returns {string[]}
 */
function buildGrpcArgs(opts, service, payload, metadata) {
  const args = ['-format', 'json'];

  if (opts.plaintext) {
    args.push('-plaintext');
  } else if (opts.cacert) {
    args.push('-cacert', opts.cacert);
  }

  // gRPC metadata headers (e.g. Authorization: Bearer <token>)
  if (metadata) {
    for (const [key, value] of Object.entries(metadata)) {
      args.push('-H', `${key}: ${value}`);
    }
  }

  // Timeout (grpcurl uses seconds)
  const timeoutSec = Math.ceil((opts.timeoutMs || DEFAULT_TIMEOUT_MS) / 1000);
  args.push('-max-time', String(timeoutSec));

  args.push('-d', JSON.stringify(payload));
  args.push(opts.gateway, service);

  return args;
}

/**
 * Execute a gRPC call via grpcurl.
 *
 * @param {GrpcCallOptions} opts
 * @param {string} service - e.g. "agent_gateway.AgentGatewayService/ExecuteAction"
 * @param {object} payload - Request body
 * @param {Record<string,string>} [metadata] - gRPC metadata headers
 * @returns {object} Parsed JSON response
 * @throws {Error} On non-zero exit or unparseable output
 */
function grpcCall(opts, service, payload, metadata) {
  const grpcurl = process.env.STRATIUM_GRPCURL_PATH || 'grpcurl';
  const args    = buildGrpcArgs(opts, service, payload, metadata);

  let stdout;
  try {
    stdout = execFileSync(grpcurl, args, {
      timeout: opts.timeoutMs || DEFAULT_TIMEOUT_MS,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    // err.stderr may contain a useful gRPC status message
    const detail = (err.stderr || '').trim();
    throw new Error(`grpcurl call failed for ${service}: ${detail || err.message}`);
  }

  try {
    return JSON.parse(stdout);
  } catch {
    throw new Error(`grpcurl returned non-JSON for ${service}: ${stdout.slice(0, 200)}`);
  }
}

/**
 * Execute an HTTP call via curl.
 *
 * @param {RestCallOptions} opts
 * @param {'GET'|'POST'|'PUT'|'DELETE'|'PATCH'} method
 * @param {string} path - URL path (appended to opts.baseUrl)
 * @param {object} [body] - Request body (JSON-encoded; omit for GET/DELETE)
 * @returns {object} Parsed JSON response
 * @throws {Error} On HTTP error or non-JSON response
 */
function restCall(opts, method, urlPath, body) {
  const curl    = process.env.STRATIUM_CURL_PATH || 'curl';
  const url     = opts.baseUrl.replace(/\/$/, '') + urlPath;
  const timeoutSec = Math.ceil((opts.timeoutMs || DEFAULT_TIMEOUT_MS) / 1000);

  const args = [
    '-s',                        // silent (no progress)
    '-X', method,
    '-H', 'Content-Type: application/json',
    '-H', 'Accept: application/json',
    '--max-time', String(timeoutSec),
    '-w', '\n__STATUS__%{http_code}',  // append status code to output
  ];

  if (opts.token) {
    args.push('-H', `Authorization: Bearer ${opts.token}`);
  }

  if (opts.cacert) {
    args.push('--cacert', opts.cacert);
  } else if (opts.baseUrl.startsWith('https://')) {
    // Skip verification only in dev; enterprises always set cacert
    // We never add -k by default — fail on cert errors.
  }

  if (body !== undefined) {
    args.push('-d', JSON.stringify(body));
  }

  args.push(url);

  let raw;
  try {
    raw = execFileSync(curl, args, {
      timeout: opts.timeoutMs || DEFAULT_TIMEOUT_MS,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (err) {
    const detail = (err.stderr || '').trim();
    throw new Error(`curl call failed for ${method} ${urlPath}: ${detail || err.message}`);
  }

  // Split body and status code appended by -w
  const statusMatch = raw.match(/\n__STATUS__(\d{3})$/);
  const statusCode  = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  const responseBody = statusMatch ? raw.slice(0, statusMatch.index) : raw;

  let parsed;
  try {
    parsed = JSON.parse(responseBody);
  } catch {
    throw new Error(`REST API returned non-JSON for ${method} ${urlPath}: ${responseBody.slice(0, 200)}`);
  }

  if (statusCode >= 400) {
    const msg = parsed.error || parsed.message || JSON.stringify(parsed);
    throw new Error(`REST API ${method} ${urlPath} returned HTTP ${statusCode}: ${msg}`);
  }

  return parsed;
}

// ── Stratium Agent Gateway calls ────────────────────────────────────────────

/**
 * Create a delegation in Stratium Agent Gateway.
 *
 * @param {GrpcCallOptions} gOpts
 * @param {object} params
 * @param {string} params.agent_id
 * @param {string} params.delegator_token   - OIDC access token of the delegating user
 * @param {string} params.agent_name
 * @param {string[]} params.approved_tools
 * @param {number}  params.max_action_tier
 * @param {number}  [params.ttl_seconds]    - Delegation TTL (default: 14400 = 4h)
 * @param {string}  [params.purpose]
 * @param {string}  [params.conversation_id]
 * @returns {{ delegation_id: string, delegation_token: string, expires_at: string }}
 */
function createDelegation(gOpts, params) {
  // delegator_token is the user's OIDC access token — sent as gRPC Authorization metadata,
  // not as a proto field (CreateDelegationRequest has no delegator_token field).
  // parent_delegation_token is for child delegations; empty string for root delegations.
  const payload = {
    agent_id:               params.agent_id,
    approved_tools:         params.approved_tools || [],
    max_action_tier:        params.max_action_tier ?? 1,
    ttl_seconds:            params.ttl_seconds    ?? 14400,
    purpose:                params.purpose        || '',
    conversation_id:        params.conversation_id || '',
    parent_delegation_token: params.parent_delegation_token || '',
  };

  // Authorization header authenticates the request.
  // x-user-id provides the user identity to store as user_id in the delegation row —
  // the server falls back to the raw auth header value if x-user-id is absent,
  // which would store the full JWT (> VARCHAR(255)).
  const metadata = {};
  if (params.delegator_token) {
    metadata['Authorization'] = `Bearer ${params.delegator_token}`;
  }
  if (params.user_id) {
    metadata['x-user-id'] = params.user_id;
  }

  const resp = grpcCall(gOpts, 'agent_gateway.AgentGatewayService/CreateDelegation', payload, metadata);

  // grpcurl returns proto fields in camelCase JSON; normalize to snake_case
  // for consistent access throughout session-init, pre-tool-use, and bin/stratium-hooks.
  return {
    delegation_id:      resp.delegationId      || resp.delegation_id      || '',
    delegation_token:   resp.delegationToken   || resp.delegation_token   || '',
    expires_at:         resp.expiresAt         || resp.expires_at         || null,
    depth:              resp.depth             || 0,
    root_delegation_id: resp.rootDelegationId  || resp.root_delegation_id || '',
  };
}

/**
 * Execute an action check against the Agent Gateway.
 *
 * @param {GrpcCallOptions} gOpts
 * @param {object} params
 * @param {string} params.delegation_token
 * @param {string} params.tool_name
 * @param {string} params.action
 * @param {number} params.action_tier
 * @param {object} [params.resource_attributes]
 * @returns {{ authorized: boolean, denial_reason?: string, decision_id?: string }}
 */
function executeAction(gOpts, params) {
  const payload = {
    delegation_token:     params.delegation_token,
    tool_name:            params.tool_name,
    action:               params.action,
    action_tier:          params.action_tier,
    resource_attributes:  params.resource_attributes || {},
  };

  return grpcCall(gOpts, 'agent_gateway.AgentGatewayService/ExecuteAction', payload);
}

// ── Stratium PAP REST calls ──────────────────────────────────────────────────

/**
 * Register or retrieve an agent via the PAP REST API.
 * The call is idempotent — if the agent already exists it returns the existing record.
 *
 * @param {RestCallOptions} rOpts
 * @param {object} params
 * @param {string} params.name           - Agent name (e.g. "claude-code")
 * @param {string} params.machine_id     - Stable machine identifier
 * @param {string[]} params.allowed_tools
 * @param {number}  params.max_tier
 * @returns {{ agent_id: string, client_id: string }}
 */
function registerAgent(rOpts, params) {
  const body = {
    name:          params.name,
    description:   `Claude Code agent on ${params.machine_id}`,
    allowed_tools: params.allowed_tools || [],
    max_tier:      params.max_tier      ?? 1,
    metadata:      { machine_id: params.machine_id, source: 'stratium-claude-hooks' },
  };

  return restCall(rOpts, 'POST', '/api/v1/agents', body);
}

/**
 * Authenticate with Keycloak using Resource Owner Password Credentials (ROPC).
 * Used for machine-level service accounts in MDM contexts.
 * For interactive developer sessions, use device flow instead (auth.js).
 *
 * @param {object} params
 * @param {string} params.keycloak_url
 * @param {string} params.realm
 * @param {string} params.client_id
 * @param {string} params.username
 * @param {string} params.password
 * @returns {{ access_token: string, refresh_token: string, expires_in: number }}
 */
function keycloakPasswordGrant(params) {
  const curl = process.env.STRATIUM_CURL_PATH || 'curl';
  const url  = `${params.keycloak_url}/realms/${params.realm}/protocol/openid-connect/token`;

  const formData = [
    `grant_type=password`,
    `client_id=${encodeURIComponent(params.client_id)}`,
    `username=${encodeURIComponent(params.username)}`,
    `password=${encodeURIComponent(params.password)}`,
    `scope=openid`,
  ].join('&');

  const args = [
    '-s',
    '-X', 'POST',
    '-H', 'Content-Type: application/x-www-form-urlencoded',
    '-d', formData,
    '-w', '\n__STATUS__%{http_code}',
    '--max-time', '10',
    url,
  ];

  let raw;
  try {
    raw = execFileSync(curl, args, { timeout: 10000, encoding: 'utf8' });
  } catch (err) {
    throw new Error(`Keycloak token request failed: ${err.message}`);
  }

  const statusMatch = raw.match(/\n__STATUS__(\d{3})$/);
  const statusCode  = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  const body        = statusMatch ? raw.slice(0, statusMatch.index) : raw;

  let parsed;
  try { parsed = JSON.parse(body); } catch {
    throw new Error(`Keycloak returned non-JSON: ${body.slice(0, 200)}`);
  }

  if (statusCode >= 400) {
    const msg = parsed.error_description || parsed.error || JSON.stringify(parsed);
    throw new Error(`Keycloak authentication failed (HTTP ${statusCode}): ${msg}`);
  }

  return parsed;
}

/**
 * Refresh an OIDC access token using a refresh token.
 *
 * @param {object} params
 * @param {string} params.keycloak_url
 * @param {string} params.realm
 * @param {string} params.client_id
 * @param {string} params.refresh_token
 * @returns {{ access_token: string, refresh_token: string, expires_in: number }}
 */
function keycloakRefreshToken(params) {
  const curl = process.env.STRATIUM_CURL_PATH || 'curl';
  const url  = `${params.keycloak_url}/realms/${params.realm}/protocol/openid-connect/token`;

  const formData = [
    `grant_type=refresh_token`,
    `client_id=${encodeURIComponent(params.client_id)}`,
    `refresh_token=${encodeURIComponent(params.refresh_token)}`,
  ].join('&');

  const args = ['-s', '-X', 'POST',
    '-H', 'Content-Type: application/x-www-form-urlencoded',
    '-d', formData,
    '-w', '\n__STATUS__%{http_code}',
    '--max-time', '10',
    url,
  ];

  let raw;
  try {
    raw = execFileSync(curl, args, { timeout: 10000, encoding: 'utf8' });
  } catch (err) {
    throw new Error(`Keycloak token refresh failed: ${err.message}`);
  }

  const statusMatch = raw.match(/\n__STATUS__(\d{3})$/);
  const statusCode  = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  const body        = statusMatch ? raw.slice(0, statusMatch.index) : raw;

  let parsed;
  try { parsed = JSON.parse(body); } catch {
    throw new Error(`Keycloak returned non-JSON on refresh: ${body.slice(0, 200)}`);
  }

  if (statusCode >= 400) {
    const msg = parsed.error_description || parsed.error || JSON.stringify(parsed);
    throw new Error(`Keycloak token refresh failed (HTTP ${statusCode}): ${msg}`);
  }

  return parsed;
}

module.exports = {
  grpcCall,
  restCall,
  createDelegation,
  executeAction,
  registerAgent,
  keycloakPasswordGrant,
  keycloakRefreshToken,
};
