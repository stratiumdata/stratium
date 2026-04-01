/**
 * agent-registry.js
 *
 * Manages the per-machine Claude Code agent registration with Stratium PAP.
 *
 * On first run, generates a stable agent identity and registers it via PAP.
 * On subsequent runs, verifies the agent still exists and re-registers if needed.
 * All state is persisted to ~/.claude/stratium-agent.json.
 *
 * Registration is idempotent — safe to call on every session init.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');
const { registerAgent, restCall } = require('./grpc-client');

/** Path to the persisted agent identity file. */
const AGENT_FILE_PATH = path.join(os.homedir(), '.claude', 'stratium-agent.json');

/**
 * @typedef {object} AgentRecord
 * @property {string} agent_id       - UUID assigned by Stratium PAP
 * @property {string} client_id      - OAuth client ID for the agent
 * @property {string} registered_at  - ISO timestamp of first registration
 * @property {string} machine_id     - Stable machine identifier
 * @property {string} stratium_gateway - Gateway used at registration time
 */

/**
 * Generate a stable machine identifier from hostname + os.userInfo.
 * This is not a secret — it's used for labeling only.
 *
 * @returns {string}
 */
function getMachineId() {
  const hostname = os.hostname().split('.')[0]; // short hostname only
  const username = os.userInfo().username;
  return `${hostname}-${username}`.replace(/[^a-zA-Z0-9-]/g, '-').slice(0, 63);
}

/**
 * Generate a v4-like UUID using Node.js crypto.
 * @returns {string}
 */
function generateUUID() {
  const { randomBytes } = require('crypto');
  const bytes = randomBytes(16);
  // Set version 4 bits
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant bits
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20, 32),
  ].join('-');
}

/**
 * Load the persisted agent record from disk.
 * Returns null if the file does not exist or is invalid.
 *
 * @returns {AgentRecord|null}
 */
function loadAgentRecord() {
  try {
    const raw = fs.readFileSync(AGENT_FILE_PATH, 'utf8');
    const rec = JSON.parse(raw);
    if (rec.agent_id && rec.machine_id) return rec;
    return null;
  } catch {
    return null;
  }
}

/**
 * Persist an agent record to disk with user-only read/write permissions.
 *
 * @param {AgentRecord} record
 */
function saveAgentRecord(record) {
  const dir = path.dirname(AGENT_FILE_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(AGENT_FILE_PATH, JSON.stringify(record, null, 2), {
    encoding: 'utf8',
    mode: 0o600,
  });
}

/**
 * Ensure the Claude Code agent is registered with Stratium PAP.
 *
 * Behavior:
 *   1. Load existing record from ~/.claude/stratium-agent.json
 *   2. If no record or gateway has changed: register via PAP + save
 *   3. If record exists and gateway matches: return existing record as-is
 *      (PAP is authoritative — we don't re-verify on every call to stay fast)
 *
 * @param {object} opts
 * @param {object} opts.restOpts      - Options for grpc-client restCall
 * @param {string} opts.agentName     - Agent name to register (from CLAUDE.md or default)
 * @param {string} opts.gatewayHost   - Current gateway host:port
 * @param {string[]} opts.allowedTools - Tools to register the agent with
 * @param {number}  opts.maxTier      - Maximum action tier
 * @returns {AgentRecord}
 */
function ensureAgentRegistered(opts) {
  const { restOpts, agentName, gatewayHost, allowedTools, maxTier } = opts;
  const machineId = getMachineId();

  const existing = loadAgentRecord();

  // Re-use existing if gateway hasn't changed — but verify the agent still exists in PAP.
  // A 404 means the agent was deleted (e.g. DB reset); fall through to re-register.
  // Any other error means PAP is temporarily unreachable; return cached optimistically.
  if (existing && existing.stratium_gateway === gatewayHost) {
    try {
      restCall(restOpts, 'GET', `/api/v1/agents/${existing.agent_id}`);
      return existing;
    } catch (err) {
      if (err.message && err.message.includes('HTTP 404')) {
        process.stderr.write('[stratium] Cached agent not found in PAP — re-registering...\n');
        // Fall through to registration below
      } else {
        process.stderr.write(`[stratium] Warning: could not verify agent registration: ${err.message}\n`);
        return existing;
      }
    }
  }

  // Register (or re-register if gateway changed)
  let papResponse;
  try {
    papResponse = registerAgent(restOpts, {
      name:          agentName || 'claude-code',
      machine_id:    machineId,
      allowed_tools: allowedTools || [],
      max_tier:      maxTier      ?? 1,
    });
  } catch (err) {
    // If we have an existing record and PAP is temporarily unreachable,
    // return the cached record rather than failing (we'll re-verify next session)
    if (existing) {
      process.stderr.write(
        `[stratium] Warning: could not verify agent registration: ${err.message}\n`
      );
      return existing;
    }
    throw err;
  }

  const record = {
    agent_id:         papResponse.agent_id || papResponse.id || generateUUID(),
    client_id:        papResponse.client_id || `agent_${(papResponse.agent_id || '').slice(0, 8)}`,
    registered_at:    existing ? existing.registered_at : new Date().toISOString(),
    machine_id:       machineId,
    stratium_gateway: gatewayHost,
  };

  saveAgentRecord(record);
  return record;
}

module.exports = { ensureAgentRegistered, loadAgentRecord, getMachineId, AGENT_FILE_PATH };
