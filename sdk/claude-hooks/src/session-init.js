/**
 * session-init.js
 *
 * UserPromptSubmit hook handler.
 *
 * Runs once per Claude Code session on the first user prompt.
 * Establishes the Stratium authorization context for the session:
 *   1. Load machine config (~/.claude/stratium.json)
 *   2. Parse CLAUDE.md stratium: block for project scope
 *   3. Authenticate user via Keycloak (token cached across sessions)
 *   4. Ensure agent is registered in Stratium PAP (idempotent)
 *   5. Create a session delegation via Agent Gateway
 *   6. Write /tmp/stratium-session-<pid>.json for pre-tool-use to read
 *
 * Input (stdin): Claude Code hook JSON
 * Output: exit 0 (allow) or exit 2 with JSON reason (block on fail_closed)
 *
 * Claude Code hook stdin format:
 * {
 *   "hook_event_name": "UserPromptSubmit",
 *   "session_id": "...",
 *   "transcript_path": "..."
 * }
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { loadScope }             = require('./claude-md-parser');
const { getToken }              = require('./auth');
const { ensureAgentRegistered } = require('./agent-registry');
const { createDelegation }      = require('./grpc-client');
const { validateScope }         = require('./scope-validator');

/** Path to session state file, keyed by Claude Code session_id. */
function sessionFilePath(sessionId) {
  return path.join(os.tmpdir(), `stratium-session-${sessionId}.json`);
}

/**
 * Load machine-level configuration from ~/.claude/stratium.json.
 *
 * @returns {object|null}
 */
function loadMachineConfig() {
  const configPath = path.join(os.homedir(), '.claude', 'stratium.json');
  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Build gRPC client options from machine config.
 *
 * @param {object} machineConfig
 * @returns {import('./grpc-client').GrpcCallOptions}
 */
function buildGrpcOpts(machineConfig) {
  const opts = { gateway: machineConfig.gateway };
  if (machineConfig.cacert)    opts.cacert    = machineConfig.cacert;
  if (machineConfig.plaintext) opts.plaintext = machineConfig.plaintext;
  return opts;
}

/**
 * Build REST client options from machine config.
 *
 * @param {object} machineConfig
 * @param {string} accessToken
 * @returns {import('./grpc-client').RestCallOptions}
 */
function buildRestOpts(machineConfig, accessToken) {
  return {
    baseUrl: machineConfig.pap_url,
    token:   accessToken,
    cacert:  machineConfig.cacert,
  };
}

/**
 * Map a numeric tier to the TIER_NAMES string.
 *
 * @param {number} tier
 * @returns {string}
 */
function tierLabel(tier) {
  const labels = ['REASONING', 'READ_ONLY', 'INTERNAL_MODIFY', 'EXTERNAL_COMMS', 'DESTRUCTIVE'];
  return labels[tier] || 'INTERNAL_MODIFY';
}

/**
 * Emit a block response to stdout and exit 2.
 * Claude Code surfaces the reason inline.
 *
 * @param {string} reason
 */
function blockSession(reason) {
  process.stdout.write(JSON.stringify({ decision: 'block', reason }) + '\n');
  process.exit(2);
}

/**
 * Emit a non-blocking warning to stderr.
 * Claude Code does not surface stderr to the user.
 *
 * @param {string} msg
 */
function warn(msg) {
  process.stderr.write(`[stratium] ${msg}\n`);
}

/**
 * Main session initialization logic.
 *
 * @param {object} hookInput  - Parsed hook JSON from stdin
 */
function runSessionInit(hookInput) {
  const sessionFile = process.env.STRATIUM_SESSION_FILE || sessionFilePath(hookInput.session_id || process.pid);
  const projectDir  = process.env.CLAUDE_PROJECT_DIR || process.cwd();

  // ── 1. Check if session already initialized (idempotent) ─────────────────
  if (fs.existsSync(sessionFile)) {
    try {
      const existing = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
      const now      = Math.floor(Date.now() / 1000);
      const expiresAt = existing.expires_at
        ? Math.floor(new Date(existing.expires_at).getTime() / 1000)
        : 0;

      if (expiresAt > now + 60) {
        // Session still valid — nothing to do
        process.exit(0);
      }
    } catch {
      // Malformed session file — reinitialize
    }
  }

  // ── 2. Load machine config ────────────────────────────────────────────────
  const machineConfig = loadMachineConfig();

  if (!machineConfig) {
    // No machine config — not installed or not configured
    // Silent exit: don't block Claude Code if stratium isn't installed
    process.exit(0);
  }

  // ── 3. Load project scope from CLAUDE.md ─────────────────────────────────
  const { scope, claudeMdPath } = loadScope(projectDir);

  // If stratium: enabled is explicitly false, skip silently
  if (scope.enabled === false && claudeMdPath !== null) {
    process.exit(0);
  }

  // Merge project scope with machine config defaults
  const defaultScope    = machineConfig.default_scope || {};
  const onUnavailable   = scope.on_unavailable || defaultScope.on_unavailable || 'fail_closed';
  const maxActionTier   = scope.max_action_tier   ?? defaultScope.max_action_tier   ?? 1;
  const approvedTools   = scope.approved_tools.length > 0
    ? scope.approved_tools
    : (defaultScope.approved_tools || []);

  // ── 4. Authenticate user ──────────────────────────────────────────────────
  const username = process.env.STRATIUM_OIDC_USER || os.userInfo().username;

  let tokenEntry;
  try {
    process.stderr.write(`[stratium] Authenticating as ${username}...\n`);
    tokenEntry = getToken({
      keycloak_url: machineConfig.keycloak_url,
      realm:        machineConfig.realm,
      client_id:    machineConfig.client_id || 'claude-code',
      username,
    });
  } catch (err) {
    if (onUnavailable === 'fail_closed') {
      blockSession(`Stratium authentication failed: ${err.message}`);
    }
    warn(`Authentication failed (fail_open): ${err.message}`);
    process.exit(0);
  }

  // ── 5. Ensure agent is registered ────────────────────────────────────────
  let agentRecord;
  try {
    agentRecord = ensureAgentRegistered({
      restOpts:     buildRestOpts(machineConfig, tokenEntry.access_token),
      agentName:    scope.agent_name || 'claude-code',
      gatewayHost:  machineConfig.gateway,
      allowedTools: approvedTools,
      maxTier:      maxActionTier,
    });
  } catch (err) {
    if (onUnavailable === 'fail_closed') {
      blockSession(`Stratium agent registration failed: ${err.message}`);
    }
    warn(`Agent registration failed (fail_open): ${err.message}`);
    process.exit(0);
  }

  // ── 5b. Validate CLAUDE.md scope against PAP entitlements ────────────────
  // This prevents CLAUDE.md widening scope beyond what the agent is registered for.
  // Violations are logged; scope is automatically capped (not a hard block).
  const validationResult = validateScope(
    buildRestOpts(machineConfig, tokenEntry.access_token),
    agentRecord.agent_id,
    { max_action_tier: maxActionTier, approved_tools: approvedTools }
  );

  if (validationResult.violations.length > 0) {
    for (const v of validationResult.violations) {
      warn(`Scope validation: ${v}`);
    }
  }

  // Use the PAP-capped effective scope
  const effectiveScope = validationResult.effectiveScope;
  const effectiveMaxTier   = effectiveScope.max_action_tier;
  const effectiveTools     = effectiveScope.approved_tools;

  // ── 6. Create session delegation ─────────────────────────────────────────
  const conversationId = hookInput.session_id || `claude-${process.pid}`;
  const purpose        = scope.purpose || `Claude Code session on ${os.hostname()}`;

  let delegation;
  try {
    delegation = createDelegation(buildGrpcOpts(machineConfig), {
      agent_id:        agentRecord.agent_id,
      delegator_token: tokenEntry.access_token,
      user_id:         tokenEntry.user_email || username,
      approved_tools:  effectiveTools,
      max_action_tier: effectiveMaxTier,
      ttl_seconds:     machineConfig.delegation_ttl_seconds || 14400,
      purpose,
      conversation_id: conversationId,
    });
  } catch (err) {
    if (onUnavailable === 'fail_closed') {
      blockSession(`Stratium delegation creation failed: ${err.message}`);
    }
    warn(`Delegation creation failed (fail_open): ${err.message}`);
    process.exit(0);
  }

  // ── 7. Write session state file ───────────────────────────────────────────
  const sessionState = {
    agent_id:         agentRecord.agent_id,
    delegation_id:    delegation.delegation_id,
    delegation_token: delegation.delegation_token,
    expires_at:       delegation.expires_at,
    user:             tokenEntry.user_email || username,
    on_unavailable:   onUnavailable,
    gateway:          machineConfig.gateway,
    cacert:           machineConfig.cacert || null,
    plaintext:        machineConfig.plaintext || false,
    project_scope: {
      max_action_tier:      effectiveMaxTier,
      approved_tools:       effectiveTools,
      tool_tiers:           scope.tool_tiers || {},
      classification_caps:  scope.classification_caps || {},
    },
  };

  fs.writeFileSync(sessionFile, JSON.stringify(sessionState, null, 2), {
    encoding: 'utf8',
    mode: 0o600,
  });

  process.stderr.write(
    `[stratium] Session initialized — ` +
    `tier: ${tierLabel(effectiveMaxTier)}, ` +
    `tools: ${effectiveTools.length > 0 ? effectiveTools.join(', ') : 'all-at-tier'}, ` +
    `delegation: ${delegation.delegation_id?.slice(0, 8) || 'ok'}\n`
  );

  process.exit(0);
}

// ── Entry point ───────────────────────────────────────────────────────────────

let inputData = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', chunk => { inputData += chunk; });
process.stdin.on('end', () => {
  let hookInput = {};
  try {
    hookInput = JSON.parse(inputData);
  } catch {
    // Not valid JSON — proceed with empty input (hooks may send nothing)
  }

  try {
    runSessionInit(hookInput);
  } catch (err) {
    // Unexpected error — fail safe
    const onUnavailable = process.env.STRATIUM_ON_UNAVAILABLE || 'fail_closed';
    if (onUnavailable === 'fail_closed') {
      process.stdout.write(JSON.stringify({
        decision: 'block',
        reason: `Stratium session-init unexpected error: ${err.message}`,
      }) + '\n');
      process.exit(2);
    }
    process.stderr.write(`[stratium] Unexpected error (fail_open): ${err.message}\n`);
    process.exit(0);
  }
});
