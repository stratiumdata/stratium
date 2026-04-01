/**
 * post-tool-use.js
 *
 * PostToolUse hook handler — audit enrichment only.
 * NEVER blocks tool execution (always exits 0).
 *
 * Appends a structured audit record to ~/.claude/stratium-audit.jsonl
 * with full context: user, agent, delegation, tool name, tier, outcome.
 *
 * Input (stdin): Claude Code hook JSON
 * {
 *   "hook_event_name": "PostToolUse",
 *   "tool_name": "Write",
 *   "tool_input": { ... },
 *   "tool_response": { ... },
 *   "session_id": "...",
 *   "transcript_path": "..."
 * }
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { getTier } = require('./tier-map');

/** Path to the local audit log. */
const AUDIT_LOG_PATH = path.join(os.homedir(), '.claude', 'stratium-audit.jsonl');

/** Path to session state file, keyed by Claude Code session_id. */
function sessionFilePath(sessionId) {
  return path.join(os.tmpdir(), `stratium-session-${sessionId}.json`);
}

/**
 * Load the session state for the current Claude Code session.
 * Returns null if not available.
 *
 * @param {string} [sessionId] - Claude Code session_id from hook input
 * @returns {object|null}
 */
function loadSession(sessionId) {
  try {
    const raw = fs.readFileSync(process.env.STRATIUM_SESSION_FILE || sessionFilePath(sessionId || process.pid), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Append a single audit record to the JSONL audit log.
 * Each line is a self-contained JSON object.
 *
 * @param {object} record
 */
function appendAuditRecord(record) {
  const dir = path.dirname(AUDIT_LOG_PATH);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.appendFileSync(AUDIT_LOG_PATH, JSON.stringify(record) + '\n', {
    encoding: 'utf8',
    mode: 0o600,
  });
}

/**
 * Check whether the tool response indicates an error.
 *
 * @param {*} toolResponse
 * @returns {boolean}
 */
function responseIsError(toolResponse) {
  if (!toolResponse) return false;
  if (typeof toolResponse === 'string') return false;
  return !!(toolResponse.error || toolResponse.isError);
}

/**
 * Main PostToolUse audit logic.
 *
 * @param {object} hookInput
 */
function runPostToolUse(hookInput) {
  const session     = loadSession(hookInput.session_id);
  const toolName    = hookInput.tool_name    || '';
  const toolInput   = hookInput.tool_input   || {};
  const toolResponse = hookInput.tool_response;

  // Resolve tier
  const tierOverrides = (session && session.project_scope && session.project_scope.tool_tiers) || {};
  const tierEntry     = getTier(toolName, toolInput, tierOverrides);

  // Build audit record
  const record = {
    ts:            new Date().toISOString(),
    event:         'tool_executed',
    tool_name:     toolName,
    action:        tierEntry.action,
    action_tier:   tierEntry.tier,
    tier_label:    tierEntry.label,
    outcome:       responseIsError(toolResponse) ? 'error' : 'success',
    session_id:    hookInput.session_id || null,

    // Session context (null if session-init didn't run)
    user:          session ? (session.user || null) : null,
    agent_id:      session ? (session.agent_id || null) : null,
    delegation_id: session ? (session.delegation_id || null) : null,

    // Resource summary (truncated for log size)
    resource: buildResourceSummary(toolName, toolInput),
  };

  try {
    appendAuditRecord(record);
  } catch {
    // Audit write failure must never block Claude Code
  }

  // PostToolUse hooks must always exit 0
  process.exit(0);
}

/**
 * Build a compact resource summary for the audit log.
 *
 * @param {string} toolName
 * @param {object} toolInput
 * @returns {object}
 */
function buildResourceSummary(toolName, toolInput) {
  if (!toolInput) return {};

  const filePath = toolInput.path || toolInput.file_path || toolInput.filepath;
  if (filePath) return { type: 'file', path: String(filePath).slice(0, 256) };

  if (toolInput.url) return { type: 'url', url: String(toolInput.url).slice(0, 256) };

  if (toolInput.command || toolInput.cmd) {
    const cmd = (toolInput.command || toolInput.cmd || '').slice(0, 128);
    return { type: 'command', preview: cmd };
  }

  return {};
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
    // Non-JSON input — no audit record
  }

  try {
    runPostToolUse(hookInput);
  } catch {
    // PostToolUse must never block Claude Code
    process.exit(0);
  }
});
