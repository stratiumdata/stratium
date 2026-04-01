/**
 * pre-tool-use.js
 *
 * PreToolUse hook handler — the enforcement checkpoint.
 *
 * Runs before every Claude Code tool execution. Fast path:
 *   1. Read session state from /tmp/stratium-session-<pid>.json
 *   2. Determine tool action tier (tier-map + CLAUDE.md overrides)
 *   3. Local pre-check: tier cap + approved_tools list
 *   4. Remote check: Agent Gateway ExecuteAction (gRPC)
 *   5. ALLOW → exit 0 | DENY → exit 2 + JSON reason
 *
 * Input (stdin): Claude Code hook JSON
 * {
 *   "hook_event_name": "PreToolUse",
 *   "tool_name": "Write",
 *   "tool_input": { ... },
 *   "session_id": "...",
 *   "transcript_path": "..."
 * }
 *
 * ALLOW output: exit 0, no stdout
 * DENY output:  exit 2, stdout = JSON block with hookSpecificOutput format
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const os   = require('os');

const { getTier, TIER_LABEL }  = require('./tier-map');
const { executeAction }        = require('./grpc-client');
const { notify }               = require('./notifications');

/** Path to session state file, keyed by Claude Code session_id. */
function sessionFilePath(sessionId) {
  return path.join(os.tmpdir(), `stratium-session-${sessionId}.json`);
}

/**
 * Load the session state for the current Claude Code session.
 * Returns null if file does not exist or is unparseable.
 *
 * STRATIUM_SESSION_FILE env var overrides the default path — used for testing.
 *
 * @param {string} [sessionId] - Claude Code session_id from hook input
 * @returns {object|null}
 */
function loadSession(sessionId) {
  const sessionFile = process.env.STRATIUM_SESSION_FILE || sessionFilePath(sessionId || process.pid);
  try {
    const raw = fs.readFileSync(sessionFile, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Check whether the session delegation is still valid.
 *
 * @param {object} session
 * @returns {boolean}
 */
function sessionIsValid(session) {
  if (!session || !session.delegation_token) return false;
  if (!session.expires_at) return true; // no expiry set — treat as valid
  const now       = Math.floor(Date.now() / 1000);
  const expiresAt = Math.floor(new Date(session.expires_at).getTime() / 1000);
  return expiresAt > now + 30; // 30-second buffer
}

/** Machine config notifications block (loaded once, lazily). */
let _notificationsConfig;
function getNotificationsConfig() {
  if (_notificationsConfig === undefined) {
    try {
      const mc = JSON.parse(require('fs').readFileSync(
        require('path').join(require('os').homedir(), '.claude', 'stratium.json'), 'utf8'
      ));
      _notificationsConfig = mc.notifications || null;
    } catch {
      _notificationsConfig = null;
    }
  }
  return _notificationsConfig;
}

/**
 * Emit a PreToolUse deny response to stdout and exit 2.
 * Also fires webhook notifications if configured.
 *
 * @param {string} reason - Human-readable reason Claude will relay to the developer
 * @param {object} [context] - Optional event context for notifications
 */
function deny(reason, context) {
  const output = {
    hookSpecificOutput: {
      hookEventName:            'PreToolUse',
      permissionDecision:       'deny',
      permissionDecisionReason: reason,
    },
  };
  process.stdout.write(JSON.stringify(output) + '\n');

  // Fire webhook notification (non-blocking background process)
  if (context) {
    try {
      notify({
        type:          'deny',
        tool_name:     context.toolName || '',
        reason,
        user:          context.user || '',
        delegation_id: context.delegationId || '',
        project:       process.env.CLAUDE_PROJECT_DIR
                         ? require('path').basename(process.env.CLAUDE_PROJECT_DIR)
                         : '',
        machine:       require('os').hostname(),
      }, getNotificationsConfig());
    } catch {
      // Notification failure must never block enforcement
    }
  }

  process.exit(2);
}

/**
 * Minimal glob-to-regex converter for classification_caps path patterns.
 * Supports: * (any chars except /), ** (any chars including /), ? (single char)
 *
 * @param {string} globPattern
 * @returns {RegExp}
 */
function globToRegex(globPattern) {
  // Strip leading **/ — the (^|/) anchor already provides "any prefix including none"
  // semantics, so keeping .* before the first segment causes root-level paths to fail.
  // e.g. **/.env → .env so that (^|/)\.env$ matches both ".env" and "config/.env"
  const normalized = globPattern.replace(/^\*\*\//, '');

  const escaped = normalized
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')   // escape regex special chars
    .replace(/\*\*/g, '\x00GLOBSTAR\x00')    // placeholder for internal **
    .replace(/\*/g, '[^/]*')                 // * → match within path segment
    .replace(/\?/g, '[^/]')                  // ? → single char
    .replace(/\x00GLOBSTAR\x00/g, '.*');     // ** → match across segments

  // Anchor to end; allow optional leading path
  return new RegExp(`(^|/)${escaped}$`, 'i');
}

/**
 * Detect data classification for a file path based on CLAUDE.md classification_caps patterns.
 *
 * The `classification_caps` block in CLAUDE.md maps path glob patterns to
 * classification labels (e.g., "**\/secret*" -> "TOP_SECRET").
 * Matched files get a `classification` resource attribute which Stratium's
 * compound decision engine uses to enforce data classification policies.
 *
 * @param {string} filePath
 * @param {object} classificationCaps - Record<pattern|label, string> from scope
 * @returns {string|null} Classification label if matched, null otherwise
 */
function detectClassification(filePath, classificationCaps) {
  if (!filePath || !classificationCaps || typeof classificationCaps !== 'object') {
    return null;
  }

  // classification_caps can be used two ways:
  //   1. Path patterns:  { "**/secret*": "TOP_SECRET", "**/.env": "CONFIDENTIAL" }
  //   2. Domain caps:    { "nato": "CONFIDENTIAL" }  (not path patterns)
  // We only process entries whose keys look like glob patterns (contain / or * or .)

  for (const [pattern, label] of Object.entries(classificationCaps)) {
    const isPathPattern = pattern.includes('/') || pattern.includes('*') || pattern.includes('?');
    if (!isPathPattern) continue;

    try {
      const regex = globToRegex(pattern);
      if (regex.test(filePath)) {
        return String(label);
      }
    } catch {
      // Malformed pattern — skip
    }
  }

  return null;
}

/**
 * Extract resource attributes from a tool's input for the ExecuteAction call.
 * Includes per-path classification detection when classification_caps are configured.
 *
 * @param {string} toolName
 * @param {object} toolInput
 * @param {object} [classificationCaps] - From session project_scope
 * @returns {object}
 */
function extractResourceAttributes(toolName, toolInput, classificationCaps) {
  if (!toolInput) return {};

  const attrs = {};

  // File path attributes
  const filePath = toolInput.path || toolInput.file_path || toolInput.filepath;
  if (filePath) {
    attrs.resource_type = 'file';
    attrs.path          = String(filePath);

    // Per-path classification detection
    const classification = detectClassification(String(filePath), classificationCaps);
    if (classification) {
      attrs.classification = classification;
    }
  }

  // URL attributes (web_fetch, web_search)
  if (toolInput.url) {
    attrs.resource_type = 'url';
    attrs.url           = String(toolInput.url);
  }

  // Bash command summary
  if (toolName === 'Bash' || toolName === 'bash') {
    const cmd = toolInput.command || toolInput.cmd || '';
    attrs.resource_type   = 'command';
    attrs.command_preview = cmd.slice(0, 200); // truncate for audit log
  }

  return attrs;
}

/**
 * Build a human-readable DENY reason message.
 *
 * @param {string} toolName
 * @param {object} tierEntry  - { tier, action, label }
 * @param {string} type       - 'tier_cap' | 'not_approved' | 'gateway_deny' | 'unavailable'
 * @param {object} session    - Session state for context
 * @param {string} [gatewayReason] - Denial reason from Agent Gateway
 * @returns {string}
 */
function buildDenyReason(toolName, tierEntry, type, session, gatewayReason) {
  const scope       = session.project_scope || {};
  const maxTier     = scope.max_action_tier ?? 1;
  const maxLabel    = TIER_LABEL[maxTier]   || 'READ_ONLY';
  const toolLabel   = tierEntry.label       || TIER_LABEL[tierEntry.tier] || 'UNKNOWN';
  const delegId     = (session.delegation_id || '').slice(0, 8);

  switch (type) {
    case 'tier_cap':
      return (
        `Stratium DENY: ${toolName} requires ${toolLabel} (tier ${tierEntry.tier}) ` +
        `but your project delegation is capped at ${maxLabel} (tier ${maxTier}).\n` +
        `To allow this tool, ask your admin to set max_action_tier: ${toolLabel} ` +
        `in the stratium: block of CLAUDE.md.\n` +
        `Delegation: ${delegId || 'unknown'}`
      );

    case 'not_approved':
      return (
        `Stratium DENY: ${toolName} is not in the approved_tools list for this project.\n` +
        `Approved tools: ${(scope.approved_tools || []).join(', ') || '(none set)'}\n` +
        `To allow ${toolName}, ask your admin to add it to the stratium: approved_tools ` +
        `list in CLAUDE.md.\n` +
        `Delegation: ${delegId || 'unknown'}`
      );

    case 'gateway_deny':
      return (
        `Stratium DENY: ${toolName} was denied by Stratium authorization policy.\n` +
        `${gatewayReason ? `Reason: ${gatewayReason}\n` : ''}` +
        `Delegation: ${delegId || 'unknown'}`
      );

    case 'unavailable':
      return (
        `Stratium authorization service is unreachable. ` +
        `Tool execution blocked (fail_closed policy).\n` +
        `Try again in a moment or contact your admin if the issue persists.`
      );

    case 'no_session':
      return (
        `Stratium session is not initialized or has expired. ` +
        `Start a new Claude Code session to re-authenticate.\n` +
        `If this persists, run: stratium-hooks status`
      );

    default:
      return `Stratium DENY: ${toolName} was blocked. (reason: ${type})`;
  }
}

/**
 * Main PreToolUse enforcement logic.
 *
 * @param {object} hookInput - Parsed hook JSON from stdin
 */
function runPreToolUse(hookInput) {
  const toolName  = hookInput.tool_name  || '';
  const toolInput = hookInput.tool_input || {};

  // ── 1. Load session state ─────────────────────────────────────────────────
  const session = loadSession(hookInput.session_id);

  if (!session) {
    // No session file — stratium not installed or session-init not run
    // If we have no machine config either, exit 0 (not configured)
    const machineConfigPath = path.join(os.homedir(), '.claude', 'stratium.json');
    if (!fs.existsSync(machineConfigPath)) {
      process.exit(0); // stratium not installed — transparent passthrough
    }

    // Machine config exists but session missing — fail per config default
    try {
      const mc = JSON.parse(fs.readFileSync(machineConfigPath, 'utf8'));
      const onUnavailable = (mc.default_scope || {}).on_unavailable || 'fail_closed';
      if (onUnavailable === 'fail_open') {
        process.stderr.write(`[stratium] No session file — fail_open passthrough for ${toolName}\n`);
        process.exit(0);
      }
    } catch {
      // Cannot read machine config — fail closed
    }

    deny(buildDenyReason(toolName, { tier: 0, label: 'UNKNOWN' }, 'no_session', {}));
    return;
  }

  if (!sessionIsValid(session)) {
    const onUnavailable = session.on_unavailable || 'fail_closed';
    if (onUnavailable === 'fail_open') {
      process.stderr.write(`[stratium] Session expired — fail_open passthrough for ${toolName}\n`);
      process.exit(0);
    }
    deny(buildDenyReason(toolName, { tier: 0, label: 'UNKNOWN' }, 'no_session', session));
    return;
  }

  const onUnavailable = session.on_unavailable || 'fail_closed';

  // ── 2. Determine action tier ──────────────────────────────────────────────
  const toolTierOverrides = (session.project_scope || {}).tool_tiers || {};
  const tierEntry         = getTier(toolName, toolInput, toolTierOverrides);

  // ── 3. Local pre-checks (no network) ─────────────────────────────────────
  const scope       = session.project_scope || {};
  const maxTier     = scope.max_action_tier ?? 1;
  const approvedTools = scope.approved_tools || [];

  /** Shared notification context for deny() calls below */
  const denyCtx = {
    toolName:     toolName,
    user:         session.user         || '',
    delegationId: session.delegation_id || '',
  };

  // Tier cap check
  if (tierEntry.tier > maxTier) {
    deny(buildDenyReason(toolName, tierEntry, 'tier_cap', session), denyCtx);
    return;
  }

  // Approved tools check (only enforced if list is non-empty)
  if (approvedTools.length > 0 && !approvedTools.includes(toolName)) {
    // Also check snake_case / camelCase variants common in Claude Code
    const toolAliases = [toolName.toLowerCase(), toolName.replace(/([A-Z])/g, '_$1').toLowerCase()];
    const isApproved  = approvedTools.some(t =>
      t === toolName || toolAliases.includes(t.toLowerCase())
    );
    if (!isApproved) {
      deny(buildDenyReason(toolName, tierEntry, 'not_approved', session), denyCtx);
      return;
    }
  }

  // ── 4. Remote authorization check via Agent Gateway ──────────────────────
  const grpcOpts = {
    gateway:   session.gateway,
    cacert:    session.cacert    || undefined,
    plaintext: session.plaintext || false,
  };

  const classificationCaps = (session.project_scope || {}).classification_caps || {};
  const resourceAttrs = extractResourceAttributes(toolName, toolInput, classificationCaps);

  let response;
  try {
    response = executeAction(grpcOpts, {
      delegation_token:    session.delegation_token,
      tool_name:           toolName,
      action:              tierEntry.action,
      action_tier:         tierEntry.tier,
      resource_attributes: resourceAttrs,
    });
  } catch (err) {
    // Gateway unreachable or error
    if (onUnavailable === 'fail_open') {
      process.stderr.write(`[stratium] ExecuteAction failed (fail_open): ${err.message}\n`);
      process.exit(0);
    }
    deny(buildDenyReason(toolName, tierEntry, 'unavailable', session), denyCtx);
    return;
  }

  // ── 5. Enforce decision ───────────────────────────────────────────────────
  if (response.authorized === true || response.authorized === 'true') {
    process.exit(0); // ALLOW — transparent
  }

  deny(
    buildDenyReason(toolName, tierEntry, 'gateway_deny', session, response.denial_reason || response.error || ''),
    denyCtx
  );
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
    // stdin was empty or non-JSON — proceed with empty input
  }

  try {
    runPreToolUse(hookInput);
  } catch (err) {
    // Unexpected error — check on_unavailable
    const onUnavailable = process.env.STRATIUM_ON_UNAVAILABLE || 'fail_closed';
    if (onUnavailable === 'fail_open') {
      process.stderr.write(`[stratium] pre-tool-use unexpected error (fail_open): ${err.message}\n`);
      process.exit(0);
    }
    const output = {
      hookSpecificOutput: {
        hookEventName:            'PreToolUse',
        permissionDecision:       'deny',
        permissionDecisionReason: `Stratium pre-tool-use error: ${err.message}`,
      },
    };
    process.stdout.write(JSON.stringify(output) + '\n');
    process.exit(2);
  }
});
