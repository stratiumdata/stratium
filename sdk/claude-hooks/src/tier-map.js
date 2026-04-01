/**
 * tier-map.js
 *
 * Maps Claude Code tool names to Stratium ActionTier values and action strings.
 * This is the policy translation layer between Claude Code's tool model and
 * Stratium's generic tier-based authorization model.
 *
 * Tier values mirror ActionTier in the Stratium proto:
 *   0 = REASONING       (no side effects)
 *   1 = READ_ONLY       (read-only access to local/remote data)
 *   2 = INTERNAL_MODIFY (write/mutate local state)
 *   3 = EXTERNAL_COMMS  (network calls to external services)
 *   4 = DESTRUCTIVE     (irreversible or high-blast-radius actions)
 *
 * Projects can override individual tools via the stratium.tool_tiers block
 * in their CLAUDE.md. See claude-md-parser.js for how overrides are applied.
 */

'use strict';

/** @typedef {{ tier: number, action: string, label: string }} TierEntry */

/**
 * Default tier map for built-in Claude Code tools.
 * Keys are tool_name values as received from Claude Code hook stdin.
 *
 * @type {Record<string, TierEntry>}
 */
const DEFAULT_TIER_MAP = {
  // ── Read-only tools (tier 1) ────────────────────────────────────────────
  read_file:        { tier: 1, action: 'read',   label: 'READ_ONLY' },
  Read:             { tier: 1, action: 'read',   label: 'READ_ONLY' },
  list_files:       { tier: 1, action: 'read',   label: 'READ_ONLY' },
  LS:               { tier: 1, action: 'read',   label: 'READ_ONLY' },
  grep_search:      { tier: 1, action: 'read',   label: 'READ_ONLY' },
  Grep:             { tier: 1, action: 'read',   label: 'READ_ONLY' },
  search_files:     { tier: 1, action: 'read',   label: 'READ_ONLY' },
  file_search:      { tier: 1, action: 'read',   label: 'READ_ONLY' },
  Glob:             { tier: 1, action: 'read',   label: 'READ_ONLY' },
  web_fetch:        { tier: 1, action: 'read',   label: 'READ_ONLY' },
  WebFetch:         { tier: 1, action: 'read',   label: 'READ_ONLY' },
  web_search:       { tier: 1, action: 'read',   label: 'READ_ONLY' },
  WebSearch:        { tier: 1, action: 'read',   label: 'READ_ONLY' },
  NotebookRead:     { tier: 1, action: 'read',   label: 'READ_ONLY' },
  TaskOutput:       { tier: 1, action: 'read',   label: 'READ_ONLY' },

  // ── Internal modify tools (tier 2) ─────────────────────────────────────
  write_file:       { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  Write:            { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  create_file:      { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  edit_file:        { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  Edit:             { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  str_replace:      { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  insert_content:   { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },
  move_file:        { tier: 2, action: 'modify', label: 'INTERNAL_MODIFY' },
  delete_file:      { tier: 2, action: 'modify', label: 'INTERNAL_MODIFY' },
  rename_file:      { tier: 2, action: 'modify', label: 'INTERNAL_MODIFY' },
  NotebookEdit:     { tier: 2, action: 'write',  label: 'INTERNAL_MODIFY' },

  // ── Bash: classified by command content (see classifyBash) ─────────────
  // Default for Bash when command inspection is inconclusive: tier 2
  Bash:             { tier: 2, action: 'execute', label: 'INTERNAL_MODIFY' },
  bash:             { tier: 2, action: 'execute', label: 'INTERNAL_MODIFY' },
  execute_command:  { tier: 2, action: 'execute', label: 'INTERNAL_MODIFY' },

  // ── Agent/task spawning (tier 2) ────────────────────────────────────────
  Agent:            { tier: 2, action: 'spawn',  label: 'INTERNAL_MODIFY' },
  Task:             { tier: 2, action: 'spawn',  label: 'INTERNAL_MODIFY' },
  TodoWrite:        { tier: 1, action: 'write',  label: 'READ_ONLY' },

  // ── MCP tools: default tier 2 (can be overridden per-tool in CLAUDE.md)
  // mcp__* tools are caught by the mcp prefix rule in getTier()
};

/** Patterns that indicate a bash command is purely read-only (tier 1). */
const BASH_READ_PATTERNS = [
  /^(cat|head|tail|less|more|wc|file|stat)\s/,
  /^(echo|printf|pwd|whoami|id|date|uname)\b/,
  /^(ls|find|locate|which|type|command)\s/,
  /^(grep|egrep|fgrep|rg|ripgrep|ag)\s/,
  /^(diff|cmp|md5sum|sha256sum|shasum)\s/,
  /^(ps|top|htop|pgrep|lsof|netstat|ss|ifconfig|ip)\s/,
  /^(git (log|status|diff|show|branch|remote|tag|describe|rev-parse|shortlog|blame|stash list))/,
  /^(docker (ps|images|inspect|logs|stats))/,
  /^(kubectl (get|describe|logs|top))/,
  /^(brew (list|info|search))/,
  /^(npm (list|ls|outdated|audit|info))/,
  /^(python3? -c ['"]?(import|print|json|sys\.stdout))/,
  /^(jq|yq|xmllint|xq)\s/,
];

/** Patterns that indicate a bash command makes external network calls (tier 3). */
const BASH_EXTERNAL_PATTERNS = [
  /\b(curl|wget|fetch|http|https?:\/\/)\b/,
  /\b(ssh|scp|rsync|sftp)\s/,
  /\b(aws|gcloud|az|terraform|pulumi)\s/,
  /\b(gh|hub)\s(pr|issue|release|repo create|deploy)/,
  /\b(docker push|docker pull|docker login)\b/,
  /\b(npm publish|pip install|pip3 install|cargo publish)\b/,
  /\b(git (push|fetch|clone|pull))\b/,
  /\b(kubectl apply|kubectl delete|kubectl create)\b/,
  /\b(helm (install|upgrade|delete|push))\b/,
];

/** Patterns that indicate a bash command is destructive (tier 4). */
const BASH_DESTRUCTIVE_PATTERNS = [
  /\brm\s+(-[rfRF]+|--recursive|--force)/,
  /\bmkfs\b/,
  /\bdd\b.*\bof=/,
  /\b(chmod|chown)\s+-R\s+\d{3,}/,
  /\bdropdb\b|\bDROP (DATABASE|TABLE)\b/i,
  /\b(sudo (rm|mkfs|dd|fdisk|parted|format))\b/,
  /\btruncate\s+--?s(ize)?\s+0\b/,
  />\s*(\/dev\/sd[a-z]|\/dev\/nvme)/,
];

/**
 * Classify a bash command string into a tier.
 * Falls back to tier 2 (INTERNAL_MODIFY) if no pattern matches.
 *
 * @param {string} command - The bash command to classify
 * @returns {TierEntry}
 */
function classifyBash(command) {
  if (!command || typeof command !== 'string') {
    return { tier: 2, action: 'execute', label: 'INTERNAL_MODIFY' };
  }

  const trimmed = command.trim();

  // Check destructive first (most dangerous → highest priority)
  for (const pattern of BASH_DESTRUCTIVE_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { tier: 4, action: 'execute', label: 'DESTRUCTIVE' };
    }
  }

  // Check external comms
  for (const pattern of BASH_EXTERNAL_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { tier: 3, action: 'network', label: 'EXTERNAL_COMMS' };
    }
  }

  // Check read-only
  for (const pattern of BASH_READ_PATTERNS) {
    if (pattern.test(trimmed)) {
      return { tier: 1, action: 'read', label: 'READ_ONLY' };
    }
  }

  // Default: internal modify
  return { tier: 2, action: 'execute', label: 'INTERNAL_MODIFY' };
}

/**
 * Get the tier entry for a given tool name and input.
 *
 * @param {string} toolName - Claude Code tool name
 * @param {object} toolInput - Tool input parameters
 * @param {Record<string, TierEntry>} [overrides] - Per-project overrides from CLAUDE.md
 * @returns {TierEntry}
 */
function getTier(toolName, toolInput, overrides = {}) {
  // Project-level overrides take precedence
  if (overrides && overrides[toolName]) {
    return overrides[toolName];
  }

  // Bash tools: classify by command content
  if (toolName === 'Bash' || toolName === 'bash' || toolName === 'execute_command') {
    const command = toolInput?.command || toolInput?.cmd || '';
    return classifyBash(command);
  }

  // MCP tools: default to tier 2, allow project override
  if (toolName?.startsWith('mcp__') || toolName?.startsWith('mcp_')) {
    return { tier: 2, action: 'call', label: 'INTERNAL_MODIFY' };
  }

  // Known tool
  if (DEFAULT_TIER_MAP[toolName]) {
    return DEFAULT_TIER_MAP[toolName];
  }

  // Unknown tool: default to tier 2 (conservative)
  return { tier: 2, action: 'call', label: 'INTERNAL_MODIFY' };
}

/** Human-readable tier label for a numeric tier value. */
const TIER_LABEL = {
  0: 'REASONING',
  1: 'READ_ONLY',
  2: 'INTERNAL_MODIFY',
  3: 'EXTERNAL_COMMS',
  4: 'DESTRUCTIVE',
};

module.exports = { getTier, classifyBash, DEFAULT_TIER_MAP, TIER_LABEL };
