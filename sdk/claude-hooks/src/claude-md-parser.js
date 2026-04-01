/**
 * claude-md-parser.js
 *
 * Finds CLAUDE.md in the project tree and extracts the `stratium:` YAML block.
 * Returns a normalized scope object used by session-init and pre-tool-use.
 *
 * No external dependencies — uses only Node.js built-ins.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

/** Cache: file_path → { mtime, scope } to avoid re-parsing on every tool call. */
const _cache = new Map();

/** Tier name → numeric value mapping. */
const TIER_NAMES = {
  REASONING:        0,
  READ_ONLY:        1,
  INTERNAL_MODIFY:  2,
  EXTERNAL_COMMS:   3,
  DESTRUCTIVE:      4,
};

/**
 * Default scope returned when no stratium: block is found or when the
 * block is incomplete.
 *
 * @type {import('./types').StratiumScope}
 */
const DEFAULT_SCOPE = {
  enabled:           false,
  agent_name:        'claude-code',
  max_action_tier:   1,          // READ_ONLY
  approved_tools:    [],         // empty = all tools at or below tier allowed
  classification_caps: {},
  on_unavailable:    'fail_closed',
  purpose:           '',
  tool_tiers:        {},         // per-tool tier overrides (also covers mcp__ tools)
  mcp_tools:         {},         // per-MCP-server tier config: { server: { default_tier, tools: { tool: tier } } }
};

/**
 * Walk up the directory tree from `startDir` to find the first CLAUDE.md.
 *
 * @param {string} startDir
 * @returns {string|null} Absolute path to CLAUDE.md, or null if not found.
 */
function findClaudeMd(startDir) {
  let dir = path.resolve(startDir);
  const root = path.parse(dir).root;

  while (true) {
    const candidate = path.join(dir, 'CLAUDE.md');
    if (fs.existsSync(candidate)) return candidate;
    const parent = path.dirname(dir);
    if (parent === dir || dir === root) return null;
    dir = parent;
  }
}

/**
 * Parse a simple YAML value token into a JS primitive.
 * Handles: quoted strings, unquoted strings, booleans, integers.
 *
 * @param {string} raw - Trimmed value string.
 * @returns {string|boolean|number}
 */
function parseValue(raw) {
  if (raw === 'true')  return true;
  if (raw === 'false') return false;
  if (/^-?\d+$/.test(raw)) return parseInt(raw, 10);
  // Strip optional surrounding quotes
  if ((raw.startsWith('"') && raw.endsWith('"')) ||
      (raw.startsWith("'") && raw.endsWith("'"))) {
    return raw.slice(1, -1);
  }
  return raw;
}

/**
 * Extract the `stratium:` YAML block from CLAUDE.md content.
 *
 * The block is detected by finding a line that is exactly `stratium:` (possibly
 * inside or after a markdown heading section).  Everything that follows with
 * greater indentation is treated as the YAML subtree until a line with equal
 * or lesser indentation is encountered.
 *
 * Supports:
 *   - Scalar keys:           key: value
 *   - Boolean/int values:    key: true / key: 42
 *   - Lists:                 - item
 *   - One level of nesting:  nested_key:\n    sub_key: value
 *   - tool_tiers block:      tool_tiers:\n    Bash: INTERNAL_MODIFY
 *
 * @param {string} content - Full CLAUDE.md text.
 * @returns {object|null} Raw parsed object, or null if no stratium: block found.
 */
function extractStratiumBlock(content) {
  const lines = content.split('\n');

  // Find the line index where `stratium:` begins (anchored to start of line).
  let startIdx = -1;
  for (let i = 0; i < lines.length; i++) {
    if (/^stratium:\s*$/.test(lines[i])) {
      startIdx = i;
      break;
    }
  }
  if (startIdx === -1) return null;

  const result = {};
  let currentKey       = null;   // key under `stratium:` (indent 2)
  let currentNested    = null;   // sub-object at indent 4 level
  let currentServerKey = null;   // last key set at indent 4 (e.g. 'context7')
  let currentLevel3Key = null;   // last empty-value key at indent 6 (e.g. 'tools')
  let isList           = false;  // whether currentKey is collecting a list

  for (let i = startIdx + 1; i < lines.length; i++) {
    const line = lines[i];

    // Blank lines within the block are allowed
    if (line.trim() === '' || line.trim().startsWith('#')) continue;

    // Indentation detection
    const indentMatch = line.match(/^(\s+)/);
    if (!indentMatch) {
      // Back to column 0 — end of block (or another top-level key)
      break;
    }

    const indent  = indentMatch[1].length;
    const trimmed = line.trim();

    if (indent === 2) {
      // Top-level key under `stratium:` (indent = 2)
      isList           = false;
      currentNested    = null;
      currentServerKey = null;
      currentLevel3Key = null;

      const kvMatch = trimmed.match(/^([\w_]+):\s*(.*)$/);
      if (kvMatch) {
        currentKey = kvMatch[1];
        const val  = kvMatch[2].trim();
        if (val === '') {
          // Value will be on the next lines (nested object or list)
          result[currentKey] = undefined;
        } else {
          result[currentKey] = parseValue(val);
        }
      }
    } else if (indent === 4) {
      // Nested content under the current key
      currentLevel3Key = null; // reset depth-3 tracking on every new indent-4 entry
      if (trimmed.startsWith('- ')) {
        // List item
        const itemVal = trimmed.slice(2).trim();
        if (!Array.isArray(result[currentKey])) result[currentKey] = [];
        result[currentKey].push(parseValue(itemVal));
        isList = true;
      } else {
        // Sub-key (nested object like classification_caps, tool_tiers, mcp_tools)
        const kvMatch = trimmed.match(/^([\w_-]+):\s*(.*)$/);
        if (kvMatch) {
          if (!currentNested) {
            currentNested = {};
            result[currentKey] = currentNested;
          }
          const subVal = kvMatch[2].trim();
          // If value is empty, this is a sub-object header (e.g. a server name under mcp_tools:)
          currentNested[kvMatch[1]] = subVal === '' ? {} : parseValue(subVal);
          currentServerKey = kvMatch[1];
          isList = false;
        }
      }
    } else if (indent === 6) {
      // Triple-nested (e.g. mcp_tools → server_name → property or sub-object header)
      if (currentNested && currentServerKey && typeof currentNested[currentServerKey] === 'object') {
        const kvMatch = trimmed.match(/^([\w_-]+):\s*(.*)$/);
        if (kvMatch) {
          const subVal = kvMatch[2].trim();
          if (subVal === '') {
            // Empty value — this key will have its own children at indent 8 (e.g. tools:)
            currentNested[currentServerKey][kvMatch[1]] = {};
            currentLevel3Key = kvMatch[1];
          } else {
            currentNested[currentServerKey][kvMatch[1]] = parseValue(subVal);
            currentLevel3Key = null;
          }
        }
      }
    } else if (indent === 8) {
      // Quad-nested (e.g. mcp_tools → server → tools → tool_name: tier)
      if (currentNested && currentServerKey && currentLevel3Key) {
        const target = currentNested[currentServerKey][currentLevel3Key];
        if (target && typeof target === 'object') {
          const kvMatch = trimmed.match(/^([\w_-]+):\s*(.*)$/);
          if (kvMatch) {
            target[kvMatch[1]] = parseValue(kvMatch[2].trim());
          }
        }
      }
    }
    // Indent > 8 — ignore; not in our schema.
  }

  return result;
}

/**
 * Map a max_action_tier string or number to a numeric tier value.
 *
 * @param {string|number} value
 * @returns {number}
 */
function normalizeTier(value) {
  if (typeof value === 'number') return Math.min(Math.max(value, 0), 4);
  if (typeof value === 'string') {
    const upper = value.toUpperCase();
    if (upper in TIER_NAMES) return TIER_NAMES[upper];
    const num = parseInt(value, 10);
    if (!isNaN(num)) return Math.min(Math.max(num, 0), 4);
  }
  return DEFAULT_SCOPE.max_action_tier;
}

/**
 * Normalize a raw parsed stratium block into a typed StratiumScope object.
 *
 * @param {object} raw - Output from extractStratiumBlock().
 * @param {string} repoName - Repository name for template substitution.
 * @returns {import('./types').StratiumScope}
 */
function normalizeScope(raw, repoName) {
  const scope = Object.assign({}, DEFAULT_SCOPE);

  if (raw.enabled !== undefined)       scope.enabled          = !!raw.enabled;
  if (raw.agent_name)                  scope.agent_name       = String(raw.agent_name);
  if (raw.max_action_tier !== undefined) scope.max_action_tier = normalizeTier(raw.max_action_tier);
  if (Array.isArray(raw.approved_tools)) scope.approved_tools = raw.approved_tools.map(String);
  if (raw.classification_caps && typeof raw.classification_caps === 'object') {
    scope.classification_caps = raw.classification_caps;
  }
  if (raw.on_unavailable) {
    scope.on_unavailable = raw.on_unavailable === 'fail_open' ? 'fail_open' : 'fail_closed';
  }
  if (raw.purpose) {
    scope.purpose = String(raw.purpose).replace(/\{\{repo_name\}\}/g, repoName || '');
  }

  // Normalize tool_tiers overrides
  if (raw.tool_tiers && typeof raw.tool_tiers === 'object') {
    const tierOverrides = {};
    for (const [toolName, tierValue] of Object.entries(raw.tool_tiers)) {
      const numeric = normalizeTier(tierValue);
      tierOverrides[toolName] = {
        tier:   numeric,
        action: 'call',
        label:  Object.keys(TIER_NAMES).find(k => TIER_NAMES[k] === numeric) || 'INTERNAL_MODIFY',
      };
    }
    scope.tool_tiers = tierOverrides;
  }

  // Normalize mcp_tools: per-server MCP tier configuration
  // Schema:
  //   mcp_tools:
  //     context7:           # MCP server name
  //       default_tier: READ_ONLY
  //       tools:
  //         resolve-library-id: READ_ONLY
  //         query-docs: READ_ONLY
  if (raw.mcp_tools && typeof raw.mcp_tools === 'object') {
    const mcpConfig = {};
    for (const [serverName, serverConfig] of Object.entries(raw.mcp_tools)) {
      if (typeof serverConfig !== 'object' || serverConfig === null) continue;

      const defaultTier = serverConfig.default_tier !== undefined
        ? normalizeTier(serverConfig.default_tier)
        : 2; // default: INTERNAL_MODIFY

      const toolOverrides = {};
      if (serverConfig.tools && typeof serverConfig.tools === 'object') {
        for (const [toolName, tierValue] of Object.entries(serverConfig.tools)) {
          const numeric = normalizeTier(tierValue);
          toolOverrides[toolName] = {
            tier:   numeric,
            action: 'call',
            label:  Object.keys(TIER_NAMES).find(k => TIER_NAMES[k] === numeric) || 'INTERNAL_MODIFY',
          };
        }
      }

      mcpConfig[serverName] = { default_tier: defaultTier, tools: toolOverrides };

      // Also inject into tool_tiers as mcp__<server>__<tool> entries
      // so getTier() picks them up transparently
      for (const [toolName, entry] of Object.entries(toolOverrides)) {
        scope.tool_tiers[`mcp__${serverName}__${toolName}`] = entry;
        scope.tool_tiers[`mcp_${serverName}_${toolName}`]   = entry;
      }
    }
    scope.mcp_tools = mcpConfig;
  }

  return scope;
}

/**
 * Load and parse the stratium: scope from the project's CLAUDE.md.
 *
 * Uses an in-memory mtime cache so the file is only re-parsed when it changes.
 *
 * @param {string} projectDir - Starting directory (usually CLAUDE_PROJECT_DIR).
 * @returns {{ scope: import('./types').StratiumScope, claudeMdPath: string|null }}
 */
function loadScope(projectDir) {
  const claudeMdPath = findClaudeMd(projectDir || process.cwd());

  if (!claudeMdPath) {
    return { scope: Object.assign({}, DEFAULT_SCOPE), claudeMdPath: null };
  }

  // Check cache
  const stat = fs.statSync(claudeMdPath);
  const mtime = stat.mtimeMs;
  const cached = _cache.get(claudeMdPath);
  if (cached && cached.mtime === mtime) {
    return { scope: cached.scope, claudeMdPath };
  }

  const content  = fs.readFileSync(claudeMdPath, 'utf8');
  const raw      = extractStratiumBlock(content);
  const repoName = path.basename(path.dirname(claudeMdPath));
  const scope    = raw ? normalizeScope(raw, repoName) : Object.assign({}, DEFAULT_SCOPE);

  _cache.set(claudeMdPath, { mtime, scope });

  return { scope, claudeMdPath };
}

/** Clear the parse cache (useful in tests). */
function clearCache() {
  _cache.clear();
}

module.exports = { loadScope, findClaudeMd, extractStratiumBlock, normalizeScope, clearCache, DEFAULT_SCOPE, TIER_NAMES };
