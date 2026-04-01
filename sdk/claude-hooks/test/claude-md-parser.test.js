/**
 * claude-md-parser.test.js
 *
 * Tests for extractStratiumBlock(), normalizeScope(), and loadScope().
 * Run with: node --test test/claude-md-parser.test.js
 */

'use strict';

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('fs');
const path   = require('path');
const os     = require('os');

const {
  extractStratiumBlock,
  normalizeScope,
  loadScope,
  clearCache,
  DEFAULT_SCOPE,
  TIER_NAMES,
} = require('../src/claude-md-parser');

// ── extractStratiumBlock ──────────────────────────────────────────────────────

describe('extractStratiumBlock', () => {
  test('returns null if no stratium: block found', () => {
    const content = `# CLAUDE.md\n\nSome content without stratium.\n`;
    assert.equal(extractStratiumBlock(content), null);
  });

  test('parses basic scalar fields', () => {
    const content = `
# CLAUDE.md

stratium:
  enabled: true
  agent_name: claude-code
  max_action_tier: READ_ONLY
  on_unavailable: fail_closed
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.enabled, true);
    assert.equal(result.agent_name, 'claude-code');
    assert.equal(result.max_action_tier, 'READ_ONLY');
    assert.equal(result.on_unavailable, 'fail_closed');
  });

  test('parses approved_tools list', () => {
    const content = `
stratium:
  enabled: true
  approved_tools:
    - read_file
    - list_files
    - grep_search
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.deepEqual(result.approved_tools, ['read_file', 'list_files', 'grep_search']);
  });

  test('parses classification_caps as nested object', () => {
    const content = `
stratium:
  enabled: true
  classification_caps:
    nato: CONFIDENTIAL
    commercial: RESTRICTED
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.classification_caps.nato, 'CONFIDENTIAL');
    assert.equal(result.classification_caps.commercial, 'RESTRICTED');
  });

  test('parses tool_tiers overrides', () => {
    const content = `
stratium:
  enabled: true
  tool_tiers:
    Bash: INTERNAL_MODIFY
    WebFetch: EXTERNAL_COMMS
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.tool_tiers.Bash, 'INTERNAL_MODIFY');
    assert.equal(result.tool_tiers.WebFetch, 'EXTERNAL_COMMS');
  });

  test('stops at next top-level key after stratium block', () => {
    const content = `
stratium:
  enabled: true
  agent_name: my-agent

other_config:
  key: value
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.enabled, true);
    assert.equal(result.agent_name, 'my-agent');
    // Should not include other_config
    assert.equal(result.other_config, undefined);
  });

  test('handles enabled: false', () => {
    const content = `
stratium:
  enabled: false
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.enabled, false);
  });

  test('handles quoted string values', () => {
    const content = `
stratium:
  purpose: "Development work on my-project"
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.purpose, 'Development work on my-project');
  });

  test('ignores comment lines inside block', () => {
    const content = `
stratium:
  # This is a comment
  enabled: true
`;
    const result = extractStratiumBlock(content);
    assert.ok(result);
    assert.equal(result.enabled, true);
  });
});

// ── normalizeScope ────────────────────────────────────────────────────────────

describe('normalizeScope', () => {
  test('converts READ_ONLY string to numeric tier 1', () => {
    const scope = normalizeScope({ enabled: true, max_action_tier: 'READ_ONLY' }, 'my-repo');
    assert.equal(scope.max_action_tier, 1);
  });

  test('converts INTERNAL_MODIFY string to numeric tier 2', () => {
    const scope = normalizeScope({ max_action_tier: 'INTERNAL_MODIFY' }, 'repo');
    assert.equal(scope.max_action_tier, 2);
  });

  test('converts EXTERNAL_COMMS string to numeric tier 3', () => {
    const scope = normalizeScope({ max_action_tier: 'EXTERNAL_COMMS' }, 'repo');
    assert.equal(scope.max_action_tier, 3);
  });

  test('converts DESTRUCTIVE string to numeric tier 4', () => {
    const scope = normalizeScope({ max_action_tier: 'DESTRUCTIVE' }, 'repo');
    assert.equal(scope.max_action_tier, 4);
  });

  test('accepts numeric tier directly', () => {
    const scope = normalizeScope({ max_action_tier: 2 }, 'repo');
    assert.equal(scope.max_action_tier, 2);
  });

  test('fills defaults for missing fields', () => {
    const scope = normalizeScope({}, 'repo');
    assert.equal(scope.agent_name, DEFAULT_SCOPE.agent_name);
    assert.equal(scope.on_unavailable, DEFAULT_SCOPE.on_unavailable);
    assert.deepEqual(scope.approved_tools, []);
  });

  test('substitutes {{repo_name}} in purpose', () => {
    const scope = normalizeScope({ purpose: 'Work on {{repo_name}}' }, 'my-repo');
    assert.equal(scope.purpose, 'Work on my-repo');
  });

  test('normalizes on_unavailable to fail_closed for unknown values', () => {
    const scope = normalizeScope({ on_unavailable: 'something_else' }, 'repo');
    assert.equal(scope.on_unavailable, 'fail_closed');
  });

  test('normalizes on_unavailable: fail_open correctly', () => {
    const scope = normalizeScope({ on_unavailable: 'fail_open' }, 'repo');
    assert.equal(scope.on_unavailable, 'fail_open');
  });

  test('clamps tier to 0-4 range', () => {
    const scope1 = normalizeScope({ max_action_tier: -1 }, 'repo');
    assert.equal(scope1.max_action_tier, 0);

    const scope2 = normalizeScope({ max_action_tier: 99 }, 'repo');
    assert.equal(scope2.max_action_tier, 4);
  });

  test('approved_tools preserved from raw block', () => {
    const scope = normalizeScope({ approved_tools: ['read_file', 'Write'] }, 'repo');
    assert.deepEqual(scope.approved_tools, ['read_file', 'Write']);
  });
});

// ── loadScope ─────────────────────────────────────────────────────────────────

describe('loadScope', () => {
  let tmpDir;

  beforeEach(() => {
    clearCache();
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stratium-test-'));
  });

  test('returns default scope when no CLAUDE.md found', () => {
    const { scope, claudeMdPath } = loadScope(tmpDir);
    assert.equal(claudeMdPath, null);
    assert.equal(scope.enabled, false);
    assert.equal(scope.max_action_tier, 1);
  });

  test('finds CLAUDE.md in current directory', () => {
    const claudeMd = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(claudeMd, `
stratium:
  enabled: true
  max_action_tier: INTERNAL_MODIFY
  agent_name: test-agent
`);
    const { scope, claudeMdPath } = loadScope(tmpDir);
    assert.equal(claudeMdPath, claudeMd);
    assert.equal(scope.enabled, true);
    assert.equal(scope.max_action_tier, 2);
    assert.equal(scope.agent_name, 'test-agent');
  });

  test('finds CLAUDE.md in parent directory', () => {
    const subDir  = path.join(tmpDir, 'sub', 'dir');
    fs.mkdirSync(subDir, { recursive: true });
    const claudeMd = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(claudeMd, `
stratium:
  enabled: true
  max_action_tier: READ_ONLY
`);
    const { scope, claudeMdPath } = loadScope(subDir);
    assert.equal(claudeMdPath, claudeMd);
    assert.equal(scope.max_action_tier, 1);
  });

  test('caches result on second call (same mtime)', () => {
    const claudeMd = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(claudeMd, `
stratium:
  enabled: true
  max_action_tier: READ_ONLY
`);
    const result1 = loadScope(tmpDir);
    const result2 = loadScope(tmpDir);
    // Same scope object reference from cache
    assert.strictEqual(result1.scope, result2.scope);
  });

  test('re-parses when file is modified (mtime changes)', () => {
    const claudeMd = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(claudeMd, `
stratium:
  enabled: true
  max_action_tier: READ_ONLY
`);
    const result1 = loadScope(tmpDir);
    assert.equal(result1.scope.max_action_tier, 1);

    // Modify file (force mtime update)
    fs.utimesSync(claudeMd, new Date(), new Date(Date.now() + 1000));
    fs.writeFileSync(claudeMd, `
stratium:
  enabled: true
  max_action_tier: INTERNAL_MODIFY
`);

    const result2 = loadScope(tmpDir);
    assert.equal(result2.scope.max_action_tier, 2);
  });

  test('returns default scope when CLAUDE.md has no stratium: block', () => {
    const claudeMd = path.join(tmpDir, 'CLAUDE.md');
    fs.writeFileSync(claudeMd, `
# Project Notes

No stratium configuration here.
`);
    const { scope } = loadScope(tmpDir);
    // Default scope values
    assert.equal(scope.enabled, false);
    assert.equal(scope.max_action_tier, DEFAULT_SCOPE.max_action_tier);
  });
});

// ── TIER_NAMES consistency ────────────────────────────────────────────────────

describe('TIER_NAMES', () => {
  test('has all five tiers', () => {
    assert.equal(TIER_NAMES.REASONING, 0);
    assert.equal(TIER_NAMES.READ_ONLY, 1);
    assert.equal(TIER_NAMES.INTERNAL_MODIFY, 2);
    assert.equal(TIER_NAMES.EXTERNAL_COMMS, 3);
    assert.equal(TIER_NAMES.DESTRUCTIVE, 4);
  });
});
