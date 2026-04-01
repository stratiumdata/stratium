/**
 * tier-map.test.js
 *
 * Tests for getTier() and classifyBash() using Node.js built-in test runner.
 * Run with: node --test test/tier-map.test.js
 */

'use strict';

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const { getTier, classifyBash, DEFAULT_TIER_MAP, TIER_LABEL } = require('../src/tier-map');

// ── classifyBash ──────────────────────────────────────────────────────────────

describe('classifyBash', () => {
  test('cat command → READ_ONLY (tier 1)', () => {
    const r = classifyBash('cat /etc/hosts');
    assert.equal(r.tier, 1);
    assert.equal(r.label, 'READ_ONLY');
  });

  test('git log → READ_ONLY (tier 1)', () => {
    const r = classifyBash('git log --oneline -10');
    assert.equal(r.tier, 1);
  });

  test('git status → READ_ONLY (tier 1)', () => {
    const r = classifyBash('git status');
    assert.equal(r.tier, 1);
  });

  test('echo → READ_ONLY (tier 1)', () => {
    const r = classifyBash('echo hello world');
    assert.equal(r.tier, 1);
  });

  test('npm list → READ_ONLY (tier 1)', () => {
    const r = classifyBash('npm list --depth=0');
    assert.equal(r.tier, 1);
  });

  test('curl → EXTERNAL_COMMS (tier 3)', () => {
    const r = classifyBash('curl -s https://api.example.com/data');
    assert.equal(r.tier, 3);
    assert.equal(r.label, 'EXTERNAL_COMMS');
  });

  test('git push → EXTERNAL_COMMS (tier 3)', () => {
    const r = classifyBash('git push origin main');
    assert.equal(r.tier, 3);
  });

  test('npm publish → EXTERNAL_COMMS (tier 3)', () => {
    const r = classifyBash('npm publish --access public');
    assert.equal(r.tier, 3);
  });

  test('kubectl apply → EXTERNAL_COMMS (tier 3)', () => {
    const r = classifyBash('kubectl apply -f deployment.yaml');
    assert.equal(r.tier, 3);
  });

  test('rm -rf → DESTRUCTIVE (tier 4)', () => {
    const r = classifyBash('rm -rf /tmp/old-data');
    assert.equal(r.tier, 4);
    assert.equal(r.label, 'DESTRUCTIVE');
  });

  test('rm -r → DESTRUCTIVE (tier 4)', () => {
    const r = classifyBash('rm -r ./dist');
    assert.equal(r.tier, 4);
  });

  test('DROP TABLE → DESTRUCTIVE (tier 4)', () => {
    const r = classifyBash('psql -c "DROP TABLE users"');
    assert.equal(r.tier, 4);
  });

  test('make build → INTERNAL_MODIFY (tier 2, default)', () => {
    const r = classifyBash('make build');
    assert.equal(r.tier, 2);
    assert.equal(r.label, 'INTERNAL_MODIFY');
  });

  test('go test → INTERNAL_MODIFY (tier 2, default)', () => {
    const r = classifyBash('go test ./...');
    assert.equal(r.tier, 2);
  });

  test('empty string → INTERNAL_MODIFY (tier 2)', () => {
    const r = classifyBash('');
    assert.equal(r.tier, 2);
  });

  test('null/undefined → INTERNAL_MODIFY (tier 2)', () => {
    assert.equal(classifyBash(null).tier, 2);
    assert.equal(classifyBash(undefined).tier, 2);
  });

  test('destructive checked before external (rm -rf with curl in path)', () => {
    // If a command is both destructive and has external patterns, destructive wins
    const r = classifyBash('rm -rf /tmp/download && curl http://example.com');
    assert.equal(r.tier, 4);
  });
});

// ── getTier ───────────────────────────────────────────────────────────────────

describe('getTier', () => {
  test('Read → tier 1', () => {
    assert.equal(getTier('Read', {}).tier, 1);
  });

  test('Write → tier 2', () => {
    assert.equal(getTier('Write', {}).tier, 2);
  });

  test('Edit → tier 2', () => {
    assert.equal(getTier('Edit', {}).tier, 2);
  });

  test('Glob → tier 1', () => {
    assert.equal(getTier('Glob', {}).tier, 1);
  });

  test('Grep → tier 1', () => {
    assert.equal(getTier('Grep', {}).tier, 1);
  });

  test('WebFetch → tier 1', () => {
    assert.equal(getTier('WebFetch', {}).tier, 1);
  });

  test('Agent → tier 2', () => {
    assert.equal(getTier('Agent', {}).tier, 2);
  });

  test('TodoWrite → tier 1', () => {
    assert.equal(getTier('TodoWrite', {}).tier, 1);
  });

  test('Bash with read command → tier 1', () => {
    const r = getTier('Bash', { command: 'cat README.md' });
    assert.equal(r.tier, 1);
  });

  test('Bash with git push → tier 3', () => {
    const r = getTier('Bash', { command: 'git push origin main' });
    assert.equal(r.tier, 3);
  });

  test('bash (lowercase) works too', () => {
    const r = getTier('bash', { command: 'cat file.txt' });
    assert.equal(r.tier, 1);
  });

  test('mcp__ prefix → tier 2 default', () => {
    const r = getTier('mcp__some_server__some_tool', {});
    assert.equal(r.tier, 2);
    assert.equal(r.label, 'INTERNAL_MODIFY');
  });

  test('mcp_ prefix → tier 2 default', () => {
    const r = getTier('mcp_context7_query', {});
    assert.equal(r.tier, 2);
  });

  test('unknown tool → tier 2 default', () => {
    const r = getTier('SomeUnknownTool', {});
    assert.equal(r.tier, 2);
  });

  test('project override takes precedence over default', () => {
    const overrides = { Write: { tier: 1, action: 'read', label: 'READ_ONLY' } };
    const r = getTier('Write', {}, overrides);
    assert.equal(r.tier, 1);
    assert.equal(r.label, 'READ_ONLY');
  });

  test('project override for Bash takes precedence over classifyBash', () => {
    const overrides = { Bash: { tier: 4, action: 'execute', label: 'DESTRUCTIVE' } };
    const r = getTier('Bash', { command: 'cat file.txt' }, overrides);
    // Override returns tier 4 regardless of command classification
    assert.equal(r.tier, 4);
  });

  test('Bash with cmd field (alternative key)', () => {
    const r = getTier('Bash', { cmd: 'cat /etc/hosts' });
    assert.equal(r.tier, 1);
  });
});

// ── TIER_LABEL ────────────────────────────────────────────────────────────────

describe('TIER_LABEL', () => {
  test('all tiers have labels', () => {
    assert.equal(TIER_LABEL[0], 'REASONING');
    assert.equal(TIER_LABEL[1], 'READ_ONLY');
    assert.equal(TIER_LABEL[2], 'INTERNAL_MODIFY');
    assert.equal(TIER_LABEL[3], 'EXTERNAL_COMMS');
    assert.equal(TIER_LABEL[4], 'DESTRUCTIVE');
  });
});

// ── DEFAULT_TIER_MAP completeness ─────────────────────────────────────────────

describe('DEFAULT_TIER_MAP', () => {
  test('all entries have tier, action, label fields', () => {
    for (const [toolName, entry] of Object.entries(DEFAULT_TIER_MAP)) {
      assert.ok(typeof entry.tier   === 'number', `${toolName}: tier must be a number`);
      assert.ok(typeof entry.action === 'string', `${toolName}: action must be a string`);
      assert.ok(typeof entry.label  === 'string', `${toolName}: label must be a string`);
      assert.ok(entry.tier >= 0 && entry.tier <= 4, `${toolName}: tier must be 0-4`);
    }
  });

  test('no write tools classified as READ_ONLY', () => {
    const writeTiers = ['Write', 'Edit', 'NotebookEdit'];
    for (const t of writeTiers) {
      assert.ok(DEFAULT_TIER_MAP[t].tier >= 2, `${t} should be tier 2+`);
    }
  });
});
