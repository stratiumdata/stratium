# Testing Guide: @stratium/claude-hooks

> **Automated test script available:** `scripts/test_claude_hooks.sh` mirrors this guide end-to-end.
> Run it instead of stepping through sections manually:
>
> ```bash
> # From the project root (stratium/)
> ./scripts/test_claude_hooks.sh           # run all sections
> ./scripts/test_claude_hooks.sh 1         # unit tests only (no Stratium needed)
> ./scripts/test_claude_hooks.sh 2         # CLI smoke tests
> ./scripts/test_claude_hooks.sh 3         # pre-tool-use mock session tests (no Stratium needed)
> ./scripts/test_claude_hooks.sh 4         # integration tests (Stratium stack required)
> ./scripts/test_claude_hooks.sh 5         # subagent delegation chain (Stratium stack required)
> ./scripts/test_claude_hooks.sh clean     # remove temp files
> ```
>
> Sections 1–3 run without the Stratium stack. Sections 4–5 require the full stack including
> Keycloak (`docker compose --profile agent-auth up -d`). State (tokens, agent IDs) is saved
> to `/tmp/stratium-hooks-test.env` so sections can be re-run independently after a full run.

This guide covers all testing levels for the `sdk/claude-hooks` package.

| Level | Requires | Covers |
|-------|----------|--------|
| 1 | Nothing | Unit tests — pure logic (tier-map, CLAUDE.md parser) |
| 2 | `npm install -g .` | CLI smoke tests — Phase 1 features |
| 2b | Node.js only | Phase 2/3 feature tests (keychain, classification, MCP, webhooks, etc.) |
| 2c | bash/pwsh only | MDM deployment script validation |
| 3 | Stratium running | Integration tests — full gRPC round-trip |
| 4 | Stratium running | Subagent delegation chain — ALLOW and DENY |
| 5 | Stratium + Claude Code | E2E — real Claude Code session |
| 6 | npm | Publishing dry-run and workflow verification |

---

## Level 1: Unit Tests (no Stratium needed)

The built-in test suite covers `tier-map.js` and `claude-md-parser.js` — the
pure-logic layer that has no external dependencies.

**Prerequisites:** Node.js installed. First-time setup:
```bash
cd /path/to/stratium/sdk/claude-hooks   # e.g. ~/Development/stratium/sdk/claude-hooks
npm install
```

```bash
cd /path/to/stratium/sdk/claude-hooks

# Run all tests (via npm script)
npm test

# Run with coverage report
npm run test:coverage

# Run individual suites
node --test test/tier-map.test.js
node --test test/claude-md-parser.test.js
```

Expected output: `64 pass, 0 fail`.

---

## Level 2: CLI Smoke Tests (no Stratium needed)

These verify the CLI, CLAUDE.md parser, and tier map work correctly in isolation.

> **All `node src/...` commands in Level 2 and 2b must run from `sdk/claude-hooks/`.**
> Open a terminal and run: `cd /path/to/stratium/sdk/claude-hooks`
> If you have not installed dependencies yet, also run `npm install`.

### 2.1 Install the package locally

```bash
cd /path/to/stratium/sdk/claude-hooks
npm install        # install dependencies (first time only)
npm install -g .   # install stratium-hooks CLI globally
```

Verify:
```bash
stratium-hooks version
# → @stratium/claude-hooks 1.0.0

stratium-hooks help
```

### 2.2 Test the `scope` command

Create a test CLAUDE.md with a `stratium:` block:

```bash
mkdir -p /tmp/stratium-test-project
cat > /tmp/stratium-test-project/CLAUDE.md << 'EOF'
# Test Project

stratium:
  enabled: true
  agent_name: claude-code
  max_action_tier: READ_ONLY
  approved_tools:
    - Read
    - Glob
    - Grep
  on_unavailable: fail_closed
  purpose: "Testing hooks locally"
EOF

CLAUDE_PROJECT_DIR=/tmp/stratium-test-project stratium-hooks scope
```

Expected:
```
── Stratium Scope ────────────────────────────────────────
  CLAUDE.md:    /tmp/stratium-test-project/CLAUDE.md
  enabled:      true
  agent_name:   claude-code
  max_tier:     1 (READ_ONLY)
  approved:     Read, Glob, Grep
  on_unavail:   fail_closed
  purpose:      Testing hooks locally
─────────────────────────────────────────────────────────
```

### 2.3 Test tier classification directly

```bash
# From sdk/claude-hooks/
node -e "
const { getTier, classifyBash } = require('./src/tier-map');

// Tool tiers
console.log('Read:', getTier('Read', {}).tier);         // → 1
console.log('Write:', getTier('Write', {}).tier);       // → 2
console.log('Agent:', getTier('Agent', {}).tier);       // → 2

// Bash classification
console.log('cat:', classifyBash('cat file.txt').tier); // → 1
console.log('curl:', classifyBash('curl http://x').tier); // → 3
console.log('rm -rf:', classifyBash('rm -rf /tmp').tier); // → 4
"
```

### 2.4 Test pre-tool-use with no session (fail_closed)

> **Note:** This test has two sub-cases depending on whether `~/.claude/stratium.json` exists.
> If you have already run `stratium-hooks configure`, skip to sub-case B.

**Sub-case A — no machine config (fresh install):**

```bash
# From sdk/claude-hooks/
# Clear any session file override left over from previous tests
unset STRATIUM_SESSION_FILE

# Check which sub-case applies and run accordingly
if test ! -f ~/.claude/stratium.json; then
  echo "No machine config — running passthrough test"
  echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"test.go"}}' \
    | node src/pre-tool-use.js
  echo "Exit code: $?"   # → 0 (silent passthrough)
else
  echo "Machine config exists — skip to sub-case B below"
fi
```

Expected (sub-case A): exit code 0 with no output — the hook is a no-op when Stratium is not configured.

**Sub-case B — machine config exists (already configured):**

If `~/.claude/stratium.json` exists, a missing session file means fail_closed blocks immediately:

```bash
# Clear any session file override from previous tests
unset STRATIUM_SESSION_FILE

echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"test.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 2 (session not initialized)
```

Expected: exit code 2 with `"permissionDecision":"deny"` and a message about session not initialized. This is correct — the hook is working.

**Creating a machine config (to test sub-case B from scratch):**

```bash
mkdir -p ~/.claude
cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "master",
  "client_id": "claude-code",
  "plaintext": true,
  "default_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "on_unavailable": "fail_closed"
  }
}
EOF

# Same call — now blocked because machine config exists but no session
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"test.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"
```

Expected: exit code 2 with a JSON deny reason on stdout.

### 2.5 Test pre-tool-use with a mock session (tier cap)

> **Important:** `pre-tool-use.js` reads `/tmp/stratium-session-<node-pid>.json` using
> Node's `process.pid`, which differs from the shell's `$$`. Use the
> `STRATIUM_SESSION_FILE` env var to point the hook at your test file.

Write a session file that limits to READ_ONLY (tier 1):

```bash
# From sdk/claude-hooks/
export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json

cat > "$STRATIUM_SESSION_FILE" << 'EOF'
{
  "agent_id": "test-agent-123",
  "delegation_id": "test-delegation-456",
  "delegation_token": "mock-token",
  "expires_at": "2099-01-01T00:00:00Z",
  "user": "testuser@corp.com",
  "on_unavailable": "fail_closed",
  "gateway": "localhost:50054",
  "plaintext": true,
  "project_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "tool_tiers": {},
    "classification_caps": {}
  }
}
EOF

# Write tool (tier 2) should be blocked locally (no gateway call needed)
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"test.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"
```

Expected output on stdout:
```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Stratium DENY: Write requires INTERNAL_MODIFY (tier 2) but your project delegation is capped at READ_ONLY (tier 1)..."
  }
}
```

```bash
# Read tool (tier 1) — passes tier cap, then attempts gateway (will fail since gateway isn't running)
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":"src/main.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"
```

Expected: exit code 2 (gateway unreachable → fail_closed).

To test fail_open instead:

```bash
# Patch the session file (STRATIUM_SESSION_FILE still set from above)
sed -i '' 's/fail_closed/fail_open/' "$STRATIUM_SESSION_FILE"

echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":"src/main.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"
# → exit 0 (passes through when gateway unreachable + fail_open)
```

### 2.6 Test approved_tools enforcement

```bash
# From sdk/claude-hooks/
export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json

cat > "$STRATIUM_SESSION_FILE" << 'EOF'
{
  "agent_id": "test-agent",
  "delegation_id": "test-delegation",
  "delegation_token": "mock-token",
  "expires_at": "2099-01-01T00:00:00Z",
  "user": "testuser@corp.com",
  "on_unavailable": "fail_open",
  "gateway": "localhost:50054",
  "plaintext": true,
  "project_scope": {
    "max_action_tier": 2,
    "approved_tools": ["Read", "Glob"],
    "tool_tiers": {}
  }
}
EOF

# Read → ALLOW (in approved_tools + fail_open skips gateway)
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 0

# Write → DENY (not in approved_tools)
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 2
```

---

## Level 2b: Phase 2 & 3 Feature Tests (no Stratium needed)

These tests exercise the new Phase 2/3 features using only mock sessions and local Node.js.

> **All commands in Level 2b run from `sdk/claude-hooks/`.**
> Run `cd /path/to/stratium/sdk/claude-hooks` before starting. `npm install` must have been run.

### 2b.1 OS Keychain integration

Check whether keychain storage is available on your machine:

```bash
cd /path/to/stratium/sdk/claude-hooks
node -e "
const { keychainAvailable, keychainSet, keychainGet, keychainDelete } = require('./src/keychain');
console.log('keychain available:', keychainAvailable());

if (keychainAvailable()) {
  const ok = keychainSet('test-account', JSON.stringify({ value: 'hello' }));
  console.log('write ok:', ok);
  const val = keychainGet('test-account');
  console.log('read back:', val);
  keychainDelete('test-account');
  console.log('deleted (read after):', keychainGet('test-account'));
}
"
```

Expected on macOS with `security` installed:
```
keychain available: true
write ok: true
read back: {"value":"hello"}
deleted (read after): null
```

Expected on machines without keychain support:
```
keychain available: false
```

In both cases, `auth.js` falls back to `~/.claude/stratium-tokens.json` with mode `0600`.

### 2b.2 Scope validation (CLAUDE.md widening prevention)

The `scope-validator.js` module is integrated into `session-init.js`. To test it in isolation:

```bash
# From sdk/claude-hooks/
node -e "
const { validateScope } = require('./src/scope-validator');

// Mock restOpts that will fail (PAP unreachable)
const restOpts = { pap_url: 'http://localhost:1', token: 'mock' };

const result = validateScope(restOpts, 'agent-123', {
  max_action_tier: 3,
  approved_tools: ['Read', 'Write', 'Bash'],
});
console.log('valid:', result.valid);
console.log('violations:', result.violations);
console.log('effectiveScope:', result.effectiveScope);
"
```

Expected (PAP unreachable — graceful pass-through with warning):
```
valid: true
violations: ['[warn] Could not fetch agent policy from PAP: ...']
effectiveScope: { max_action_tier: 3, approved_tools: [...] }
```

The real enforcement happens at the `ExecuteAction` gRPC call — the scope validator is a pre-flight advisory, not a hard gate.

### 2b.3 Per-path classification detection

Test the glob-based classification matching built into `pre-tool-use.js`:

```bash
# From sdk/claude-hooks/
node -e "
// Access the unexported helpers via the module source
const src = require('fs').readFileSync('./src/pre-tool-use.js', 'utf8');

// Inline test of the logic (mirrors globToRegex in pre-tool-use.js)
const globToRegex = (p) => {
  const normalized = p.replace(/^\*\*\//, '');  // strip leading **/ (handled by anchor)
  const escaped = normalized
    .replace(/[.+^\${}()|[\]\\\\]/g, '\\\$&')
    .replace(/\*\*/g, '\x00GLOBSTAR\x00')
    .replace(/\*/g, '[^/]*')
    .replace(/\?/g, '[^/]')
    .replace(/\x00GLOBSTAR\x00/g, '.*');
  return new RegExp('(^|/)' + escaped + '\$', 'i');
};

const patterns = {
  '**/.env':     'CONFIDENTIAL',
  '**/secret*':  'TOP_SECRET',
  '**/public/**': 'PUBLIC',
};

const paths = [
  '.env',
  'config/.env',
  'src/secrets.go',
  'docs/secret-notes.md',
  'public/index.html',
  'src/main.go',
];

for (const filePath of paths) {
  let matched = null;
  for (const [pattern, label] of Object.entries(patterns)) {
    if (globToRegex(pattern).test(filePath)) { matched = label; break; }
  }
  console.log(filePath.padEnd(30), '->', matched || '(no classification)');
}
"
```

Expected:
```
.env                           -> CONFIDENTIAL
config/.env                    -> CONFIDENTIAL
src/secrets.go                 -> TOP_SECRET
docs/secret-notes.md           -> TOP_SECRET
public/index.html              -> PUBLIC
src/main.go                    -> (no classification)
```

To wire this into a live pre-tool-use test, add `classification_caps` to your mock session:

```bash
# From sdk/claude-hooks/
export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json

cat > "$STRATIUM_SESSION_FILE" << 'EOF'
{
  "agent_id": "test-agent",
  "delegation_id": "test-delegation",
  "delegation_token": "mock-token",
  "expires_at": "2099-01-01T00:00:00Z",
  "user": "testuser@corp.com",
  "on_unavailable": "fail_open",
  "gateway": "localhost:50054",
  "plaintext": true,
  "project_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "tool_tiers": {},
    "classification_caps": {
      "**/.env": "CONFIDENTIAL",
      "**/secret*": "TOP_SECRET"
    }
  }
}
EOF

# Read a normal file — passes tier check, hits gateway (fail_open → allow)
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":"src/main.go"}}' \
  | node src/pre-tool-use.js
echo "Exit: $?"   # → 0

# Read .env — classification=CONFIDENTIAL attribute sent to ExecuteAction
# (gateway will receive this attribute and can enforce classification policy)
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":".env"}}' \
  | node src/pre-tool-use.js
echo "Exit: $?"
```

### 2b.4 MCP tool tier configuration

Test that `mcp_tools:` CLAUDE.md blocks are parsed and injected into `tool_tiers`:

```bash
# From sdk/claude-hooks/
cat > /tmp/mcp-test-claude.md << 'EOF'
# MCP Test

stratium:
  enabled: true
  agent_name: claude-code
  max_action_tier: READ_ONLY
  mcp_tools:
    context7:
      default_tier: READ_ONLY
      tools:
        resolve-library-id: READ_ONLY
        query-docs: READ_ONLY
    filesystem:
      default_tier: INTERNAL_MODIFY
      tools:
        write_file: INTERNAL_MODIFY
        read_file: READ_ONLY
EOF

CLAUDE_PROJECT_DIR=/tmp node -e "
process.env.CLAUDE_PROJECT_DIR = '/tmp';
require('fs').writeFileSync('/tmp/CLAUDE.md', require('fs').readFileSync('/tmp/mcp-test-claude.md'));
const { loadScope } = require('./src/claude-md-parser');
const { scope } = loadScope('/tmp');
console.log('mcp_tools:', JSON.stringify(scope.mcp_tools, null, 2));
console.log('tool_tiers (mcp__ entries):');
for (const [k, v] of Object.entries(scope.tool_tiers)) {
  if (k.startsWith('mcp')) console.log('  ', k, '->', v.label);
}
"
```

Expected:
```json
mcp_tools: {
  "context7": { "default_tier": 1, "tools": { "resolve-library-id": ..., "query-docs": ... } },
  "filesystem": { "default_tier": 2, "tools": { "write_file": ..., "read_file": ... } }
}
tool_tiers (mcp__ entries):
   mcp__context7__resolve-library-id -> READ_ONLY
   mcp__context7__query-docs -> READ_ONLY
   mcp__filesystem__write_file -> INTERNAL_MODIFY
   mcp__filesystem__read_file -> READ_ONLY
```

Then verify these are enforced at the hook level:

```bash
# MCP tool call at tier 1 (READ_ONLY session)
echo '{"hook_event_name":"PreToolUse","tool_name":"mcp__context7__query-docs","tool_input":{}}' \
  | node src/pre-tool-use.js
echo "Exit: $?"   # → 0 (tier 1 = allowed)

# MCP write tool at tier 2 (should be blocked by session tier cap of 1)
echo '{"hook_event_name":"PreToolUse","tool_name":"mcp__filesystem__write_file","tool_input":{}}' \
  | node src/pre-tool-use.js
echo "Exit: $?"   # → 2 (tier 2 > session cap of 1)
```

### 2b.5 Break-glass override CLI

Test the override command (requires Stratium running for the gRPC call, but you can test validation alone):

```bash
# Missing --reason should exit 1 with usage message
stratium-hooks override
echo "Exit: $?"   # → 1
```

Expected:
```
Error: --reason <justification> is required for break-glass overrides.
Example: stratium-hooks override --reason "Production incident P1-1234 - need to patch auth.go"
Exit: 1
```

To test the full flow with Stratium running, perform the following quick setup first (skip if you already have the stack running and a valid session):

```bash
# 1. Start Stratium (from the project root)
docker-compose -f /path/to/stratium/deployment/docker/docker-compose.yml \
  --profile agent-auth up -d

# 2. Write the machine config if it doesn't exist
mkdir -p ~/.claude
[ -f ~/.claude/stratium.json ] || cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "stratium",
  "client_id": "stratium-cli",
  "cacert": "/path/to/stratium/config/examples/certs/ca.crt",
  "plaintext": false,
  "default_scope": { "max_action_tier": 1, "approved_tools": [], "on_unavailable": "fail_closed" }
}
EOF

# 3. Login and cache the token
stratium-hooks login --user admin456
```

Then run the override:

```bash
# Override — uses cached token, no password needed
STRATIUM_OIDC_USER=admin456 \
  stratium-hooks override --reason "Test break-glass flow" --tier 3 --ttl 300
echo "Exit: $?"
```

If Stratium is running, expected output:
```
[stratium] ⚠️  BREAK-GLASS OVERRIDE ACTIVE
[stratium]    Delegation: <8-char-id>
[stratium]    Tier:       EXTERNAL_COMMS (3)
[stratium]    TTL:        300s
[stratium]    Reason:     Test break-glass flow
[stratium]    This override is logged and will be reviewed by your security team.
```

### 2b.6 Revoke command

The no-op path requires no setup:

```bash
# Without an active session (no-op) — no Stratium needed
stratium-hooks revoke
# → "[stratium] No active session delegation found in this process."
```

The full revoke flow requires a running Stratium stack. Start it if not already running:

```bash
# Start Stratium (from project root)
docker-compose -f /path/to/stratium/deployment/docker/docker-compose.yml \
  --profile agent-auth up -d

# Write machine config if needed
mkdir -p ~/.claude
[ -f ~/.claude/stratium.json ] || cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "stratium",
  "client_id": "stratium-cli",
  "cacert": "/path/to/stratium/config/examples/certs/ca.crt",
  "plaintext": false,
  "default_scope": { "max_action_tier": 1, "approved_tools": [], "on_unavailable": "fail_closed" }
}
EOF
```

Then create a session and revoke it:

```bash
# From sdk/claude-hooks/
export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json
export STRATIUM_OIDC_USER=admin456
export CLAUDE_PROJECT_DIR=/tmp/stratium-test-project

stratium-hooks login --user admin456

rm -f "$STRATIUM_SESSION_FILE"
echo '{"hook_event_name":"UserPromptSubmit","session_id":"revoke-test"}' \
  | node src/session-init.js

stratium-hooks revoke
# → "[stratium] Delegation <8chars> revoked."
```

### 2b.7 Webhook notifications (dry run)

Test the notification payload builder without sending to real URLs:

```bash
node -e "
const { buildSlackPayload, buildTeamsPayload, buildGenericPayload } = require('./src/notifications');

const event = {
  type: 'deny',
  tool_name: 'Write',
  reason: 'INTERNAL_MODIFY (tier 2) exceeds READ_ONLY cap',
  user: 'alice@corp.com',
  delegation_id: 'abc12345-0000-0000-0000-000000000000',
  project: 'stratium',
  machine: 'alice-mbp.local',
};

console.log('=== Slack payload ===');
console.log(JSON.stringify(buildSlackPayload(event, '#security-alerts'), null, 2));

console.log('=== Generic payload ===');
console.log(JSON.stringify(buildGenericPayload(event), null, 2));
"
```

To test actual delivery (replace with a real Slack webhook URL):

```bash
node -e "
const { notify } = require('./src/notifications');
notify(
  {
    type: 'deny',
    tool_name: 'Write',
    reason: 'Test webhook delivery',
    user: 'testuser',
    delegation_id: 'test-000',
    project: 'stratium',
    machine: require('os').hostname(),
  },
  {
    on_deny: true,
    webhooks: [
      { type: 'slack', url: 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL' }
    ]
  }
);
console.log('Notification queued (fire-and-forget)');
"
```

---

## Level 2c: MDM Deployment Dry Run

> **All commands in Level 2c run from the project root** (the directory containing `sdk/`).
> `cd /path/to/stratium` before running.

Verify the deployment scripts are valid before pushing to MDM:

```bash
# From project root
bash -n sdk/claude-hooks/deployment/jamf/jamf-policy.sh && echo "Jamf script: OK"

# Validate Intune macOS remediation syntax
bash -n sdk/claude-hooks/deployment/intune/intune-remediation-remediate.sh && echo "Intune sh: OK"

# Validate PowerShell syntax (requires pwsh)
if command -v pwsh &>/dev/null; then
  pwsh -Command "
    \$null = [System.Management.Automation.Language.Parser]::ParseFile(
      'sdk/claude-hooks/deployment/intune/intune-remediation-remediate.ps1',
      [ref]\$null, [ref]\$null
    );
    Write-Host 'Intune ps1: OK'
  "
fi
```

Simulate a Jamf dry-run (no actual install — just verify parameter handling):

```bash
# Override npm install to a no-op, test the rest of the script logic
bash -c '
  function npm() { echo "[dry-run] npm $*"; }
  function stratium-hooks() { echo "[dry-run] stratium-hooks $*"; }
  export -f npm stratium-hooks
  bash sdk/claude-hooks/deployment/jamf/jamf-policy.sh \
    "" "" "" "stratium.corp.com:50054" "https://stratium.corp.com:8090" \
    "https://keycloak.corp.com" "corp" "" "" "fail_closed"
'
# Log written to /tmp/stratium-hooks-install.log (falls back from /var/log when not root)
cat /tmp/stratium-hooks-install.log
```

---

## Level 3: Integration Tests (Stratium running locally)

These tests require the full Stratium stack running via Docker Compose.
Run sections 3.1 → 3.2 → 3.3 in order; or jump directly to any subsection —
each has its own prerequisite block.

### 3.1 Start Stratium with agent-auth

The agent-gateway service uses the `agent-auth` Docker Compose profile and is not started by a plain `up -d`. You must activate the profile explicitly:

```bash
# From project root — activate the agent-auth profile to include the gateway
docker-compose -f deployment/docker/docker-compose.yml \
  --profile agent-auth up -d

# Verify agent gateway is up (uses TLS — pass cacert)
grpcurl -cacert config/examples/certs/ca.crt localhost:50054 list
# → agent_gateway.AgentGatewayService
```

> **Why a profile?** The agent-gateway requires the `agent-auth` build feature flag and the
> agent-auth database schema migration. The profile gate prevents accidental startup on
> deployments where agent auth hasn't been enabled.

### 3.2 Configure ~/.claude/stratium.json for local Stratium

The `claude-code` Keycloak client does not exist in the default realm. Use the existing
`stratium-cli` public client (direct access grants enabled):

```bash
mkdir -p ~/.claude
cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "stratium",
  "client_id": "stratium-cli",
  "cacert": "<absolute-path-to>/config/examples/certs/ca.crt",
  "plaintext": false,
  "default_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "on_unavailable": "fail_closed"
  }
}
EOF
```

> **Note:** Replace `<absolute-path-to>` with the actual path to your clone.
> `cacert` is required — the Agent Gateway and PAP both use self-signed TLS.
> `plaintext: false` must be set; `-plaintext` bypasses TLS and the gateway will reject it.
> The Keycloak realm is `stratium` (not `master`) and the client is `stratium-cli`.

### 3.3 Login and register the agent

Session-init (which registers the agent and creates the first delegation) must run at least once
before `stratium-hooks override` or `stratium-hooks revoke` will work, since those commands depend
on `~/.claude/stratium-agent.json` written by `ensureAgentRegistered`.

**If jumping directly to this section,** run sections 3.1 and 3.2 first, or run these
equivalent setup commands:

```bash
# Start the stack (skip if already running)
docker-compose -f /path/to/stratium/deployment/docker/docker-compose.yml \
  --profile agent-auth up -d

# Write the machine config (skip if already written)
mkdir -p ~/.claude
[ -f ~/.claude/stratium.json ] || cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "stratium",
  "client_id": "stratium-cli",
  "cacert": "/path/to/stratium/config/examples/certs/ca.crt",
  "plaintext": false,
  "default_scope": { "max_action_tier": 1, "approved_tools": [], "on_unavailable": "fail_closed" }
}
EOF
```

```bash
  # Authenticate and cache your token.
  # Tokens expire after a few hours — re-run this at the start of every test session.
  stratium-hooks login --user admin456

  # Set env vars used by session-init.
  # STRATIUM_SESSION_FILE overrides the default path so both session-init and pre-tool-use
  # read/write the same file during manual testing. When running via Claude Code, session_id
  # from the hook input is used instead — no env var needed in production.
  export STRATIUM_OIDC_USER=admin456
  export CLAUDE_PROJECT_DIR=/tmp/stratium-test-project
  export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json

  # All node src/ commands must run from sdk/claude-hooks/.
  # cd to the project root first, then into the hooks package.
  # (If your shell's cwd is invalid after exiting a deleted directory, open a new terminal.)
  cd /path/to/stratium          # e.g. ~/Development/stratium
  cd sdk/claude-hooks

  # Delete any stale mock session (the 2099 expiry mock causes session-init to exit early)
  rm -f "$STRATIUM_SESSION_FILE"

  # Run session-init — registers agent, creates delegation, writes session file
  echo '{"hook_event_name":"UserPromptSubmit","session_id":"test-session-001"}' \
    | node src/session-init.js
  echo "Exit code: $?"
```

Expected stderr:
```
[stratium] Authenticating as admin456...
[stratium] Session initialized — tier: READ_ONLY, tools: Read, Glob, Grep, delegation: <8-char-id>
```

> **Troubleshooting:**
> - `"no cached OIDC token for admin456"` → Token expired. Run `stratium-hooks login --user admin456` and retry.
> - `"agent lookup failed: not found"` → The PAP database was reset (e.g. `docker-compose down -v`).
>   Delete the stale agent cache and retry:
>   ```bash
>   rm -f ~/.claude/stratium-agent.json
>   ```
>   The `agent-registry.js` module detects 404s automatically on subsequent runs, but the first
>   attempt after a DB reset will fail. Clearing the cache file bypasses the initial 404 detection.

Verify the session file was written:
```bash
cat "$STRATIUM_SESSION_FILE" | python3 -m json.tool
```

Expected fields: `agent_id`, `delegation_id`, `delegation_token`, `expires_at`, `user`, `gateway`, `project_scope`.

### 3.4 Test full pre-tool-use with real gateway

**If jumping directly to this section,** run this quick setup to get a valid session file:

```bash
# Start the stack (skip if already running)
docker-compose -f /path/to/stratium/deployment/docker/docker-compose.yml \
  --profile agent-auth up -d

# Write machine config (skip if already written)
mkdir -p ~/.claude
[ -f ~/.claude/stratium.json ] || cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "stratium",
  "client_id": "stratium-cli",
  "cacert": "/path/to/stratium/config/examples/certs/ca.crt",
  "plaintext": false,
  "default_scope": { "max_action_tier": 1, "approved_tools": [], "on_unavailable": "fail_closed" }
}
EOF

# Login, set env vars, and create the session
stratium-hooks login --user admin456
export STRATIUM_OIDC_USER=admin456
export CLAUDE_PROJECT_DIR=/tmp/stratium-test-project
export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json
rm -f "$STRATIUM_SESSION_FILE"
cd /path/to/stratium/sdk/claude-hooks
echo '{"hook_event_name":"UserPromptSubmit","session_id":"test-session-001"}' \
  | node src/session-init.js
```

After section 3.3 (or the quick setup above), `STRATIUM_SESSION_FILE` is set. Test enforcement end-to-end:

```bash
# Read → ALLOW (tier 1, within cap, gateway authorizes)
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"path":"src/main.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 0

# Write → DENY (tier 2 > READ_ONLY cap — blocked locally, no gateway call)
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"src/main.go"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 2

# Bash git status → depends on delegation scope:
#   approved_tools: [Read, Glob, Grep] (from CLAUDE.md) → exit 2 (Bash not in list)
#   approved_tools: [] (all-at-tier, default machine scope) → exit 0 (tier 1 within cap)
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git status"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 0 or 2 depending on delegation approved_tools

# Bash git push → DENY (tier 3 > READ_ONLY cap; tier check fires before approved_tools check)
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"git push origin main"}}' \
  | node src/pre-tool-use.js
echo "Exit code: $?"   # → 2
```

### 3.5 Test Claude Code hooks end-to-end

**If jumping directly to this section,** start the Stratium stack first:

```bash
docker-compose -f /path/to/stratium/deployment/docker/docker-compose.yml \
  --profile agent-auth up -d
```

**Install the stratium hooks** into Claude Code's `~/.claude/settings.json`.
The `configure` command writes the machine config AND registers the three hook entries:

```bash
stratium-hooks configure \
  --gateway localhost:50054 \
  --pap-url https://localhost:8090 \
  --keycloak http://localhost:8080 \
  --realm stratium \
  --client-id stratium-cli \
  --cacert /path/to/config/examples/certs/ca.crt \
  --fail-closed
```

This writes `~/.claude/stratium.json` (same content as section 3.2) and adds
`UserPromptSubmit`, `PreToolUse`, and `PostToolUse` hook entries to `~/.claude/settings.json`.

> **Important:** Use `--client-id stratium-cli`. The default (`claude-code`) does not exist
> in the local Keycloak realm. A wrong client ID will cause every session to block with
> `"Stratium authentication failed: Keycloak authentication failed (HTTP 401)"`.

> **Note:** If you already manually wrote `~/.claude/stratium.json` in section 3.2,
> `configure` will overwrite it — check `client_id` afterwards with `cat ~/.claude/stratium.json`.

After configuring, set the test user override and open a new Claude Code session in the test project.
**Both steps must be done in the same terminal** — env vars set in one shell are not inherited by
a separately-opened terminal or IDE window.

```bash
# Must be exported in the same shell that launches claude
stratium-hooks login --user admin456
export STRATIUM_OIDC_USER=admin456

cd /tmp/stratium-test-project
claude   # or: code . if using VS Code extension
```

> **Note:** You may see a `SessionStart:startup hook error` on startup from an unrelated
> global plugin hook. This is harmless — it does not affect the stratium `UserPromptSubmit` hook.

> **Warning — hooks are global:** The registered hooks fire in **every** Claude Code session,
> including sessions in other projects. If you open a project that doesn't have a `stratium:` block
> in its CLAUDE.md and authentication fails, that session will be blocked (fail_closed).
> To prevent this, either:
> - Add `stratium:\n  enabled: false` to any project's CLAUDE.md where you don't want enforcement, or
> - Remove the hooks from `~/.claude/settings.json` after E2E testing:
>   ```bash
>   python3 -c "import json,pathlib; p=pathlib.Path('~/.claude/settings.json').expanduser(); s=json.loads(p.read_text()); s['hooks']={} ; p.write_text(json.dumps(s,indent=2))"
>   ```

On the first prompt, you should see on stderr (visible in Claude Code's Output panel):
```
[stratium] Authenticating as admin456...
[stratium] Session initialized — tier: READ_ONLY, tools: Read, Glob, Grep, delegation: <8-char-id>
```

> **Note:** If you see no "Authenticating..." message but enforcement is still working (tools are
> being denied), session-init found a valid existing session and reused it silently. Delete
> `/tmp/stratium-session-*.json` to force a fresh authentication.

**Test ALLOW — ask Claude to read a file:**
> "what files are in this project?"

Claude will use `Glob` or `Read` (both in the approved_tools list at tier 1). The `PreToolUse` hook
fires but allows the call through — no block message, Claude returns the file listing normally.

**Test DENY — ask Claude to run a shell command:**
> "run a test to see if python is active"

Claude will attempt `Bash(python3 --version)`. The `PreToolUse` hook blocks it:
```
PreToolUse:Bash hook returned blocking error
Stratium DENY: Bash requires INTERNAL_MODIFY (tier 2) but your project delegation is capped at
READ_ONLY (tier 1).
To allow this tool, ask your admin to set max_action_tier: INTERNAL_MODIFY in the stratium: block
of CLAUDE.md.
Delegation: <8-char-id>
```

---

## Level 4: Subagent Delegation Tests (Stratium running locally)

These tests verify the delegation chain enforcement: a child delegation inherits the parent's
scope and cannot exceed it, even if the child requests broader access.

### 4.0 Setup (self-contained — run this even if you haven't run sections 1–3)

**Step 1 — Start the Stratium stack with agent-auth profile.**

```bash
cd /path/to/stratium   # e.g. ~/Development/stratium

docker-compose -f deployment/docker/docker-compose.yml \
  --profile agent-auth up -d

# Verify the agent gateway is up
grpcurl -cacert config/examples/certs/ca.crt localhost:50054 list
# → agent_gateway.AgentGatewayService
```

**Step 2 — Write the machine config.**

Replace `<absolute-path-to-stratium>` with the actual path to your clone (e.g. `/Users/you/Development/stratium`):

```bash
mkdir -p ~/.claude
cat > ~/.claude/stratium.json << 'EOF'
{
  "gateway": "localhost:50054",
  "pap_url": "https://localhost:8090",
  "keycloak_url": "http://localhost:8080",
  "realm": "stratium",
  "client_id": "stratium-cli",
  "cacert": "<absolute-path-to-stratium>/config/examples/certs/ca.crt",
  "plaintext": false,
  "default_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "on_unavailable": "fail_closed"
  }
}
EOF
```

Verify the `cacert` path is correct:
```bash
python3 -c "import json; mc=json.load(open('${HOME}/.claude/stratium.json')); print('cacert:', mc['cacert'])"
```

**Step 3 — Authenticate and initialize the parent delegation.**

```bash
# Open a new terminal from the project root if your shell's cwd is stale.
cd /path/to/stratium
cd sdk/claude-hooks

# Authenticate and cache the OIDC token (re-run at the start of each test session)
stratium-hooks login --user admin456

# Export env vars — all commands below assume these are set
export STRATIUM_OIDC_USER=admin456
export CLAUDE_PROJECT_DIR=/tmp/stratium-test-project
export STRATIUM_SESSION_FILE=/tmp/stratium-test-session.json

# Clear any stale session file (a mock 2099-expiry file causes session-init to exit early)
rm -f "$STRATIUM_SESSION_FILE"

# Clear stale agent cache if the PAP DB was reset since you last ran (e.g. after docker-compose down -v)
# rm -f ~/.claude/stratium-agent.json

# Run session-init — registers the agent in PAP, creates the parent delegation, writes the session file
echo '{"hook_event_name":"UserPromptSubmit","session_id":"test-session-001"}' \
  | node src/session-init.js
echo "Exit code: $?"   # → 0
```

Expected stderr:
```
[stratium] Authenticating as admin456...
[stratium] Session initialized — tier: READ_ONLY, tools: all-at-tier, delegation: <8-char-id>
```

Verify the session file and extract the IDs needed for subsequent steps:
```bash
cat "$STRATIUM_SESSION_FILE" | python3 -m json.tool

PARENT_TOKEN=$(python3 -c "import json,os; s=json.load(open(os.environ['STRATIUM_SESSION_FILE'])); print(s['delegation_token'])")
AGENT_ID=$(python3 -c "import json; print(json.load(open('${HOME}/.claude/stratium-agent.json'))['agent_id'])")

# The delegator_token is the user's OIDC access token — required by CreateDelegation as the
# Authorization header so the gateway can record user identity on the delegation row.
# STRATIUM_OIDC_PASSWORD must be set so getToken doesn't fall through to an interactive TTY
# prompt (which hangs silently inside $(...) command substitutions).
DELEGATOR_TOKEN=$(STRATIUM_OIDC_PASSWORD=admin123 node -e "
const { getToken } = require('./src/auth');
const mc = JSON.parse(require('fs').readFileSync(require('os').homedir()+'/.claude/stratium.json'));
const t = getToken({ keycloak_url: mc.keycloak_url, realm: mc.realm, client_id: mc.client_id, username: process.env.STRATIUM_OIDC_USER });
process.stdout.write(t.access_token);
")

echo "AGENT_ID=$AGENT_ID"
echo "PARENT_TOKEN=${PARENT_TOKEN:0:40}..."     # truncated for readability
echo "DELEGATOR_TOKEN=${DELEGATOR_TOKEN:0:40}..." # truncated for readability
```

> **Troubleshooting:**
> - `"no cached OIDC token for admin456"` → Run `stratium-hooks login --user admin456` and retry.
> - `"agent lookup failed: not found"` or `"HTTP 404"` → The PAP DB was reset.
>   Delete `~/.claude/stratium-agent.json` and rerun step 3 — `agent-registry.js`
>   will re-register the agent automatically on the next attempt.
> - Connection refused on port 50054 → Docker Compose started without `--profile agent-auth`.
>   Run the `docker-compose up` command from step 1 again.

---

### 4.1 Create a child delegation

A subagent (e.g. a tool-use sub-process or spawned agent) creates a delegation scoped below
the parent. The parent delegation token is passed as `parent_delegation_token`.

```bash
# Assumes AGENT_ID, PARENT_TOKEN, and STRATIUM_SESSION_FILE are set from section 4.0.
# If you skipped there, set them now:
#   PARENT_TOKEN=$(python3 -c "import json,os; print(json.load(open(os.environ['STRATIUM_SESSION_FILE']))['delegation_token'])")
#   AGENT_ID=$(python3 -c "import json; print(json.load(open('${HOME}/.claude/stratium-agent.json'))['agent_id'])")

# Ensure you are in sdk/claude-hooks/
cd /path/to/stratium/sdk/claude-hooks

# Also need the user's OIDC access token — the gateway uses it as the Authorization header
# to establish user identity.
# STRATIUM_OIDC_PASSWORD must be set: getToken falls through to an interactive TTY prompt
# when no token is cached, which hangs silently inside $(...) command substitutions.
DELEGATOR_TOKEN=$(STRATIUM_OIDC_PASSWORD=admin123 node -e "
const { getToken } = require('./src/auth');
const mc = JSON.parse(require('fs').readFileSync(require('os').homedir()+'/.claude/stratium.json'));
try {
  const t = getToken({ keycloak_url: mc.keycloak_url, realm: mc.realm, client_id: mc.client_id, username: process.env.STRATIUM_OIDC_USER || require('os').userInfo().username });
  process.stdout.write(t.access_token);
} catch (e) { process.stderr.write('[error] ' + e.message + '\n'); process.exit(1); }
")

# Create a child delegation — same tier, same tools (valid narrowing).
# Pass all tokens via env vars to avoid shell quoting issues with JWT strings.
CHILD_DELEGATION=$(AGENT_ID="$AGENT_ID" PARENT_TOKEN="$PARENT_TOKEN" DELEGATOR_TOKEN="$DELEGATOR_TOKEN" node -e "
const { createDelegation } = require('./src/grpc-client');
const mc = JSON.parse(require('fs').readFileSync(require('os').homedir()+'/.claude/stratium.json'));
const gOpts = { gateway: mc.gateway, cacert: mc.cacert, plaintext: mc.plaintext || false };
const d = createDelegation(gOpts, {
  agent_id:                process.env.AGENT_ID,
  delegator_token:         process.env.DELEGATOR_TOKEN,
  parent_delegation_token: process.env.PARENT_TOKEN,
  max_action_tier:         1,
  approved_tools:          [],
  ttl_seconds:             3600,
  purpose:                 'subagent test',
  conversation_id:         'subagent-test-001',
});
console.log(JSON.stringify(d));
")
echo "Child delegation: $CHILD_DELEGATION"
```

Expected: JSON with `delegation_id`, `delegation_token`, `depth: 1`, `root_delegation_id` matching the parent.

### 4.2 Test ALLOW — child uses Read within inherited scope

Write a session file using the child delegation token and run pre-tool-use:

```bash
CHILD_TOKEN=$(echo "$CHILD_DELEGATION" | python3 -c "import json,sys; print(json.load(sys.stdin)['delegation_token'])")
CHILD_ID=$(echo "$CHILD_DELEGATION" | python3 -c "import json,sys; print(json.load(sys.stdin)['delegation_id'])")

# Write a child session file, using env vars to avoid JWT quoting issues
CHILD_SESSION_FILE=/tmp/stratium-child-session.json
CHILD_ID="$CHILD_ID" CHILD_TOKEN="$CHILD_TOKEN" CHILD_SESSION_FILE="$CHILD_SESSION_FILE" \
  python3 -c "
import json, os, copy
parent = json.load(open(os.environ['STRATIUM_SESSION_FILE']))
child = copy.deepcopy(parent)
child['delegation_id']    = os.environ['CHILD_ID']
child['delegation_token'] = os.environ['CHILD_TOKEN']
child['project_scope']['max_action_tier'] = 1
json.dump(child, open(os.environ['CHILD_SESSION_FILE'], 'w'), indent=2)
"

# Read → ALLOW (tier 1, within child scope)
# Note: STRATIUM_SESSION_FILE prefix applies to node, not to echo
echo '{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"subagent-test-001","tool_input":{"path":"src/main.go"}}' \
  | STRATIUM_SESSION_FILE=$CHILD_SESSION_FILE node src/pre-tool-use.js
echo "Exit code: $?"   # → 0
```

### 4.3 Test DENY — child attempts to exceed parent scope

The parent delegation is capped at READ_ONLY (tier 1). A child requesting INTERNAL_MODIFY
(tier 2) must be denied even if the child's own delegation claims tier 2 — the chain
enforces the parent's cap.

```bash
# Try to create a child delegation with a HIGHER tier than the parent — gateway should reject.
# All tokens are passed via env vars to avoid JWT shell-quoting issues.
AGENT_ID="$AGENT_ID" PARENT_TOKEN="$PARENT_TOKEN" DELEGATOR_TOKEN="$DELEGATOR_TOKEN" node -e "
const { createDelegation } = require('./src/grpc-client');
const mc = JSON.parse(require('fs').readFileSync(require('os').homedir()+'/.claude/stratium.json'));
const gOpts = { gateway: mc.gateway, cacert: mc.cacert, plaintext: mc.plaintext || false };
try {
  const d = createDelegation(gOpts, {
    agent_id:                process.env.AGENT_ID,
    delegator_token:         process.env.DELEGATOR_TOKEN,
    parent_delegation_token: process.env.PARENT_TOKEN,
    max_action_tier:         2,   // INTERNAL_MODIFY — exceeds parent READ_ONLY cap
    approved_tools:          [],
    ttl_seconds:             3600,
    purpose:                 'subagent escalation attempt',
    conversation_id:         'subagent-test-002',
  });
  console.log('ERROR: Expected rejection but got:', JSON.stringify(d));
  process.exit(1);
} catch (err) {
  console.log('CORRECTLY REJECTED:', err.message);
  process.exit(0);
}
"
echo "Exit code: $?"   # → 0 (correctly rejected)
```

Expected: gateway returns an error such as `child max_action_tier exceeds parent delegation cap`.

### 4.4 Test DENY — child session blocked at Write tier

Using the child session file (tier 1 cap), verify Write is blocked locally:

```bash
STRATIUM_SESSION_FILE=$CHILD_SESSION_FILE \
echo '{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"subagent-test-001","tool_input":{"path":"src/main.go"}}' \
  | STRATIUM_SESSION_FILE=$CHILD_SESSION_FILE node src/pre-tool-use.js
echo "Exit code: $?"   # → 2 (tier 2 > child delegation cap of tier 1)
```

---

## Level 5: Automated Integration Test Script

> **Not yet implemented.** `test/integration.test.js` does not exist. The manual steps in
> sections 3.3–4.4 cover the same ground. Contributions welcome.
>
> When implemented, the command will be:
> ```bash
> STRATIUM_OIDC_USER=admin456 \
> STRATIUM_OIDC_PASSWORD=admin123 \
> CLAUDE_PROJECT_DIR=/tmp/stratium-test-project \
>   node --test test/integration.test.js
> ```

---

## Level 6: npm Publishing Verification

Verify the package is publishable before sending to a real registry.

> **All commands in Level 6 run from `sdk/claude-hooks/`.**
> Run `cd /path/to/stratium/sdk/claude-hooks` before starting.

### 6.1 Dry-run publish (no registry needed)

```bash
cd /path/to/stratium/sdk/claude-hooks

# Test that package contents, prepublishOnly hook, and output are correct
npm publish --dry-run
```

Expected: tests run (`prepublishOnly`), then a list of files that would be published:
```
npm notice === Tarball Contents ===
npm notice ... bin/stratium-hooks
npm notice ... src/agent-registry.js
npm notice ... src/auth.js
npm notice ... src/claude-md-parser.js
npm notice ... src/grpc-client.js
npm notice ... src/keychain.js
npm notice ... src/notifications.js
npm notice ... src/post-tool-use.js
npm notice ... src/pre-tool-use.js
npm notice ... src/scope-validator.js
npm notice ... src/session-init.js
npm notice ... src/tier-map.js
npm notice ... scripts/install-hooks.sh
npm notice ... deployment/jamf/jamf-policy.sh
npm notice ... deployment/intune/intune-remediation-remediate.ps1
npm notice ... README.md
npm notice ... package.json
npm notice === Tarball Details ===
```

Verify that no sensitive files are included (`src/keychain.js` stores tokens securely — ensure `.npmignore` or `files` in `package.json` excludes `.npmrc`, `.github/`, and `test/`).

### 6.2 Validate package contents

```bash
# List exactly what would be packed
npm pack --dry-run 2>&1 | grep "npm notice"

# Or create the tarball and inspect it
npm pack
tar -tzf stratium-claude-hooks-*.tgz | sort
rm stratium-claude-hooks-*.tgz
```

### 6.3 GitHub Actions publish workflow dry run

```bash
# Validate workflow YAML syntax (requires actionlint or yq)
if command -v actionlint &>/dev/null; then
  actionlint sdk/claude-hooks/.github/workflows/publish.yml
  echo "Workflow syntax: OK"
elif command -v yq &>/dev/null; then
  yq e '.' sdk/claude-hooks/.github/workflows/publish.yml > /dev/null && echo "YAML valid"
fi
```

To test the version-tag check logic locally:
```bash
GITHUB_REF_NAME=v1.0.0 node -e "
const pkg = require('./sdk/claude-hooks/package.json');
const tagVersion = process.env.GITHUB_REF_NAME.replace(/^v/, '');
if (pkg.version !== tagVersion) {
  console.error('FAIL: package version', pkg.version, '≠ tag', tagVersion);
  process.exit(1);
}
console.log('PASS: version', pkg.version, 'matches tag', process.env.GITHUB_REF_NAME);
"
```

---

## Bash-Based Hooks (Alternative to Node.js Package)

In addition to the `sdk/claude-hooks` Node.js package, there are lightweight bash-based hooks in `demos/mcp/hooks/` that provide the same enforcement without requiring npm install. These are especially useful for quick testing or environments where Node.js isn't available.

### Files

| Hook | Script | Description |
|------|--------|-------------|
| `SessionStart` | `demos/mcp/hooks/session-start.sh` | Bootstraps delegation via PAP REST API, writes token to `~/.stratium/delegation.json` |
| `PreToolUse` | `demos/mcp/hooks/pre-tool-use.sh` | Reads delegation from file, checks authorization via Agent Gateway gRPC |

### Key Differences from Node.js Package

| Aspect | `sdk/claude-hooks` (Node.js) | `demos/mcp/hooks/` (Bash) |
|--------|------------------------------|---------------------------|
| Session init | `UserPromptSubmit` hook (runs on first prompt) | `SessionStart` hook (runs on session start/resume) |
| Delegation creation | Via gRPC (`createDelegation`) | Via PAP REST (`POST /api/v1/delegations`) |
| Auth check | Via gRPC (`ExecuteAction`) | Via gRPC (`grpcurl`) |
| Dependencies | Node.js, npm | bash, curl, jq, grpcurl |
| Fail behavior | Configurable (fail_open/fail_closed per project) | **Always fail-closed** |
| Delegation storage | `/tmp/stratium-session-<id>.json` | `~/.stratium/delegation.json` |
| CLAUDE.md parsing | Full `stratium:` block parsing | None (uses env vars) |

### Quick Test (Bash Hooks)

> **All commands must run from the stratium project root** (the directory containing `demos/`).
> Run `cd /path/to/stratium` (e.g., `cd ~/Development/stratium`) before starting.

```bash
cd ~/Development/stratium   # adjust to your clone location

# 1. SessionStart — creates delegation via PAP REST
echo '{"hook_event_name":"SessionStart"}' \
  | STRATIUM_PAP_URL="https://localhost:8090" \
    STRATIUM_AGENT_ID="$(curl -sk https://localhost:8090/api/v1/agents \
      -H "Authorization: Bearer $(cat ~/.stratium/token.json | jq -r '.access_token')" \
      | jq -r '.agents[0].id')" \
    STRATIUM_AUTH_TOKEN="$(cat ~/.stratium/token.json | jq -r '.access_token')" \
    bash demos/mcp/hooks/session-start.sh 2>&1
# Expected: "[stratium] SessionStart: delegation created (id: ...)"

# 2. Verify delegation file
cat ~/.stratium/delegation.json | jq .

# 3. PreToolUse ALLOW — read file
echo '{"tool_name":"Read","tool_input":{"path":"README.md"}}' \
  | STRATIUM_GATEWAY_ADDRESS="localhost:50054" \
    STRATIUM_TLS_CA="config/examples/certs/ca.crt" \
    bash demos/mcp/hooks/pre-tool-use.sh 2>/dev/null
echo "Exit: $?"  # → 0 (ALLOW)

# 4. PreToolUse DENY — destructive command
echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /"}}' \
  | STRATIUM_GATEWAY_ADDRESS="localhost:50054" \
    STRATIUM_TLS_CA="config/examples/certs/ca.crt" \
    bash demos/mcp/hooks/pre-tool-use.sh 2>/dev/null
echo "Exit: $?"  # → 2 (DENY)

# 5. PreToolUse DENY — no delegation file (fail-closed)
mv ~/.stratium/delegation.json ~/.stratium/delegation.json.bak
echo '{"tool_name":"Read","tool_input":{}}' \
  | STRATIUM_DELEGATION_TOKEN="" \
    bash demos/mcp/hooks/pre-tool-use.sh 2>/dev/null
echo "Exit: $?"  # → 2 (DENY — SessionStart never ran)
mv ~/.stratium/delegation.json.bak ~/.stratium/delegation.json
```

### Environment Variables (Bash Hooks)

**SessionStart (`session-start.sh`):**

| Variable | Required | Description |
|----------|----------|-------------|
| `STRATIUM_PAP_URL` | Yes | PAP server URL (e.g., `https://localhost:8090`) |
| `STRATIUM_AGENT_ID` | Yes | Registered agent UUID |
| `STRATIUM_AUTH_TOKEN` | Yes* | OIDC access token (*falls back to `~/.stratium/token.json`) |
| `STRATIUM_APPROVED_TOOLS` | No | Comma-separated tools (default: `read_file,write_file,edit_file,bash,list_files,grep_search`) |
| `STRATIUM_MAX_ACTION_TIER` | No | 0-4 (default: 2) |
| `STRATIUM_CLASSIFICATION_CAP` | No | Default: `INTERNAL` |
| `STRATIUM_TTL_SECONDS` | No | Delegation TTL (default: 14400 / 4 hours) |
| `STRATIUM_DELEGATION_TOKEN` | No | Pre-created token (skips PAP call) |

**PreToolUse (`pre-tool-use.sh`):**

| Variable | Required | Description |
|----------|----------|-------------|
| `STRATIUM_GATEWAY_ADDRESS` | Yes | Agent Gateway gRPC address (default: `localhost:50054`) |
| `STRATIUM_TLS_CA` | No | TLS CA cert path (empty = plaintext) |

### Important: Fail-Closed Behavior

The bash `pre-tool-use.sh` now fails **closed** in all error cases:

- No delegation file → DENY
- Gateway unreachable → DENY
- Token expired → DENY

This differs from the original demo behavior (fail-open). If you register PreToolUse without also registering SessionStart, **all tool calls will be denied** because the delegation file won't exist.

**Always register both hooks together:**

```json
{
  "hooks": {
    "SessionStart": [{ "matcher": "", "hooks": [{ "type": "command", "command": "/path/to/demos/mcp/hooks/session-start.sh" }] }],
    "PreToolUse": [{ "matcher": "", "hooks": [{ "type": "command", "command": "/path/to/demos/mcp/hooks/pre-tool-use.sh" }] }]
  }
}
```

---

## Cleanup

```bash
# Remove test session files
rm -f /tmp/stratium-test-session.json
rm -f /tmp/stratium-session-*.json  # any PID-named sessions from real runs

# Remove test project and any test CLAUDE.md files
rm -rf /tmp/stratium-test-project /tmp/CLAUDE.md /tmp/mcp-test-claude.md

# Remove machine config (if you want to start fresh)
rm -f ~/.claude/stratium.json
rm -f ~/.claude/stratium-agent.json
rm -f ~/.claude/stratium-tokens.json

# Remove bash hook delegation file
rm -f ~/.stratium/delegation.json

# Remove keychain entries (Phase 2)
# macOS Keychain — remove via Keychain Access app or:
security delete-generic-password -s "stratium-claude-hooks" 2>/dev/null || true
# Linux GNOME Keyring:
secret-tool clear service stratium-claude-hooks 2>/dev/null || true

# Remove hooks from Claude Code settings
stratium-hooks configure --gateway localhost:50054  # re-run reconfigure to clean up
# or manually edit ~/.claude/settings.json to remove stratium hook entries
```

---

## Quick Reference: Exit Codes

| Exit code | Meaning | Claude Code behavior |
|-----------|---------|----------------------|
| 0 | ALLOW | Tool executes normally |
| 2 | DENY | Claude Code blocks tool, Claude sees the reason |

## Quick Reference: Test Matrix

| Scenario | Expected exit | Level |
|----------|--------------|-------|
| No machine config | 0 (passthrough) | 2 |
| Machine config, no session | 2 (fail_closed) | 2 |
| Machine config, no session, fail_open | 0 | 2 |
| Session exists, tool tier > max_tier | 2 | 2 |
| Session exists, tool not in approved_tools | 2 | 2 |
| Session exists, gateway unreachable, fail_closed | 2 | 2 |
| Session exists, gateway unreachable, fail_open | 0 | 2 |
| Session exists, gateway ALLOW | 0 | 3 |
| Session exists, gateway DENY | 2 | 3 |
| Session expired | 2 (fail_closed) | 2 |
| MCP tool at tier ≤ session cap | 0 | 2b.4 |
| MCP tool at tier > session cap | 2 | 2b.4 |
| File matches classification_caps pattern | resource attr sent to gateway | 2b.3 |
| CLAUDE.md requests wider tier than PAP allows | capped + warning, no block | 2b.2 |
| `stratium-hooks override --reason` | elevated delegation created | 2b.5 |
| `stratium-hooks revoke` with active session | delegation revoked | 2b.6 |
| Webhook on DENY (Slack) | background curl spawned | 2b.7 |
| OS keychain available | tokens stored in keychain + file | 2b.1 |
| OS keychain unavailable | tokens stored in file only | 2b.1 |
| **Bash hooks** | | |
| SessionStart creates delegation via PAP REST | delegation.json written | Bash |
| PreToolUse reads delegation file, ALLOW | 0 | Bash |
| PreToolUse reads delegation file, DENY (tier exceeded) | 2 | Bash |
| PreToolUse no delegation file (fail-closed) | 2 | Bash |
| PreToolUse gateway unreachable (fail-closed) | 2 | Bash |
