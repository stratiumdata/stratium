#!/bin/bash
# test_claude_hooks.sh — Automated test runner for @stratium/claude-hooks
#
# Mirrors docs/TESTING_CLAUDE_HOOKS.md end-to-end.
#
# Usage:
#   ./scripts/test_claude_hooks.sh           # run all sections
#   ./scripts/test_claude_hooks.sh 1         # unit tests only
#   ./scripts/test_claude_hooks.sh 2         # CLI smoke tests
#   ./scripts/test_claude_hooks.sh 3         # pre-tool-use mock session tests
#   ./scripts/test_claude_hooks.sh 4         # integration tests (Stratium required)
#   ./scripts/test_claude_hooks.sh 5         # subagent delegation (Stratium required)
#   ./scripts/test_claude_hooks.sh clean     # remove temp files
#
# State (tokens, agent IDs) is saved to STATE_FILE between runs so individual
# sections can be re-run after a full run without re-authenticating.

set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PAP_URL="${PAP_URL:-https://localhost:8090}"
GATEWAY_ADDR="${GATEWAY_ADDR:-localhost:50054}"
REALM="${REALM:-stratium}"
CLIENT_ID="${CLIENT_ID:-stratium-cli}"
ADMIN_USER="${ADMIN_USER:-admin456}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
CACERT="${CACERT:-config/examples/certs/ca.crt}"
STATE_FILE="${STATE_FILE:-/tmp/stratium-hooks-test.env}"
HOOKS_DIR="${HOOKS_DIR:-$(cd "$(dirname "$0")/../sdk/claude-hooks" && pwd)}"
TEST_SESSION_FILE="${TEST_SESSION_FILE:-/tmp/stratium-hooks-test-session.json}"
CHILD_SESSION_FILE="${CHILD_SESSION_FILE:-/tmp/stratium-hooks-test-child-session.json}"
TEST_PROJECT_DIR="${TEST_PROJECT_DIR:-/tmp/stratium-hooks-test-project}"

# ─── Colors ───────────────────────────────────────────────────────────────────

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# ─── Counters ─────────────────────────────────────────────────────────────────

PASS=0
FAIL=0
SKIP=0

# ─── Helpers ──────────────────────────────────────────────────────────────────

section_header() {
    echo ""
    echo -e "${BOLD}${CYAN}━━━ Section $1: $2 ━━━${NC}"
    echo ""
}

step() { echo -e "${YELLOW}▶ $*${NC}"; }

pass() {
    echo -e "  ${GREEN}✓ PASS${NC}: $*"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  ${RED}✗ FAIL${NC}: $*"
    FAIL=$((FAIL + 1))
}

skip() {
    echo -e "  ${YELLOW}– SKIP${NC}: $*"
    SKIP=$((SKIP + 1))
}

assert_exit() {
    local label="$1" expected="$2" actual="$3"
    if [ "$actual" = "$expected" ]; then
        pass "$label (exit $actual)"
    else
        fail "$label — expected exit $expected, got exit $actual"
    fi
}

assert_contains() {
    local label="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -q "$expected"; then
        pass "$label"
    else
        fail "$label — expected '$expected' in: $actual"
    fi
}

assert_not_contains() {
    local label="$1" unexpected="$2" actual="$3"
    if echo "$actual" | grep -q "$unexpected"; then
        fail "$label — unexpected '$unexpected' found in: $actual"
    else
        pass "$label"
    fi
}

assert_json_field_nonempty() {
    local label="$1" field="$2" json="$3"
    local actual
    actual=$(echo "$json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('${field}',''))" 2>/dev/null || true)
    if [ -n "$actual" ] && [ "$actual" != "None" ] && [ "$actual" != "null" ]; then
        pass "$label ($field: ${actual:0:20}...)"
    else
        fail "$label — $field empty or null in: $json"
    fi
}

# Run a hook script with JSON input; return exit code in HOOK_EXIT, stdout in HOOK_OUT
run_hook() {
    local script="$1" json_input="$2"
    HOOK_EXIT=0
    HOOK_OUT=$(echo "$json_input" | node "$HOOKS_DIR/src/$script" 2>/tmp/hook-stderr.txt) || HOOK_EXIT=$?
}

# Check if Stratium stack is available (gateway gRPC responds)
stratium_available() {
    grpcurl -cacert "$CACERT" "$GATEWAY_ADDR" list >/dev/null 2>&1
}

save_state() {
    cat > "$STATE_FILE" <<EOF
DELEGATOR_TOKEN='${DELEGATOR_TOKEN:-}'
AGENT_ID='${AGENT_ID:-}'
DELEGATION_ID='${DELEGATION_ID:-}'
DELEGATION_TOKEN='${DELEGATION_TOKEN:-}'
CHILD_DELEGATION_ID='${CHILD_DELEGATION_ID:-}'
CHILD_TOKEN='${CHILD_TOKEN:-}'
EOF
    echo -e "  ${CYAN}(state saved → $STATE_FILE)${NC}"
}

load_state() {
    if [ -f "$STATE_FILE" ]; then
        # shellcheck disable=SC1090
        source "$STATE_FILE"
        echo -e "${CYAN}Loaded state from $STATE_FILE${NC}"
    fi
}

summary() {
    echo ""
    echo -e "${BOLD}━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${GREEN}PASS${NC}: $PASS"
    [ "$FAIL" -gt 0 ] && echo -e "  ${RED}FAIL${NC}: $FAIL" || echo -e "  FAIL: $FAIL"
    [ "$SKIP" -gt 0 ] && echo -e "  SKIP: $SKIP"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    [ "$FAIL" -eq 0 ]
}

write_machine_config() {
    mkdir -p ~/.claude
    # stratium-cli is a public client with ROPC enabled — no client_secret needed.
    # This is what session-init.js uses via getToken (keycloakPasswordGrant doesn't send a secret).
    local cacert_abs
    cacert_abs="$(pwd)/$CACERT"
    cat > ~/.claude/stratium.json <<EOF
{
  "gateway": "$GATEWAY_ADDR",
  "pap_url": "$PAP_URL",
  "keycloak_url": "$KEYCLOAK_URL",
  "realm": "$REALM",
  "client_id": "$CLIENT_ID",
  "cacert": "$cacert_abs",
  "plaintext": false,
  "default_scope": {
    "max_action_tier": 1,
    "approved_tools": [],
    "on_unavailable": "fail_closed"
  }
}
EOF
}

write_test_claude_md() {
    mkdir -p "$TEST_PROJECT_DIR"
    cat > "$TEST_PROJECT_DIR/CLAUDE.md" <<'EOF'
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
  purpose: "Automated hook test"
EOF
}

write_mock_session() {
    local session_file="$1" tier="${2:-1}" tools="${3:-[]}" on_unavail="${4:-fail_closed}" gateway="${5:-localhost:1}"
    # Default gateway is localhost:1 (no listener) so gateway-call tests get a clean network error.
    # For fail_closed tests expecting a real gateway response, pass the actual gateway address.
    cat > "$session_file" <<EOF
{
  "agent_id": "test-agent-mock",
  "delegation_id": "test-delegation-mock",
  "delegation_token": "mock-token",
  "expires_at": "2099-01-01T00:00:00Z",
  "user": "testuser@corp.com",
  "on_unavailable": "$on_unavail",
  "gateway": "$gateway",
  "cacert": "$(pwd)/$CACERT",
  "plaintext": false,
  "project_scope": {
    "max_action_tier": $tier,
    "approved_tools": $tools,
    "tool_tiers": {},
    "classification_caps": {}
  }
}
EOF
}

# ─── Section 1: Unit Tests ────────────────────────────────────────────────────

section_1() {
    section_header 1 "Unit Tests (npm test)"

    step "1.1 npm install"
    npm --prefix "$HOOKS_DIR" install --silent
    pass "1.1 npm install complete"

    step "1.2 npm test"
    npm_exit=0
    test_out=$(npm --prefix "$HOOKS_DIR" test 2>&1) || npm_exit=$?
    if [ "$npm_exit" -eq 0 ]; then
        pass "1.2 all tests pass"
        count=$(echo "$test_out" | grep -oE '# pass [0-9]+' | tail -1 | grep -oE '[0-9]+' || true)
        [ -n "$count" ] && echo -e "    ${CYAN}($count assertions passed)${NC}"
    else
        fail "1.2 test suite exited $npm_exit"
        echo "$test_out" | grep -E '^not ok|# fail' | head -10
    fi

    step "1.3 Individual suites — tier-map"
    tm_exit=0
    tm_out=$(node --test "$HOOKS_DIR/test/tier-map.test.js" 2>&1) || tm_exit=$?
    if [ "$tm_exit" -eq 0 ]; then
        pass "1.3 tier-map suite passes"
    else
        fail "1.3 tier-map suite exited $tm_exit"
        echo "$tm_out" | grep -E '^not ok' | head -5
    fi

    step "1.4 Individual suites — claude-md-parser"
    cm_exit=0
    cm_out=$(node --test "$HOOKS_DIR/test/claude-md-parser.test.js" 2>&1) || cm_exit=$?
    if [ "$cm_exit" -eq 0 ]; then
        pass "1.4 claude-md-parser suite passes"
    else
        fail "1.4 claude-md-parser suite exited $cm_exit"
        echo "$cm_out" | grep -E '^not ok' | head -5
    fi
}

# ─── Section 2: CLI Smoke Tests ───────────────────────────────────────────────

section_2() {
    section_header 2 "CLI Smoke Tests"

    step "2.1 stratium-hooks version"
    ver=$(node "$HOOKS_DIR/bin/stratium-hooks" version 2>&1) || true
    assert_contains "2.1 version string" "stratium" "$ver"

    step "2.2 stratium-hooks scope (parses CLAUDE.md)"
    write_test_claude_md
    scope_out=$(CLAUDE_PROJECT_DIR="$TEST_PROJECT_DIR" \
        node "$HOOKS_DIR/bin/stratium-hooks" scope 2>&1) || true
    assert_contains "2.2 enabled: true" "true" "$scope_out"
    assert_contains "2.2 max_tier READ_ONLY" "READ_ONLY" "$scope_out"
    assert_contains "2.2 approved Read" "Read" "$scope_out"

    step "2.3 Tier map — Read=1, Write=2, Bash curl=3"
    tier_out=$(node -e "
const { getTier, classifyBash } = require('$HOOKS_DIR/src/tier-map');
console.log('read:', getTier('Read', {}).tier);
console.log('write:', getTier('Write', {}).tier);
console.log('curl:', classifyBash('curl http://x').tier);
console.log('rm-rf:', classifyBash('rm -rf /tmp').tier);
" 2>&1) || true
    assert_contains "2.3 Read tier 1"    "read: 1"   "$tier_out"
    assert_contains "2.3 Write tier 2"   "write: 2"  "$tier_out"
    assert_contains "2.3 curl tier 3"    "curl: 3"   "$tier_out"
    assert_contains "2.3 rm -rf tier 4"  "rm-rf: 4"  "$tier_out"

    step "2.4 stratium-hooks override — missing --reason exits 1"
    ovr_exit=0
    node "$HOOKS_DIR/bin/stratium-hooks" override >/dev/null 2>&1 || ovr_exit=$?
    assert_exit "2.4 missing --reason exits 1" "1" "$ovr_exit"

    step "2.5 stratium-hooks revoke — no session is a no-op"
    unset STRATIUM_SESSION_FILE 2>/dev/null || true
    rev_out=$(node "$HOOKS_DIR/bin/stratium-hooks" revoke 2>&1) || true
    assert_contains "2.5 no active session message" "No active session" "$rev_out"
}

# ─── Section 3: Pre-tool-use Mock Session Tests ───────────────────────────────

section_3() {
    section_header 3 "Pre-tool-use Hook (Mock Session)"

    step "3.1 No machine config → silent passthrough (exit 0)"
    # Temporarily hide machine config if present
    local cfg_hidden=false
    if [ -f ~/.claude/stratium.json ]; then
        mv ~/.claude/stratium.json ~/.claude/stratium.json.bak
        cfg_hidden=true
    fi
    unset STRATIUM_SESSION_FILE 2>/dev/null || true
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"test.go"}}'
    assert_exit "3.1 no config → exit 0 passthrough" "0" "$HOOK_EXIT"
    if $cfg_hidden; then
        mv ~/.claude/stratium.json.bak ~/.claude/stratium.json
    fi

    step "3.2 Machine config present, no session → fail_closed blocks (exit 2)"
    write_machine_config
    unset STRATIUM_SESSION_FILE 2>/dev/null || true
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"path":"test.go"}}'
    assert_exit "3.2 no session → exit 2 (fail_closed)" "2" "$HOOK_EXIT"
    assert_contains "3.2 deny decision in output" "deny" "$HOOK_OUT"

    step "3.3 Mock session (tier 1) — Write blocked locally (tier 2 > cap)"
    export STRATIUM_SESSION_FILE="$TEST_SESSION_FILE"
    write_mock_session "$TEST_SESSION_FILE" 1 "[]" "fail_closed"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"mock-001","tool_input":{"path":"test.go"}}'
    assert_exit "3.3 Write blocked at tier cap" "2" "$HOOK_EXIT"
    assert_contains "3.3 INTERNAL_MODIFY in reason" "INTERNAL_MODIFY" "$HOOK_OUT"

    step "3.4 Mock session (tier 1, fail_open) — Read passes tier, fails gateway → exit 0"
    write_mock_session "$TEST_SESSION_FILE" 1 "[]" "fail_open"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"mock-001","tool_input":{"path":"src/main.go"}}'
    assert_exit "3.4 Read + fail_open → exit 0" "0" "$HOOK_EXIT"

    step "3.5 Mock session (tier 1, fail_closed) — Read passes tier, fails gateway → exit 2"
    write_mock_session "$TEST_SESSION_FILE" 1 "[]" "fail_closed"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"mock-001","tool_input":{"path":"src/main.go"}}'
    assert_exit "3.5 Read + fail_closed → exit 2 (gateway down)" "2" "$HOOK_EXIT"

    step "3.6 Approved_tools enforcement — Write not in list → exit 2"
    write_mock_session "$TEST_SESSION_FILE" 2 '["Read","Glob"]' "fail_open"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"mock-001","tool_input":{}}'
    assert_exit "3.6 Write not in approved_tools → exit 2" "2" "$HOOK_EXIT"

    step "3.7 Approved_tools enforcement — Read in list → passes tier (fail_open → exit 0)"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"mock-001","tool_input":{}}'
    assert_exit "3.7 Read in approved_tools + fail_open → exit 0" "0" "$HOOK_EXIT"

    step "3.8 MCP tool tier — mcp__context7__query-docs at tier 1 within cap → pass tier"
    write_mock_session "$TEST_SESSION_FILE" 1 "[]" "fail_open"
    # Override session to add mcp tool_tiers
    python3 -c "
import json
s = json.load(open('$TEST_SESSION_FILE'))
s['project_scope']['tool_tiers'] = {'mcp__context7__query-docs': {'tier': 1, 'label': 'READ_ONLY'}}
json.dump(s, open('$TEST_SESSION_FILE', 'w'), indent=2)
"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"mcp__context7__query-docs","session_id":"mock-001","tool_input":{}}'
    assert_exit "3.8 MCP tier 1 within cap → exit 0 (fail_open)" "0" "$HOOK_EXIT"

    step "3.9 Post-tool-use — always exits 0 (audit only)"
    run_hook "post-tool-use.js" \
        '{"hook_event_name":"PostToolUse","tool_name":"Write","session_id":"mock-001","tool_input":{"path":"test.go"},"tool_response":{"content":"ok"}}'
    assert_exit "3.9 PostToolUse always exits 0" "0" "$HOOK_EXIT"
}

# ─── Section 4: Integration Tests (Stratium required) ─────────────────────────

section_4() {
    section_header 4 "Integration Tests (live Stratium stack)"

    if ! stratium_available; then
        skip "4.x — Agent Gateway not reachable at $GATEWAY_ADDR (start with --profile agent-auth)"
        return
    fi

    write_machine_config
    write_test_claude_md

    step "4.1 Login — get OIDC token via Keycloak password grant"
    # Use direct curl (same approach as test_agent_auth.sh) to avoid getToken's keychain/cache
    # layers that can hide failures.  stratium-pap is a confidential client with ROPC enabled.
    local token_err_file="/tmp/stratium-hooks-test-token-err.txt"
    local token_resp
    token_resp=$(curl -s -X POST \
        "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        -d "client_id=stratium-pap" \
        -d "client_secret=stratium-pap-secret" \
        -d "grant_type=password" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASS" \
        --max-time 10 2>"$token_err_file") || true
    DELEGATOR_TOKEN=$(echo "$token_resp" | python3 -c "import json,sys; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null || true)
    if [ -n "$DELEGATOR_TOKEN" ] && [ "$DELEGATOR_TOKEN" != "null" ]; then
        pass "4.1 OIDC token obtained"
        export DELEGATOR_TOKEN
        # Pre-seed the file token cache so session-init.js getToken() finds it
        # without needing to make a Keycloak ROPC call (stratium-cli path).
        # Cache key = "${keycloak_url}|${realm}|${username}" — must match exactly.
        local token_exp
        token_exp=$(echo "$DELEGATOR_TOKEN" | python3 -c "
import sys, base64, json
parts = sys.stdin.read().strip().split('.')
payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
print(payload.get('exp', 0))
" 2>/dev/null || echo "9999999999")
        local cache_key="${KEYCLOAK_URL}|${REALM}|${ADMIN_USER}"
        python3 -c "
import json, os
cache_file = os.path.expanduser('~/.claude/stratium-tokens.json')
try:
    cache = json.load(open(cache_file))
except Exception:
    cache = {'tokens': {}}
cache['tokens']['$cache_key'] = {
    'access_token':  '$DELEGATOR_TOKEN',
    'refresh_token': '',
    'expires_at':    $token_exp,
    'user_email':    '$ADMIN_USER',
}
open(cache_file, 'w').write(json.dumps(cache, indent=2))
os.chmod(cache_file, 0o600)
" 2>/dev/null || true
        # Also export env vars as fallback
        export STRATIUM_OIDC_PASSWORD="$ADMIN_PASS"
        export STRATIUM_OIDC_USER="$ADMIN_USER"
    else
        local curl_err
        curl_err=$(cat "$token_err_file" 2>/dev/null || true)
        local kc_err
        kc_err=$(echo "$token_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('error_description') or d.get('error',''))" 2>/dev/null || true)
        skip "4.1 OIDC token empty — Keycloak not running or credentials wrong"
        [ -n "$kc_err" ]   && echo -e "    ${RED}Keycloak error:${NC} $kc_err"
        [ -n "$curl_err" ] && echo -e "    ${RED}curl error:${NC} $curl_err"
        echo -e "    ${CYAN}Tried:${NC} $KEYCLOAK_URL/realms/$REALM (user=$ADMIN_USER)"
        skip "4.2–4.6 (skipped — no auth token)"
        return
    fi

    step "4.2 Session-init — register agent, create root delegation"
    export STRATIUM_OIDC_USER="$ADMIN_USER"
    export STRATIUM_SESSION_FILE="$TEST_SESSION_FILE"
    export CLAUDE_PROJECT_DIR="$TEST_PROJECT_DIR"
    rm -f "$TEST_SESSION_FILE"
    # Also clear stale agent cache to force re-registration check
    [ -f ~/.claude/stratium-agent.json ] && \
        echo "  (agent cache exists — will verify against PAP)" || true

    init_stderr=$(echo '{"hook_event_name":"UserPromptSubmit","session_id":"auto-test-001"}' \
        | node "$HOOKS_DIR/src/session-init.js" 2>&1 >/dev/null) || true

    if [ -f "$TEST_SESSION_FILE" ]; then
        pass "4.2 session file created"
        AGENT_ID=$(python3 -c "import json; print(json.load(open('${HOME}/.claude/stratium-agent.json'))['agent_id'])" 2>/dev/null || true)
        DELEGATION_TOKEN=$(python3 -c "import json; print(json.load(open('$TEST_SESSION_FILE'))['delegation_token'])")
        DELEGATION_ID=$(python3 -c "import json; print(json.load(open('$TEST_SESSION_FILE'))['delegation_id'])")
        export AGENT_ID DELEGATION_TOKEN DELEGATION_ID
        pass "4.2 delegation_id: ${DELEGATION_ID:0:8}..."
    else
        fail "4.2 session-init did not write session file — stderr: $init_stderr"
        return
    fi
    assert_contains "4.2 tier in init output" "tier:" "$init_stderr"

    step "4.3 Pre-tool-use — Read ALLOW (tier 1, gateway authorizes)"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"auto-test-001","tool_input":{"path":"src/main.go"}}'
    assert_exit "4.3 Read → exit 0 (ALLOW)" "0" "$HOOK_EXIT"

    step "4.4 Pre-tool-use — Write DENY (tier 2 > READ_ONLY cap)"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"auto-test-001","tool_input":{"path":"src/main.go"}}'
    assert_exit "4.4 Write → exit 2 (DENY, tier cap)" "2" "$HOOK_EXIT"
    assert_contains "4.4 INTERNAL_MODIFY in reason" "INTERNAL_MODIFY" "$HOOK_OUT"

    step "4.5 Pre-tool-use — Bash git push DENY (tier 3 > READ_ONLY)"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Bash","session_id":"auto-test-001","tool_input":{"command":"git push origin main"}}'
    assert_exit "4.5 Bash git push → exit 2 (DENY)" "2" "$HOOK_EXIT"

    step "4.6 Post-tool-use — audit record written to stratium-audit.jsonl"
    audit_log="${HOME}/.claude/stratium-audit.jsonl"
    run_hook "post-tool-use.js" \
        '{"hook_event_name":"PostToolUse","tool_name":"Read","session_id":"auto-test-001","tool_input":{"path":"test.go"},"tool_response":{}}'
    assert_exit "4.6 PostToolUse exits 0" "0" "$HOOK_EXIT"
    if [ -f "$audit_log" ] && tail -1 "$audit_log" | grep -q "tool_executed"; then
        pass "4.6 audit record written to stratium-audit.jsonl"
    else
        skip "4.6 audit log not found or empty (may be first run)"
    fi

    save_state
}

# ─── Section 5: Subagent Delegation Chain ────────────────────────────────────

section_5() {
    section_header 5 "Subagent Delegation Chain"

    if ! stratium_available; then
        skip "5.x — Agent Gateway not reachable at $GATEWAY_ADDR"
        return
    fi

    # Require state from section 4
    if [ -z "${DELEGATOR_TOKEN:-}" ] || [ -z "${AGENT_ID:-}" ] || [ -z "${DELEGATION_TOKEN:-}" ]; then
        load_state
    fi
    if [ -z "${DELEGATOR_TOKEN:-}" ] || [ -z "${AGENT_ID:-}" ]; then
        skip "5.x — missing DELEGATOR_TOKEN or AGENT_ID; run section 4 first (or start full Stratium stack)"
        return
    fi

    # Ensure session file env var is set (may not be set if section 5 runs standalone)
    export STRATIUM_SESSION_FILE="${STRATIUM_SESSION_FILE:-$TEST_SESSION_FILE}"

    step "5.1 Create child delegation (same tier, valid narrowing)"
    child_resp=$(AGENT_ID="$AGENT_ID" \
        PARENT_TOKEN="$DELEGATION_TOKEN" \
        DELEGATOR_TOKEN="$DELEGATOR_TOKEN" \
        node -e "
const { createDelegation } = require('$HOOKS_DIR/src/grpc-client');
const mc = JSON.parse(require('fs').readFileSync(require('os').homedir()+'/.claude/stratium.json'));
const gOpts = { gateway: mc.gateway, cacert: mc.cacert, plaintext: mc.plaintext || false };
const d = createDelegation(gOpts, {
  agent_id:                process.env.AGENT_ID,
  delegator_token:         process.env.DELEGATOR_TOKEN,
  parent_delegation_token: process.env.PARENT_TOKEN,
  max_action_tier:         1,
  approved_tools:          [],
  ttl_seconds:             3600,
  purpose:                 'automated subagent test',
  conversation_id:         'auto-test-child-001',
});
console.log(JSON.stringify(d));
" 2>/dev/null) || true

    CHILD_DELEGATION_ID=$(echo "$child_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('delegation_id',''))" 2>/dev/null || true)
    CHILD_TOKEN=$(echo "$child_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('delegation_token',''))" 2>/dev/null || true)
    child_depth=$(echo "$child_resp" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('depth',''))" 2>/dev/null || true)

    if [ -n "$CHILD_DELEGATION_ID" ] && [ "$CHILD_DELEGATION_ID" != "" ]; then
        pass "5.1 child delegation created: ${CHILD_DELEGATION_ID:0:8}..."
        export CHILD_DELEGATION_ID CHILD_TOKEN
    else
        fail "5.1 child delegation creation failed — response: $child_resp"
        return
    fi

    if [ "$child_depth" = "1" ]; then
        pass "5.1 depth=1 (correct chain depth)"
    else
        fail "5.1 depth expected 1, got: $child_depth"
    fi

    step "5.2 Write child session file"
    CHILD_DELEGATION_ID="$CHILD_DELEGATION_ID" \
    CHILD_TOKEN="$CHILD_TOKEN" \
    CHILD_SESSION_FILE="$CHILD_SESSION_FILE" \
    python3 -c "
import json, os, copy
parent = json.load(open(os.environ['STRATIUM_SESSION_FILE']))
child = copy.deepcopy(parent)
child['delegation_id']    = os.environ['CHILD_DELEGATION_ID']
child['delegation_token'] = os.environ['CHILD_TOKEN']
child['project_scope']['max_action_tier'] = 1
json.dump(child, open(os.environ['CHILD_SESSION_FILE'], 'w'), indent=2)
"
    pass "5.2 child session file written"

    step "5.3 Child Read → ALLOW (tier 1 within child scope)"
    STRATIUM_SESSION_FILE_ORIG="${STRATIUM_SESSION_FILE:-}"
    export STRATIUM_SESSION_FILE="$CHILD_SESSION_FILE"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Read","session_id":"auto-test-child-001","tool_input":{"path":"src/main.go"}}'
    assert_exit "5.3 child Read → exit 0 (ALLOW)" "0" "$HOOK_EXIT"
    export STRATIUM_SESSION_FILE="$STRATIUM_SESSION_FILE_ORIG"

    step "5.4 Child Write → DENY (tier 2 > child cap of 1)"
    export STRATIUM_SESSION_FILE="$CHILD_SESSION_FILE"
    run_hook "pre-tool-use.js" \
        '{"hook_event_name":"PreToolUse","tool_name":"Write","session_id":"auto-test-child-001","tool_input":{"path":"src/main.go"}}'
    assert_exit "5.4 child Write → exit 2 (DENY)" "2" "$HOOK_EXIT"
    export STRATIUM_SESSION_FILE="$STRATIUM_SESSION_FILE_ORIG"

    step "5.5 Escalation attempt — child at tier 2 rejected by gateway"
    escalate_exit=0
    AGENT_ID="$AGENT_ID" \
    PARENT_TOKEN="$DELEGATION_TOKEN" \
    DELEGATOR_TOKEN="$DELEGATOR_TOKEN" \
    node -e "
const { createDelegation } = require('$HOOKS_DIR/src/grpc-client');
const mc = JSON.parse(require('fs').readFileSync(require('os').homedir()+'/.claude/stratium.json'));
const gOpts = { gateway: mc.gateway, cacert: mc.cacert, plaintext: mc.plaintext || false };
try {
  createDelegation(gOpts, {
    agent_id:                process.env.AGENT_ID,
    delegator_token:         process.env.DELEGATOR_TOKEN,
    parent_delegation_token: process.env.PARENT_TOKEN,
    max_action_tier:         2,
    approved_tools:          [],
    ttl_seconds:             3600,
    purpose:                 'escalation test',
    conversation_id:         'auto-test-escalation',
  });
  process.exit(1);   // should never reach here
} catch (e) {
  process.exit(0);   // error = correctly rejected
}
" 2>/dev/null || escalate_exit=$?
    assert_exit "5.5 escalation attempt rejected by gateway" "0" "$escalate_exit"

    save_state
}

# ─── Section clean ────────────────────────────────────────────────────────────

section_clean() {
    section_header "clean" "Cleanup"
    rm -f "$TEST_SESSION_FILE" "$CHILD_SESSION_FILE" "$STATE_FILE" /tmp/hook-stderr.txt
    rm -rf "$TEST_PROJECT_DIR"
    echo -e "  ${GREEN}✓${NC} Temp files removed"
}

# ─── Main ──────────────────────────────────────────────────────────────────────

# Must run from project root
if [ ! -f "go/config/config.go" ]; then
    echo "Error: run from the project root (stratium/)"
    exit 1
fi

if [ ! -d "$HOOKS_DIR" ]; then
    echo "Error: sdk/claude-hooks not found at $HOOKS_DIR"
    exit 1
fi

SECTION="${1:-all}"

load_state

case "$SECTION" in
    1)    section_1 ;;
    2)    section_2 ;;
    3)    section_3 ;;
    4)    section_4 ;;
    5)    section_5 ;;
    clean) section_clean; exit 0 ;;
    all)
        section_1
        section_2
        section_3
        section_4
        section_5
        ;;
    *)
        echo "Usage: $0 [1|2|3|4|5|all|clean]"
        exit 1
        ;;
esac

summary
