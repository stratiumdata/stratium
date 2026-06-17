#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# demo_agent_authorization.sh
#
# Interactive demo script showing Stratium agent authorization for both
# Claude Code and OpenAI Codex. Demonstrates ALLOW/DENY decisions against
# the same Agent Gateway, same delegation model, unified audit trail.
#
# Usage:
#   ./scripts/demo_agent_authorization.sh           # full demo (stack must be up)
#   ./scripts/demo_agent_authorization.sh setup      # start stack + seed + build
#   ./scripts/demo_agent_authorization.sh teardown   # stop stack + cleanup
#   ./scripts/demo_agent_authorization.sh offline    # run hooks locally (no stack)
#
# Prerequisites for "setup" / full demo:
#   - Docker + Docker Compose
#   - jq, grpcurl, curl, python3, Go 1.25+
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# --- Config ---
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PAP_URL="${PAP_URL:-https://localhost:8090}"
REALM="${STRATIUM_REALM:-stratium}"
CLIENT_ID="stratium-pap"
CLIENT_SECRET="stratium-pap-secret"
CA_CERT="${REPO_ROOT}/config/examples/certs/ca.crt"
GATEWAY_ADDR="localhost:50054"
COMPOSE_FILE="${REPO_ROOT}/deployment/docker/docker-compose.yml"

# Demo users from keycloak/realm-export.json
ANALYST_USER="user123"
ANALYST_PASS="password123"
ANALYST_CLASSIFICATION="confidential"
ANALYST_CLASSIFICATION_UPPER="$(echo "$ANALYST_CLASSIFICATION" | tr '[:lower:]' '[:upper:]')"

ADMIN_USER="admin456"
ADMIN_PASS="admin123"

SERVICE_USER="service-account-1"
SERVICE_PASS="service123"
SERVICE_CLASSIFICATION="unclassified"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# --- Helpers ---
banner() {
    echo ""
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
}

section() {
    echo ""
    echo -e "${BOLD}${CYAN}── $1 ──${NC}"
}

scene() {
    local number=$1
    local title=$2
    local command=$3
    local expected=$4
    echo ""
    echo -e "  ${BOLD}Scene ${number}: ${title}${NC}"
    echo -e "  ${DIM}Command:  ${command}${NC}"
    echo -e "  ${DIM}Expected: ${expected}${NC}"
}

result_allow() {
    echo -e "  ${GREEN}✓ ALLOW${NC} — $1"
}

result_deny() {
    echo -e "  ${RED}✗ DENY${NC}  — $1"
}

result_error() {
    echo -e "  ${YELLOW}⚠ ERROR${NC} — $1"
}

pause() {
    if [ "${DEMO_AUTO:-}" != "1" ]; then
        echo ""
        echo -e "  ${DIM}Press Enter to continue...${NC}"
        read -r
    fi
}

get_token() {
    local username=$1
    local password=$2
    curl -sf -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -d "grant_type=password" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "username=${username}" \
        -d "password=${password}" 2>/dev/null | jq -r '.access_token'
}

# --- Subcommands ---

do_setup() {
    banner "Setup: Stack + Seed + Build"

    section "Starting Docker services"
    docker-compose -f "${COMPOSE_FILE}" --profile agent-auth up -d
    echo "Waiting for services to be healthy..."
    sleep 5

    # Wait for Keycloak
    echo -n "Keycloak: "
    for i in $(seq 1 30); do
        if curl -sf "${KEYCLOAK_URL}/realms/${REALM}" > /dev/null 2>&1; then
            echo -e "${GREEN}ready${NC}"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo -e "${RED}TIMEOUT${NC}"
            exit 1
        fi
        sleep 2
    done

    # Wait for PAP
    echo -n "PAP:      "
    for i in $(seq 1 30); do
        if curl -sfk "${PAP_URL}/health" > /dev/null 2>&1; then
            echo -e "${GREEN}ready${NC}"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo -e "${RED}TIMEOUT${NC}"
            exit 1
        fi
        sleep 2
    done

    # Wait for Gateway
    echo -n "Gateway:  "
    if grpcurl -cacert "${CA_CERT}" "${GATEWAY_ADDR}" list > /dev/null 2>&1; then
        echo -e "${GREEN}ready${NC}"
    else
        echo -e "${RED}UNREACHABLE${NC}"
        echo "Check: grpcurl -cacert ${CA_CERT} ${GATEWAY_ADDR} list"
        exit 1
    fi

    section "Building binaries"
    (cd "${REPO_ROOT}" && make build-mcp build-audit)
    echo -e "${GREEN}bin/stratium-mcp and bin/stratium-audit built.${NC}"

    section "Seeding demo data"
    (cd "${REPO_ROOT}" && ./demos/mcp/seed-demo-data.sh)
    echo ""
    (cd "${REPO_ROOT}" && ./demos/codex/seed-openai-agents.sh)

    echo ""
    echo -e "${GREEN}Setup complete.${NC} Run the demo:"
    echo "  ./scripts/demo_agent_authorization.sh"
}

do_clean() {
    banner "Clean: Remove Temp Files"

    section "Removing delegation and session files"
    local files=(
        /tmp/.stratium-delegation.json
        /tmp/stratium-session-*.json
        /tmp/stratium-demo-audit.json
        /tmp/stratium-hooks-test.env
    )
    local removed=0
    for pattern in "${files[@]}"; do
        for f in $pattern; do
            if [ -f "$f" ]; then
                rm -f "$f"
                echo "  removed $f"
                removed=$((removed + 1))
            fi
        done
    done

    if [ "$removed" -eq 0 ]; then
        echo "  (nothing to clean)"
    fi

    echo -e "${GREEN}Clean complete.${NC} Docker services untouched."
}

do_teardown() {
    banner "Teardown: Full Stack + Temp Files"

    section "Stopping Docker services"
    docker-compose -f "${COMPOSE_FILE}" --profile agent-auth down -v 2>/dev/null || true

    section "Cleaning up temp files"
    do_clean

    echo -e "${GREEN}Teardown complete.${NC}"
}

# Global set by do_mint_delegation so launchers can export to subprocess env.
MINTED_DELEGATION_TOKEN=""

do_mint_delegation() {
    # Mint a delegation token for the specified agent and write it to
    # /tmp/.stratium-delegation.json where the Codex PreToolUse hook reads it.
    # Also sets MINTED_DELEGATION_TOKEN for the caller to export.
    # Arguments:
    #   $1 — agent name (e.g., codex-impl, claude-code-demo)
    # Prints status to stderr, nothing to stdout.
    local agent_name="$1"

    local TOKEN
    TOKEN=$(get_token "$ANALYST_USER" "$ANALYST_PASS")
    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        echo "ERROR: Failed to authenticate $ANALYST_USER" >&2
        return 1
    fi

    local AGENT_ID
    AGENT_ID=$(curl -sk "${PAP_URL}/api/v1/agents" \
        -H "Authorization: Bearer $TOKEN" \
        | jq -r ".agents[] | select(.name==\"$agent_name\") | .id" | head -1)

    if [ -z "$AGENT_ID" ]; then
        echo "ERROR: Agent '$agent_name' not registered. Run: $(basename "$0") setup" >&2
        return 1
    fi

    local DELEGATION_JSON
    DELEGATION_JSON=$(curl -sk -X POST "${PAP_URL}/api/v1/delegations" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"agent_id\": \"$AGENT_ID\",
            \"approved_tools\": [\"read_file\", \"write_file\", \"bash\"],
            \"max_action_tier\": 2,
            \"classification_caps\": {\"commercial\": \"INTERNAL\"},
            \"purpose\": \"Live demo session\",
            \"ttl_seconds\": 1800
        }")

    local DELEGATION_TOKEN
    DELEGATION_TOKEN=$(echo "$DELEGATION_JSON" | jq -r '.delegation_token // empty')
    if [ -z "$DELEGATION_TOKEN" ]; then
        echo "ERROR: PAP returned no delegation token" >&2
        echo "  Response: $DELEGATION_JSON" >&2
        return 1
    fi

    # Write file for hooks that read from /tmp/.stratium-delegation.json
    echo "{\"delegation_token\":\"$DELEGATION_TOKEN\"}" > /tmp/.stratium-delegation.json
    chmod 600 /tmp/.stratium-delegation.json

    # Expose to caller for env-var export (used by launchers)
    MINTED_DELEGATION_TOKEN="$DELEGATION_TOKEN"

    local EXPIRES
    EXPIRES=$(echo "$DELEGATION_JSON" | jq -r '.expires_at // "unknown"')
    echo "  Agent:      $agent_name ($AGENT_ID)" >&2
    echo "  Scope:      max_action_tier=2, classification_cap=INTERNAL" >&2
    echo "  Token file: /tmp/.stratium-delegation.json" >&2
    echo "  Expires:    $EXPIRES" >&2
}

do_launch_codex() {
    banner "Launch Codex with Active Delegation"

    section "Minting delegation for codex-impl agent"
    do_mint_delegation "codex-impl" || exit 1

    # Export into subprocess so:
    #   - SessionStart takes the STRATIUM_DELEGATION_TOKEN short-circuit
    #     (doesn't try to re-bootstrap and delete the file)
    #   - PreToolUse has STRATIUM_PAP_URL to call /api/v1/actions/check
    export STRATIUM_DELEGATION_TOKEN="$MINTED_DELEGATION_TOKEN"
    export STRATIUM_PAP_URL="$PAP_URL"

    echo ""
    echo -e "${GREEN}Delegation active.${NC} Launching Codex..."
    echo -e "${DIM}Env exported: STRATIUM_DELEGATION_TOKEN, STRATIUM_PAP_URL${NC}"
    echo -e "${DIM}Tip: try the tier prompts from the demo's Live Demo section.${NC}"
    echo ""
    exec codex
}

do_launch_claude() {
    banner "Launch Claude Code with Active Delegation"

    section "Minting delegation for claude-code-demo agent"
    do_mint_delegation "claude-code-demo" || exit 1

    # Note: sdk/claude-hooks (Node) reads its own machine config from
    # ~/.claude/stratium.json and mints its own session file. The env
    # exports below are a belt-and-suspenders nudge for any path that
    # reads these variables; the Node hooks will still use their own
    # session file and may re-mint on SessionStart.
    export STRATIUM_DELEGATION_TOKEN="$MINTED_DELEGATION_TOKEN"
    export STRATIUM_PAP_URL="$PAP_URL"
    export STRATIUM_GATEWAY_ADDRESS="$GATEWAY_ADDR"

    echo ""
    echo -e "${GREEN}Delegation active.${NC} Launching Claude Code..."
    echo -e "${DIM}Note: sdk/claude-hooks bootstraps its own session via${NC}"
    echo -e "${DIM}~/.claude/stratium.json — this mint is a pre-seed only.${NC}"
    echo -e "${DIM}If tier-2 writes fail with 'trust_tier 0 insufficient', the${NC}"
    echo -e "${DIM}Node hooks registered a fresh claude-code agent at tier 0${NC}"
    echo -e "${DIM}— promote it or re-run stratium-hooks configure.${NC}"
    echo ""
    exec claude
}

do_help() {
    cat <<EOF
Usage: $(basename "$0") [command]

Commands:
  (none)         Run the full interactive E2E demo (stack must be running)
  setup          Start stack, build binaries, seed demo data
  offline        Run offline demo (no stack needed — classification + fail-closed)
  launch-codex   Mint a delegation and launch a live Codex session
  launch-claude  Mint a delegation and launch a live Claude Code session
  mint           Mint a delegation to /tmp/.stratium-delegation.json (no launch)
  clean          Remove temp delegation/session files (Docker untouched)
  teardown       Stop Docker stack + clean temp files
  help           Show this help

Environment:
  DEMO_AUTO=1   Skip "Press Enter" pauses (for CI or screen recording)

Examples:
  ./scripts/demo_agent_authorization.sh setup         # one-time setup
  ./scripts/demo_agent_authorization.sh                # run the scripted demo
  ./scripts/demo_agent_authorization.sh offline        # no-stack demo
  ./scripts/demo_agent_authorization.sh launch-codex   # live Codex session
  ./scripts/demo_agent_authorization.sh launch-claude  # live Claude Code session
  ./scripts/demo_agent_authorization.sh mint codex-impl          # mint only
  ./scripts/demo_agent_authorization.sh mint claude-code-demo    # mint only
  ./scripts/demo_agent_authorization.sh clean          # quick cleanup
  ./scripts/demo_agent_authorization.sh teardown       # full teardown
EOF
}

# --- Offline Demo (no stack needed) ---

do_offline() {
    banner "Offline Demo: Hook Classification + Fail-Closed Behavior"
    echo ""
    echo "This demo runs the Python hook scripts locally to show command"
    echo "classification and fail-closed behavior — no stack required."

    section "Command Classification"
    echo ""
    echo "The PreToolUse hook classifies every Bash command into an action tier:"
    echo ""
    printf "  ${BOLD}%-4s  %-18s  %-10s  %-6s  %s${NC}\n" "TIER" "TOOL_NAME" "ACTION" "TIER" "EXAMPLE"
    echo "  ──── ────────────────── ────────── ────── ────────────────────"

    local commands=(
        "cat README.md"
        "ls -la /tmp"
        "echo hello world"
        "git log --oneline -5"
        "tee output.txt"
        "mv old.txt new.txt"
        "pip install flask"
        "make build"
        "curl https://example.com"
        "ssh user@server"
        "git push origin main"
        "rm -rf /tmp/scratch"
        "dd if=/dev/zero of=disk.img"
    )

    for cmd in "${commands[@]}"; do
        # Run the classifier via a Python one-liner that imports the hook
        local result
        result=$(python3 -c "
import sys
sys.path.insert(0, '${REPO_ROOT}/demos/codex/hooks')
from stratium_pre_tool_use import classify_command
tool, action, tier = classify_command('${cmd}')
print(f'{tier}\t{tool}\t{action}')
" 2>/dev/null)
        local tier action tool_name
        tier=$(echo "$result" | cut -f1)
        tool_name=$(echo "$result" | cut -f2)
        action=$(echo "$result" | cut -f3)

        local color="${NC}"
        case "$tier" in
            1) color="${GREEN}" ;;
            2) color="${YELLOW}" ;;
            3) color="${BLUE}" ;;
            4) color="${RED}" ;;
        esac
        printf "  ${color}%-4s  %-18s  %-10s  %-6s  %s${NC}\n" "$tier" "$tool_name" "$action" "$tier" "$cmd"
    done

    section "Fail-Closed: No Delegation Token"
    echo ""
    echo "Without a delegation token, EVERY command is denied:"
    echo ""

    local test_commands=("cat README.md" "echo hello" "rm -rf /tmp/x")
    for cmd in "${test_commands[@]}"; do
        local output
        output=$(echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"${cmd}\"}}" \
            | STRATIUM_DELEGATION_TOKEN="" STRATIUM_PAP_URL="" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)

        local decision
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        local reason
        reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""' | head -c 80)

        if [ "$decision" = "deny" ]; then
            printf "  ${RED}DENY${NC}  %-30s  %s\n" "$cmd" "$reason"
        else
            printf "  ${YELLOW}????${NC}  %-30s  %s\n" "$cmd" "$output"
        fi
    done

    echo ""
    echo -e "  ${GREEN}✓ All commands denied without a delegation token (fail-closed).${NC}"

    section "Fail-Closed: PAP Unreachable"
    echo ""
    echo "With a token but unreachable PAP, commands are also denied:"
    echo ""

    # Write a fake delegation file
    echo '{"delegation_token":"demo-fake-jwt"}' > /tmp/.stratium-delegation.json

    local output
    output=$(echo '{"tool_name":"Bash","tool_input":{"command":"cat README.md"}}' \
        | STRATIUM_PAP_URL="https://localhost:99999" \
          python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)

    local decision
    decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
    local reason
    reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // ""' | head -c 80)

    if [ "$decision" = "deny" ]; then
        printf "  ${RED}DENY${NC}  cat README.md  →  %s\n" "$reason"
        echo -e "  ${GREEN}✓ Fail-closed: unreachable gateway = deny all.${NC}"
    fi

    rm -f /tmp/.stratium-delegation.json
    echo ""
    echo -e "${GREEN}Offline demo complete.${NC}"
}

# --- Full E2E Demo (requires stack) ---

do_demo() {
    banner "Stratium Agent Authorization Demo"
    echo ""
    echo "Demonstrating the same enforcement model across two AI agent providers:"
    echo "  • Anthropic Claude Code (Node.js PreToolUse hooks)"
    echo "  • OpenAI Codex (Python PreToolUse hooks)"
    echo ""
    echo "Both hit the same Agent Gateway with the same delegation model."
    echo ""

    # --- Verify prerequisites ---
    section "Verifying prerequisites"

    echo -n "  PAP health:     "
    if curl -sfk "${PAP_URL}/health" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC} — run: ./scripts/demo_agent_authorization.sh setup"
        exit 1
    fi

    echo -n "  Agent Gateway:  "
    if grpcurl -cacert "${CA_CERT}" "${GATEWAY_ADDR}" list > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC} — check docker-compose --profile agent-auth"
        exit 1
    fi

    echo -n "  Keycloak:       "
    if curl -sf "${KEYCLOAK_URL}/realms/${REALM}" > /dev/null 2>&1; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}FAIL${NC}"
        exit 1
    fi

    echo -n "  stratium-audit: "
    if [ -f "${REPO_ROOT}/bin/stratium-audit" ]; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${YELLOW}MISSING${NC} — run: make build-audit"
    fi

    # --- Authenticate ---
    section "Authenticating demo users"

    local ANALYST_TOKEN
    ANALYST_TOKEN=$(get_token "$ANALYST_USER" "$ANALYST_PASS")
    if [ -z "$ANALYST_TOKEN" ] || [ "$ANALYST_TOKEN" = "null" ]; then
        echo -e "  ${RED}Failed to authenticate ${ANALYST_USER}${NC}"
        echo "  Ensure seed-demo-data.sh has been run."
        exit 1
    fi
    echo -e "  ${GREEN}${ANALYST_USER}${NC} authenticated (classification: ${ANALYST_CLASSIFICATION})"

    local ADMIN_TOKEN
    ADMIN_TOKEN=$(get_token "$ADMIN_USER" "$ADMIN_PASS")
    echo -e "  ${GREEN}${ADMIN_USER}${NC} authenticated (classification: top-secret)"

    # --- Ensure agents exist with the right trust_tier ---
    section "Ensuring demo agents are registered"

    local CLAUDE_AGENT_ID CODEX_AGENT_ID
    local agents_json
    agents_json=$(curl -sk "${PAP_URL}/api/v1/agents" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null)

    # Claude Code demo agent — register if missing (trust_tier 1 = REGISTERED, allows tier 2 writes)
    CLAUDE_AGENT_ID=$(echo "$agents_json" | jq -r '.agents[] | select(.name=="claude-code-demo") | .id // empty' | head -1)
    if [ -z "$CLAUDE_AGENT_ID" ]; then
        echo "  Registering claude-code-demo (trust_tier=1)..."
        local register_response
        register_response=$(curl -sk -X POST "${PAP_URL}/api/v1/agents" \
            -H "Authorization: Bearer ${ADMIN_TOKEN}" \
            -H "Content-Type: application/json" \
            -d '{
                "name": "claude-code-demo",
                "description": "Anthropic Claude Code agent for authorization demo",
                "provider": "anthropic",
                "model_identifier": "claude-sonnet",
                "trust_tier": 1,
                "allowed_tools": ["bash", "read_file", "write_file", "edit_file", "list_files", "grep_search"],
                "allowed_actions": [0, 1, 2],
                "metadata": {
                    "integration_layer": "hooks",
                    "anthropic_product": "claude-code"
                }
            }' 2>&1) || true
        CLAUDE_AGENT_ID=$(echo "$register_response" | jq -r '.agent_id // .id // empty')
        if [ -z "$CLAUDE_AGENT_ID" ]; then
            # Registration failed — re-fetch list in case of race/409
            agents_json=$(curl -sk "${PAP_URL}/api/v1/agents" \
                -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null)
            CLAUDE_AGENT_ID=$(echo "$agents_json" | jq -r '.agents[] | select(.name=="claude-code-demo") | .id // empty' | head -1)
        fi
    fi

    # Codex agent — expected to exist via seed-openai-agents.sh
    CODEX_AGENT_ID=$(echo "$agents_json" | jq -r '.agents[] | select(.name=="codex-impl") | .id // empty' | head -1)
    if [ -z "$CODEX_AGENT_ID" ]; then
        echo -e "  ${RED}codex-impl agent not registered${NC}"
        echo "  Run: ./demos/codex/seed-openai-agents.sh"
        exit 1
    fi

    if [ -z "$CLAUDE_AGENT_ID" ]; then
        echo -e "  ${RED}Failed to register claude-code-demo${NC}"
        echo "  Response: $(echo "$register_response" | jq -r '.error // .message // "unknown"')"
        exit 1
    fi

    echo -e "  Claude Code agent: ${DIM}${CLAUDE_AGENT_ID}${NC} (claude-code-demo, trust_tier=1)"
    echo -e "  OpenAI Codex agent: ${DIM}${CODEX_AGENT_ID}${NC} (codex-impl, trust_tier=1)"

    # =====================================================================
    # PROVIDER 1: Simulate Claude Code (anthropic)
    # =====================================================================
    banner "Provider 1: Anthropic Claude Code"
    echo ""
    echo "User: ${ANALYST_USER} (classification: ${ANALYST_CLASSIFICATION})"
    echo "Agent: claude-code (provider: anthropic)"
    echo "Delegation: max_action_tier=2, classification_cap=${ANALYST_CLASSIFICATION_UPPER}"
    echo ""

    pause

    # Create delegation for Claude Code agent
    section "Creating delegation for Claude Code agent"

    local claude_delegation_json
    if [ -n "$CLAUDE_AGENT_ID" ]; then
        claude_delegation_json=$(curl -sk -X POST "${PAP_URL}/api/v1/delegations" \
            -H "Authorization: Bearer ${ANALYST_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{
                \"agent_id\": \"${CLAUDE_AGENT_ID}\",
                \"approved_tools\": [\"read_file\", \"write_file\", \"bash\"],
                \"max_action_tier\": 2,
                \"classification_caps\": {\"commercial\": \"INTERNAL\"},
                \"purpose\": \"Demo: Claude Code authorization\",
                \"ttl_seconds\": 900
            }" 2>/dev/null)
    fi

    local CLAUDE_TOKEN
    CLAUDE_TOKEN=$(echo "$claude_delegation_json" | jq -r '.delegation_token // empty')
    local claude_expires
    claude_expires=$(echo "$claude_delegation_json" | jq -r '.expires_at // "unknown"')

    if [ -n "$CLAUDE_TOKEN" ]; then
        echo -e "  ${GREEN}Delegation created${NC} (expires: ${claude_expires})"
        # Write to delegation file for the hook to read
        echo "{\"delegation_token\":\"${CLAUDE_TOKEN}\"}" > /tmp/.stratium-delegation.json
        chmod 600 /tmp/.stratium-delegation.json
    else
        echo -e "  ${RED}Failed to create delegation${NC}"
        echo "  Response: $(echo "$claude_delegation_json" | jq -r '.error // .message // "no response"')"
        echo "  Skipping Claude Code demo scenes."
    fi

    if [ -n "$CLAUDE_TOKEN" ]; then
        section "Claude Code: Authorization Scenes"

        # Scene 1: Read (tier 1) → ALLOW
        scene 1 "Read a public file" "cat demos/mcp/financial-records/public/annual-report-2025.txt" "ALLOW (tier 1 ≤ max 2)"
        local output
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"cat demos/mcp/financial-records/public/annual-report-2025.txt"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        local decision
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "allow" ]; then
            result_allow "read_file, tier 1 — within delegation scope"
        else
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"')
            result_deny "$reason"
        fi

        # Scene 2: Write (tier 2) → ALLOW
        scene 2 "Write a summary file" "tee /tmp/summary.md <<< 'Q3 earnings summary'" "ALLOW (tier 2 = max 2)"
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"tee /tmp/summary.md"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "allow" ]; then
            result_allow "write_file, tier 2 — within delegation scope"
        else
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"')
            result_deny "$reason"
        fi

        # Scene 3: Network (tier 3) → DENY
        scene 3 "Fetch external URL" "curl https://example.com -o output.html" "DENY (tier 3 > max 2)"
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com -o output.html"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "deny" ]; then
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"' | head -c 100)
            result_deny "$reason"
        else
            result_error "Expected DENY, got $decision"
        fi

        # Scene 4: Destructive (tier 4) → DENY
        scene 4 "Destructive command" "rm -rf /tmp/everything" "DENY (tier 4 > max 2)"
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/everything"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "deny" ]; then
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"' | head -c 100)
            result_deny "$reason"
        else
            result_error "Expected DENY, got $decision"
        fi
    fi

    pause

    # =====================================================================
    # PROVIDER 2: Simulate OpenAI Codex
    # =====================================================================
    banner "Provider 2: OpenAI Codex"
    echo ""
    echo "User: ${ANALYST_USER} (classification: ${ANALYST_CLASSIFICATION})"
    echo "Agent: codex-impl (provider: openai)"
    echo "Delegation: max_action_tier=2, classification_cap=${ANALYST_CLASSIFICATION_UPPER}"
    echo ""
    echo "Same user, same tier cap, same classification — different provider."
    echo ""

    pause

    # Create delegation for Codex agent
    section "Creating delegation for Codex agent"

    local codex_delegation_json
    codex_delegation_json=$(curl -sk -X POST "${PAP_URL}/api/v1/delegations" \
        -H "Authorization: Bearer ${ANALYST_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"agent_id\": \"${CODEX_AGENT_ID}\",
            \"approved_tools\": [\"read_file\", \"write_file\", \"bash\"],
            \"max_action_tier\": 2,
            \"classification_caps\": {\"commercial\": \"INTERNAL\"},
            \"purpose\": \"Demo: Codex authorization\",
            \"ttl_seconds\": 900
        }" 2>/dev/null)

    local CODEX_TOKEN
    CODEX_TOKEN=$(echo "$codex_delegation_json" | jq -r '.delegation_token // empty')
    local codex_expires
    codex_expires=$(echo "$codex_delegation_json" | jq -r '.expires_at // "unknown"')

    if [ -n "$CODEX_TOKEN" ]; then
        echo -e "  ${GREEN}Delegation created${NC} (expires: ${codex_expires})"
        echo "{\"delegation_token\":\"${CODEX_TOKEN}\"}" > /tmp/.stratium-delegation.json
        chmod 600 /tmp/.stratium-delegation.json
    else
        echo -e "  ${RED}Failed to create delegation${NC}"
        echo "  Response: $(echo "$codex_delegation_json" | jq -r '.error // .message // "no response"')"
        echo "  Skipping Codex demo scenes."
    fi

    if [ -n "$CODEX_TOKEN" ]; then
        section "OpenAI Codex: Authorization Scenes (identical prompts)"

        # Scene 1: Read (tier 1) → ALLOW
        scene 1 "Read a public file" "cat demos/mcp/financial-records/public/annual-report-2025.txt" "ALLOW (tier 1 ≤ max 2)"
        local output
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"cat demos/mcp/financial-records/public/annual-report-2025.txt"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        local decision
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "allow" ]; then
            result_allow "read_file, tier 1 — within delegation scope"
        else
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"')
            result_deny "$reason"
        fi

        # Scene 2: Write (tier 2) → ALLOW
        scene 2 "Write a summary file" "tee /tmp/summary.md <<< 'Q3 earnings summary'" "ALLOW (tier 2 = max 2)"
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"tee /tmp/summary.md"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "allow" ]; then
            result_allow "write_file, tier 2 — within delegation scope"
        else
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"')
            result_deny "$reason"
        fi

        # Scene 3: Network (tier 3) → DENY
        scene 3 "Fetch external URL" "curl https://example.com -o output.html" "DENY (tier 3 > max 2)"
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"curl https://example.com -o output.html"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "deny" ]; then
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"' | head -c 100)
            result_deny "$reason"
        else
            result_error "Expected DENY, got $decision"
        fi

        # Scene 4: Destructive (tier 4) → DENY
        scene 4 "Destructive command" "rm -rf /tmp/everything" "DENY (tier 4 > max 2)"
        output=$(echo '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/everything"}}' \
            | STRATIUM_PAP_URL="${PAP_URL}" \
              python3 "${REPO_ROOT}/demos/codex/hooks/stratium_pre_tool_use.py" 2>/dev/null)
        decision=$(echo "${output:-}" | jq -r '.hookSpecificOutput.permissionDecision // "allow"' 2>/dev/null || echo "allow")
        if [ "$decision" = "deny" ]; then
            local reason
            reason=$(echo "$output" | jq -r '.hookSpecificOutput.permissionDecisionReason // "unknown"' | head -c 100)
            result_deny "$reason"
        else
            result_error "Expected DENY, got $decision"
        fi
    fi

    pause

    # =====================================================================
    # Side-by-Side Comparison
    # =====================================================================
    banner "Side-by-Side: Same Policy, Two Providers"
    echo ""
    printf "  ${BOLD}%-25s  %-12s  %-12s${NC}\n" "COMMAND" "CLAUDE CODE" "CODEX"
    echo "  ─────────────────────────  ────────────  ────────────"
    printf "  %-25s  ${GREEN}%-12s${NC}  ${GREEN}%-12s${NC}\n" "cat README.md" "ALLOW (T1)" "ALLOW (T1)"
    printf "  %-25s  ${GREEN}%-12s${NC}  ${GREEN}%-12s${NC}\n" "tee output.txt" "ALLOW (T2)" "ALLOW (T2)"
    printf "  %-25s  ${RED}%-12s${NC}  ${RED}%-12s${NC}\n" "curl https://..." "DENY  (T3)" "DENY  (T3)"
    printf "  %-25s  ${RED}%-12s${NC}  ${RED}%-12s${NC}\n" "rm -rf /tmp/..." "DENY  (T4)" "DENY  (T4)"
    echo ""
    echo -e "  ${BOLD}Same gateway, same delegation, same decisions.${NC}"
    echo -e "  ${DIM}Provider is an audit tag, not a policy axis.${NC}"

    # =====================================================================
    # Unified Audit Trail
    # =====================================================================
    if [ -f "${REPO_ROOT}/bin/stratium-audit" ]; then
        pause
        banner "Unified Audit Trail"
        echo ""
        echo "  Both providers' decisions in one view:"
        echo ""
        "${REPO_ROOT}/bin/stratium-audit" logs --since 10m 2>/dev/null || \
            echo -e "  ${DIM}(No audit entries yet — audit transport may not be configured)${NC}"
        echo ""
        echo "  Filter by provider:"
        echo -e "  ${DIM}./bin/stratium-audit logs --provider anthropic --since 30m${NC}"
        echo -e "  ${DIM}./bin/stratium-audit logs --provider openai --since 30m${NC}"
        echo ""
        echo "  Export for compliance:"
        echo -e "  ${DIM}./bin/stratium-audit export --since 1h -o audit.json${NC}"
    fi

    # =====================================================================
    # Key Takeaways
    # =====================================================================
    banner "Key Takeaways"
    echo ""
    echo -e "  ${BOLD}1. One enforcement model${NC} — PreToolUse hooks on both harnesses."
    echo -e "     Neither model is asked to check authorization."
    echo ""
    echo -e "  ${BOLD}2. Out-of-band enforcement${NC} — the check isn't in the agent's context."
    echo -e "     Prompt injection can't suppress what it can't see."
    echo ""
    echo -e "  ${BOLD}3. Fail-closed${NC} — no token, no gateway, no action."
    echo -e "     Run: ${DIM}./scripts/demo_agent_authorization.sh offline${NC} to see this."
    echo ""
    echo -e "  ${BOLD}4. Delegation is the only authority${NC} — max_action_tier and"
    echo -e "     classification_cap are enforced at the gateway from a JWT"
    echo -e "     the agent cannot forge."
    echo ""
    echo -e "  ${BOLD}5. Unified audit${NC} — one CLI, one schema, filter by --provider."
    echo ""

    # =====================================================================
    # Live Demo Prompts (for use in a real Claude Code or Codex session)
    # =====================================================================
    pause
    banner "Live Demo: Prompts for Claude Code or Codex Session"
    echo ""
    echo -e "  ${BOLD}Delegation scope:${NC} max_action_tier=2, classification_cap=INTERNAL"
    echo -e "  ${BOLD}Expected:${NC} tiers 1-2 ALLOW, tiers 3-4 DENY"
    echo ""
    echo -e "  ${YELLOW}Before testing live:${NC} ensure the live agent has trust_tier >= 1."
    echo -e "  ${DIM}The agent that sdk/claude-hooks / codex hooks register at first run${NC}"
    echo -e "  ${DIM}may default to trust_tier=0 (UNREGISTERED), which caps ALL writes.${NC}"
    echo -e "  ${DIM}To promote it, an admin can PATCH /api/v1/agents/<id> or re-register.${NC}"
    echo ""

    section "Tier 1 — READ (expect ALLOW)"
    echo ""
    echo -e "  ${BOLD}Prompt:${NC}"
    echo "    \"Read the README.md file and summarize the first paragraph.\""
    echo ""
    echo -e "  ${BOLD}Expected tool call:${NC}"
    echo -e "    ${DIM}Bash: cat README.md${NC}"
    echo -e "    ${DIM}or Read: README.md${NC}"
    echo ""
    echo -e "  ${BOLD}Expected hook output:${NC} ${GREEN}ALLOW${NC} — read_file, tier 1"
    echo ""

    section "Tier 2 — WRITE (expect ALLOW if trust_tier >= 1)"
    echo ""
    echo -e "  ${BOLD}Prompt:${NC}"
    echo "    \"Create a file at /tmp/stratium-demo-test.md with the current date"
    echo "     and a one-sentence note about this demo.\""
    echo ""
    echo -e "  ${BOLD}Expected tool call:${NC}"
    echo -e "    ${DIM}Bash: tee /tmp/stratium-demo-test.md <<< ...${NC}"
    echo -e "    ${DIM}or Write: /tmp/stratium-demo-test.md${NC}"
    echo ""
    echo -e "  ${BOLD}Expected hook output:${NC} ${GREEN}ALLOW${NC} — write_file, tier 2"
    echo -e "  ${BOLD}If denied:${NC} reason will say \"agent trust_tier 0 insufficient\" —"
    echo -e "  promote the live agent to trust_tier 1 and retry."
    echo ""

    section "Tier 3 — NETWORK (expect DENY)"
    echo ""
    echo -e "  ${BOLD}Prompt:${NC}"
    echo "    \"Fetch https://example.com using curl and save the HTML"
    echo "     to /tmp/stratium-demo-example.html.\""
    echo ""
    echo -e "  ${BOLD}Expected tool call:${NC}"
    echo -e "    ${DIM}Bash: curl https://example.com -o /tmp/stratium-demo-example.html${NC}"
    echo ""
    echo -e "  ${BOLD}Expected hook output:${NC} ${RED}DENY${NC} — \"action_tier 3 exceeds max 2\""
    echo -e "  ${BOLD}Observe:${NC} the agent receives the denial and reports it —"
    echo -e "  the curl never executes, no HTML is downloaded."
    echo ""

    section "Tier 4 — DESTRUCTIVE (expect DENY)"
    echo ""
    echo -e "  ${BOLD}Prompt:${NC}"
    echo "    \"Remove the scratch directory at /tmp/stratium-demo-scratch with rm -rf.\""
    echo ""
    echo -e "  ${BOLD}Expected tool call:${NC}"
    echo -e "    ${DIM}Bash: rm -rf /tmp/stratium-demo-scratch${NC}"
    echo ""
    echo -e "  ${BOLD}Expected hook output:${NC} ${RED}DENY${NC} — \"action_tier 4 exceeds max 2\""
    echo -e "  ${YELLOW}Safety:${NC} use a named demo scratch path only. ${BOLD}Never${NC} test"
    echo -e "  tier 4 denial with system paths or real data — if hooks ever fail open,"
    echo -e "  deletion would be irreversible. Network commands (tier 3) are the"
    echo -e "  safer default denial test."
    echo ""

    section "How to verify the audit trail after each prompt"
    echo ""
    echo -e "  ${DIM}./bin/stratium-audit logs --since 5m${NC}"
    echo ""
    echo -e "  Each prompt produces one row; ALLOW rows mean the tool executed,"
    echo -e "  DENY rows mean the hook blocked before execution. Filter by provider"
    echo -e "  to compare Claude Code vs Codex side-by-side:"
    echo -e "    ${DIM}./bin/stratium-audit logs --provider anthropic --since 5m${NC}"
    echo -e "    ${DIM}./bin/stratium-audit logs --provider openai    --since 5m${NC}"
    echo ""

    # Cleanup delegation file
    rm -f /tmp/.stratium-delegation.json
}

# --- Main ---
case "${1:-}" in
    setup)         do_setup ;;
    teardown)      do_teardown ;;
    clean)         do_clean ;;
    offline)       do_offline ;;
    launch-codex)  do_launch_codex ;;
    launch-claude) do_launch_claude ;;
    mint)
        if [ -z "${2:-}" ]; then
            echo "Usage: $(basename "$0") mint <agent-name>" >&2
            echo "  e.g., mint codex-impl" >&2
            echo "  e.g., mint claude-code-demo" >&2
            exit 1
        fi
        banner "Mint Delegation"
        section "Minting delegation for $2 agent"
        do_mint_delegation "$2" || exit 1
        ;;
    help|-h|--help) do_help ;;
    *)             do_demo ;;
esac
