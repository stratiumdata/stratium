#!/usr/bin/env bash
# Stratium SessionStart hook for Claude Code.
#
# Bootstraps a delegation token on session start by calling the PAP REST API.
# The token is written to ~/.stratium/delegation.json so PreToolUse hooks can
# read it. If delegation cannot be created, injects a warning into the session.
#
# This mirrors the Codex SessionStart hook (demos/codex/hooks/stratium_session_start.py)
# but uses bash + curl instead of Python.
#
# Required env vars:
#   STRATIUM_PAP_URL       — PAP server URL (e.g., https://localhost:8090)
#   STRATIUM_AGENT_ID      — Registered agent UUID
#   STRATIUM_AUTH_TOKEN     — OIDC access token (or reads from ~/.stratium/token.json)
#
# Optional env vars:
#   STRATIUM_APPROVED_TOOLS    — Comma-separated (default: read_file,write_file,edit_file,bash,list_files,grep_search)
#   STRATIUM_MAX_ACTION_TIER   — 0-4 (default: 2)
#   STRATIUM_CLASSIFICATION_CAP — default: INTERNAL
#   STRATIUM_TTL_SECONDS       — default: 14400 (4 hours)
#
# Hook protocol:
#   stdin:  JSON with session_id, hook_event_name
#   stdout: empty (allow) or JSON with additionalContext
#   exit 0: always (SessionStart hooks don't block)

set -uo pipefail

# Read hook input from stdin
INPUT=$(cat)

# ── Configuration ─────────────────────────────────────────────────────────────

PAP_URL="${STRATIUM_PAP_URL:-}"
AGENT_ID="${STRATIUM_AGENT_ID:-}"
AUTH_TOKEN="${STRATIUM_AUTH_TOKEN:-}"
DELEGATION_FILE="$HOME/.stratium/delegation.json"

# If no explicit auth token, try to load from cached OIDC session
if [ -z "$AUTH_TOKEN" ] && [ -f "$HOME/.stratium/token.json" ]; then
    AUTH_TOKEN=$(jq -r '.access_token // empty' "$HOME/.stratium/token.json" 2>/dev/null)
fi

# Emit a SessionStart success message visible to Claude Code as additionalContext
emit_success() {
    local id="$1"
    local expires="$2"
    local source="$3"
    jq -n \
        --arg msg "Stratium delegation active (id: ${id:0:8}..., expires: $expires, source: $source). Bash and other tool calls will be authorized via the Agent Gateway." \
        '{
            hookSpecificOutput: {
                hookEventName: "SessionStart",
                additionalContext: $msg
            }
        }'
}

# If a delegation token already exists (pre-created or from MCP server), validate and keep it
if [ -n "${STRATIUM_DELEGATION_TOKEN:-}" ]; then
    mkdir -p "$(dirname "$DELEGATION_FILE")"
    echo "{\"delegation_token\": \"$STRATIUM_DELEGATION_TOKEN\"}" > "$DELEGATION_FILE"
    chmod 600 "$DELEGATION_FILE"
    emit_success "preset" "see token" "env-var"
    exit 0
fi

# If delegation file already exists and is not expired, reuse it
if [ -f "$DELEGATION_FILE" ]; then
    EXISTING_TOKEN=$(jq -r '.delegation_token // empty' "$DELEGATION_FILE" 2>/dev/null)
    if [ -n "$EXISTING_TOKEN" ]; then
        # Check if token is still valid (decode exp claim)
        EXP=$(echo "$EXISTING_TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq -r '.exp // 0' 2>/dev/null)
        NOW=$(date +%s)
        if [ "$EXP" -gt "$((NOW + 60))" ] 2>/dev/null; then
            EXISTING_ID=$(jq -r '.delegation_id // "unknown"' "$DELEGATION_FILE" 2>/dev/null)
            EXISTING_EXPIRES=$(jq -r '.expires_at // "unknown"' "$DELEGATION_FILE" 2>/dev/null)
            emit_success "$EXISTING_ID" "$EXISTING_EXPIRES" "cached"
            exit 0
        fi
    fi
fi

# ── Bootstrap delegation ──────────────────────────────────────────────────────

# Check required vars
MISSING=""
if [ -z "$PAP_URL" ]; then MISSING="$MISSING STRATIUM_PAP_URL"; fi
if [ -z "$AGENT_ID" ]; then MISSING="$MISSING STRATIUM_AGENT_ID"; fi
if [ -z "$AUTH_TOKEN" ]; then MISSING="$MISSING STRATIUM_AUTH_TOKEN"; fi

if [ -n "$MISSING" ]; then
    # Can't bootstrap — remove stale delegation file
    rm -f "$DELEGATION_FILE"
    echo "[stratium] SessionStart: missing env vars:$MISSING — delegation not created" >&2
    exit 0
fi

# Build request
APPROVED_TOOLS="${STRATIUM_APPROVED_TOOLS:-read_file,write_file,edit_file,bash,list_files,grep_search}"
MAX_TIER="${STRATIUM_MAX_ACTION_TIER:-2}"
CAP="${STRATIUM_CLASSIFICATION_CAP:-INTERNAL}"
TTL="${STRATIUM_TTL_SECONDS:-14400}"

# Convert comma-separated tools to JSON array
TOOLS_JSON=$(echo "$APPROVED_TOOLS" | tr ',' '\n' | jq -R . | jq -s .)

BODY=$(jq -n \
    --arg agent_id "$AGENT_ID" \
    --argjson tools "$TOOLS_JSON" \
    --argjson max_tier "$MAX_TIER" \
    --arg cap "$CAP" \
    --argjson ttl "$TTL" \
    '{
        agent_id: $agent_id,
        approved_tools: $tools,
        max_action_tier: $max_tier,
        classification_caps: { commercial: $cap },
        purpose: "Claude Code session (auto-delegated)",
        ttl_seconds: $ttl
    }')

# Call PAP to create delegation
RESPONSE=$(curl -sk -X POST "$PAP_URL/api/v1/delegations" \
    -H "Authorization: Bearer $AUTH_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$BODY" 2>/dev/null)

if [ $? -ne 0 ] || [ -z "$RESPONSE" ]; then
    rm -f "$DELEGATION_FILE"
    echo "[stratium] SessionStart: PAP unreachable at $PAP_URL — delegation not created" >&2
    exit 0
fi

# Check for error
ERROR=$(echo "$RESPONSE" | jq -r '.error // empty' 2>/dev/null)
if [ -n "$ERROR" ]; then
    rm -f "$DELEGATION_FILE"
    echo "[stratium] SessionStart: PAP returned error: $ERROR" >&2
    exit 0
fi

# Extract token
TOKEN=$(echo "$RESPONSE" | jq -r '.delegation_token // empty' 2>/dev/null)
EXPIRES=$(echo "$RESPONSE" | jq -r '.expires_at // "unknown"' 2>/dev/null)
DELEGATION_ID=$(echo "$RESPONSE" | jq -r '.delegation_id // "unknown"' 2>/dev/null)

if [ -z "$TOKEN" ]; then
    rm -f "$DELEGATION_FILE"
    echo "[stratium] SessionStart: PAP returned no delegation token" >&2
    exit 0
fi

# Write delegation file
mkdir -p "$(dirname "$DELEGATION_FILE")"
cat > "$DELEGATION_FILE" << EOF
{
  "delegation_token": "$TOKEN",
  "delegation_id": "$DELEGATION_ID",
  "agent_id": "$AGENT_ID",
  "expires_at": "$EXPIRES"
}
EOF
chmod 600 "$DELEGATION_FILE"

echo "[stratium] SessionStart: delegation created (id: ${DELEGATION_ID:0:8}..., expires: $EXPIRES)" >&2
emit_success "$DELEGATION_ID" "$EXPIRES" "newly-created"
exit 0
