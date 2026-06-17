#!/usr/bin/env bash
# Stratium PreToolUse hook — enforces agent authorization on every Claude tool call.
#
# This hook reads the MCP server's cached session state and calls the Agent Gateway
# to check if the tool call is authorized. If denied, it exits 2 with a reason.
#
# Requires: STRATIUM_GATEWAY_ADDRESS, STRATIUM_TLS_CA, grpcurl
#
# Hook protocol:
#   stdin:  JSON with tool_name, tool_input
#   exit 0: ALLOW (no output needed)
#   exit 2: DENY  (stdout: JSON with reason)

set -uo pipefail

# Read hook input from stdin
INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')
TOOL_INPUT=$(echo "$INPUT" | jq -c '.tool_input // {}')

# Skip if no tool name
if [ -z "$TOOL_NAME" ]; then
    exit 0
fi

# Skip authorization for the stratium MCP tools themselves (avoid recursion)
case "$TOOL_NAME" in
    register_agent|get_agent|list_agents|suspend_agent|\
    create_delegation|create_sub_delegation|revoke_delegation|list_delegations|\
    execute_action|check_permission|validate_action_plan|get_delegation_chain|\
    orchestrate_sub_agent)
        exit 0
        ;;
esac

# Read delegation token from session state (written by SessionStart hook or MCP server)
DELEGATION_FILE="$HOME/.stratium/delegation.json"
DELEGATION_TOKEN=""

if [ -f "$DELEGATION_FILE" ]; then
    DELEGATION_TOKEN=$(jq -r '.delegation_token // empty' "$DELEGATION_FILE" 2>/dev/null)
fi

# Also check env var (backward compat with MCP server flow)
if [ -z "$DELEGATION_TOKEN" ]; then
    DELEGATION_TOKEN="${STRATIUM_DELEGATION_TOKEN:-}"
fi

if [ -z "$DELEGATION_TOKEN" ]; then
    # No delegation — fail closed. SessionStart hook may not have run.
    cat << 'DENY_EOF'
{
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "No Stratium delegation token. SessionStart hook may not have run. All actions denied (fail-closed)."
    }
}
DENY_EOF
    exit 2
fi

# Load OIDC token for gRPC auth headers
SESSION_FILE="$HOME/.stratium/token.json"

# Map tool name to action tier
classify_tool() {
    case "$1" in
        Read|read_file|Glob|glob|Grep|grep_search|WebFetch|web_fetch|WebSearch|web_search)
            echo "1"  # READ_ONLY
            ;;
        Write|write_file|Edit|edit_file|NotebookEdit)
            echo "2"  # INTERNAL_MODIFY
            ;;
        Bash)
            classify_bash "$2"
            ;;
        Agent|Task)
            echo "2"  # INTERNAL_MODIFY
            ;;
        *)
            echo "1"  # Default to READ_ONLY
            ;;
    esac
}

# Classify bash commands by inspecting the command string
classify_bash() {
    local cmd
    cmd=$(echo "$1" | jq -r '.command // empty' 2>/dev/null)
    if [ -z "$cmd" ]; then
        echo "2"
        return
    fi

    # Destructive patterns (tier 4)
    if echo "$cmd" | grep -qE 'rm\s+-rf|mkfs|dd\s+if=|DROP\s+TABLE|dropdb|truncate'; then
        echo "4"
        return
    fi

    # External communication patterns (tier 3)
    if echo "$cmd" | grep -qE 'curl|wget|ssh|git\s+push|docker\s+push|npm\s+publish|aws\s|gcloud\s'; then
        echo "3"
        return
    fi

    # Read-only patterns (tier 1)
    if echo "$cmd" | grep -qE '^(cat|ls|grep|git\s+log|git\s+status|git\s+diff|ps|docker\s+ps|echo|pwd|head|tail|wc)\s'; then
        echo "1"
        return
    fi

    # Default bash = INTERNAL_MODIFY
    echo "2"
}

# Map tool name to action string
action_for_tool() {
    case "$1" in
        Read|read_file|Glob|glob|Grep|grep_search|WebFetch|web_fetch|WebSearch|web_search)
            echo "read"
            ;;
        Write|write_file|Edit|edit_file|NotebookEdit)
            echo "write"
            ;;
        Bash)
            echo "execute"
            ;;
        Agent|Task)
            echo "spawn"
            ;;
        *)
            echo "read"
            ;;
    esac
}

# Map Claude Code internal tool names to Stratium tool names
# Claude Code uses "Read", "Write", "Edit", etc. but delegations use "read_file", "write_file", etc.
normalize_tool_name() {
    case "$1" in
        Read)       echo "read_file" ;;
        Write)      echo "write_file" ;;
        Edit)       echo "edit_file" ;;
        Glob)       echo "list_files" ;;
        Grep)       echo "grep_search" ;;
        Bash)       echo "bash" ;;
        WebFetch)   echo "web_fetch" ;;
        WebSearch)  echo "web_search" ;;
        Agent)      echo "agent" ;;
        Task)       echo "task" ;;
        NotebookEdit) echo "notebook_edit" ;;
        *)          echo "$1" ;;  # pass through (already normalized or MCP tool)
    esac
}

ACTION_TIER=$(classify_tool "$TOOL_NAME" "$TOOL_INPUT")
ACTION=$(action_for_tool "$TOOL_NAME")
STRATIUM_TOOL=$(normalize_tool_name "$TOOL_NAME")

# Check with Agent Gateway via grpcurl
GATEWAY="${STRATIUM_GATEWAY_ADDRESS:-localhost:50054}"
CA_CERT="${STRATIUM_TLS_CA:-}"
AUTH_TOKEN=$(cat "$SESSION_FILE" | jq -r '.access_token // empty')
USER_ID=$(cat "$SESSION_FILE" | jq -r '.user_id // empty')

GRPC_FLAGS="-plaintext"
if [ -n "$CA_CERT" ] && [ -f "$CA_CERT" ]; then
    GRPC_FLAGS="-cacert $CA_CERT"
fi

RESULT=$(grpcurl $GRPC_FLAGS \
    -H "authorization: Bearer $AUTH_TOKEN" \
    -H "x-user-id: $USER_ID" \
    -d "{
        \"delegation_token\": \"$DELEGATION_TOKEN\",
        \"tool_name\": \"$STRATIUM_TOOL\",
        \"action\": \"$ACTION\",
        \"action_tier\": $ACTION_TIER
    }" \
    "$GATEWAY" agent_gateway.AgentGatewayService/ExecuteAction 2>/dev/null)

if [ $? -ne 0 ]; then
    # Gateway unreachable — fail closed
    cat << 'DENY_EOF'
{
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "Stratium Agent Gateway unreachable. All actions denied (fail-closed)."
    }
}
DENY_EOF
    exit 2
fi

AUTHORIZED=$(echo "$RESULT" | jq -r '.authorized // false')

if [ "$AUTHORIZED" = "true" ]; then
    exit 0
else
    REASON=$(echo "$RESULT" | jq -r '.error // .decision.delegationReason // "authorization denied"')
    # Exit 2 = DENY with reason
    cat << EOF
{
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "Stratium authorization denied: $REASON (tool=$STRATIUM_TOOL, action=$ACTION, tier=$ACTION_TIER)"
    }
}
EOF
    exit 2
fi
