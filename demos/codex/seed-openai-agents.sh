#!/usr/bin/env bash
set -euo pipefail

# Seed OpenAI agent registrations for the multi-provider demo.
# Run AFTER demos/mcp/seed-demo-data.sh (which creates users and policies).
#
# Prerequisites:
#   - docker-compose --profile agent-auth up -d
#   - demos/mcp/seed-demo-data.sh completed
#
# This script registers OpenAI agents (Codex and Desktop) in the Stratium
# platform alongside the existing Claude agents.

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PAP_URL="${PAP_URL:-https://localhost:8090}"
REALM="${STRATIUM_REALM:-stratium}"
ADMIN_USER="${ADMIN_USER:-admin456}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
PAP_CLIENT="stratium-pap"
PAP_SECRET="stratium-pap-secret"

echo "=== Stratium Multi-Provider Demo: Seeding OpenAI Agents ==="

# Authenticate as admin
echo "Authenticating as ${ADMIN_USER}..."
TOKEN_RESPONSE=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=${PAP_CLIENT}" \
    -d "client_secret=${PAP_SECRET}" \
    -d "username=${ADMIN_USER}" \
    -d "password=${ADMIN_PASS}" 2>&1) || {
    echo "ERROR: Failed to authenticate. Is the stack running?"
    exit 1
}

ADMIN_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token')
if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "ERROR: No access_token in response."
    exit 1
fi
echo "Authenticated."

# Register OpenAI Codex agent (REGISTERED tier, for coding tasks)
echo ""
echo "--- Registering OpenAI Codex agent ---"
CODEX_RESPONSE=$(curl -sk -X POST "${PAP_URL}/api/v1/agents" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "codex-impl",
        "description": "OpenAI Codex coding agent for implementation tasks",
        "provider": "openai",
        "model_identifier": "codex-mini",
        "trust_tier": 1,
        "allowed_tools": ["bash", "read_file", "write_file", "edit_file", "list_files", "grep_search"],
        "allowed_actions": [0, 1, 2],
        "metadata": {
            "integration_layer": "hooks",
            "openai_product": "codex"
        }
    }' 2>&1) || true

CODEX_ID=$(echo "$CODEX_RESPONSE" | jq -r '.agent_id // empty')
if [ -n "$CODEX_ID" ]; then
    echo "  Agent ID: ${CODEX_ID}"
    echo "  Client ID: $(echo "$CODEX_RESPONSE" | jq -r '.client_id')"
    echo "  Provider: openai"
    echo "  Trust Tier: 1 (REGISTERED)"
else
    echo "  Agent may already exist or creation failed: $(echo "$CODEX_RESPONSE" | jq -r '.error // .message // "unknown error"')"
fi

# Register OpenAI Desktop (ChatGPT) agent (REGISTERED tier, for document review)
echo ""
echo "--- Registering OpenAI Desktop (ChatGPT) agent ---"
DESKTOP_RESPONSE=$(curl -sk -X POST "${PAP_URL}/api/v1/agents" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "desktop-reviewer",
        "description": "ChatGPT Desktop agent for document review",
        "provider": "openai",
        "model_identifier": "gpt-4o",
        "trust_tier": 1,
        "allowed_tools": ["read_file", "list_files", "grep_search", "web_search"],
        "allowed_actions": [0, 1],
        "metadata": {
            "integration_layer": "mcp",
            "openai_product": "desktop"
        }
    }' 2>&1) || true

DESKTOP_ID=$(echo "$DESKTOP_RESPONSE" | jq -r '.agent_id // empty')
if [ -n "$DESKTOP_ID" ]; then
    echo "  Agent ID: ${DESKTOP_ID}"
    echo "  Client ID: $(echo "$DESKTOP_RESPONSE" | jq -r '.client_id')"
    echo "  Provider: openai"
    echo "  Trust Tier: 1 (REGISTERED)"
else
    echo "  Agent may already exist or creation failed: $(echo "$DESKTOP_RESPONSE" | jq -r '.error // .message // "unknown error"')"
fi

# Register OpenAI Codex sub-agent (for cross-provider delegation chain demo)
echo ""
echo "--- Registering OpenAI Codex sub-agent (for delegation chain demo) ---"
SUB_RESPONSE=$(curl -sk -X POST "${PAP_URL}/api/v1/agents" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "codex-sub-agent",
        "description": "OpenAI Codex sub-agent receiving delegated scope from Claude",
        "provider": "openai",
        "model_identifier": "codex-mini",
        "trust_tier": 1,
        "allowed_tools": ["bash", "read_file"],
        "allowed_actions": [0, 1],
        "metadata": {
            "integration_layer": "hooks",
            "openai_product": "codex",
            "role": "sub-agent"
        }
    }' 2>&1) || true

SUB_ID=$(echo "$SUB_RESPONSE" | jq -r '.agent_id // empty')
if [ -n "$SUB_ID" ]; then
    echo "  Agent ID: ${SUB_ID}"
    echo "  Client ID: $(echo "$SUB_RESPONSE" | jq -r '.client_id')"
    echo "  Provider: openai"
    echo "  Trust Tier: 1 (REGISTERED)"
else
    echo "  Agent may already exist or creation failed: $(echo "$SUB_RESPONSE" | jq -r '.error // .message // "unknown error"')"
fi

echo ""
echo "=== OpenAI Agent Seeding Complete ==="
echo ""
echo "Registered agents:"
echo "  codex-impl       (openai, codex-mini, tier 1, hooks layer)"
echo "  desktop-reviewer (openai, gpt-4o, tier 1, MCP layer)"
echo "  codex-sub-agent  (openai, codex-mini, tier 1, hooks layer, sub-agent)"
echo ""
echo "To list all agents:"
echo "  curl -sk ${PAP_URL}/api/v1/agents -H 'Authorization: Bearer <token>' | jq"
