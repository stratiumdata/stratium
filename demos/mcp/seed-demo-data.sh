#!/usr/bin/env bash
set -euo pipefail

# Seed demo data for the Stratium MCP Agent Auth Demo.
# Prerequisites: docker-compose --profile agent-auth up -d

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PAP_URL="${PAP_URL:-https://localhost:8090}"
REALM="${STRATIUM_REALM:-stratium}"
ADMIN_USER="${ADMIN_USER:-admin456}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
PAP_CLIENT="stratium-pap"
PAP_SECRET="stratium-pap-secret"

echo "=== Stratium MCP Demo: Seeding Data ==="

# Wait for Keycloak
echo "Waiting for Keycloak..."
for i in $(seq 1 30); do
    if curl -sf "${KEYCLOAK_URL}/realms/${REALM}" > /dev/null 2>&1; then
        echo "Keycloak ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "ERROR: Keycloak not reachable at ${KEYCLOAK_URL}/realms/${REALM}"
        exit 1
    fi
    sleep 2
done

# Get user token for PAP operations
echo "Authenticating as ${ADMIN_USER}..."
TOKEN_RESPONSE=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=${PAP_CLIENT}" \
    -d "client_secret=${PAP_SECRET}" \
    -d "username=${ADMIN_USER}" \
    -d "password=${ADMIN_PASS}" 2>&1) || {
    echo "ERROR: Failed to authenticate. Response: ${TOKEN_RESPONSE}"
    echo "Check that Keycloak is running and credentials are correct."
    exit 1
}

ADMIN_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token')
if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
    echo "ERROR: No access_token in response: ${TOKEN_RESPONSE}"
    exit 1
fi
echo "Authenticated successfully."

# Get Keycloak master admin token for user management
echo "Getting Keycloak admin token..."
KC_ADMIN_TOKEN=""
KC_ADMIN_RESPONSE=$(curl -sf -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" \
    -d "client_id=admin-cli" \
    -d "username=admin" \
    -d "password=admin" 2>&1) || true

if [ -n "$KC_ADMIN_RESPONSE" ]; then
    KC_ADMIN_TOKEN=$(echo "${KC_ADMIN_RESPONSE}" | jq -r '.access_token' 2>/dev/null || echo "")
fi

# Add protocol mappers to an existing stratium-mcp client
add_protocol_mappers() {
    # Look up the client's internal UUID
    local client_json
    client_json=$(curl -s \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/clients?clientId=stratium-mcp" \
        -H "Authorization: Bearer ${KC_ADMIN_TOKEN}")

    local client_uuid
    client_uuid=$(echo "${client_json}" | jq -r '.[0].id // empty')

    if [ -z "$client_uuid" ]; then
        echo "    Could not find client UUID for stratium-mcp."
        return
    fi

    for attr in classification department role; do
        local http_code
        http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${client_uuid}/protocol-mappers/models" \
            -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{
                \"name\": \"${attr}\",
                \"protocol\": \"openid-connect\",
                \"protocolMapper\": \"oidc-usermodel-attribute-mapper\",
                \"config\": {
                    \"userinfo.token.claim\": \"true\",
                    \"user.attribute\": \"${attr}\",
                    \"id.token.claim\": \"true\",
                    \"access.token.claim\": \"true\",
                    \"claim.name\": \"${attr}\",
                    \"jsonType.label\": \"String\"
                }
            }")

        case "$http_code" in
            201) echo "    Mapper '${attr}' added." ;;
            409) echo "    Mapper '${attr}' already exists." ;;
            *)   echo "    Warning: got HTTP ${http_code} adding mapper '${attr}'." ;;
        esac
    done

    # Assign default client scopes (profile, email, roles, web-origins, classification)
    echo "    Assigning default client scopes..."
    for scope_name in profile email roles web-origins classification; do
        local scope_id
        scope_id=$(curl -s "${KEYCLOAK_URL}/admin/realms/${REALM}/client-scopes" \
            -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
            | jq -r ".[] | select(.name==\"${scope_name}\") | .id // empty")

        if [ -n "$scope_id" ]; then
            curl -s -o /dev/null -X PUT \
                "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${client_uuid}/default-client-scopes/${scope_id}" \
                -H "Authorization: Bearer ${KC_ADMIN_TOKEN}"
        fi
    done
    echo "    Scopes assigned."
}

# Create demo users in Keycloak (idempotent)
create_user() {
    local username=$1
    local password=$2
    local first_name=$3
    local last_name=$4
    local classification=$5
    local department=$6
    local role=$7

    if [ -z "$KC_ADMIN_TOKEN" ] || [ "$KC_ADMIN_TOKEN" = "null" ]; then
        echo "  Skipping user creation (no Keycloak master admin access)"
        return
    fi

    echo "Creating user: ${username} (classification: ${classification})..."
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/users" \
        -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"username\": \"${username}\",
            \"firstName\": \"${first_name}\",
            \"lastName\": \"${last_name}\",
            \"email\": \"${username}@stratium.local\",
            \"enabled\": true,
            \"credentials\": [{
                \"type\": \"password\",
                \"value\": \"${password}\",
                \"temporary\": false
            }],
            \"attributes\": {
                \"classification\": [\"${classification}\"],
                \"department\": [\"${department}\"],
                \"role\": [\"${role}\"]
            }
        }")

    case "$http_code" in
        201) echo "  Created ${username}." ;;
        409)
            echo "  User ${username} already exists — updating attributes..."
            set_user_attributes "${username}" "${classification}" "${department}" "${role}"
            ;;
        *)   echo "  Warning: got HTTP ${http_code} creating ${username}." ;;
    esac
}

# Update attributes on an existing Keycloak user
set_user_attributes() {
    local username=$1
    local classification=$2
    local department=$3
    local role=$4

    # Look up user ID by username
    local user_json
    user_json=$(curl -s \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/users?username=${username}&exact=true" \
        -H "Authorization: Bearer ${KC_ADMIN_TOKEN}")

    local user_id
    user_id=$(echo "${user_json}" | jq -r '.[0].id // empty')

    if [ -z "$user_id" ]; then
        echo "    Could not find user ID for ${username}."
        return
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X PUT \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/users/${user_id}" \
        -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"attributes\": {
                \"classification\": [\"${classification}\"],
                \"department\": [\"${department}\"],
                \"role\": [\"${role}\"]
            }
        }")

    case "$http_code" in
        204) echo "    Attributes updated." ;;
        *)   echo "    Warning: got HTTP ${http_code} updating attributes." ;;
    esac
}

#                  username          password  first   last       classification  department  role
create_user "demo-analyst"   "demo123" "Alex"  "Analyst"  "internal"      "finance"   "analyst"
create_user "demo-director"  "demo123" "Dana"  "Director" "confidential"  "finance"   "director"
create_user "demo-admin"     "demo123" "Admin" "Security" "restricted"    "security"  "admin"

# Create OIDC client for stratium-mcp with protocol mappers (idempotent)
if [ -n "$KC_ADMIN_TOKEN" ] && [ "$KC_ADMIN_TOKEN" != "null" ]; then
    echo "Creating OIDC client: stratium-mcp..."
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
        "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
        -H "Authorization: Bearer ${KC_ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "stratium-mcp",
            "name": "Stratium MCP Server",
            "publicClient": true,
            "redirectUris": ["http://127.0.0.1:*", "http://localhost:*"],
            "webOrigins": ["http://127.0.0.1", "http://localhost"],
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": true,
            "protocolMappers": [
                {
                    "name": "classification",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "userinfo.token.claim": "true",
                        "user.attribute": "classification",
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "classification",
                        "jsonType.label": "String"
                    }
                },
                {
                    "name": "department",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "userinfo.token.claim": "true",
                        "user.attribute": "department",
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "department",
                        "jsonType.label": "String"
                    }
                },
                {
                    "name": "role",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-usermodel-attribute-mapper",
                    "config": {
                        "userinfo.token.claim": "true",
                        "user.attribute": "role",
                        "id.token.claim": "true",
                        "access.token.claim": "true",
                        "claim.name": "role",
                        "jsonType.label": "String"
                    }
                }
            ]
        }')

    case "$http_code" in
        201) echo "  Client created with protocol mappers." ;;
        409)
            echo "  Client already exists — adding protocol mappers..."
            add_protocol_mappers
            ;;
        *)   echo "  Warning: got HTTP ${http_code} creating client." ;;
    esac
else
    echo "Skipping OIDC client creation (no Keycloak master admin access)."
fi

# Wait for PAP
echo "Waiting for PAP..."
for i in $(seq 1 30); do
    if curl -sfk "${PAP_URL}/health" > /dev/null 2>&1; then
        echo "PAP ready."
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "WARNING: PAP not reachable at ${PAP_URL}. Skipping policy seeding."
        echo ""
        echo "=== Demo Data Partially Seeded ==="
        exit 0
    fi
    sleep 2
done

# Seed classification policies via PAP
echo "Creating classification policies..."

create_policy() {
    local name=$1
    local description=$2
    local content=$3

    local http_code
    http_code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "${PAP_URL}/api/v1/policies" \
        -H "Authorization: Bearer ${ADMIN_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"${name}\",
            \"description\": \"${description}\",
            \"language\": \"opa\",
            \"effect\": \"allow\",
            \"policy_content\": \"${content}\",
            \"enabled\": true,
            \"tenant_id\": \"demo\"
        }")

    case "$http_code" in
        200|201) echo "  Policy '${name}' created." ;;
        409)     echo "  Policy '${name}' already exists." ;;
        *)       echo "  Warning: got HTTP ${http_code} creating policy '${name}'." ;;
    esac
}

create_policy \
    "financial-classification-public" \
    "Allow access to PUBLIC financial records" \
    "package stratium.financial\\ndefault allow = false\\nallow { input.resource.classification == \\\"PUBLIC\\\" }"

create_policy \
    "financial-classification-internal" \
    "Allow access to INTERNAL and below financial records" \
    "package stratium.financial\\ndefault allow = false\\nallow { input.resource.classification == \\\"PUBLIC\\\" }\\nallow { input.resource.classification == \\\"INTERNAL\\\"; input.subject.clearance_level >= 1 }"

create_policy \
    "financial-classification-confidential" \
    "Allow access to CONFIDENTIAL and below financial records" \
    "package stratium.financial\\ndefault allow = false\\nallow { input.resource.classification == \\\"PUBLIC\\\" }\\nallow { input.resource.classification == \\\"INTERNAL\\\" }\\nallow { input.resource.classification == \\\"CONFIDENTIAL\\\"; input.subject.clearance_level >= 2 }"

create_policy \
    "financial-classification-restricted" \
    "Allow access to RESTRICTED and below financial records" \
    "package stratium.financial\\ndefault allow = false\\nallow { input.resource.classification == \\\"PUBLIC\\\" }\\nallow { input.resource.classification == \\\"INTERNAL\\\" }\\nallow { input.resource.classification == \\\"CONFIDENTIAL\\\" }\\nallow { input.resource.classification == \\\"RESTRICTED\\\"; input.subject.clearance_level >= 3 }"

echo ""
echo "=== Demo Data Seeded Successfully ==="
echo ""
echo "Demo users (password / classification attribute / department):"
echo "  admin456       / admin123  / top-secret    / administration"
echo "  demo-analyst   / demo123   / internal      / finance"
echo "  demo-director  / demo123   / confidential  / finance"
echo "  demo-admin     / demo123   / restricted    / security"
echo ""
echo "Financial records at: demos/mcp/financial-records/"
echo "  public/        — PUBLIC (annual report, press release)"
echo "  internal/      — INTERNAL (revenue forecast, headcount plan)"
echo "  confidential/  — CONFIDENTIAL (board deck, strategic plan)"
echo "  restricted/    — RESTRICTED (M&A target, insider watchlist)"
echo ""
echo "To start the demo:"
echo "  1. Build: make build-mcp build-audit"
echo "  2a. Claude Code: add stratium to ~/.claude/settings.json (see demos/mcp/README.md)"
echo "  2b. Claude Desktop: merge demos/mcp/claude_desktop_config.json into"
echo "      ~/Library/Application Support/Claude/claude_desktop_config.json"
echo "  3. Start Claude and interact with the stratium tools"
