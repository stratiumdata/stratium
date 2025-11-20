#!/bin/bash

# Test script for Platform Service with Policy Decision Point
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PLATFORM_ADDR="${PLATFORM_ADDR:-localhost:50051}"
PAP_URL="${PAP_URL:-http://localhost:8090}"
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"

echo -e "${YELLOW}=== Platform Service PDP Integration Test ===${NC}\n"

# Function to get access token
get_token() {
    local username=$1
    local password=$2

    response=$(curl -s -X POST \
        "${KEYCLOAK_URL}/realms/stratium/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=stratium-pap" \
        -d "client_secret=stratium-pap-secret" \
        -d "grant_type=password" \
        -d "username=${username}" \
        -d "password=${password}")

    echo $response | jq -r '.access_token'
}

echo -e "${YELLOW}Step 1: Create test policy in PAP${NC}"
TOKEN=$(get_token "admin456" "admin123")

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
    echo -e "${RED}Failed to get access token. Is Keycloak running?${NC}"
    exit 1
fi

# Create an OPA policy that allows admin users
POLICY_JSON=$(cat <<'EOF'
{
  "name": "admin-full-access-test",
  "description": "Test policy: Administrators have full access",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 100,
  "enabled": true
}
EOF
)

echo "Creating policy..."
POLICY_RESPONSE=$(curl -s -X POST "${PAP_URL}/api/v1/policies" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$POLICY_JSON")

POLICY_ID=$(echo $POLICY_RESPONSE | jq -r '.id')

if [ "$POLICY_ID" = "null" ] || [ -z "$POLICY_ID" ]; then
    echo -e "${RED}Failed to create policy${NC}"
    echo "$POLICY_RESPONSE" | jq '.'
    exit 1
fi

echo -e "${GREEN}✓ Policy created: $POLICY_ID${NC}"

# Create an entitlement for engineering department
echo -e "\n${YELLOW}Step 2: Create test entitlement in PAP${NC}"

ENTITLEMENT_JSON=$(cat <<'EOF'
{
  "name": "engineering-document-access",
  "description": "Engineering can access engineering documents",
  "subject_attributes": {
    "department": "engineering"
  },
  "resource_attributes": {
    "type": "document"
  },
  "actions": ["read", "write"],
  "enabled": true
}
EOF
)

echo "Creating entitlement..."
ENTITLEMENT_RESPONSE=$(curl -s -X POST "${PAP_URL}/api/v1/entitlements" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    -d "$ENTITLEMENT_JSON")

ENTITLEMENT_ID=$(echo $ENTITLEMENT_RESPONSE | jq -r '.id')

if [ "$ENTITLEMENT_ID" = "null" ] || [ -z "$ENTITLEMENT_ID" ]; then
    echo -e "${RED}Failed to create entitlement${NC}"
    echo "$ENTITLEMENT_RESPONSE" | jq '.'
else
    echo -e "${GREEN}✓ Entitlement created: $ENTITLEMENT_ID${NC}"
fi

# Test platform service GetDecision
echo -e "\n${YELLOW}Step 3: Test Platform Service GetDecision${NC}"

# Test 1: Admin user (should be allowed by policy)
echo -e "\n${YELLOW}Test 1: Admin user access${NC}"
grpcurl -plaintext -d '{
  "subject": "admin456",
  "resource": "test-resource",
  "action": "read",
  "context": {
    "role": "admin",
    "department": "administration"
  }
}' ${PLATFORM_ADDR} platform.PlatformService/GetDecision | jq '.'

# Test 2: Engineering user with matching entitlement
echo -e "\n${YELLOW}Test 2: Engineering user with entitlement${NC}"
grpcurl -plaintext -d '{
  "subject": "user123",
  "resource": "engineering-doc",
  "action": "read",
  "context": {
    "role": "developer",
    "department": "engineering",
    "type": "document"
  }
}' ${PLATFORM_ADDR} platform.PlatformService/GetDecision | jq '.'

# Test 3: Regular user without permissions (should be denied)
echo -e "\n${YELLOW}Test 3: Regular user without permissions${NC}"
grpcurl -plaintext -d '{
  "subject": "test-user",
  "resource": "secret-resource",
  "action": "delete",
  "context": {
    "role": "tester",
    "department": "qa"
  }
}' ${PLATFORM_ADDR} platform.PlatformService/GetDecision | jq '.'

# Check audit logs
echo -e "\n${YELLOW}Step 4: Check audit logs${NC}"
curl -s -H "Authorization: Bearer ${TOKEN}" \
    "${PAP_URL}/api/v1/audit-logs?action=evaluate&limit=5" | jq '.audit_logs[] | {timestamp, actor, result}'

# Cleanup
echo -e "\n${YELLOW}Step 5: Cleanup${NC}"
echo "Deleting test policy..."
curl -s -X DELETE "${PAP_URL}/api/v1/policies/${POLICY_ID}" \
    -H "Authorization: Bearer ${TOKEN}" > /dev/null

if [ -n "$ENTITLEMENT_ID" ] && [ "$ENTITLEMENT_ID" != "null" ]; then
    echo "Deleting test entitlement..."
    curl -s -X DELETE "${PAP_URL}/api/v1/entitlements/${ENTITLEMENT_ID}" \
        -H "Authorization: Bearer ${TOKEN}" > /dev/null
fi

echo -e "\n${GREEN}=== Test Complete ===${NC}"
echo -e "${YELLOW}Summary:${NC}"
echo "- Created and tested OPA policy for admin access"
echo "- Created and tested entitlement for engineering department"
echo "- Verified policy decision point integration"
echo "- Checked audit logging"
echo "- Cleaned up test resources"
