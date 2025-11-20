#!/bin/bash

# Test script for PAP API authentication with Keycloak
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
PAP_URL="${PAP_URL:-http://localhost:8090}"
REALM="${REALM:-stratium}"
CLIENT_ID="${CLIENT_ID:-stratium-pap}"
CLIENT_SECRET="${CLIENT_SECRET:-stratium-pap-secret}"

echo -e "${YELLOW}=== Stratium PAP API Authentication Test ===${NC}\n"

# Function to get access token using password grant
get_token() {
    local username=$1
    local password=$2

    echo -e "${YELLOW}Getting access token for user: $username${NC}" >&2

    response=$(curl -s -X POST \
        "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "client_id=${CLIENT_ID}" \
        -d "client_secret=${CLIENT_SECRET}" \
        -d "grant_type=password" \
        -d "username=${username}" \
        -d "password=${password}")

    access_token=$(echo $response | jq -r '.access_token')

    if [ "$access_token" = "null" ] || [ -z "$access_token" ]; then
        echo -e "${RED}Failed to get access token${NC}" >&2
        echo "Response: $response" >&2
        return 1
    fi

    echo -e "${GREEN}Successfully obtained access token${NC}" >&2
    echo "$access_token"
}

# Function to decode JWT and show claims
decode_token() {
    local token=$1

    echo -e "\n${YELLOW}Token Claims:${NC}"

    # Extract payload and add padding if needed for base64
    local payload=$(echo "$token" | cut -d'.' -f2)
    case $((${#payload} % 4)) in
        2) payload="${payload}==" ;;
        3) payload="${payload}=" ;;
    esac

    echo "$payload" | base64 -d 2>/dev/null | jq '.' || echo "Failed to decode token"
}

# Function to test PAP API endpoint
test_pap_endpoint() {
    local token=$1
    local endpoint=$2
    local method=${3:-GET}

    echo -e "\n${YELLOW}Testing ${method} ${endpoint}${NC}"

    http_code=$(curl -s -w "%{http_code}" -o /tmp/pap_test_response.txt -X $method \
        "${PAP_URL}${endpoint}" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json")

    body=$(cat /tmp/pap_test_response.txt)

    if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
        echo -e "${GREEN}✓ Success (HTTP $http_code)${NC}"
        echo "$body" | jq '.' 2>/dev/null || echo "$body"
    else
        echo -e "${RED}✗ Failed (HTTP $http_code)${NC}"
        echo "$body"
    fi
}

# Function to create a test policy
create_test_policy() {
    local token=$1

    echo -e "\n${YELLOW}Creating test policy${NC}" >&2

    policy_json='{
  "name": "test-policy-'$(date +%s)'",
  "description": "Test policy created via API",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 10,
  "enabled": true
}'

    http_code=$(curl -s -w "%{http_code}" -o /tmp/pap_create_response.txt -X POST \
        "${PAP_URL}/api/v1/policies" \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$policy_json")

    body=$(cat /tmp/pap_create_response.txt)

    if [ "$http_code" = "201" ]; then
        echo -e "${GREEN}✓ Policy created successfully${NC}" >&2
        echo "$body" | jq '.' >&2
        policy_id=$(echo "$body" | jq -r '.id')
        echo "$policy_id"
    else
        echo -e "${RED}✗ Failed to create policy (HTTP $http_code)${NC}" >&2
        echo "$body" >&2
        return 1
    fi
}

# Main test flow
main() {
    echo -e "${YELLOW}Step 1: Testing health endpoint (no auth required)${NC}"
    curl -s "${PAP_URL}/health" | jq '.' || echo "PAP service not available"

    echo -e "\n${YELLOW}Step 2: Authenticating as admin456${NC}"
    TOKEN=$(get_token "admin456" "admin123")

    if [ -z "$TOKEN" ]; then
        echo -e "${RED}Authentication failed. Exiting.${NC}"
        exit 1
    fi

    # Decode and show token claims
    decode_token "$TOKEN"

    # Test various endpoints
    test_pap_endpoint "$TOKEN" "/api/v1/policies"
    test_pap_endpoint "$TOKEN" "/api/v1/entitlements"
    test_pap_endpoint "$TOKEN" "/api/v1/audit-logs"

    # Try to create a policy
    POLICY_ID=$(create_test_policy "$TOKEN")

    if [ -n "$POLICY_ID" ] && [ "$POLICY_ID" != "null" ]; then
        echo -e "\n${YELLOW}Step 3: Getting created policy${NC}"
        test_pap_endpoint "$TOKEN" "/api/v1/policies/${POLICY_ID}"

        echo -e "\n${YELLOW}Step 4: Deleting test policy${NC}"
        test_pap_endpoint "$TOKEN" "/api/v1/policies/${POLICY_ID}" "DELETE"
    fi

    echo -e "\n${YELLOW}Step 5: Testing with regular user (user123)${NC}"
    USER_TOKEN=$(get_token "user123" "password123")

    if [ -n "$USER_TOKEN" ]; then
        decode_token "$USER_TOKEN"
        test_pap_endpoint "$USER_TOKEN" "/api/v1/policies"
    fi

    echo -e "\n${GREEN}=== Test Complete ===${NC}"
}

# Check dependencies
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is required but not installed.${NC}"
    echo "Install with: brew install jq (macOS) or apt-get install jq (Linux)"
    exit 1
fi

if ! command -v curl &> /dev/null; then
    echo -e "${RED}Error: curl is required but not installed.${NC}"
    exit 1
fi

# Run main test
main
