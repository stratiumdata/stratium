#!/bin/bash

# Keycloak Login Script
# This script obtains an access token from Keycloak for testing

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-stratium}"
CLIENT_ID="${KEYCLOAK_CLIENT_ID:-stratium-cli}"
USERNAME="$1"
PASSWORD="$2"

if [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "Usage: $0 <username> <password>"
    echo ""
    echo "Available users (from realm-export.json):"
    echo "  - user123 / password123"
    echo "  - admin456 / admin123"
    echo "  - test-user / test123"
    echo "  - service-account-1 / service123"
    echo ""
    echo "Example:"
    echo "  $0 user123 password123"
    exit 1
fi

echo "Obtaining token from Keycloak..."
echo "URL: $KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token"
echo "User: $USERNAME"
echo ""

# Get access token using Resource Owner Password Credentials flow
RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/realms/$REALM/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=$CLIENT_ID" \
  -d "username=$USERNAME" \
  -d "password=$PASSWORD" \
  -d "grant_type=password" \
  -d "scope=openid profile email")

# Check if we got an error
ERROR=$(echo $RESPONSE | jq -r '.error // empty')
if [ ! -z "$ERROR" ]; then
    echo "❌ Authentication failed:"
    echo $RESPONSE | jq .
    exit 1
fi

# Extract tokens
ACCESS_TOKEN=$(echo $RESPONSE | jq -r '.access_token')
REFRESH_TOKEN=$(echo $RESPONSE | jq -r '.refresh_token')
ID_TOKEN=$(echo $RESPONSE | jq -r '.id_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo "❌ Failed to obtain access token"
    echo $RESPONSE | jq .
    exit 1
fi

echo "✅ Authentication successful!"
echo ""
echo "=== Access Token ==="
echo $ACCESS_TOKEN
echo ""
echo "=== ID Token ==="
echo $ID_TOKEN
echo ""
echo "=== Refresh Token ==="
echo $RESPONSE | jq -r '.refresh_token'
echo ""

# Decode and display token claims
echo "=== Token Claims ==="
echo $ACCESS_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq . || echo "(Could not decode token)"
echo ""

# Save tokens to file for easy reuse
TOKEN_FILE=".keycloak-tokens-${USERNAME}.json"
echo $RESPONSE | jq . > $TOKEN_FILE
echo "📝 Tokens saved to: $TOKEN_FILE"
echo ""

# Export for immediate use
echo "=== Export Commands ==="
echo "export ACCESS_TOKEN='$ACCESS_TOKEN'"
echo "export ID_TOKEN='$ID_TOKEN'"
echo ""

# Example gRPC command
echo "=== Example gRPC Command ==="
echo "grpcurl -plaintext -H \"authorization: Bearer \$ACCESS_TOKEN\" -d '{\"resource\":\"test-resource\",\"action\":\"wrap_dek\",\"dek\":\"dGVzdC1kZWs=\"}' localhost:50053 key_access.KeyAccessService/WrapDEK"