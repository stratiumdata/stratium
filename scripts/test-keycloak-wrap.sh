#!/bin/bash

set -e

echo "=== Testing Keycloak-authenticated DEK wrapping ==="
echo ""

# Check if services are running
if ! curl -s http://localhost:8080 > /dev/null 2>&1; then
    echo "❌ Keycloak is not running. Please start with: cd deployment && docker-compose up -d"
    exit 1
fi

if ! nc -z localhost 50053 2>/dev/null; then
    echo "❌ Key Access service is not running on port 50053"
    echo "Start it with: OIDC_ISSUER_URL=http://localhost:8080/realms/stratium OIDC_CLIENT_ID=stratium-key-access ./bin/key-access-server"
    exit 1
fi

# Get token
echo "Step 1: Obtaining Keycloak token for user123..."
RESPONSE=$(curl -s -X POST "http://localhost:8080/realms/stratium/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=stratium-cli" \
  -d "username=user123" \
  -d "password=password123" \
  -d "grant_type=password" \
  -d "scope=openid profile email")

ACCESS_TOKEN=$(echo $RESPONSE | jq -r '.access_token')

if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" == "null" ]; then
    echo "❌ Failed to obtain access token"
    echo $RESPONSE | jq .
    exit 1
fi

echo "✅ Token obtained"
echo ""

# Decode token to show claims
echo "Step 2: Token claims:"
echo $ACCESS_TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '{sub, preferred_username, email, groups}'
echo ""

# Test WrapDEK
echo "Step 3: Calling WrapDEK with token..."
RESULT=$(grpcurl -plaintext -H "authorization: Bearer $ACCESS_TOKEN" \
  -d '{"resource":"test-resource","action":"wrap_dek","dek":"dGVzdC1kZWs="}' \
  localhost:50053 key_access.KeyAccessService/WrapDEK)

echo "$RESULT"
echo ""

# Check if successful
if echo "$RESULT" | jq -e '.accessGranted == true' > /dev/null 2>&1; then
    echo "✅ SUCCESS: DEK wrapped successfully!"
    echo "Wrapped DEK length:" $(echo "$RESULT" | jq -r '.wrappedDek' | wc -c)
else
    echo "❌ FAILED: Access denied"
    echo "Reason:" $(echo "$RESULT" | jq -r '.accessReason')
fi