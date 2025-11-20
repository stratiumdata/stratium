#!/bin/bash

# Script to create Keycloak client for the UI application
# This creates a public client for the React SPA

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-stratium}"
CLIENT_ID="${CLIENT_ID:-micro-research-ui}"

echo "Creating Keycloak client for UI..."
echo "Keycloak URL: $KEYCLOAK_URL"
echo "Realm: $REALM"
echo "Client ID: $CLIENT_ID"

# Get admin token
echo "Getting admin token..."
ADMIN_TOKEN=$(curl -s -X POST "${KEYCLOAK_URL}/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin" \
  -d "password=admin" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" = "null" ]; then
  echo "Failed to get admin token"
  exit 1
fi

echo "Admin token obtained"

# Check if client already exists
CLIENT_EXISTS=$(curl -s -X GET "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" | jq -r ".[] | select(.clientId==\"${CLIENT_ID}\") | .id")

if [ ! -z "$CLIENT_EXISTS" ]; then
  echo "Client ${CLIENT_ID} already exists. Deleting..."
  curl -s -X DELETE "${KEYCLOAK_URL}/admin/realms/${REALM}/clients/${CLIENT_EXISTS}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}"
  echo "Client deleted"
fi

# Create the client
echo "Creating client ${CLIENT_ID}..."
curl -s -X POST "${KEYCLOAK_URL}/admin/realms/${REALM}/clients" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "clientId": "'"${CLIENT_ID}"'",
    "name": "Micro Research UI",
    "description": "React UI for the Micro Research Platform",
    "enabled": true,
    "publicClient": true,
    "standardFlowEnabled": true,
    "implicitFlowEnabled": false,
    "directAccessGrantsEnabled": false,
    "serviceAccountsEnabled": false,
    "protocol": "openid-connect",
    "redirectUris": [
      "http://localhost:3000/*",
      "http://localhost/*",
      "http://ui:3000/*"
    ],
    "webOrigins": [
      "http://localhost:3000",
      "http://localhost",
      "http://ui:3000"
    ],
    "attributes": {
      "pkce.code.challenge.method": "S256"
    }
  }'

echo ""
echo "Client ${CLIENT_ID} created successfully!"
echo ""
echo "Client configuration:"
echo "  Client ID: ${CLIENT_ID}"
echo "  Type: Public (SPA)"
echo "  Flow: Authorization Code with PKCE"
echo "  Redirect URIs: http://localhost:3000/*, http://localhost/*"
echo ""
echo "Make sure your .env file has:"
echo "  VITE_KEYCLOAK_URL=${KEYCLOAK_URL}"
echo "  VITE_KEYCLOAK_REALM=${REALM}"
echo "  VITE_KEYCLOAK_CLIENT_ID=${CLIENT_ID}"