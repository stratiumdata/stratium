#!/bin/bash

set -e

echo "Getting Keycloak admin token..."
ADMIN_TOKEN=$(curl -s -X POST 'http://localhost:8080/realms/master/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'username=admin' \
  -d 'password=admin' \
  -d 'grant_type=password' \
  -d 'client_id=admin-cli' | jq -r '.access_token')

if [ "$ADMIN_TOKEN" = "null" ] || [ -z "$ADMIN_TOKEN" ]; then
  echo "ERROR: Failed to get admin token"
  exit 1
fi

echo "Creating stratium-pap client..."

cat > /tmp/pap-client.json << 'EOF'
{
  "clientId": "stratium-pap",
  "name": "Stratium Policy Administration Point",
  "description": "API service for policy and entitlement administration",
  "enabled": true,
  "clientAuthenticatorType": "client-secret",
  "secret": "stratium-pap-secret",
  "bearerOnly": false,
  "consentRequired": false,
  "standardFlowEnabled": true,
  "implicitFlowEnabled": false,
  "directAccessGrantsEnabled": true,
  "serviceAccountsEnabled": false,
  "publicClient": false,
  "protocol": "openid-connect",
  "attributes": {
    "access.token.lifespan": "3600"
  },
  "redirectUris": [
    "http://localhost:8090/*",
    "http://localhost:8090/callback"
  ],
  "webOrigins": [
    "http://localhost:8090"
  ],
  "protocolMappers": [
    {
      "name": "classification",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-usermodel-attribute-mapper",
      "consentRequired": false,
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
      "consentRequired": false,
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
      "consentRequired": false,
      "config": {
        "userinfo.token.claim": "true",
        "user.attribute": "role",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "claim.name": "role",
        "jsonType.label": "String"
      }
    },
    {
      "name": "audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "consentRequired": false,
      "config": {
        "included.client.audience": "stratium-pap",
        "id.token.claim": "false",
        "access.token.claim": "true"
      }
    }
  ]
}
EOF

HTTP_CODE=$(curl -s -w "%{http_code}" -o /tmp/pap-response.txt -X POST 'http://localhost:8080/admin/realms/stratium/clients' \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d @/tmp/pap-client.json)

BODY=$(cat /tmp/pap-response.txt)

if [ "$HTTP_CODE" = "201" ]; then
  echo "✓ Client created successfully!"
elif [ "$HTTP_CODE" = "409" ]; then
  echo "⚠ Client already exists"
else
  echo "✗ Failed to create client (HTTP $HTTP_CODE)"
  echo "$BODY"
  exit 1
fi

echo ""
echo "Testing token retrieval with new client..."
TOKEN=$(curl -s -X POST 'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=stratium-pap' \
  -d 'client_secret=stratium-pap-secret' \
  -d 'grant_type=password' \
  -d 'username=admin456' \
  -d 'password=admin123' | jq -r '.access_token')

if [ "$TOKEN" != "null" ] && [ -n "$TOKEN" ]; then
  echo "✓ Successfully retrieved token for stratium-pap client"
  echo ""
  echo "Token claims:"
  echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq . || echo "(could not decode token)"
else
  echo "✗ Failed to retrieve token"
fi