#!/bin/bash

# Script to get an access token from Keycloak
# Usage: ./get_token.sh [username] [password]

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8080}"
REALM="${REALM:-stratium}"
CLIENT_ID="${CLIENT_ID:-stratium-pap}"
CLIENT_SECRET="${CLIENT_SECRET:-stratium-pap-secret}"

USERNAME="${1:-admin456}"
PASSWORD="${2:-admin123}"

echo "Getting token for user: $USERNAME" >&2
echo "Keycloak URL: $KEYCLOAK_URL" >&2
echo "Realm: $REALM" >&2
echo "" >&2

response=$(curl -s -X POST \
    "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${CLIENT_ID}" \
    -d "client_secret=${CLIENT_SECRET}" \
    -d "grant_type=password" \
    -d "username=${USERNAME}" \
    -d "password=${PASSWORD}")

access_token=$(echo $response | jq -r '.access_token')

if [ "$access_token" = "null" ] || [ -z "$access_token" ]; then
    echo "Failed to get access token" >&2
    echo "Response: $response" >&2
    exit 1
fi

echo "Access token obtained successfully!" >&2
echo "" >&2
echo "To use in curl:" >&2
echo "  curl -H \"Authorization: Bearer \$TOKEN\" http://localhost:8090/api/v1/policies" >&2
echo "" >&2
echo "Token (copy this):" >&2
echo "$access_token"

# Also decode and show claims
echo "" >&2
echo "Token claims:" >&2
echo $access_token | cut -d'.' -f2 | base64 -d 2>/dev/null | jq '.' >&2 || echo "Failed to decode token" >&2
