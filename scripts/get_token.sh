#!/bin/bash

# Script to get an access token from Keycloak
# Usage: ./get_token.sh [--ssl] [username] [password]
#
# --ssl  Show PAP curl examples with https and -k (Keycloak itself is always HTTP in local dev)

# Parse flags
PAP_SCHEME="http"
PAP_CURL_FLAGS=""
while [[ "$1" == --* ]]; do
    case "$1" in
        --ssl)
            PAP_SCHEME="https"
            PAP_CURL_FLAGS="-k"
            shift
            ;;
        *)
            echo "Unknown flag: $1" >&2
            exit 1
            ;;
    esac
done

STRATIUM_KEYCLOAK_URL="${STRATIUM_KEYCLOAK_URL:-http://localhost:8080}"
STRATIUM_REALM="${STRATIUM_REALM:-stratium}"
STRATIUM_CLIENT_ID="${STRATIUM_CLIENT_ID:-stratium-pap}"
STRATIUM_CLIENT_SECRET="${STRATIUM_CLIENT_SECRET:-stratium-pap-secret}"
STRATIUM_PAP_URL="${STRATIUM_PAP_URL:-${PAP_SCHEME}://localhost:8090}"

USERNAME="${1:-admin456}"
PASSWORD="${2:-admin123}"

echo "Getting token for user: $USERNAME" >&2
echo "Keycloak URL: $STRATIUM_KEYCLOAK_URL" >&2
echo "Realm: $STRATIUM_REALM" >&2
echo "" >&2

response=$(curl -s -X POST \
    "${STRATIUM_KEYCLOAK_URL}/realms/${STRATIUM_REALM}/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "client_id=${STRATIUM_CLIENT_ID}" \
    -d "client_secret=${STRATIUM_CLIENT_SECRET}" \
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
echo "  curl ${PAP_CURL_FLAGS:+$PAP_CURL_FLAGS }-H \"Authorization: Bearer \$TOKEN\" ${STRATIUM_PAP_URL}/api/v1/policies" >&2
echo "" >&2
echo "Token (copy this):" >&2
echo "$access_token"

# Also decode and show claims
echo "" >&2
echo "Token claims:" >&2
payload=$(echo "$access_token" | cut -d'.' -f2 | tr '_-' '/+')
# Pad to multiple of 4 for base64
padding=$(( (4 - ${#payload} % 4) % 4 ))
payload="${payload}$(printf '%0.s=' $(seq 1 $padding 2>/dev/null))"
echo "$payload" | base64 -d 2>/dev/null | jq '.' >&2 || echo "Failed to decode token" >&2
