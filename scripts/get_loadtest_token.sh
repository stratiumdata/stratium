#!/bin/bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./scripts/get_loadtest_token.sh [-u base_url] [-r realm] [-i client_id] [-s client_secret]

Retrieves a Keycloak access token using the stratium-load-test client (client credentials grant).
Environment overrides:
  KEYCLOAK_BASE_URL         Default: http://localhost:8080
  KEYCLOAK_REALM            Default: stratium
  LOADTEST_CLIENT_ID        Default: stratium-load-test
  LOADTEST_CLIENT_SECRET    Default: stratium-load-test-secret
EOF
}

BASE_URL="${KEYCLOAK_BASE_URL:-http://localhost:8080}"
REALM="${KEYCLOAK_REALM:-stratium}"
CLIENT_ID="${LOADTEST_CLIENT_ID:-stratium-load-test}"
CLIENT_SECRET="${LOADTEST_CLIENT_SECRET:-stratium-load-test-secret}"

while getopts "u:r:i:s:h" opt; do
  case "$opt" in
    u) BASE_URL="$OPTARG" ;;
    r) REALM="$OPTARG" ;;
    i) CLIENT_ID="$OPTARG" ;;
    s) CLIENT_SECRET="$OPTARG" ;;
    h)
      usage
      exit 0
      ;;
    *)
      usage
      exit 1
      ;;
  esac
done

TOKEN_ENDPOINT="${BASE_URL%/}/realms/${REALM}/protocol/openid-connect/token"

echo "Requesting token from ${TOKEN_ENDPOINT} for client ${CLIENT_ID}..."

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}")

HTTP_BODY=$(echo "$RESPONSE" | sed '$d')
HTTP_CODE=$(echo "$RESPONSE" | tail -n1)

if [ "$HTTP_CODE" != "200" ]; then
  echo "Failed to retrieve token (HTTP $HTTP_CODE)"
  echo "$HTTP_BODY"
  exit 1
fi

ACCESS_TOKEN=$(echo "$HTTP_BODY" | jq -r '.access_token')
EXPIRES_IN=$(echo "$HTTP_BODY" | jq -r '.expires_in')

if [ -z "${ACCESS_TOKEN}" ] || [ "${ACCESS_TOKEN}" = "null" ]; then
  echo "No access_token field found in response:"
  echo "$HTTP_BODY"
  exit 1
fi

echo ""
echo "Access token (expires in ${EXPIRES_IN}s):"
echo "$ACCESS_TOKEN"
echo ""
echo "Token claims preview:"
PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null || true)
if [ -n "$PAYLOAD" ]; then
  echo "$PAYLOAD" | jq .
else
  echo "(could not decode token payload)"
fi
