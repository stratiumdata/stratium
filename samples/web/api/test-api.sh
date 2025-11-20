#!/bin/bash

# Get access token
TOKEN=$(curl -s -X POST 'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=micro-research-api' \
  -d 'client_secret=micro-research-secret' \
  -d 'username=user123' \
  -d 'password=password123' | jq -r '.access_token')

if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
  echo "Failed to get access token"
  exit 1
fi

echo "SUCCESS: Got access token!"
echo "Token: ${TOKEN}"
echo ""

# Test the /api/v1/users/me endpoint
echo "Testing /api/v1/users/me endpoint:"
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:8888/api/v1/users/me | jq .
