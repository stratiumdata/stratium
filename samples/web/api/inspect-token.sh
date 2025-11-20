#!/bin/bash

# Get access token
TOKEN=$(curl -s -X POST 'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=micro-research-api' \
  -d 'client_secret=micro-research-secret' \
  -d 'username=user123' \
  -d 'password=password123')

echo "Full token response:"
echo "$TOKEN" | jq .

# Extract and decode access token
ACCESS_TOKEN=$(echo "$TOKEN" | jq -r '.access_token')

if [ -n "$ACCESS_TOKEN" ] && [ "$ACCESS_TOKEN" != "null" ]; then
  echo ""
  echo "Decoded access token payload:"
  echo "$ACCESS_TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .
fi
