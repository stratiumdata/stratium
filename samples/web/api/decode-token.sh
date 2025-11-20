#!/bin/bash
curl -s -X POST 'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=password' \
  -d 'client_id=micro-research-api' \
  -d 'client_secret=micro-research-secret' \
  -d 'username=user123' \
  -d 'password=password123' > /tmp/token.json

cat /tmp/token.json | jq -r '.access_token' | cut -d'.' -f2 | base64 -d 2>/dev/null | jq .