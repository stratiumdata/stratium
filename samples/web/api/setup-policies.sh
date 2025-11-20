#!/bin/bash

PAP_URL="http://localhost:8090/api/v1/policies"

echo "================================================="
echo "Creating ABAC Policies for Micro Research API"
echo "================================================="
echo ""

# Policy 1: Admin Full Access (Highest Priority)
echo "1. Creating admin-full-access policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "admin-full-access",
  "description": "Administrators have full access to all datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.resource.resource_type == \"dataset\"\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 100,
  "enabled": true
}' | jq -r 'if .id then "✓ Created: \(.name) (ID: \(.id))" else "✗ Error: \(.error // .message)" end'

echo ""

# Policy 2: Department Read Isolation
echo "2. Creating department-read-isolation policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "department-read-isolation",
  "description": "Users can only read datasets from their department",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.action == \"read\"\n    input.resource.resource_type == \"dataset\"\n    input.subject.department == input.resource.department\n}",
  "effect": "allow",
  "priority": 200,
  "enabled": true
}' | jq -r 'if .id then "✓ Created: \(.name) (ID: \(.id))" else "✗ Error: \(.error // .message)" end'

echo ""

# Policy 3: Department Editor Access
echo "3. Creating department-editor-access policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "department-editor-access",
  "description": "Editors can read and update datasets in their department",
  "language": "opa",
  "policy_content": "package stratium.authz\n\nimport future.keywords.in\n\ndefault allow = false\n\nallow {\n    input.action in [\"read\", \"update\"]\n    input.resource.resource_type == \"dataset\"\n    input.subject.department == input.resource.department\n    input.subject.role == \"editor\"\n}",
  "effect": "allow",
  "priority": 250,
  "enabled": true
}' | jq -r 'if .id then "✓ Created: \(.name) (ID: \(.id))" else "✗ Error: \(.error // .message)" end'

echo ""

# Policy 4: Owner Write Access (Highest Priority for Ownership)
echo "4. Creating owner-write-access policy..."
curl -s -X POST "$PAP_URL" \
  -H 'Content-Type: application/json' \
  -d '{
  "name": "owner-write-access",
  "description": "Dataset owners can update and delete their datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\nimport future.keywords.in\n\ndefault allow = false\n\nallow {\n    input.action in [\"update\", \"delete\"]\n    input.resource.resource_type == \"dataset\"\n    input.resource.owner_id == input.subject.subject_id\n}",
  "effect": "allow",
  "priority": 300,
  "enabled": true
}' | jq -r 'if .id then "✓ Created: \(.name) (ID: \(.id))" else "✗ Error: \(.error // .message)" end'

echo ""
echo "================================================="
echo "Policy Setup Complete!"
echo "================================================="
echo ""
echo "Summary of Access Control Policies:"
echo ""
echo "Priority 100: Admin Full Access"
echo "  - Admins can perform any action on all datasets"
echo ""
echo "Priority 200: Department Read Isolation"
echo "  - Users can read datasets from their department"
echo ""
echo "Priority 250: Department Editor Access"
echo "  - Editors can read and update datasets in their department"
echo ""
echo "Priority 300: Owner Write Access"
echo "  - Dataset owners can update and delete their datasets"
echo ""
echo "================================================="
echo ""
echo "To view all policies:"
echo "  curl http://localhost:8090/api/v1/policies | jq ."
echo ""
echo "To test the ABAC demo:"
echo "  ./test-abac-scenarios.sh"
echo ""