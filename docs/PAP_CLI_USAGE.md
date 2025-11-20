# Stratium PAP CLI Usage Guide

The Stratium PAP CLI (`pap-cli`) is a command-line interface for managing policies, entitlements, and audit logs in the Policy Administration Point.

## Installation

### Build from Source

```bash
make build-pap-cli
```

The binary will be created at `bin/pap-cli`.

### Install to System PATH

```bash
make install-pap-cli
```

This installs the CLI to `/usr/local/bin/pap-cli`, making it available system-wide.

## Getting Started

### Authentication

Before using the CLI, you need to authenticate with Keycloak:

```bash
pap-cli login --username admin456 --password admin123
```

This retrieves an access token and saves it to `~/.stratium/pap-token` for subsequent commands.

**Environment Variables:**
- `KEYCLOAK_URL`: Keycloak server URL (default: `http://localhost:8080`)
- `REALM`: Keycloak realm (default: `stratium`)
- `CLIENT_ID`: Client ID (default: `stratium-pap`)
- `CLIENT_SECRET`: Client secret (default: `stratium-pap-secret`)

**Token Management:**
- Token is automatically loaded from `~/.stratium/pap-token`
- Override with `--token` flag or `PAP_TOKEN` environment variable
- Logout with `pap-cli logout` to remove saved token

### Global Flags

All commands support these global flags:

- `--server <url>`: PAP server URL (default: `http://localhost:8090`, env: `PAP_SERVER_URL`)
- `--token <token>`: Access token for authentication (env: `PAP_TOKEN`)
- `--output, -o <format>`: Output format: `json`, `yaml`, or `table` (default: `table`)
- `--verbose, -v`: Enable verbose output for debugging

## Policy Management

### List Policies

```bash
# List all policies
pap-cli policy list

# List with filters
pap-cli policy list --language opa --enabled true --effect allow

# List with pagination
pap-cli policy list --limit 10 --offset 20

# Output as JSON
pap-cli policy list --output json
```

**Filters:**
- `--language <lang>`: Filter by language (`opa`, `xacml`)
- `--enabled <bool>`: Filter by enabled status (`true`, `false`)
- `--effect <effect>`: Filter by effect (`allow`, `deny`)
- `--limit <n>`: Maximum number of results (default: 50)
- `--offset <n>`: Pagination offset (default: 0)

### Get Policy by ID

```bash
pap-cli policy get <policy-id>

# Examples
pap-cli policy get a6b493ff-ee9d-4c67-8ff7-3e579a74b68d
pap-cli policy get a6b493ff-ee9d-4c67-8ff7-3e579a74b68d --output json
```

### Create Policy

**From JSON file:**
```bash
pap-cli policy create --file policy.json
```

**From inline JSON:**
```bash
pap-cli policy create --data '{
  "name": "my-policy",
  "description": "Test policy",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 50,
  "enabled": true
}'
```

**Using flags:**
```bash
pap-cli policy create \
  --name "my-policy" \
  --description "Test policy" \
  --language opa \
  --content "package stratium.authz..." \
  --effect allow \
  --priority 50 \
  --enabled true
```

**Example policy.json:**
```json
{
  "name": "admin-full-access",
  "description": "Administrators have full access",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 100,
  "enabled": true
}
```

### Update Policy

```bash
# Update from file
pap-cli policy update <policy-id> --file policy-update.json

# Update with inline JSON
pap-cli policy update <policy-id> --data '{"enabled": false}'
```

**Example policy-update.json:**
```json
{
  "enabled": false,
  "priority": 75
}
```

### Delete Policy

```bash
# Delete with confirmation prompt
pap-cli policy delete <policy-id>

# Force delete without confirmation
pap-cli policy delete <policy-id> --force
```

### Evaluate Policy

Test a policy against a set of attributes:

```bash
# Evaluate from file
pap-cli policy evaluate --file eval-request.json

# Evaluate with inline JSON
pap-cli policy evaluate --data '{
  "policy_id": "a6b493ff-ee9d-4c67-8ff7-3e579a74b68d",
  "language": "opa",
  "subject_attributes": {
    "role": "admin",
    "department": "engineering"
  },
  "resource_attributes": {
    "type": "document"
  },
  "action": "read"
}'
```

**Example eval-request.json:**
```json
{
  "policy_id": "a6b493ff-ee9d-4c67-8ff7-3e579a74b68d",
  "language": "opa",
  "subject_attributes": {
    "role": "admin",
    "department": "engineering"
  },
  "resource_attributes": {
    "type": "document",
    "classification": "confidential"
  },
  "action": "read",
  "environment": {
    "time": "2025-10-09T12:00:00Z",
    "ip_address": "192.168.1.1"
  }
}
```

## Entitlement Management

### List Entitlements

```bash
# List all entitlements
pap-cli entitlement list

# List with filters
pap-cli entitlement list --enabled true --action read

# List with pagination
pap-cli entitlement list --limit 10 --offset 0
```

**Filters:**
- `--enabled <bool>`: Filter by enabled status
- `--action <action>`: Filter by action (e.g., `read`, `write`, `delete`)
- `--limit <n>`: Maximum number of results (default: 50)
- `--offset <n>`: Pagination offset (default: 0)

### Get Entitlement by ID

```bash
pap-cli entitlement get <entitlement-id>
```

### Create Entitlement

```bash
# Create from file
pap-cli entitlement create --file entitlement.json

# Create with inline JSON
pap-cli entitlement create --data '{
  "name": "engineering-read-access",
  "description": "Engineering department read access",
  "subject_attributes": {
    "department": "engineering"
  },
  "resource_attributes": {
    "department": "engineering"
  },
  "actions": ["read", "list"],
  "conditions": {},
  "enabled": true
}'
```

**Example entitlement.json:**
```json
{
  "name": "engineering-document-access",
  "description": "Engineering team can access engineering documents",
  "subject_attributes": {
    "department": "engineering",
    "role": "developer"
  },
  "resource_attributes": {
    "type": "document",
    "department": "engineering"
  },
  "actions": ["read", "write"],
  "conditions": {
    "time_based": {
      "start_time": "09:00:00",
      "end_time": "17:00:00"
    }
  },
  "enabled": true,
  "expires_at": "2026-12-31T23:59:59Z"
}
```

### Update Entitlement

```bash
# Update from file
pap-cli entitlement update <entitlement-id> --file entitlement-update.json

# Update with inline JSON
pap-cli entitlement update <entitlement-id> --data '{"enabled": false}'
```

### Delete Entitlement

```bash
# Delete with confirmation
pap-cli entitlement delete <entitlement-id>

# Force delete
pap-cli entitlement delete <entitlement-id> --force
```

### Match Entitlements

Find entitlements that match given subject attributes and action:

```bash
# Match from file
pap-cli entitlement match --file match-request.json

# Match with inline JSON
pap-cli entitlement match --data '{
  "subject_attributes": {
    "role": "developer",
    "department": "engineering"
  },
  "action": "read"
}'
```

**Example match-request.json:**
```json
{
  "subject_attributes": {
    "role": "developer",
    "department": "engineering",
    "classification": "confidential"
  },
  "action": "read"
}
```

## Audit Log Management

### List Audit Logs

```bash
# List all audit logs
pap-cli audit list

# List with filters
pap-cli audit list --entity-type policy --action create --actor admin456

# List with time range
pap-cli audit list --start-time "2025-10-09T00:00:00Z" --end-time "2025-10-09T23:59:59Z"

# List with pagination
pap-cli audit list --limit 20 --offset 0
```

**Filters:**
- `--entity-type <type>`: Filter by entity type (`policy`, `entitlement`)
- `--entity-id <id>`: Filter by specific entity ID
- `--action <action>`: Filter by action (`create`, `update`, `delete`, `evaluate`)
- `--actor <username>`: Filter by actor (username)
- `--start-time <time>`: Filter by start time (RFC3339 format)
- `--end-time <time>`: Filter by end time (RFC3339 format)
- `--limit <n>`: Maximum number of results (default: 50)
- `--offset <n>`: Pagination offset (default: 0)

### Get Audit Log by ID

```bash
pap-cli audit get <log-id>
```

## Output Formats

The CLI supports three output formats:

### Table (Default)

Human-readable table format:

```bash
pap-cli policy list
```

### JSON

Machine-readable JSON format:

```bash
pap-cli policy list --output json
```

### YAML

YAML format for configuration management:

```bash
pap-cli policy list --output yaml
```

## Examples

### Complete Workflow Example

```bash
# 1. Login
pap-cli login --username admin456 --password admin123

# 2. List existing policies
pap-cli policy list

# 3. Create a new policy
cat > my-policy.json <<EOF
{
  "name": "data-scientist-access",
  "description": "Data scientists can read datasets",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"data-scientist\"\n    input.resource.type == \"dataset\"\n    input.action == \"read\"\n}",
  "effect": "allow",
  "priority": 60,
  "enabled": true
}
EOF

pap-cli policy create --file my-policy.json

# 4. Get the policy (save ID from previous output)
POLICY_ID="<policy-id-from-create>"
pap-cli policy get $POLICY_ID

# 5. Test the policy
pap-cli policy evaluate --data '{
  "policy_id": "'$POLICY_ID'",
  "language": "opa",
  "subject_attributes": {"role": "data-scientist"},
  "resource_attributes": {"type": "dataset"},
  "action": "read"
}'

# 6. Create an entitlement
pap-cli entitlement create --data '{
  "name": "data-scientist-entitlement",
  "subject_attributes": {"role": "data-scientist"},
  "resource_attributes": {"type": "dataset"},
  "actions": ["read"],
  "enabled": true
}'

# 7. View audit logs
pap-cli audit list --action create --actor admin456

# 8. Logout
pap-cli logout
```

### Scripting Example

```bash
#!/bin/bash
# Script to export all policies to JSON files

# Login
pap-cli login --username admin456 --password admin123

# Get all policies as JSON
pap-cli policy list --output json --limit 1000 > policies.json

# Extract each policy ID and save individually
jq -r '.policies[].id' policies.json | while read -r id; do
    echo "Exporting policy: $id"
    pap-cli policy get "$id" --output json > "policy-$id.json"
done

echo "Export complete!"
```

### CI/CD Integration Example

```bash
#!/bin/bash
# Deploy policies in CI/CD pipeline

set -e

# Authenticate with service account
pap-cli login \
  --username "${PAP_USERNAME}" \
  --password "${PAP_PASSWORD}" \
  --keycloak-url "${KEYCLOAK_URL}"

# Deploy all policies from policies/ directory
for policy_file in policies/*.json; do
    echo "Deploying $policy_file"
    pap-cli policy create --file "$policy_file" || true
done

# Verify deployment
pap-cli policy list --enabled true

echo "Deployment successful!"
```

## Troubleshooting

### Authentication Issues

**Problem:** `No authentication token found`

**Solution:**
```bash
# Login again
pap-cli login --username admin456 --password admin123

# Or set token manually
export PAP_TOKEN="your-token-here"
pap-cli policy list
```

### Connection Issues

**Problem:** `failed to send request: connection refused`

**Solution:**
```bash
# Check if PAP server is running
docker-compose ps

# Or check local server
curl http://localhost:8090/health

# Use correct server URL
pap-cli policy list --server http://your-pap-server:8090
```

### Verbose Mode

Enable verbose mode for debugging:

```bash
pap-cli policy list --verbose
```

This shows HTTP requests, responses, and other debug information.

## Configuration

### Environment Variables

- `PAP_SERVER_URL`: PAP server URL (default: `http://localhost:8090`)
- `PAP_TOKEN`: Authentication token
- `KEYCLOAK_URL`: Keycloak server URL (default: `http://localhost:8080`)
- `REALM`: Keycloak realm (default: `stratium`)
- `CLIENT_ID`: Client ID (default: `stratium-pap`)
- `CLIENT_SECRET`: Client secret (default: `stratium-pap-secret`)

### Token Storage

Tokens are stored in `~/.stratium/pap-token` with file permissions `0600` (read/write for owner only).

## Command Reference

| Command | Description |
|---------|-------------|
| `pap-cli login` | Authenticate and save token |
| `pap-cli logout` | Remove saved token |
| `pap-cli policy list` | List policies |
| `pap-cli policy get <id>` | Get policy by ID |
| `pap-cli policy create` | Create policy |
| `pap-cli policy update <id>` | Update policy |
| `pap-cli policy delete <id>` | Delete policy |
| `pap-cli policy evaluate` | Evaluate policy |
| `pap-cli entitlement list` | List entitlements |
| `pap-cli entitlement get <id>` | Get entitlement by ID |
| `pap-cli entitlement create` | Create entitlement |
| `pap-cli entitlement update <id>` | Update entitlement |
| `pap-cli entitlement delete <id>` | Delete entitlement |
| `pap-cli entitlement match` | Find matching entitlements |
| `pap-cli audit list` | List audit logs |
| `pap-cli audit get <id>` | Get audit log by ID |
| `pap-cli version` | Print version |
| `pap-cli help` | Show help |

## Additional Resources

- [PAP API Documentation](./PAP_API.md)
- [Policy Language Guide](./POLICY_LANGUAGE.md)
- [Stratium Architecture](./ARCHITECTURE.md)
