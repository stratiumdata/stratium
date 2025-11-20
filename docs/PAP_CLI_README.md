# Stratium PAP CLI

A powerful command-line interface for managing the Stratium Policy Administration Point (PAP).

## Features

- **Policy Management**: Create, read, update, delete, and evaluate ABAC policies
- **Entitlement Management**: Manage fine-grained access entitlements with attribute-based matching
- **Audit Logging**: Query and analyze audit logs for compliance and security monitoring
- **Authentication**: Integrated Keycloak authentication with automatic token management
- **Multiple Output Formats**: Table, JSON, and YAML output for human and machine consumption
- **Scripting Support**: Perfect for CI/CD pipelines and automation workflows

## Quick Start

### Installation

```bash
# Build the CLI
make build-pap-cli

# Install to system PATH (optional)
make install-pap-cli
```

### Basic Usage

```bash
# Authenticate
pap-cli login --username admin456 --password admin123

# List policies
pap-cli policy list

# Create a policy from file
pap-cli policy create --file my-policy.json

# List entitlements
pap-cli entitlement list

# View audit logs
pap-cli audit list --action create --actor admin456

# Logout
pap-cli logout
```

## Commands Overview

### Policy Commands

| Command | Description |
|---------|-------------|
| `policy list` | List all policies with optional filtering |
| `policy get <id>` | Get a specific policy by ID |
| `policy create` | Create a new policy from file or inline JSON |
| `policy update <id>` | Update an existing policy |
| `policy delete <id>` | Delete a policy |
| `policy evaluate` | Test a policy against attributes |

### Entitlement Commands

| Command | Description |
|---------|-------------|
| `entitlement list` | List all entitlements with optional filtering |
| `entitlement get <id>` | Get a specific entitlement by ID |
| `entitlement create` | Create a new entitlement |
| `entitlement update <id>` | Update an existing entitlement |
| `entitlement delete <id>` | Delete an entitlement |
| `entitlement match` | Find matching entitlements for subject/action |

### Audit Commands

| Command | Description |
|---------|-------------|
| `audit list` | List audit logs with extensive filtering options |
| `audit get <id>` | Get a specific audit log entry by ID |

### Authentication Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate with Keycloak and save token |
| `logout` | Remove saved authentication token |

## Output Formats

The CLI supports three output formats:

- **Table** (default): Human-readable table format
- **JSON**: Machine-readable JSON for scripting
- **YAML**: YAML format for configuration management

```bash
# Table output
pap-cli policy list

# JSON output
pap-cli policy list --output json

# YAML output
pap-cli policy list --output yaml
```

## Configuration

### Environment Variables

- `PAP_SERVER_URL`: PAP server URL (default: `http://localhost:8090`)
- `PAP_TOKEN`: Authentication token (auto-loaded from `~/.stratium/pap-token`)
- `KEYCLOAK_URL`: Keycloak server URL (default: `http://localhost:8080`)
- `REALM`: Keycloak realm (default: `stratium`)
- `CLIENT_ID`: Client ID (default: `stratium-pap`)
- `CLIENT_SECRET`: Client secret (default: `stratium-pap-secret`)

### Global Flags

All commands support:

- `--server <url>`: Override PAP server URL
- `--token <token>`: Override authentication token
- `--output, -o <format>`: Output format (table, json, yaml)
- `--verbose, -v`: Enable verbose/debug output

## Examples

### Create and Test a Policy

```bash
# Create a policy
cat > admin-policy.json <<EOF
{
  "name": "admin-full-access",
  "description": "Administrators have full access",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
  "effect": "allow",
  "priority": 100,
  "enabled": true
}
EOF

pap-cli policy create --file admin-policy.json

# Test the policy
pap-cli policy evaluate --data '{
  "policy_id": "<policy-id>",
  "language": "opa",
  "subject_attributes": {"role": "admin"},
  "resource_attributes": {"type": "document"},
  "action": "read"
}'
```

### Export All Policies

```bash
# Get all policies as JSON
pap-cli policy list --output json --limit 1000 > policies.json

# Extract and save individually
jq -r '.policies[].id' policies.json | while read id; do
    pap-cli policy get "$id" --output json > "policy-$id.json"
done
```

### CI/CD Integration

```bash
#!/bin/bash
set -e

# Authenticate
pap-cli login --username "$PAP_USER" --password "$PAP_PASS"

# Deploy policies
for policy in policies/*.json; do
    echo "Deploying $policy"
    pap-cli policy create --file "$policy"
done

# Verify
pap-cli policy list --enabled true
```

### Monitor Policy Changes

```bash
# View all policy modifications today
pap-cli audit list \
  --entity-type policy \
  --action update \
  --start-time "$(date -u +%Y-%m-%dT00:00:00Z)" \
  --output json | jq '.audit_logs[] | {actor, policy: .changes.policy_name, time: .timestamp}'
```

## Architecture

The CLI is built with:

- **Cobra**: Modern CLI framework with subcommands and flags
- **HTTP Client**: RESTful API communication with the PAP server
- **Token Management**: Automatic token storage and retrieval
- **Multiple Output Formats**: Table, JSON, and YAML rendering

```
pap-cli
├── cmd/
│   ├── root.go          # Root command and global flags
│   ├── policy.go        # Policy management commands
│   ├── entitlement.go   # Entitlement management commands
│   ├── audit.go         # Audit log commands
│   ├── login.go         # Authentication commands
│   ├── client.go        # HTTP client implementation
│   └── output.go        # Output formatting utilities
└── main.go              # Entry point
```

## Testing

The CLI has been tested against the live PAP API:

```bash
# Start the services
make docker-up

# Build the CLI
make build-pap-cli

# Test authentication
./bin/pap-cli login --username admin456 --password admin123

# Test policy operations
./bin/pap-cli policy list
./bin/pap-cli policy get <policy-id>

# Test entitlement operations
./bin/pap-cli entitlement list

# Test audit operations
./bin/pap-cli audit list --action create
```

## Documentation

- [Complete Usage Guide](./PAP_CLI_USAGE.md) - Comprehensive CLI documentation with all commands and examples
- [PAP API Documentation](./PAP_API.md) - REST API reference
- [Policy Language Guide](./POLICY_LANGUAGE.md) - OPA and XACML policy syntax

## Development

### Building

```bash
# Build locally
cd go && go build -o ../bin/pap-cli ./cmd/pap-cli

# Or use Make
make build-pap-cli
```

### Adding New Commands

1. Create a new command file in `go/cmd/pap-cli/cmd/`
2. Define cobra commands with appropriate flags
3. Implement the command logic using the API client
4. Register the command in `root.go`

### Dependencies

- `github.com/spf13/cobra` - CLI framework
- `gopkg.in/yaml.v3` - YAML output support

## Troubleshooting

### Authentication Errors

```bash
# Clear saved token and re-authenticate
pap-cli logout
pap-cli login --username admin456 --password admin123
```

### Connection Issues

```bash
# Check server status
curl http://localhost:8090/health

# Use verbose mode for debugging
pap-cli policy list --verbose
```

### Token Expired

```bash
# Tokens expire after 1 hour by default
# Simply login again to get a new token
pap-cli login --username admin456 --password admin123
```

## License

Part of the Stratium project.

## Support

For issues and feature requests, please refer to the main Stratium documentation.
