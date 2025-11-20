# Stratium Policy Administration Point (PAP) API Guide

## Overview

The PAP API provides a RESTful interface for managing ABAC (Attribute-Based Access Control) policies and entitlements in the Stratium platform.

## Features

- **Policy Management**: Create, read, update, and delete OPA and XACML policies
- **Entitlement Management**: Manage attribute-based entitlements
- **Policy Testing**: Test and simulate policies before deployment
- **Audit Logging**: Track all policy and entitlement changes
- **Keycloak Authentication**: Secure API access with OIDC tokens

## Getting Started

### Prerequisites

- Docker and Docker Compose
- jq (for testing scripts)
- curl

### Starting the Services

```bash
cd deployment
docker-compose up -d
```

This starts:
- PostgreSQL (with stratium_pap database)
- Keycloak (OIDC provider)
- PAP API (port 8090)

### Verify Services

```bash
# Check PAP health
curl http://localhost:8090/health

# Check Keycloak
curl http://localhost:8080/realms/stratium
```

## Authentication

All PAP API endpoints require authentication via Keycloak. You need a valid Bearer token in the Authorization header.

### Getting an Access Token

#### Using the Helper Script

```bash
# Get token for admin user
./scripts/get_token.sh admin456 admin123

# Get token for regular user
./scripts/get_token.sh user123 password123
```

#### Manual Token Request

```bash
curl -X POST \
  'http://localhost:8080/realms/stratium/protocol/openid-connect/token' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'client_id=stratium-pap' \
  -d 'client_secret=stratium-pap-secret' \
  -d 'grant_type=password' \
  -d 'username=admin456' \
  -d 'password=admin123'
```

### Using the Token

```bash
TOKEN="your-access-token-here"

curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/policies
```

## API Endpoints

### Policies

#### Create Policy

```bash
curl -X POST http://localhost:8090/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "admin-full-access",
    "description": "Administrators have full access",
    "language": "opa",
    "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
    "effect": "allow",
    "priority": 100,
    "enabled": true
  }'
```

#### List Policies

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8090/api/v1/policies?limit=10&offset=0"
```

#### Get Policy by ID

```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/policies/{policy-id}
```

#### Update Policy

```bash
curl -X PUT http://localhost:8090/api/v1/policies/{policy-id} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": false,
    "description": "Updated description"
  }'
```

#### Delete Policy

```bash
curl -X DELETE http://localhost:8090/api/v1/policies/{policy-id} \
  -H "Authorization: Bearer $TOKEN"
```

#### Validate Policy

```bash
curl -X POST http://localhost:8090/api/v1/policies/validate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "language": "opa",
    "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}"
  }'
```

#### Test Policy

```bash
curl -X POST http://localhost:8090/api/v1/policies/test \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "language": "opa",
    "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}",
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

### Entitlements

#### Create Entitlement

```bash
curl -X POST http://localhost:8090/api/v1/entitlements \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "engineering-read-access",
    "description": "Engineering can read engineering resources",
    "subject_attributes": {
      "department": "engineering"
    },
    "resource_attributes": {
      "department": "engineering"
    },
    "actions": ["read", "list"],
    "enabled": true
  }'
```

#### List Entitlements

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8090/api/v1/entitlements?limit=10"
```

#### Find Matching Entitlements

```bash
curl -X POST http://localhost:8090/api/v1/entitlements/match \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_attributes": {
      "department": "engineering"
    },
    "action": "read"
  }'
```

### Audit Logs

#### List Audit Logs

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8090/api/v1/audit-logs?limit=20"
```

#### Filter Audit Logs

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8090/api/v1/audit-logs?entity_type=policy&action=create"
```

## Test Users

The system includes several pre-configured test users:

| Username | Password | Role | Classification | Department |
|----------|----------|------|----------------|------------|
| admin456 | admin123 | admin | top-secret | administration |
| user123 | password123 | developer | confidential | engineering |
| test-user | test123 | tester | secret | engineering |
| service-account-1 | service123 | service | unclassified | services |

## OPA Policy Examples

### Admin Access Policy

```rego
package stratium.authz

default allow = false

allow {
    input.subject.role == "admin"
}
```

### Classification-Based Access

```rego
package stratium.authz

default allow = false

classification_levels := {
    "unclassified": 0,
    "confidential": 1,
    "secret": 2,
    "top-secret": 3
}

allow {
    subject_level := classification_levels[input.subject.classification]
    resource_level := classification_levels[input.resource.classification]
    subject_level >= resource_level
}
```

### Department-Based Access

```rego
package stratium.authz

default allow = false

allow {
    input.subject.department == input.resource.department
    input.action == "read"
}
```

## Testing

### Automated Tests

Run the comprehensive test suite:

```bash
./scripts/test_pap_auth.sh
```

This script:
1. Tests health endpoint
2. Authenticates users
3. Tests all API endpoints
4. Creates, reads, updates, and deletes policies
5. Validates tokens and claims

### Manual Testing

1. Get a token:
```bash
TOKEN=$(./scripts/get_token.sh admin456 admin123 | tail -1)
```

2. Test endpoints:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8090/api/v1/policies
```

## Environment Variables

Configure the PAP service via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| PAP_SERVER_ADDR | :8090 | Server listen address |
| DATABASE_URL | postgres://... | PostgreSQL connection string |
| OIDC_ISSUER_URL | http://keycloak:8080/realms/stratium | Keycloak issuer URL |
| OIDC_CLIENT_ID | stratium-pap | OAuth2 client ID |
| OIDC_CLIENT_SECRET | stratium-pap-secret | OAuth2 client secret |

## Troubleshooting

### Token Validation Fails

- Verify Keycloak is running: `curl http://localhost:8080/realms/stratium`
- Check token hasn't expired (default: 1 hour)
- Ensure correct client ID and secret
- Verify OIDC_ISSUER_URL matches your Keycloak URL

### Database Connection Issues

- Check PostgreSQL is running: `docker-compose ps postgres`
- Verify database exists: `docker-compose exec postgres psql -U stratium -d stratium_pap -c '\dt'`
- Check DATABASE_URL environment variable

### Policy Validation Errors

- For OPA policies, ensure they compile: Use the `/policies/validate` endpoint first
- Check policy syntax follows OPA Rego language specification
- Verify the policy package is `stratium.authz`

## Next Steps

- Set up the React Web UI for visual policy management
- Create CLI client for automation
- Integrate with Platform Service (PDP) for policy enforcement
- Implement policy caching for improved performance

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [Stratium Architecture](./ARCHITECTURE.md)
