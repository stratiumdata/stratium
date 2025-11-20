# Keycloak OIDC Setup

This document describes how to use Keycloak for authentication with the Stratium key management system.

## Overview

Stratium uses Keycloak as an OpenID Connect (OIDC) provider to authenticate users and issue JWT tokens. These tokens contain user claims (subject ID, email, groups, etc.) that are used for:

1. **Identity verification** - Ensuring the user is who they claim to be
2. **Authorization** - Evaluating ABAC rules based on user attributes
3. **Audit logging** - Tracking which users access which keys

## Architecture

```
┌─────────┐         ┌──────────┐         ┌──────────────┐         ┌─────────────┐
│  User   │────────▶│ Keycloak │────────▶│ Key Access   │────────▶│ Key Manager │
│ /Client │  Login  │   OIDC   │  Token  │   Service    │  gRPC   │   Service   │
└─────────┘         └──────────┘         └──────────────┘         └─────────────┘
                         │                       │
                         │                       │
                         ▼                       ▼
                    JWT Token              Token Validation
                    with Claims            + ABAC Evaluation
```

## Quick Start

### 1. Start Keycloak and Services

```bash
# Navigate to deployment directory
cd deployment

# Start all services including Keycloak
docker-compose up -d

# Wait for Keycloak to be ready (about 30-60 seconds)
docker-compose logs -f keycloak
```

### 2. Access Keycloak Admin Console

- URL: http://localhost:8080
- Username: `admin`
- Password: `admin`

The Stratium realm is automatically imported with pre-configured users and clients.

### 3. Get an Access Token

Use the provided script to obtain a token:

```bash
./scripts/keycloak-login.sh user123 password123
```

This will:
- Authenticate with Keycloak
- Retrieve an access token
- Display token claims
- Save tokens to a file
- Show example commands

### 4. Use the Token with gRPC Services

```bash
# Export the token
export ACCESS_TOKEN="<token from previous step>"

# Make an authenticated request
grpcurl -plaintext -H "authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "resource": "test-resource",
    "action": "wrap_dek",
    "dek": "dGVzdC1kZWs="
  }' \
  localhost:50053 \
  key_access.KeyAccessService/WrapDEK
```

## Pre-configured Users

The realm comes with these test users:

| Username           | Password     | Roles         | Use Case                    |
|--------------------|--------------|---------------|-----------------------------|
| user123            | password123  | user          | Standard user access        |
| admin456           | admin123     | admin, user   | Administrative access       |
| test-user          | test123      | user          | Testing purposes            |
| service-account-1  | service123   | service       | Service-to-service calls    |
| loadtest-user      | loadtest123  | user          | Load testing with PAP attrs |

## Pre-configured Clients

### stratium-key-access (Confidential Client)

- **Client ID**: `stratium-key-access`
- **Client Secret**: `stratium-key-access-secret`
- **Type**: Confidential
- **Flows**: Standard Flow, Direct Access Grants, Service Accounts
- **Use Case**: Backend service authentication

### stratium-pap (Confidential Client)

- **Client ID**: `stratium-pap`
- **Client Secret**: `stratium-pap-secret`
- **Type**: Confidential
- **Flows**: Standard Flow, Direct Access Grants, Service Accounts
- **Use Case**: Policy Administration Point API
- **Custom Claims**: Includes `classification`, `department`, and `role` user attributes

### stratium-cli (Public Client)

- **Client ID**: `stratium-cli`
- **Type**: Public
- **Flows**: Standard Flow, Direct Access Grants
- **Use Case**: CLI tools and testing

### stratium-load-test (Confidential Client)

- **Client ID**: `stratium-load-test`
- **Client Secret**: `stratium-load-test-secret` (override this in staging by updating the realm export or rotating the secret after import)
- **Type**: Confidential (service account)
- **Flows**: Client Credentials, Direct Access Grants
- **Use Case**: Dedicated identity for automated WrapDEK/UnwrapDEK load testing. Tokens include hardcoded claims `role=load-test`, `department=platform-engineering`, and `classification=confidential`. The subject (`sub`) is `service-account-stratium-load-test`, so include that identity (or the `load-test` role attribute) in PAP policies used for performance tests.

Retrieve a token for this client via the helper script (defaults to `http://localhost:8080`):

```bash
./scripts/get_loadtest_token.sh \
  -u https://keycloak.staging.example.com \
  -s '<rotated-secret>'
```

The script prints the raw access token and a decoded payload similar to:

```json
{
  "sub": "service-account-stratium-load-test",
  "preferred_username": "service-account-stratium-load-test",
  "role": "load-test",
  "department": "platform-engineering",
  "classification": "confidential",
  "aud": "account"
}
```

These stable claims let you craft PAP entitlements/policies that authorize only the load-test identity without reusing production user accounts. When the Key Access service requires a real user subject, use the `loadtest-user` credentials with the `stratium-load-test` client (password grant) so the resulting JWT contains the `classification=confidential`, `department=engineering`, and `role=developer` attributes.

### Load Testing User (password flow)

- **Username**: `loadtest-user`
- **Password**: `loadtest123`
- **Attributes**: `classification=confidential`, `role=developer`, `department=engineering`

Ensure PAP policies/entitlements include this user (or the attribute combination) before running high-volume WrapDEK/UnwrapDEK tests.

## Token Claims

Tokens issued by Keycloak include standard OIDC claims plus custom user attributes:

**Standard Claims:**
```json
{
  "sub": "user123",
  "email": "user123@stratium.local",
  "email_verified": true,
  "preferred_username": "user123",
  "name": "Test User",
  "given_name": "Test",
  "family_name": "User",
  "groups": ["/users"]
}
```

**Custom User Attributes (PAP Client):**

For the `stratium-pap` client, additional attributes are included:

```json
{
  "classification": "confidential",
  "department": "engineering",
  "role": "developer"
}
```

These attributes are used for ABAC policy evaluation in the PAP system.

## Configuration

### Environment Variables

The Key Access service uses these environment variables:

```bash
# Keycloak OIDC configuration
OIDC_ISSUER_URL=http://keycloak:8080/realms/stratium
OIDC_CLIENT_ID=stratium-key-access
OIDC_CLIENT_SECRET=stratium-key-access-secret  # Optional for public clients
```

### Fallback to Mock Auth

If Keycloak is not available, the key-access service automatically falls back to mock authentication for development:

```
Warning: Failed to create OIDC auth service: <error>. Using mock auth.
```

In mock mode, you can use simple bearer tokens like:
- `Bearer user-token` → authenticated as `user123`
- `Bearer admin-token` → authenticated as `admin456`

## Security Considerations

### Production Deployment

For production use:

1. **Use HTTPS** - Enable TLS for Keycloak
2. **Strong Passwords** - Change all default passwords
3. **Client Secrets** - Rotate client secrets regularly
4. **Token Expiration** - Configure appropriate token lifespans
5. **Database** - Use a production-grade database (not H2)
6. **Network** - Isolate Keycloak in a private network

### Token Validation

The Key Access service validates tokens by:

1. **Signature Verification** - Validates JWT signature using Keycloak's public keys
2. **Issuer Check** - Ensures token is from the configured issuer
3. **Audience Check** - Validates the client ID
4. **Expiration** - Checks token hasn't expired
5. **Claims Extraction** - Extracts user claims for ABAC evaluation

## ABAC Integration

User claims from Keycloak tokens are used in ABAC rules:

```go
// Example ABAC rule
{
  "subjects": ["user123", "admin456"],    // From 'sub' claim
  "resources": ["test-resource"],
  "actions": ["wrap_dek", "unwrap_dek"],
  "enabled": true
}
```

The `sub` (subject) claim is used to match against ABAC rule subjects.

## Troubleshooting

### Keycloak Not Starting

```bash
# Check logs
docker-compose logs keycloak

# Common issues:
# - Database connection failed
# - Port 8080 already in use
# - Insufficient memory
```

### Token Validation Failed

```bash
# Check issuer URL is correct
curl http://localhost:8080/realms/stratium/.well-known/openid-configuration

# Verify token
./scripts/keycloak-login.sh user123 password123

# Check key-access logs
docker-compose logs key-access-service
```

### Cannot Access Keycloak from Service

```bash
# From host: http://localhost:8080
# From Docker network: http://keycloak:8080

# Verify network connectivity
docker-compose exec key-access-service ping keycloak
```

## Advanced Usage

### Custom Realms

To use a custom realm:

1. Create realm in Keycloak admin console
2. Export realm to JSON
3. Place in `keycloak/` directory
4. Update `docker-compose.yml` volume mount
5. Update `OIDC_ISSUER_URL` environment variable

### Token Refresh

```bash
# Get refresh token from login
REFRESH_TOKEN=$(cat .keycloak-tokens-user123.json | jq -r '.refresh_token')

# Use refresh token to get new access token
curl -X POST http://localhost:8080/realms/stratium/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=stratium-cli" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=$REFRESH_TOKEN"
```

### Service Account Authentication

For service-to-service communication:

```bash
# Use client credentials flow
curl -X POST http://localhost:8080/realms/stratium/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=stratium-key-access" \
  -d "client_secret=stratium-key-access-secret" \
  -d "grant_type=client_credentials"
```

## References

- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [OpenID Connect Specification](https://openid.net/connect/)
- [JWT.io](https://jwt.io/) - Token decoder
