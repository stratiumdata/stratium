# OIDC Integration Guide

Learn how to integrate Stratium with OpenID Connect (OIDC) providers for authentication and identity management.

## Table of Contents
- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [OIDC Concepts](#oidc-concepts)
- [Configuration](#configuration)
- [Provider Setup](#provider-setup)
- [Attribute Mapping](#attribute-mapping)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)

## Overview

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 that allows Stratium to verify user identities and obtain user profile information from external identity providers.

**Benefits of OIDC Integration:**
- Single Sign-On (SSO) across applications
- Centralized user management
- Standardized authentication flow
- User attribute synchronization
- Multi-factor authentication (MFA) support

## Prerequisites

Before configuring OIDC integration, ensure you have:

1.  **OIDC Provider Account**
   - Access to an OIDC-compliant identity provider
   - Administrative privileges to create clients/applications

2.  **Stratium Installation**
   - Stratium PAP and PDP services deployed
   - Network connectivity between Stratium and the OIDC provider
   - HTTPS/TLS configured for production environments

3.  **Required Information**
   - OIDC Provider Issuer URL
   - Client credentials (Client ID and Client Secret)
   - Redirect URIs for your application
   - Scope requirements

## OIDC Concepts

### Key Components

**Issuer**: The identity provider's base URL (e.g., `https://auth.example.com`)

**Client ID**: Unique identifier for your application registered with the provider

**Client Secret**: Confidential credential for your application (keep secure!)

**Redirect URI**: Where users are sent after authentication (e.g., `https://app.example.com/callback`)

**Scopes**: Permissions requested from the user (e.g., `openid`, `profile`, `email`)

**Claims**: User attributes returned in ID tokens (e.g., `sub`, `email`, `name`, `groups`)

### Authentication Flow

```

┌──────────┐                                           ┌─────────────┐
│  User    │                                           │   Stratium  │
└────┬─────┘                                           └──────┬──────┘
     │                                                        │
     │ 1. Access Stratium                                     │
     │───────────────────────────────────────────────────────>│
     │                                                        │
     │ 2. Redirect to OIDC provider                           │
     │<───────────────────────────────────────────────────────│
     │                                                        │
┌────▼─────┐                                                  │
│  OIDC    │                                                  │
│ Provider │                                                  │
└────┬─────┘                                                  │
     │ 3. User authenticates                                  │
     │                                                        │
     │ 4. Authorization code                                  │
     │───────────────────────────────────────────────────────>│
     │                                                        │
     │                    5. Exchange code for tokens         │
     │<───────────────────────────────────────────────────────│
     │                                                        │
     │                    6. ID Token + Access Token          │
     │───────────────────────────────────────────────────────>│
     │                                                        │
     │                    7. Access granted with user context │
     │<───────────────────────────────────────────────────────│
```

## Configuration

### Stratium Configuration File

Configure OIDC in your Stratium configuration file (typically `config.yaml`):

```yaml
# config.yaml
oidc:
  enabled: true
  issuer: "https://auth.example.com/realms/stratium"
  client_id: "stratium-app"
  client_secret: "${OIDC_CLIENT_SECRET}"  # Use environment variable
  redirect_uri: "https://stratium.example.com/auth/callback"
  scopes:
    - openid
    - profile
    - email
    - groups

  # Optional: Additional configuration
  token_endpoint_auth_method: "client_secret_post"  # or "client_secret_basic"
  response_type: "code"  # Authorization Code flow

  # Claim mappings
  claim_mappings:
    user_id: "sub"
    email: "email"
    name: "name"
    groups: "groups"
    department: "department"
    role: "role"
    clearance: "clearance"

  # Session configuration
  session:
    cookie_name: "stratium_session"
    max_age: 3600  # 1 hour
    secure: true
    same_site: "lax"
```

### Environment Variables

Store sensitive credentials as environment variables:

```bash
# .env
OIDC_CLIENT_SECRET=your_client_secret_here
OIDC_ISSUER=https://auth.example.com/realms/stratium
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `enabled` | Yes | Enable/disable OIDC integration |
| `issuer` | Yes | OIDC provider's issuer URL |
| `client_id` | Yes | Application client ID |
| `client_secret` | Yes | Application client secret |
| `redirect_uri` | Yes | Callback URL after authentication |
| `scopes` | Yes | Requested OAuth scopes |
| `token_endpoint_auth_method` | No | How to authenticate to token endpoint |
| `response_type` | No | OAuth flow type (default: "code") |
| `claim_mappings` | No | Map OIDC claims to Stratium attributes |
| `session` | No | Session management settings |

## Provider Setup

### Keycloak

Keycloak is a popular open-source identity provider.

#### 1. Create Realm

```
Admin Console → Realms → Add realm
Name: stratium
```

#### 2. Create Client

```
Clients → Create
Client ID: stratium-app
Client Protocol: openid-connect
Root URL: https://stratium.example.com
```

#### 3. Configure Client Settings

```
Access Type: confidential
Valid Redirect URIs: https://stratium.example.com/auth/callback
Web Origins: https://stratium.example.com
```

#### 4. Get Client Secret

```
Clients → stratium-app → Credentials tab
Copy "Secret" value
```

#### 5. Configure Mappers

Add custom claim mappers for Stratium attributes:

```
Clients → stratium-app → Mappers → Create

# Department Mapper
Name: department
Mapper Type: User Attribute
User Attribute: department
Token Claim Name: department
Claim JSON Type: String
Add to ID token: ON

# Role Mapper
Name: role
Mapper Type: User Attribute
User Attribute: role
Token Claim Name: role
Claim JSON Type: String
Add to ID token: ON

# Clearance Mapper
Name: clearance
Mapper Type: User Attribute
User Attribute: clearance
Token Claim Name: clearance
Claim JSON Type: String
Add to ID token: ON

# Groups Mapper
Name: groups
Mapper Type: Group Membership
Token Claim Name: groups
Full group path: OFF
Add to ID token: ON
```

#### 6. Stratium Configuration for Keycloak

```yaml
oidc:
  enabled: true
  issuer: "https://keycloak.example.com/realms/stratium"
  client_id: "stratium-app"
  client_secret: "${KEYCLOAK_CLIENT_SECRET}"
  redirect_uri: "https://stratium.example.com/auth/callback"
  scopes:
    - openid
    - profile
    - email
  claim_mappings:
    user_id: "sub"
    email: "email"
    name: "name"
    department: "department"
    role: "role"
    clearance: "clearance"
    groups: "groups"
```

### Auth0

#### 1. Create Application

```
Applications → Create Application
Name: Stratium
Type: Regular Web Application
```

#### 2. Configure Settings

```
Allowed Callback URLs: https://stratium.example.com/auth/callback
Allowed Logout URLs: https://stratium.example.com/logout
Allowed Web Origins: https://stratium.example.com
```

#### 3. Get Credentials

```
Domain: your-tenant.auth0.com
Client ID: [copy value]
Client Secret: [copy value]
```

#### 4. Create Custom Claims

Create an Action to add custom claims:

```javascript
// Auth0 Action: Add Custom Claims
exports.onExecutePostLogin = async (event, api) => {
  const namespace = 'https://stratium.example.com';

  if (event.authorization) {
    // Add custom claims
    api.idToken.setCustomClaim(`${namespace}/department`, event.user.user_metadata.department);
    api.idToken.setCustomClaim(`${namespace}/role`, event.user.user_metadata.role);
    api.idToken.setCustomClaim(`${namespace}/clearance`, event.user.user_metadata.clearance);
    api.idToken.setCustomClaim(`${namespace}/groups`, event.user.user_metadata.groups || []);
  }
};
```

#### 5. Stratium Configuration for Auth0

```yaml
oidc:
  enabled: true
  issuer: "https://your-tenant.auth0.com/"
  client_id: "your_client_id"
  client_secret: "${AUTH0_CLIENT_SECRET}"
  redirect_uri: "https://stratium.example.com/auth/callback"
  scopes:
    - openid
    - profile
    - email
  claim_mappings:
    user_id: "sub"
    email: "email"
    name: "name"
    department: "https://stratium.example.com/department"
    role: "https://stratium.example.com/role"
    clearance: "https://stratium.example.com/clearance"
    groups: "https://stratium.example.com/groups"
```

### Okta

#### 1. Create Application

```
Applications → Create App Integration
Sign-in method: OIDC
Application type: Web Application
```

#### 2. Configure Application

```
App integration name: Stratium
Grant type: Authorization Code
Sign-in redirect URIs: https://stratium.example.com/auth/callback
Sign-out redirect URIs: https://stratium.example.com/logout
Controlled access: Choose appropriate option
```

#### 3. Get Credentials

```
Client ID: [copy value]
Client secret: [copy value]
Okta domain: your-domain.okta.com
```

#### 4. Add Custom Claims

```
Security → API → Authorization Servers → default → Claims → Add Claim

# Department Claim
Name: department
Include in token type: ID Token (Always)
Value type: Expression
Value: user.department

# Role Claim
Name: role
Include in token type: ID Token (Always)
Value type: Expression
Value: user.role

# Groups Claim
Name: groups
Include in token type: ID Token (Always)
Value type: Groups
Filter: Matches regex .*
```

#### 5. Stratium Configuration for Okta

```yaml
oidc:
  enabled: true
  issuer: "https://your-domain.okta.com"
  client_id: "your_client_id"
  client_secret: "${OKTA_CLIENT_SECRET}"
  redirect_uri: "https://stratium.example.com/auth/callback"
  scopes:
    - openid
    - profile
    - email
    - groups
  claim_mappings:
    user_id: "sub"
    email: "email"
    name: "name"
    department: "department"
    role: "role"
    groups: "groups"
```

### Azure Active Directory (Azure AD)

#### 1. Register Application

```
Azure Portal → Azure Active Directory → App registrations → New registration
Name: Stratium
Supported account types: Choose appropriate option
Redirect URI: Web - https://stratium.example.com/auth/callback
```

#### 2. Create Client Secret

```
Certificates & secrets → New client secret
Description: Stratium Integration
Expires: Choose appropriate duration
[Copy the secret value immediately]
```

#### 3. Configure API Permissions

```
API permissions → Add a permission → Microsoft Graph
Delegated permissions:
- OpenId permissions: openid, profile, email
- User.Read
- Group.Read.All (if using group-based access)
```

#### 4. Configure Optional Claims

```
Token configuration → Add optional claim
Token type: ID
Claims: email, family_name, given_name, upn
```

#### 5. Stratium Configuration for Azure AD

```yaml
oidc:
  enabled: true
  issuer: "https://login.microsoftonline.com/{tenant-id}/v2.0"
  client_id: "your_application_id"
  client_secret: "${AZURE_CLIENT_SECRET}"
  redirect_uri: "https://stratium.example.com/auth/callback"
  scopes:
    - openid
    - profile
    - email
    - User.Read
  claim_mappings:
    user_id: "oid"  # Azure uses 'oid' for unique user ID
    email: "email"
    name: "name"
    groups: "groups"
```

**Note**: Replace `{tenant-id}` with your Azure AD tenant ID.

## Attribute Mapping

### Understanding Claims

OIDC providers return user information as "claims" in ID tokens. Stratium needs to map these claims to its internal attribute model.

### Standard OIDC Claims

Most providers include these standard claims:

| Claim | Description | Example |
|-------|-------------|---------|
| `sub` | Subject (unique user ID) | "1234567890" |
| `email` | User's email address | "user@example.com" |
| `name` | Full name | "John Doe" |
| `given_name` | First name | "John" |
| `family_name` | Last name | "Doe" |
| `preferred_username` | Username | "jdoe" |
| `email_verified` | Email verification status | true |

### Custom Attribute Mapping

Map custom claims to Stratium attributes:

```yaml
claim_mappings:
  # Standard mappings
  user_id: "sub"
  email: "email"
  name: "name"

  # Custom attribute mappings
  department: "department"              # From custom claim
  role: "role"                          # From custom claim
  clearance: "security_clearance"       # Provider uses different name
  groups: "groups"                      # Array of group names
  employee_type: "employment_type"      # Map to different attribute name
  location: "office_location"           # Geographic location

  # Nested claims (if provider supports)
  project: "custom_claims.project"
  division: "org.division"
```

### Example ID Token

Here's what a decoded ID token might look like:

```json
{
  "sub": "user123",
  "email": "alice@example.com",
  "name": "Alice Engineer",
  "given_name": "Alice",
  "family_name": "Engineer",
  "department": "engineering",
  "role": "senior_engineer",
  "security_clearance": "SECRET",
  "groups": ["developers", "security-team", "project-alpha"],
  "employment_type": "full-time",
  "office_location": "US-East",
  "iat": 1642521600,
  "exp": 1642525200
}
```

After mapping, Stratium will have these subject attributes:

```json
{
  "user_id": "user123",
  "email": "alice@example.com",
  "name": "Alice Engineer",
  "department": "engineering",
  "role": "senior_engineer",
  "clearance": "SECRET",
  "groups": ["developers", "security-team", "project-alpha"],
  "employee_type": "full-time",
  "location": "US-East"
}
```

### Attribute Transformation

For complex transformations, you may need to configure attribute processing rules:

```yaml
attribute_transformations:
  # Normalize clearance levels
  clearance:
    source: "security_clearance"
    transform: "uppercase"  # "secret" → "SECRET"

  # Extract department from email domain
  department:
    source: "email"
    regex: ".*@([^.]+)\\.example\\.com"
    group: 1  # Extract first capture group

  # Convert single group to array
  groups:
    source: "group"
    to_array: true
```

## Testing

### 1. Test OIDC Discovery

Verify the provider's discovery endpoint is accessible:

```bash
curl https://auth.example.com/realms/stratium/.well-known/openid-configuration
```

**Expected response includes:**

```json
{
  "issuer": "https://auth.example.com/realms/stratium",
  "authorization_endpoint": "https://auth.example.com/realms/stratium/protocol/openid-connect/auth",
  "token_endpoint": "https://auth.example.com/realms/stratium/protocol/openid-connect/token",
  "userinfo_endpoint": "https://auth.example.com/realms/stratium/protocol/openid-connect/userinfo",
  "jwks_uri": "https://auth.example.com/realms/stratium/protocol/openid-connect/certs"
}
```

### 2. Test Authentication Flow

Attempt to log in through Stratium:

```bash
# 1. Start authentication
GET https://stratium.example.com/auth/login

# User will be redirected to OIDC provider
# After successful auth, user returns to callback URL with code

# 2. Verify callback handling
GET https://stratium.example.com/auth/callback?code=<auth_code>&state=<state>
```

### 3. Verify Token Claims

Use a test endpoint to view decoded token claims:

```bash
GET /api/v1/auth/user-info
Authorization: Bearer <access_token>
```

**Response:**

```json
{
  "user_id": "user123",
  "email": "alice@example.com",
  "attributes": {
    "department": "engineering",
    "role": "senior_engineer",
    "clearance": "SECRET",
    "groups": ["developers", "security-team"]
  },
  "token_claims": {
    "sub": "user123",
    "email": "alice@example.com",
    "department": "engineering",
    "role": "senior_engineer",
    "security_clearance": "SECRET",
    "groups": ["developers", "security-team"]
  }
}
```

## Troubleshooting

### Invalid Client Credentials

**Error**: `invalid_client` or `unauthorized_client`

**Solutions:**

1.  **Verify Client ID and Secret**:
   ```bash
   # Check configuration
   echo $OIDC_CLIENT_SECRET
   ```

2.  **Check Client Secret Encoding**:
   - Some providers require URL encoding
   - Remove any extra whitespace or newlines

3.  **Verify Token Endpoint Auth Method**:
   ```yaml
   # Try changing auth method
   token_endpoint_auth_method: "client_secret_basic"  # or "client_secret_post"
   ```

### Redirect URI Mismatch

**Error**: `redirect_uri_mismatch`

**Solutions:**

1.  **Exact Match Required**:
   ```yaml
   # Configured in Stratium
   redirect_uri: "https://stratium.example.com/auth/callback"

   # Must exactly match provider configuration (case-sensitive, no trailing slash)
   ```

2.  **Check Provider Configuration**:
   - Verify redirect URI in provider console
   - Ensure protocol matches (http vs https)
   - Check for trailing slashes

### Missing Claims

**Error**: Expected user attributes not present

**Solutions:**

1.  **Request Correct Scopes**:
   ```yaml
   scopes:
     - openid      # Required
     - profile     # For name, given_name, etc.
     - email       # For email claim
     - groups      # For group memberships (provider-specific)
   ```

2.  **Configure Claim Mappers** (provider-specific):
   - Add custom attribute mappers in your OIDC provider
   - Ensure claims are included in ID token

3.  **Check User Attributes**:
   - Verify user has the attribute set in the provider
   - Check attribute names match exactly (case-sensitive)

### Token Validation Failures

**Error**: `invalid_token` or signature verification failures

**Solutions:**

1.  **Check Issuer URL**:
   ```yaml
   # Must match exactly (including trailing slash or not)
   issuer: "https://auth.example.com/realms/stratium"
   ```

2.  **Verify JWKS Endpoint**:
   ```bash
   # Should return public keys
   curl https://auth.example.com/realms/stratium/protocol/openid-connect/certs
   ```

3.  **Clock Skew**:
   - Ensure server clocks are synchronized (use NTP)
   - Allow for small clock skew (typically 5 minutes)

### Session Expires Too Quickly

**Error**: Users logged out unexpectedly

**Solutions:**

1. **Increase Session Duration**:
   ```yaml
   session:
     max_age: 28800  # 8 hours instead of 1 hour
   ```

2. **Implement Token Refresh**:
   ```yaml
   oidc:
     enable_refresh_tokens: true
     refresh_before_expiry: 300  # Refresh 5 minutes before expiry
   ```

3. **Check Provider Token Lifetime**:
   - Adjust access token lifetime in provider settings
   - Enable refresh token rotation

### CORS Errors

**Error**: Cross-Origin Resource Sharing errors in browser

**Solutions:**

```yaml
# Configure CORS in Stratium
cors:
  allowed_origins:
    - "https://stratium.example.com"
  allowed_methods:
    - GET
    - POST
    - OPTIONS
  allowed_headers:
    - Authorization
    - Content-Type
  expose_headers:
    - Authorization
  allow_credentials: true
```

## Security Best Practices

### 1. Use HTTPS Everywhere

```yaml
# Production configuration
oidc:
  issuer: "https://auth.example.com"  # ✅ HTTPS
  redirect_uri: "https://stratium.example.com/auth/callback"  # ✅ HTTPS
```

Never use HTTP in production!

### 2. Secure Client Secrets

```yaml
# ❌ Bad - Hardcoded secret
client_secret: "my-secret-123"

# ✅ Good - Environment variable
client_secret: "${OIDC_CLIENT_SECRET}"
```

Store secrets in:
- Environment variables
- Secrets management systems (HashiCorp Vault, AWS Secrets Manager)
- Kubernetes secrets

### 3. Validate Tokens Properly

Ensure Stratium validates:
- Token signature (using provider's JWKS)
- Issuer claim matches configured issuer
- Audience claim includes client ID
- Expiration time (exp claim)
- Not-before time (nbf claim)

### 4. Use State Parameter

Prevent CSRF attacks by using the state parameter:

```yaml
oidc:
  use_state_parameter: true  # Enabled by default
```

### 5. Implement Proper Logout

```yaml
oidc:
  # Post-logout redirect
  post_logout_redirect_uri: "https://stratium.example.com"

  # Revoke tokens on logout
  revoke_tokens_on_logout: true
```

### 6. Limit Token Scope

Request only necessary scopes:

```yaml
# ✅ Good - Minimal scopes
scopes:
  - openid
  - profile
  - email

# ❌ Bad - Excessive scopes
scopes:
  - openid
  - profile
  - email
  - admin
  - full_access
```

### 7. Rotate Client Secrets Regularly

- Rotate client secrets every 90 days
- Use secret versioning for zero-downtime rotation
- Monitor secret expiration

### 8. Monitor Authentication Events

Enable audit logging for:
- Successful logins
- Failed login attempts
- Token validation failures
- Session expirations
- Logout events

```yaml
audit:
  enabled: true
  log_authentication: true
  log_authorization: true
  retention_days: 90
```

### 9. Implement Rate Limiting

Protect against brute force attacks:

```yaml
rate_limiting:
  enabled: true
  login_attempts:
    max_attempts: 5
    window_seconds: 300  # 5 attempts per 5 minutes
    lockout_duration: 900  # 15 minute lockout
```

### 10. Use Secure Session Cookies

```yaml
session:
  cookie_name: "stratium_session"
  secure: true          # HTTPS only
  http_only: true       # Not accessible via JavaScript
  same_site: "strict"   # CSRF protection
  max_age: 3600
```

## Advanced Configuration

### Multi-Tenancy

Support multiple OIDC providers:

```yaml
oidc:
  providers:
    - name: "corporate"
      issuer: "https://corporate-auth.example.com"
      client_id: "stratium-corp"
      client_secret: "${CORP_CLIENT_SECRET}"

    - name: "partners"
      issuer: "https://partner-auth.example.com"
      client_id: "stratium-partners"
      client_secret: "${PARTNER_CLIENT_SECRET}"
```

### Custom Authorization Endpoint

Override specific endpoints if needed:

```yaml
oidc:
  issuer: "https://auth.example.com"
  # Override discovery
  authorization_endpoint: "https://custom-auth.example.com/authorize"
  token_endpoint: "https://custom-auth.example.com/token"
  userinfo_endpoint: "https://custom-auth.example.com/userinfo"
```

### Token Caching

Improve performance with token caching:

```yaml
oidc:
  token_cache:
    enabled: true
    ttl: 300  # Cache for 5 minutes
    max_size: 1000  # Maximum cached tokens
```

## API Reference

### Login Endpoint

Initiates OIDC authentication:

```bash
GET /api/v1/auth/login
```

Redirects to OIDC provider for authentication.

### Callback Endpoint

Handles OIDC callback with authorization code:

```bash
GET /api/v1/auth/callback?code=<code>&state=<state>
```

### User Info Endpoint

Returns current user's information:

```bash
GET /api/v1/auth/user-info
Authorization: Bearer <access_token>
```

### Logout Endpoint

Terminates session and optionally logs out from provider:

```bash
POST /api/v1/auth/logout
Cookie: stratium_session=<session_cookie>
```

## Next Steps

- [Database Integration](./DATABASE_INTEGRATION.md)
- [Secrets Manager Integration](./SECRETS_MANAGER.md)
- [Key Manager Integration](./KEY_MANAGER.md)
- [Create Policies](../policies/JSON_POLICIES.md)
- [Create Entitlements](../entitlements/CREATING_ENTITLEMENTS.md)

## License

Copyright © 2025 Stratium Data
