# Platform Service - Policy Decision Point Integration

## Overview

The Platform Service now includes a Policy Decision Point (PDP) that evaluates access control decisions using policies and entitlements stored in PostgreSQL. This document describes the integration architecture and usage.

## Architecture

```
┌─────────────────┐
│   gRPC Client   │
│  (Key Access,   │
│   etc.)         │
└────────┬────────┘
         │
         │ GetDecision(subject, resource, action)
         ▼
┌────────────────────────────────────────────────────┐
│            Platform Service (PDP)                  │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  1. Check Entitlements (specific rules)      │  │
│  │     - Match subject attributes               │  │
│  │     - Match resource attributes              │  │
│  │     - Match action                           │  │
│  │     - Check active/not expired               │  │
│  └──────────────────────────────────────────────┘  │
│                     │                              │
│                     │ No match                     │
│                     ▼                              │
│  ┌──────────────────────────────────────────────┐  │
│  │  2. Evaluate Policies (general rules)        │  │
│  │     - Get enabled policies by priority       │  │
│  │     - Evaluate using OPA/XACML engine        │  │
│  │     - Apply policy effect (allow/deny)       │  │
│  └──────────────────────────────────────────────┘  │
│                     │                              │
│                     │ No match                     │
│                     ▼                              │
│  ┌──────────────────────────────────────────────┐  │
│  │  3. Default Deny                             │  │
│  │     - Return DENY decision                   │  │
│  │     - Log to audit trail                     │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
                      │
                      │ Read/Write
                      ▼
               ┌──────────────┐
               │  PostgreSQL  │
               │  (Policies,  │
               │   Entitle-   │
               │   ments,     │
               │   Audit)     │
               └──────────────┘
```

## Components

### PolicyDecisionPoint (PDP)

Located in `services/platform/pdp.go`, the PDP handles:

1. **Entitlement Evaluation**: Checks attribute-based entitlements first
2. **Policy Evaluation**: Evaluates OPA/XACML policies in priority order
3. **Default Deny**: Returns deny if no rules match
4. **Audit Logging**: Records all decisions for compliance

### Policy Cache

In-memory cache for frequently accessed policies to improve performance.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| DATABASE_URL | postgres://... | PostgreSQL connection string |
| Use `-use-pdp` flag | true | Enable/disable PDP mode |

### Command-Line Flags

```bash
./platform-server --help

Flags:
  -port int
        The server port (default 50051)
  -use-pdp
        Use Policy Decision Point for authorization (default true)
  -db string
        PostgreSQL connection string (if empty, uses DATABASE_URL env var)
```

## Decision Flow

### 1. Entitlement Matching

Entitlements are checked first as they represent specific, attribute-based access grants:

```
Subject Attributes (from request context) → Match → Entitlement Subject Attributes
Resource Attributes (from request context) → Match → Entitlement Resource Attributes
Action (from request) → Match → Entitlement Actions
```

**Example**:
```json
{
  "subject_attributes": {"department": "engineering"},
  "resource_attributes": {"type": "document"},
  "actions": ["read", "write"]
}
```

Matches request with:
- `context.department = "engineering"`
- `context.type = "document"`
- `action = "read"` or `"write"`

### 2. Policy Evaluation

If no entitlement matches, policies are evaluated in priority order (highest first):

```
Input = {
  subject: {sub: "user123", ...context},
  resource: {name: "resource-name"},
  action: "read",
  environment: {}
}

↓ OPA Engine

Result = {allow: true/false, reason: "..."}
```

**Policy Effect**:
- `effect: allow` + `result.allow = true` → **ALLOW**
- `effect: deny` + `result.allow = true` → **DENY**
- No match → Continue to next policy

### 3. Default Deny

If neither entitlements nor policies grant access, the request is denied.

## Example OPA Policies

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

## Usage Example

### Creating a Policy via PAP API

```bash
# Get token
TOKEN=$(./scripts/get_token.sh admin456 admin123 | tail -1)

# Create policy
curl -X POST http://localhost:8090/api/v1/policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "engineering-access",
    "description": "Engineering department access",
    "language": "opa",
    "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.department == \"engineering\"\n    input.action == \"read\"\n}",
    "effect": "allow",
    "priority": 50,
    "enabled": true
  }'
```

### Testing Decision via Platform Service

```bash
grpcurl -plaintext -d '{
  "subject": "user123",
  "resource": "engineering-doc",
  "action": "read",
  "context": {
    "department": "engineering",
    "role": "developer"
  }
}' localhost:50051 platform.PlatformService/GetDecision
```

**Response**:
```json
{
  "decision": "DECISION_ALLOW",
  "reason": "Access granted by policy: engineering-access",
  "details": {
    "policy_id": "abc-123...",
    "policy_name": "engineering-access",
    "language": "opa"
  },
  "timestamp": "2025-10-08T12:00:00Z",
  "evaluatedPolicy": "abc-123..."
}
```

## Audit Logging

All decisions are logged to the audit table:

```sql
SELECT
    timestamp,
    actor,
    changes->>'action' as action,
    changes->>'resource' as resource,
    result->>'allowed' as allowed,
    result->>'reason' as reason
FROM audit_logs
WHERE action = 'evaluate'
ORDER BY timestamp DESC
LIMIT 10;
```

Via PAP API:
```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8090/api/v1/audit-logs?action=evaluate&limit=10"
```

## Performance Optimization

### Policy Caching

The PDP includes an in-memory cache for policies:

```go
type InMemoryPolicyCache struct {
    cache map[string]*models.Policy
}
```

**Cache Operations**:
- `Get(key)` - Retrieve from cache
- `Set(key, policy)` - Store in cache
- `Invalidate(key)` - Remove from cache
- `Clear()` - Clear all cache

### Future Enhancements

1. **Redis Cache**: Distributed caching across multiple PDP instances
2. **Policy Compilation**: Pre-compile OPA policies on load
3. **Bulk Evaluation**: Evaluate multiple requests in batch
4. **Hot Reload**: Reload policies without restart

## Migration from Legacy Mode

### Legacy Mode (Deprecated)

```go
// In-memory policies and entitlements
server := platform.NewServer()
```

### PDP Mode (Recommended)

```go
// PostgreSQL-backed policies
repo, _ := postgres.NewRepository(connStr)
pdp := platform.NewPolicyDecisionPoint(repo)
server := platform.NewServerWithPDP(pdp)
```

### Gradual Migration

1. Start platform service with PDP enabled
2. Create policies in PAP that match legacy rules
3. Test thoroughly with `-use-pdp=true`
4. Monitor audit logs for discrepancies
5. Remove legacy in-memory policies

## Troubleshooting

### PDP Not Loading

**Symptom**: "Using legacy decision evaluation (no PDP configured)"

**Causes**:
- `DATABASE_URL` not set
- Database connection failed
- `-use-pdp=false` flag set

**Solution**:
```bash
export DATABASE_URL="postgres://stratium:stratium@localhost:5432/stratium_pap?sslmode=disable"
./platform-server -use-pdp=true
```

### Policy Not Evaluating

**Symptom**: Decisions return DENY when they should ALLOW

**Debug Steps**:
1. Check policy is enabled:
   ```sql
   SELECT id, name, enabled, priority FROM policies WHERE name = 'your-policy';
   ```

2. Test policy syntax:
   ```bash
   curl -X POST http://localhost:8090/api/v1/policies/validate \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"language":"opa","policy_content":"..."}'
   ```

3. Test policy evaluation:
   ```bash
   curl -X POST http://localhost:8090/api/v1/policies/test \
     -H "Authorization: Bearer $TOKEN" \
     -d '{
       "language": "opa",
       "policy_content": "...",
       "subject_attributes": {...},
       "resource_attributes": {...},
       "action": "read"
     }'
   ```

4. Check platform service logs:
   ```bash
   docker-compose logs platform | grep "PDP:"
   ```

### Database Connection Issues

**Symptom**: "Warning: Database connection failed"

**Solution**:
```bash
# Check PostgreSQL is running
docker-compose ps postgres

# Verify database exists
docker-compose exec postgres psql -U stratium -d stratium_pap -c '\dt'

# Check connection from platform container
docker-compose exec platform env | grep DATABASE_URL
```

## Testing

Run the comprehensive integration test:

```bash
./scripts/test_platform_pdp.sh
```

This test:
1. Creates test policy and entitlement via PAP API
2. Tests GetDecision with various scenarios
3. Verifies audit logging
4. Cleans up test resources

## References

- [PAP API Guide](./PAP_API_GUIDE.md)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Platform Service gRPC API](../proto/services/platform/platform.proto)
