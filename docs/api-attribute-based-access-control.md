# Attribute-Based Access Control API Documentation

## Overview

The Platform service provides attribute-based access control (ABAC) through the `GetDecision` API. This enables fine-grained authorization decisions based on subject attributes, resource attributes, contextual information, and policy evaluation.

## API Reference

### GetDecision

Evaluates an access decision request based on subject attributes, resource attributes, and context.

**Request: `GetDecisionRequest`**

```protobuf
message GetDecisionRequest {
    map<string, string> subject_attributes = 1;
    map<string, string> resource_attributes = 2;
    string action = 3;
    map<string, string> context = 4;
    string policy_id = 5;  // Optional: specific policy to evaluate
}
```

**Response: `DecisionResult`**

```protobuf
message DecisionResult {
    Decision decision = 1;  // ALLOW or DENY
    string reason = 2;
    map<string, string> details = 3;
    string policy_id = 4;
}

enum Decision {
    DECISION_UNSPECIFIED = 0;
    DECISION_ALLOW = 1;
    DECISION_DENY = 2;
}
```

## Field Descriptions

### subject_attributes (map<string, string>)

**Purpose**: Identifies WHO is making the request (identity attributes)

**Required Fields**: At least one of:
- `sub` - Subject identifier (preferred, follows OIDC conventions)
- `user_id` - User identifier
- `id` - Generic identifier

**Common Attributes**:
- `role` - User's role (e.g., "admin", "developer", "viewer")
- `department` - User's department (e.g., "engineering", "sales")
- `clearance` - Security clearance level (e.g., "high", "medium", "low")
- `classification` - User's classification level (for ZTDF)
- `organization` - User's organization
- `team` - User's team
- `email` - User's email address

**Example**:
```json
{
  "sub": "user123",
  "role": "developer",
  "department": "engineering",
  "clearance": "high"
}
```

### resource_attributes (map<string, string>)

**Purpose**: Identifies WHAT is being accessed (resource attributes)

**Common Fields**:
- `name` - Resource name or identifier (preferred)
- `id` - Resource ID
- `resource` - Generic resource identifier
- `type` - Resource type (e.g., "document", "api", "database")
- `classification` - Resource classification level
- `owner` - Resource owner
- `project_id` - Associated project

**Example**:
```json
{
  "name": "document-service",
  "type": "api",
  "classification": "confidential"
}
```

### action (string)

**Purpose**: Specifies the operation being performed

**Common Values**:
- `read` - Read/view access
- `write` - Write/modify access
- `delete` - Delete access
- `execute` - Execute/run access
- `admin` - Administrative access

**Example**: `"read"`

### context (map<string, string>)

**Purpose**: Provides additional contextual information for decision making

**Key Behavior**: Context attributes are merged into both subject and resource attributes during evaluation, allowing for dynamic, contextual access control.

**Common Attributes**:
- `ip_address` - Request IP address
- `location` - Geographic location
- `time` - Request timestamp
- `environment` - Environment (e.g., "production", "staging")
- `mfa` - Multi-factor authentication status
- `device_type` - Device type (e.g., "mobile", "desktop")
- `project_id` - Current project context (can be used for resource matching)

**Example**:
```json
{
  "ip_address": "192.168.1.100",
  "environment": "production",
  "mfa": "enabled"
}
```

## Evaluation Flow

The system evaluates access decisions in the following order:

1. **Admin Check**: If subject has an admin role (configurable), access is granted immediately
2. **Entitlement Evaluation**: Check for specific entitlements matching subject and resource attributes
3. **Policy Evaluation**: Evaluate policies in priority order (highest first)
4. **Default Deny**: If no allow decision is found, access is denied

## API Examples

### Example 1: Basic Access Request

**Request**:
```json
{
  "subject_attributes": {
    "sub": "alice@example.com",
    "role": "developer"
  },
  "resource_attributes": {
    "name": "api-gateway",
    "type": "api"
  },
  "action": "read",
  "context": {}
}
```

**Response** (Allow):
```json
{
  "decision": "DECISION_ALLOW",
  "reason": "Access granted by entitlement: developer-api-access",
  "details": {
    "entitlement_id": "ent-123",
    "entitlement_name": "developer-api-access"
  },
  "policy_id": "ent-123"
}
```

### Example 2: Classification-Based Access (ZTDF)

**Request**:
```json
{
  "subject_attributes": {
    "sub": "bob@example.com",
    "classification": "SECRET"
  },
  "resource_attributes": {
    "classification": "CONFIDENTIAL"
  },
  "action": "read",
  "context": {}
}
```

**Response** (Allow - higher classification can access lower):
```json
{
  "decision": "DECISION_ALLOW",
  "reason": "All resource attribute requirements satisfied by subject attributes",
  "details": {
    "evaluation_mode": "attribute-based-access-control",
    "subject_id": "bob@example.com"
  },
  "policy_id": "abac-policy"
}
```

### Example 3: Context-Based Access Control

**Request**:
```json
{
  "subject_attributes": {
    "sub": "charlie@example.com",
    "role": "deployer"
  },
  "resource_attributes": {
    "name": "production-deploy"
  },
  "action": "execute",
  "context": {
    "environment": "production",
    "mfa": "enabled",
    "ip_address": "10.0.1.50"
  }
}
```

**Response** (Allow if policy matches):
```json
{
  "decision": "DECISION_ALLOW",
  "reason": "Access granted by policy: production-deploy-policy",
  "details": {
    "policy_id": "policy-789",
    "policy_name": "production-deploy-policy",
    "language": "json"
  },
  "policy_id": "policy-789"
}
```

### Example 4: Deny Decision

**Request**:
```json
{
  "subject_attributes": {
    "sub": "guest@example.com",
    "role": "guest"
  },
  "resource_attributes": {
    "name": "admin-panel",
    "type": "webapp"
  },
  "action": "access",
  "context": {}
}
```

**Response** (Deny):
```json
{
  "decision": "DECISION_DENY",
  "reason": "No matching policies or entitlements found",
  "details": {
    "subject_attrs_count": "2",
    "resource_attrs_count": "2",
    "action": "access",
    "subject_id": "guest@example.com",
    "resource_id": "admin-panel"
  },
  "policy_id": "default-deny"
}
```

### Example 5: Project-Scoped Access

**Request**:
```json
{
  "subject_attributes": {
    "sub": "dev@example.com",
    "role": "developer"
  },
  "resource_attributes": {
    "name": "project-files",
    "type": "storage"
  },
  "action": "read",
  "context": {
    "project_id": "proj-alpha",
    "team": "frontend"
  }
}
```

**Response** (Allow if entitlement matches project):
```json
{
  "decision": "DECISION_ALLOW",
  "reason": "Access granted by entitlement: project-access",
  "details": {
    "entitlement_id": "ent-456",
    "entitlement_name": "project-access"
  },
  "policy_id": "ent-456"
}
```

**Note**: The `project_id` from context is used to match against entitlement resource attributes.

## Best Practices

### 1. Subject Attribute Design

- Always include a unique identifier (`sub`, `user_id`, or `id`)
- Use consistent attribute naming across your organization
- Include only necessary attributes to minimize payload size
- Use lowercase for attribute keys for consistency

### 2. Resource Attribute Design

- Include a primary identifier (`name`, `id`, or `resource`)
- Add classification or sensitivity attributes when applicable
- Consider resource hierarchy (e.g., `project_id`, `workspace_id`)
- Use descriptive type fields for auditing

### 3. Context Usage

- Use context for dynamic, request-specific information
- Avoid putting static identity information in context (use subject_attributes instead)
- Context attributes can be used for both subject and resource matching
- Include security-relevant context (IP, MFA status, device type)

### 4. Action Naming

- Use consistent action names across your application
- Consider using hierarchical actions (e.g., `documents:read`, `documents:write`)
- Document your action vocabulary
- Use lowercase for consistency

### 5. Error Handling

- Always check the `decision` field (not just HTTP status)
- Log deny decisions with details for security auditing
- Handle both `DECISION_ALLOW` and `DECISION_DENY` explicitly
- Don't assume the reason field is human-readable

## Performance Considerations

### Caching

- The PDP includes built-in policy caching
- Consider client-side caching of decisions for read-heavy workloads
- Cache TTL should balance performance and security freshness

### Attribute Payload Size

- Keep attribute maps small (< 20 attributes)
- Use short, descriptive keys
- Avoid embedding large data structures in attribute values

### Request Batching

- For bulk authorization checks, consider batching requests
- Evaluate caching frequently-used decisions

## Security Considerations

### Attribute Validation

- The service validates that at least one subject identifier is present
- Action is required
- Resource and subject attributes are optional (empty = no requirements)

### Admin Privileges

- Admin checks occur before entitlement/policy evaluation
- Configure admin keys carefully in server configuration
- Consider using a dedicated admin policy instead of hardcoded checks

### Audit Logging

- All decisions are logged for audit purposes
- Logs include subject, resource, action, context, and decision
- Use audit logs for security monitoring and compliance

### Context Attribute Security

- Context attributes are merged into both subject and resource matching
- Context can override subject attributes (use with caution)
- Validate context attributes at the application layer before sending

## Integration Example (Go)

```go
import (
    "context"
    "fmt"
    pb "stratium/services/platform"
    "google.golang.org/grpc"
)

func checkAccess(client pb.PlatformClient, userID, resource, action string) (bool, error) {
    req := &pb.GetDecisionRequest{
        SubjectAttributes: map[string]string{
            "sub":  userID,
            "role": "developer",
        },
        ResourceAttributes: map[string]string{
            "name": resource,
        },
        Action: action,
        Context: map[string]string{
            "environment": "production",
        },
    }

    resp, err := client.GetDecision(context.Background(), req)
    if err != nil {
        return false, fmt.Errorf("failed to get decision: %w", err)
    }

    if resp.Decision == pb.Decision_DECISION_ALLOW {
        fmt.Printf("Access granted: %s\n", resp.Reason)
        return true, nil
    }

    fmt.Printf("Access denied: %s\n", resp.Reason)
    return false, nil
}
```

## Related Documentation

- [Migration Guide](./migration-guide-attribute-based.md)
- [ZTDF Attribute URI Conventions](./ztdf-attribute-conventions.md)
- [Policy Language Reference](./policy-language-reference.md)
