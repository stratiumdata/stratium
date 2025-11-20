# Example ABAC Policies for Micro Research API

This document provides example policies for implementing fine-grained access control in the Micro Research API using the Stratium Platform PAP service.

## Policy Language: OPA (Open Policy Agent - Rego)

All policies use the Rego language, which is a declarative query language designed for policy evaluation.

## Basic Policy Structure

```rego
package stratium.authz

# Default deny - all access is denied unless explicitly allowed
default allow = false

# Rule that grants access
allow {
    # Conditions that must be true for access to be granted
    input.subject.role == "admin"
}
```

## Input Structure

When the Platform service evaluates a policy, it receives the following input:

```json
{
  "subject": {
    "subject_id": "user-uuid",
    "subject_email": "user@example.com",
    "department": "engineering",
    "role": "editor"
  },
  "resource": {
    "resource_type": "dataset",
    "resource_id": "dataset-uuid",
    "owner_id": "owner-uuid",
    "department": "engineering"
  },
  "action": "read"
}
```

## Example Policies

### 1. Admin Full Access

**Use Case**: Administrators should have unrestricted access to all resources.

**Policy**:
```rego
package stratium.authz

default allow = false

# Grant full access to admins for dataset resources
allow {
    input.resource.resource_type == "dataset"
    input.subject.role == "admin"
}
```

**Priority**: 100 (highest priority - evaluated first)

### 2. Department-Based Read Access

**Use Case**: Users can only read datasets from their own department.

**Policy**:
```rego
package stratium.authz

default allow = false

# Allow read access within same department
allow {
    input.action == "read"
    input.resource.resource_type == "dataset"
    input.subject.department == input.resource.department
}
```

**Priority**: 200

### 3. Owner-Based Write Access

**Use Case**: Dataset owners can update and delete their own datasets.

**Policy**:
```rego
package stratium.authz

default allow = false

# Allow owners to modify their datasets
allow {
    input.action in ["update", "delete"]
    input.resource.resource_type == "dataset"
    input.resource.owner_id == input.subject.subject_id
}
```

**Priority**: 300

### 4. Role and Department Combined Access

**Use Case**: Editors can read and update datasets within their department.

**Policy**:
```rego
package stratium.authz

default allow = false

# Editors can read and update within their department
allow {
    input.action in ["read", "update"]
    input.resource.resource_type == "dataset"
    input.subject.department == input.resource.department
    input.subject.role == "editor"
}
```

**Priority**: 250

## Advanced Policy Examples

### 5. Time-Based Access Control

**Use Case**: Allow access only during business hours (9 AM - 5 PM).

**Policy**:
```rego
package stratium.authz

default allow = false

# Allow access during business hours
allow {
    input.action == "read"
    input.resource.resource_type == "dataset"
    input.subject.department == input.resource.department

    # Get current hour (0-23)
    now := time.now_ns()
    hour := time.clock(now)[0]

    # Business hours: 9 AM to 5 PM
    hour >= 9
    hour < 17
}
```

### 6. Multi-Department Access for Specific Roles

**Use Case**: Data scientists can access datasets from any department.

**Policy**:
```rego
package stratium.authz

default allow = false

# Data scientists have cross-department read access
allow {
    input.action == "read"
    input.resource.resource_type == "dataset"
    input.subject.role == "data-scientist"
}
```

### 7. Tag-Based Access Control

**Use Case**: Users with specific attributes can access datasets with matching tags.

**Policy**:
```rego
package stratium.authz

default allow = false

# Allow access to public datasets
allow {
    input.action == "read"
    input.resource.resource_type == "dataset"
    "public" in input.resource.tags
}
```

### 8. Hierarchical Department Access

**Use Case**: Engineering managers can access datasets from engineering and sub-departments.

**Policy**:
```rego
package stratium.authz

default allow = false

# Define department hierarchy
dept_hierarchy := {
    "engineering": ["engineering", "ml-engineering", "robotics"],
    "biology": ["biology", "genetics", "microbiology"]
}

# Allow access within department hierarchy
allow {
    input.action == "read"
    input.resource.resource_type == "dataset"
    input.subject.role == "manager"

    # Check if resource department is in subject's hierarchy
    allowed_depts := dept_hierarchy[input.subject.department]
    input.resource.department in allowed_depts
}
```

### 9. Conditional Write Access

**Use Case**: Editors can update datasets, but only certain fields.

**Note**: This requires the API to send field-level information in the resource attributes.

**Policy**:
```rego
package stratium.authz

default allow = false

# Read-only fields that editors cannot modify
protected_fields := ["owner_id", "created_at", "department"]

# Allow update if not modifying protected fields
allow {
    input.action == "update"
    input.resource.resource_type == "dataset"
    input.subject.role == "editor"
    input.subject.department == input.resource.department

    # Ensure no protected fields are being modified
    # (This would require the API to send modified_fields in the request)
    count({field | field := input.modified_fields[_]; field in protected_fields}) == 0
}
```

### 10. Approval-Based Access

**Use Case**: Access requires explicit approval recorded in the system.

**Policy**:
```rego
package stratium.authz

default allow = false

# Allow access if user has approval
allow {
    input.action in ["read", "update"]
    input.resource.resource_type == "dataset"

    # Check if subject has approval for this resource
    # (This assumes approvals are stored in a data source accessible to OPA)
    approval := data.approvals[input.subject.subject_id][input.resource.resource_id]
    approval.status == "approved"
    approval.expires_at > time.now_ns()
}
```

## Policy Testing

### Testing with curl

Test a policy before deploying:

```bash
curl -X POST 'http://localhost:8090/api/v1/policies/test' \
  -H 'Content-Type: application/json' \
  -d '{
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.department == input.resource.department\n}",
  "subject_attributes": {
    "subject_id": "alice-123",
    "department": "engineering",
    "role": "editor"
  },
  "resource_attributes": {
    "resource_type": "dataset",
    "resource_id": "dataset-456",
    "department": "engineering",
    "owner_id": "alice-123"
  },
  "action": "read"
}'
```

### Expected Response

```json
{
  "allowed": true,
  "reason": "Policy evaluation successful",
  "policy_results": [
    {
      "policy": "test-policy",
      "allowed": true
    }
  ]
}
```

## Policy Priority and Evaluation Order

Policies are evaluated in priority order (lower number = higher priority):

1. **Priority 100**: Admin policies (override everything)
2. **Priority 200-299**: General access policies
3. **Priority 300+**: Specific ownership and fine-grained policies

### How Priorities Work

- Policies are evaluated from lowest to highest priority number
- The first policy that explicitly allows or denies access determines the result
- If no policy matches, the default deny is applied

## Best Practices

### 1. Default Deny

Always start with `default allow = false` to ensure secure defaults.

### 2. Explicit Conditions

Be explicit about all conditions required for access:

```rego
# Good: Explicit conditions
allow {
    input.action == "read"
    input.resource.resource_type == "dataset"
    input.subject.department == input.resource.department
}

# Bad: Too broad
allow {
    input.subject.department == input.resource.department
}
```

### 3. Use Descriptive Names

Policy names should clearly indicate their purpose:
- ✓ `department-read-isolation`
- ✓ `owner-write-access`
- ✗ `policy-1`
- ✗ `access-rule`

### 4. Document Policies

Include descriptions when creating policies:

```json
{
  "name": "department-read-isolation",
  "description": "Users can only read datasets from their department. Prevents cross-department data access except for admins.",
  "language": "opa",
  "policy_content": "..."
}
```

### 5. Test Before Deploying

Always test policies with the `/policies/test` endpoint before enabling them in production.

### 6. Use Appropriate Priorities

- 1-99: Reserved for system-critical overrides
- 100-199: Admin and elevated access
- 200-299: Standard access policies
- 300-399: Ownership and specific rules
- 400+: Exceptions and edge cases

## Troubleshooting

### Policy Not Applying

1. Check if policy is enabled: `"enabled": true`
2. Verify priority - higher priority policies might override
3. Check policy syntax with `/policies/test`
4. Review Platform service logs for evaluation errors

### Access Denied Unexpectedly

1. Test the exact scenario with `/policies/test`
2. Check that input attributes match expectations
3. Verify no higher-priority policy is denying access
4. Review policy conditions - all must be true

### Policy Evaluation Errors

Common issues:
- Syntax errors in Rego code
- Referencing undefined attributes
- Type mismatches (string vs array)
- Missing default allow/deny

## Additional Resources

- [OPA Policy Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Rego Language Guide](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [Stratium PAP API Guide](../../../docs/PAP_API_GUIDE.md)
- [Policy Testing Guide](../../../docs/policy-testing.md)