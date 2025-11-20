# OPA Policy Creation Guide

Open Policy Agent (OPA) policies use the Rego language to express complex authorization logic with advanced features like iteration, comprehensions, and custom functions.

## Table of Contents
- [Overview](#overview)
- [When to Use OPA](#when-to-use-opa)
- [Rego Basics](#rego-basics)
- [Policy Structure](#policy-structure)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

OPA (Open Policy Agent) is a powerful policy engine that uses the Rego language. Rego is a declarative query language designed specifically for writing policies over complex hierarchical data structures.

**Key Features:**
- Advanced logic and iteration
- Set operations and comprehensions
- Built-in functions for strings, arrays, objects
- Policy composition and reuse
- Partial evaluation
- Debugging and testing tools

## When to Use OPA

Choose OPA policies when you need:

✅ **Complex Logic**
- Multiple nested conditions
- Iterating over arrays or sets
- Dynamic rule evaluation
- Mathematical computations

✅ **Data Transformation**
- Filtering arrays
- Building new data structures
- Complex string manipulation

✅ **Reusable Rules**
- Shared helper functions
- Policy libraries
- Organization-wide standards

❌ **Don't use OPA when:**
- Simple attribute comparisons are sufficient (use JSON instead)
- Team is unfamiliar with Rego (stick with JSON)
- Performance is critical (JSON is faster)

## Rego Basics

### Rules and Expressions

A Rego rule is a boolean expression that evaluates to `true` or `false`:

```rego
# Simple rule
allow {
    input.subject.role == "admin"
}
```

### Input Document

The `input` document contains the evaluation context:

```rego
# Input structure
input = {
    "subject": {
        "user_id": "user123",
        "role": "engineer",
        "clearance": "SECRET"
    },
    "resource": {
        "id": "doc456",
        "classification": "CONFIDENTIAL",
        "owner": "user789"
    },
    "action": "read"
}
```

### Multiple Rules

Rules with the same name are OR'd together:

```rego
# Allow if admin
allow {
    input.subject.role == "admin"
}

# OR allow if owner
allow {
    input.subject.user_id == input.resource.owner
}
```

### Variables

```rego
allow {
    user := input.subject
    resource := input.resource
    user.department == resource.department
}
```

### Comprehensions

```rego
# Check if user has any required role
required_roles := {"admin", "manager", "supervisor"}
allow {
    some role in required_roles
    role == input.subject.role
}
```

## Policy Structure

### Basic OPA Policy for Stratium

```json
{
  "name": "OPA Policy Name",
  "description": "What this policy does",
  "effect": "allow",
  "language": "opa",
  "priority": 100,
  "enabled": true,
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    # Your rules here\n}"
}
```

### Rego Package Structure

```rego
package stratium.authz

# Import built-in functions if needed
import future.keywords.in
import future.keywords.if

# Default deny
default allow = false

# Main decision rule
allow if {
    # Condition 1
    input.subject.role == "admin"
}

allow if {
    # Condition 2
    is_resource_owner
}

# Helper rules
is_resource_owner if {
    input.subject.user_id == input.resource.owner
}
```

### Required Elements

1. **Package declaration**: Must be `package stratium.authz`
2. **Default rule**: `default allow = false` (deny by default)
3. **Allow rule**: At least one `allow` rule that evaluates to `true`

## Examples

### Example 1: Role-Based Access with Conditions

```rego
package stratium.authz

default allow = false

# Admins can do anything
allow if {
    input.subject.role == "admin"
}

# Managers can read and update
allow if {
    input.subject.role == "manager"
    input.action in ["read", "update"]
}

# Regular users can only read
allow if {
    input.subject.role == "user"
    input.action == "read"
}
```

**JSON Wrapper:**
```json
{
  "name": "Role-Based Access Control",
  "effect": "allow",
  "language": "opa",
  "priority": 100,
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow if {\n    input.subject.role == \"admin\"\n}\n\nallow if {\n    input.subject.role == \"manager\"\n    input.action in [\"read\", \"update\"]\n}\n\nallow if {\n    input.subject.role == \"user\"\n    input.action == \"read\"\n}"
}
```

### Example 2: Hierarchical Clearance Check

```rego
package stratium.authz

default allow = false

# Classification hierarchy
classification_levels := {
    "UNCLASSIFIED": 0,
    "RESTRICTED": 1,
    "CONFIDENTIAL": 2,
    "SECRET": 3,
    "TOP-SECRET": 4
}

# Check if clearance >= classification
allow if {
    subject_level := classification_levels[input.subject.clearance]
    resource_level := classification_levels[input.resource.classification]
    subject_level >= resource_level
}
```

### Example 3: Array Membership and Iteration

Check if user belongs to any authorized group:

```rego
package stratium.authz

default allow = false

# Authorized groups for this resource
authorized_groups := {"engineering", "security", "management"}

# Allow if user is in any authorized group
allow if {
    some group in input.subject.groups
    authorized_groups[group]
}
```

### Example 4: Complex Business Logic

Multiple conditions with helper functions:

```rego
package stratium.authz

import future.keywords.if

default allow = false

# Main authorization rules
allow if {
    is_business_hours
    has_required_training
    is_authorized_for_action
}

# Helper: Check business hours
is_business_hours if {
    hour := time.clock([time.now_ns()])[0]
    hour >= 9
    hour <= 17
}

# Helper: Check training completion
has_required_training if {
    resource_type := input.resource.type
    required := required_training[resource_type]
    completed := {t | t := input.subject.training_completed[_]}
    required_set := {r | r := required[_]}
    required_set - completed == set()
}

# Training requirements by resource type
required_training := {
    "sensitive_data": ["data_protection", "security_awareness"],
    "financial_data": ["sox_compliance", "data_protection"],
    "health_data": ["hipaa_training", "data_protection"]
}

# Helper: Check action authorization
is_authorized_for_action if {
    action := input.action
    role := input.subject.role
    allowed_actions := role_permissions[role]
    allowed_actions[action]
}

# Role permissions
role_permissions := {
    "admin": {"read": true, "write": true, "delete": true, "approve": true},
    "manager": {"read": true, "write": true, "approve": true},
    "user": {"read": true, "write": true},
    "viewer": {"read": true}
}
```

### Example 5: Resource Ownership with Delegation

```rego
package stratium.authz

default allow = false

# Owner can do anything with their resources
allow if {
    input.subject.user_id == input.resource.owner
}

# Delegated access
allow if {
    is_delegated_access
}

is_delegated_access if {
    some delegation in input.resource.delegations
    delegation.delegate_id == input.subject.user_id
    delegation.action == input.action
    not is_expired(delegation.expires_at)
}

# Check if timestamp is expired
is_expired(timestamp) if {
    now := time.now_ns()
    expiry := time.parse_rfc3339_ns(timestamp)
    now > expiry
}
```

### Example 6: Data Filtering

Filter resources based on user attributes:

```rego
package stratium.authz

default allow = false

# User can access resources from their region
allow if {
    user_regions := input.subject.regions
    resource_region := input.resource.region
    resource_region in user_regions
}

# OR user has global access
allow if {
    input.subject.global_access == true
}

# Generate list of accessible resources
accessible_resources[resource.id] {
    resource := data.resources[_]
    resource.region in input.subject.regions
}

accessible_resources[resource.id] {
    resource := data.resources[_]
    input.subject.global_access == true
}
```

### Example 7: Time-Based and Conditional Access

```rego
package stratium.authz

import future.keywords.if

default allow = false

# Access allowed during maintenance window
allow if {
    in_maintenance_window
    input.subject.role == "admin"
}

# Regular access outside maintenance window
allow if {
    not in_maintenance_window
    regular_access_allowed
}

in_maintenance_window if {
    # Check if current time is in maintenance window
    now := time.now_ns()
    maintenance_start := time.parse_rfc3339_ns("2025-01-15T02:00:00Z")
    maintenance_end := time.parse_rfc3339_ns("2025-01-15T04:00:00Z")
    now >= maintenance_start
    now <= maintenance_end
}

regular_access_allowed if {
    input.subject.role in ["admin", "operator"]
    input.action in ["read", "monitor"]
}
```

## Best Practices

### 1. Always Set Default Deny

```rego
# ✅ Good - Explicit default
default allow = false

# ❌ Bad - No default (ambiguous)
allow {
    # rules
}
```

### 2. Use Helper Functions for Readability

```rego
# ✅ Good - Clear helper functions
allow if {
    is_admin_or_owner
    has_valid_clearance
}

is_admin_or_owner if {
    input.subject.role == "admin"
}

is_admin_or_owner if {
    input.subject.user_id == input.resource.owner
}

has_valid_clearance if {
    clearance_level(input.subject.clearance) >=
    clearance_level(input.resource.classification)
}

# ❌ Bad - Everything inline
allow if {
    (input.subject.role == "admin" or
     input.subject.user_id == input.resource.owner)
    classification_levels[input.subject.clearance] >=
    classification_levels[input.resource.classification]
}
```

### 3. Use Comprehensions for Set Operations

```rego
# ✅ Good - Comprehension
user_groups := {g | g := input.subject.groups[_]}
required_groups := {"admin", "security"}
allow if {
    count(user_groups & required_groups) > 0
}

# ❌ Bad - Manual iteration
allow if {
    some i
    input.subject.groups[i] == "admin"
}
allow if {
    some i
    input.subject.groups[i] == "security"
}
```

### 4. Validate Input

```rego
# Add input validation
allow if {
    # Ensure required fields exist
    input.subject.user_id
    input.resource.id
    input.action

    # Then evaluate rules
    evaluate_rules
}
```

### 5. Use Constants for Magic Values

```rego
# ✅ Good - Named constants
admin_role := "admin"
manager_role := "manager"

allow if {
    input.subject.role == admin_role
}

# ❌ Bad - Magic strings everywhere
allow if {
    input.subject.role == "admin"
}
```

### 6. Document Complex Logic

```rego
# Approve high-value transactions
# Requires:
# - User has approver role
# - Transaction amount under user's approval limit
# - Transaction is not already approved
approve_transaction if {
    input.subject.role == "approver"
    input.transaction.amount <= input.subject.approval_limit
    not input.transaction.approved
}
```

## Testing

### Test with Rego Playground

Use the [OPA Playground](https://play.openpolicyagent.org) to test policies:

1. Paste your Rego policy
2. Provide sample input
3. Check the output

### Example Test Input

```json
{
  "subject": {
    "user_id": "user123",
    "role": "manager",
    "clearance": "SECRET",
    "groups": ["engineering", "security"]
  },
  "resource": {
    "id": "doc456",
    "classification": "CONFIDENTIAL",
    "owner": "user789",
    "type": "document"
  },
  "action": "read"
}
```

### Test with Stratium API

```bash
POST /api/v1/policies/test
Content-Type: application/json

{
  "policy": {
    "effect": "allow",
    "language": "opa",
    "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}"
  },
  "evaluation_context": {
    "subject": {"role": "admin"},
    "resource": {"id": "test"},
    "action": "read"
  }
}
```

### Unit Testing in Rego

Create test files alongside policies:

```rego
# policy_test.rego
package stratium.authz

test_admin_allowed {
    allow with input as {
        "subject": {"role": "admin"},
        "action": "read"
    }
}

test_user_denied_write {
    not allow with input as {
        "subject": {"role": "user"},
        "action": "write"
    }
}

test_clearance_hierarchy {
    allow with input as {
        "subject": {"clearance": "SECRET"},
        "resource": {"classification": "CONFIDENTIAL"}
    }
}
```

Run tests:
```bash
opa test policy.rego policy_test.rego
```

## Troubleshooting

### Policy Always Returns False

**Problem**: `allow` rule never evaluates to `true`

**Debug steps:**

1. **Check package name**:
   ```rego
   # Must be exactly this
   package stratium.authz
   ```

2. **Verify input structure**:
   ```rego
   # Add debug output
   debug := input
   ```

3. **Test individual rules**:
   ```rego
   # Isolate each condition
   test_condition_1 {
       input.subject.role == "admin"
   }
   ```

### Syntax Errors

**Problem**: Policy fails to compile

**Common mistakes:**

```rego
# ❌ Wrong - Missing brackets
allow if
    input.subject.role == "admin"

# ✅ Correct
allow if {
    input.subject.role == "admin"
}

# ❌ Wrong - Wrong operator
allow if {
    input.subject.role = "admin"  # Single =
}

# ✅ Correct
allow if {
    input.subject.role == "admin"  # Double ==
}
```

### Undefined Values

**Problem**: Accessing undefined fields causes errors

**Solution**: Use default values or check existence:

```rego
# ✅ Provide default
clearance := object.get(input.subject, "clearance", "UNCLASSIFIED")

# ✅ Check existence
allow if {
    input.subject.clearance  # Ensures field exists
    # ... rest of logic
}
```

### Performance Issues

**Problem**: Policy evaluation is slow

**Solutions:**

1. **Avoid unnecessary iterations**:
   ```rego
   # ❌ Slow - Iterates everything
   allow if {
       some resource in data.all_resources
       resource.id == input.resource.id
   }

   # ✅ Fast - Direct lookup
   allow if {
       resource := data.resources[input.resource.id]
   }
   ```

2. **Cache computed values**:
   ```rego
   # ✅ Compute once
   user_level := classification_levels[input.subject.clearance]
   resource_level := classification_levels[input.resource.classification]

   allow if {
       user_level >= resource_level
   }
   ```

## OPA vs JSON Comparison

| Feature | JSON | OPA |
|---------|------|-----|
| **Learning Curve** | Low | Medium-High |
| **Complex Logic** | Limited | Excellent |
| **Performance** | Fast | Good |
| **Iteration** | No | Yes |
| **Functions** | Limited | Extensive |
| **Debugging** | Basic | Advanced |
| **Best For** | Simple rules | Complex policies |

## Next Steps

- [Learn about XACML Policies](./XACML_POLICIES.md)
- [Policy Best Practices](./BEST_PRACTICES.md)
- [Back to JSON Policies](./JSON_POLICIES.md)
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)

## API Reference

### Create OPA Policy

```bash
POST /api/v1/policies
Content-Type: application/json

{
  "name": "My OPA Policy",
  "effect": "allow",
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}"
}
```

**Note**: The `policy_content` must be a string with newlines (`\n`).

### Validate OPA Policy

```bash
POST /api/v1/policies/validate
Content-Type: application/json

{
  "language": "opa",
  "policy_content": "package stratium.authz\n\ndefault allow = false\n\nallow {\n    input.subject.role == \"admin\"\n}"
}
```

## Support

Need help with OPA policies?
- [OPA Documentation](https://www.openpolicyagent.org/docs/latest/)
- [Rego Playground](https://play.openpolicyagent.org)
- [Policy Examples](./EXAMPLES.md)
- Contact support: support@stratium.example