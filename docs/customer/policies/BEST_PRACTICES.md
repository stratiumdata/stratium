# Policy Best Practices

Guidelines and best practices for creating, managing, and maintaining effective policies in Stratium.

## Table of Contents
- [General Principles](#general-principles)
- [Policy Design](#policy-design)
- [Choosing the Right Policy Language](#choosing-the-right-policy-language)
- [Naming and Documentation](#naming-and-documentation)
- [Priority Management](#priority-management)
- [Testing and Validation](#testing-and-validation)
- [Performance Optimization](#performance-optimization)
- [Security Considerations](#security-considerations)
- [Maintenance and Updates](#maintenance-and-updates)
- [Common Pitfalls](#common-pitfalls)

## General Principles

### 1. Principle of Least Privilege

Grant the minimum access necessary:

✅ **Good**: Specific, limited access
```json
{
  "name": "Engineering Read Access to Dev Databases",
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {
        "department": {"$eq": "engineering"}
      },
      "resource": {
        "resource_type": {"$eq": "database"},
        "environment": {"$eq": "development"}
      },
      "action": {
        "action_name": {"$eq": "read"}
      }
    }
  }
}
```

❌ **Bad**: Overly permissive
```json
{
  "name": "Engineering Access",
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {
        "department": {"$eq": "engineering"}
      }
    }
  }
}
```

### 2. Default Deny

Always use explicit allow policies rather than relying on absence of deny:

✅ **Good**: Explicit allow with specific conditions
```json
{
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {"role": {"$eq": "admin"}},
      "action": {"action_name": {"$in": ["read", "write"]}}
    }
  }
}
```

Use deny policies sparingly for exceptional cases:
```json
{
  "name": "Deny Suspended Users",
  "effect": "deny",
  "priority": 9999,
  "policy_content": {
    "conditions": {
      "subject": {
        "account_status": {"$eq": "suspended"}
      }
    }
  }
}
```

### 3. Defense in Depth

Layer multiple policies for critical resources:

```json
// Layer 1: Department access
{
  "name": "Finance Department Access",
  "effect": "allow",
  "priority": 100,
  "policy_content": {
    "conditions": {
      "subject": {"department": {"$eq": "finance"}},
      "resource": {"owner": {"$eq": "finance"}}
    }
  }
}

// Layer 2: Clearance check
{
  "name": "Clearance Verification",
  "effect": "allow",
  "priority": 500,
  "policy_content": {
    "conditions": {
      "subject": {
        "clearance": {"$gte": "$resource.classification"}
      }
    }
  }
}

// Layer 3: Time restriction
{
  "name": "Business Hours Only",
  "effect": "allow",
  "priority": 200,
  "policy_content": {
    "conditions": {
      "environment": {
        "hour": {"$gte": 9, "$lte": 17}
      }
    }
  }
}
```

## Policy Design

### Keep Policies Focused

One policy should address one concern:

✅ **Good**: Separate policies for separate concerns
```json
// Policy 1: Check department
{
  "name": "Department Access Check",
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {"department": {"$eq": "engineering"}},
      "resource": {"owner": {"$eq": "engineering"}}
    }
  }
}

// Policy 2: Check role
{
  "name": "Engineer Role Check",
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {"role": {"$in": ["engineer", "senior_engineer"]}}
    }
  }
}
```

❌ **Bad**: Everything in one policy
```json
{
  "name": "Complex Access Policy",
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {
        "department": {"$eq": "engineering"},
        "role": {"$in": ["engineer", "senior_engineer"]},
        "clearance": {"$gte": "CONFIDENTIAL"},
        "training_completed": {"$eq": true},
        "location": {"$in": ["US-East", "US-West"]}
      },
      "resource": {
        "owner": {"$eq": "engineering"},
        "classification": {"$lte": "SECRET"},
        "project": {"$in": ["alpha", "beta"]}
      }
    }
  }
}
```

### Use Hierarchical Organization

Organize policies by domain or purpose:

```
policies/
├── authentication/
│   ├── mfa-requirements.json
│   ├── password-policy.json
│   └── session-policy.json
├── authorization/
│   ├── department-access.json
│   ├── role-based-access.json
│   └── clearance-checks.json
├── compliance/
│   ├── gdpr-restrictions.json
│   ├── hipaa-requirements.json
│   └── sox-controls.json
└── security/
    ├── deny-suspended-users.json
    ├── ip-restrictions.json
    └── time-restrictions.json
```

### Reusability

Create reusable policy patterns:

**Pattern: Clearance Check**
```json
{
  "name": "Clearance Check - {RESOURCE_TYPE}",
  "effect": "allow",
  "policy_content": {
    "conditions": {
      "subject": {
        "clearance": {"$gte": "$resource.classification"}
      }
    }
  }
}
```

Apply pattern to different resource types by creating policy instances.

## Choosing the Right Policy Language

### JSON Policies

**Use when:**
- Simple attribute comparisons
- Straightforward boolean logic
- Team unfamiliar with Rego/XACML
- Performance is critical
- Rapid development needed

**Example use cases:**
- Department-based access
- Role-based access control
- Simple clearance checks

### OPA/Rego Policies

**Use when:**
- Complex logic required
- Iterating over arrays/sets
- Dynamic rule evaluation
- Need helper functions
- Policy composition/reuse

**Example use cases:**
- Complex business rules
- Multi-step validation
- Data transformation
- Set operations

### XACML Policies

**Use when:**
- Enterprise compliance requirements
- Interoperability with other systems
- Complex policy combining
- Standardization mandated
- Existing XACML infrastructure

**Example use cases:**
- Government/defense systems
- Healthcare (HIPAA)
- Financial services (SOX, PCI-DSS)

### Comparison Matrix

| Criteria | JSON | OPA | XACML |
|----------|------|-----|-------|
| **Learning Curve** | Low | Medium | High |
| **Complexity** | Simple | Complex | Very Complex |
| **Performance** | Fast | Good | Medium |
| **Flexibility** | Limited | High | Very High |
| **Tooling** | Excellent | Good | Limited |
| **Enterprise Adoption** | High | Growing | Established |

## Naming and Documentation

### Descriptive Names

Use clear, descriptive policy names:

✅ **Good**:
- "Engineering Department Database Read Access"
- "Manager Approval Rights for Purchase Orders"
- "HIPAA Compliance - Patient Record Access"
- "Deny Access from Blacklisted IP Ranges"

❌ **Bad**:
- "Policy 1"
- "Access Policy"
- "Important"
- "New Policy 2025"

### Comprehensive Descriptions

Provide detailed descriptions:

✅ **Good**:
```json
{
  "name": "Contractor Project Access - Limited Duration",
  "description": "Grants contractors read/write access to assigned project resources during their contract period. Requires background check completion. Access limited to business hours (9 AM - 5 PM) Monday-Friday. Expires with contract end date.",
  "effect": "allow"
}
```

❌ **Bad**:
```json
{
  "name": "Contractor Access",
  "description": "Access for contractors",
  "effect": "allow"
}
```

### Document Policy Intent

Explain the "why" not just the "what":

```json
{
  "name": "Production Database - Read-Only During Business Hours",
  "description": "INTENT: Prevent accidental data modifications during peak business hours. CONTEXT: Incident #1234 where analyst accidentally updated production data. COMPLIANCE: SOX control requirement for data integrity.",
  "effect": "allow",
  "metadata": {
    "owner": "data-governance-team",
    "compliance_requirement": "SOX-404",
    "related_incident": "INC-1234",
    "review_date": "2025-06-30"
  }
}
```

## Priority Management

### Priority Ranges

Establish consistent priority ranges:

| Range | Purpose | Examples |
|-------|---------|----------|
| **9000-10000** | Critical deny policies | Suspended accounts, blacklisted IPs |
| **7000-8999** | Security policies | Clearance checks, MFA requirements |
| **5000-6999** | Compliance policies | HIPAA, GDPR, SOX controls |
| **3000-4999** | Department/role policies | Department access, RBAC |
| **1000-2999** | General access policies | Default resource access |
| **0-999** | Baseline policies | Public resource access |

### Priority Examples

```json
// High priority deny
{
  "name": "Deny Suspended Users",
  "effect": "deny",
  "priority": 9999
}

// Security clearance check
{
  "name": "Clearance Verification",
  "effect": "allow",
  "priority": 7500
}

// Department access
{
  "name": "Engineering Department Access",
  "effect": "allow",
  "priority": 4000
}

// General access
{
  "name": "Public Resource Access",
  "effect": "allow",
  "priority": 500
}
```

### Deny Overrides Allow

Remember: At the same priority level, deny policies override allow policies.

```json
// Even if allow policy matches...
{
  "name": "Engineering Access",
  "effect": "allow",
  "priority": 100
}

// ...this deny will take precedence
{
  "name": "Deny Suspended Engineers",
  "effect": "deny",
  "priority": 100,
  "policy_content": {
    "conditions": {
      "subject": {
        "department": {"$eq": "engineering"},
        "account_status": {"$eq": "suspended"}
      }
    }
  }
}
```

## Testing and Validation

### Test Before Deployment

Always test policies before enabling:

```bash
# 1. Create policy with enabled: false
POST /api/v1/policies
{
  "name": "Test Policy",
  "enabled": false,
  "policy_content": {...}
}

# 2. Test with sample data
POST /api/v1/policies/test
{
  "policy": {...},
  "evaluation_context": {...}
}

# 3. Enable after successful tests
PUT /api/v1/policies/{id}
{
  "enabled": true
}
```

### Test Multiple Scenarios

Test at least these cases:

1. **Expected Allow**: Should grant access
2. **Expected Deny**: Should block access
3. **Missing Attributes**: Handle gracefully
4. **Edge Cases**: Boundary conditions
5. **Invalid Data**: Malformed inputs

### Use Policy Versioning

Version your policies:

```json
{
  "name": "Engineering Database Access v2.0",
  "description": "Updated to add time restrictions",
  "metadata": {
    "version": "2.0",
    "changelog": "Added business hours restriction",
    "previous_version_id": "policy-123-v1",
    "updated_by": "admin@example.com",
    "updated_date": "2025-01-15"
  }
}
```

## Performance Optimization

### Optimize Conditions

Order conditions by selectivity (most restrictive first):

✅ **Good**: Check specific conditions first
```json
{
  "conditions": {
    "subject": {
      "role": {"$eq": "admin"}  // Very selective
    },
    "resource": {
      "resource_type": {"$eq": "database"}  // Moderately selective
    },
    "action": {
      "action_name": {"$in": ["read", "write"]}  // Less selective
    }
  }
}
```

### Avoid Complex Regex

Regex can be slow. Use simple comparisons when possible:

✅ **Good**: Simple comparison
```json
{
  "subject": {
    "email_domain": {"$eq": "example.com"}
  }
}
```

❌ **Bad**: Complex regex
```json
{
  "subject": {
    "email": {"$regex": "^[a-zA-Z0-9._%+-]+@example\\.com$"}
  }
}
```

### Cache Policy Results

For frequently accessed policies, enable caching:

```yaml
policy_engine:
  cache:
    enabled: true
    ttl: 300  # 5 minutes
    max_size: 1000
```

### Index Attributes

Ensure commonly queried attributes are indexed in the database:

```sql
CREATE INDEX idx_policies_subject_dept ON policies
USING GIN ((policy_content->'conditions'->'subject'->'department'));
```

## Security Considerations

### Avoid Hardcoding Secrets

Never include secrets in policies:

❌ **Bad**:
```json
{
  "conditions": {
    "subject": {
      "api_key": {"$eq": "sk_live_abc123xyz789"}  // NEVER DO THIS!
    }
  }
}
```

✅ **Good**: Reference secrets securely
```json
{
  "conditions": {
    "subject": {
      "api_key_valid": {"$eq": true}  // Validated elsewhere
    }
  }
}
```

### Sanitize Input

Validate all policy inputs:

```json
{
  "name": "Input Validation Policy",
  "policy_content": {
    "conditions": {
      "subject": {
        "user_id": {
          "$regex": "^user-[0-9]{1,10}$"  // Validate format
        }
      }
    }
  }
}
```

### Audit Policy Changes

Log all policy modifications:

```yaml
audit:
  log_policy_changes: true
  events:
    - policy_created
    - policy_updated
    - policy_deleted
    - policy_enabled
    - policy_disabled
```

### Implement Policy Reviews

Regular policy audits:

```json
{
  "metadata": {
    "owner": "security-team",
    "last_review_date": "2025-01-15",
    "next_review_date": "2025-04-15",
    "review_frequency": "quarterly"
  }
}
```

## Maintenance and Updates

### Gradual Rollout

Deploy policy changes gradually:

1. **Test in dev/staging**
2. **Enable with low priority**
3. **Monitor for issues**
4. **Increase priority gradually**
5. **Full deployment**

### Monitor Policy Effectiveness

Track policy metrics:

```sql
-- Check policy usage
SELECT policy_id, COUNT(*) as evaluation_count
FROM audit_logs
WHERE timestamp >= NOW() - INTERVAL '7 days'
GROUP BY policy_id
ORDER BY evaluation_count DESC;

-- Find unused policies
SELECT id, name
FROM policies
WHERE id NOT IN (
    SELECT DISTINCT policy_id
    FROM audit_logs
    WHERE timestamp >= NOW() - INTERVAL '30 days'
)
AND enabled = true;
```

### Deprecate Obsolete Policies

Remove or disable unused policies:

```bash
# 1. Disable policy
PUT /api/v1/policies/{id}
{
  "enabled": false,
  "metadata": {
    "deprecated": true,
    "deprecation_date": "2025-01-15",
    "deprecation_reason": "Replaced by policy-xyz"
  }
}

# 2. Monitor for 30 days

# 3. Delete if no issues
DELETE /api/v1/policies/{id}
```

## Common Pitfalls

### 1. Overly Complex Policies

**Problem**: One policy does too much

**Solution**: Split into multiple focused policies

### 2. Conflicting Priorities

**Problem**: Policies with same priority conflict

**Solution**: Use distinct priority levels and document ordering

### 3. Missing Default Deny

**Problem**: Relying on absence of allow

**Solution**: Explicit deny for critical resources

### 4. Ignoring Performance

**Problem**: Slow policy evaluation

**Solution**: Optimize conditions, use caching, profile performance

### 5. Insufficient Testing

**Problem**: Policies deployed without testing

**Solution**: Comprehensive test suite before deployment

### 6. Poor Documentation

**Problem**: Nobody understands policy purpose

**Solution**: Detailed names, descriptions, and metadata

### 7. No Versioning

**Problem**: Can't track changes or rollback

**Solution**: Implement policy versioning and changelog

### 8. Hardcoded Values

**Problem**: Policies with hardcoded values

**Solution**: Use attribute references and dynamic values

### 9. Security by Obscurity

**Problem**: Relying on hidden/undocumented policies

**Solution**: Transparent, well-documented access control

### 10. No Audit Trail

**Problem**: Can't track who changed what

**Solution**: Comprehensive audit logging

## Policy Lifecycle Checklist

- [ ] **Design**
  - [ ] Clear purpose defined
  - [ ] Appropriate policy language chosen
  - [ ] Principle of least privilege applied
  - [ ] Performance considerations addressed

- [ ] **Development**
  - [ ] Descriptive name and description
  - [ ] Proper priority assigned
  - [ ] Metadata included
  - [ ] Reviewed by team

- [ ] **Testing**
  - [ ] Unit tests created
  - [ ] Edge cases tested
  - [ ] Performance tested
  - [ ] Security reviewed

- [ ] **Deployment**
  - [ ] Deployed to staging first
  - [ ] Monitored for issues
  - [ ] Gradually enabled
  - [ ] Documented

- [ ] **Maintenance**
  - [ ] Regular reviews scheduled
  - [ ] Metrics monitored
  - [ ] Updated as needed
  - [ ] Deprecated when obsolete

## Next Steps

- [JSON Policy Guide](./JSON_POLICIES.md)
- [OPA Policy Guide](./OPA_POLICIES.md)
- [XACML Policy Guide](./XACML_POLICIES.md)
- [Entitlement Best Practices](../entitlements/CREATING_ENTITLEMENTS.md)

## License

Copyright © 2025 Stratium Data