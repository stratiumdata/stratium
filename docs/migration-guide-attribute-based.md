# Migration Guide: String-Based to Attribute-Based Access Control

## Overview

This guide helps you migrate from the legacy string-based `GetDecisionRequest` API to the new attribute-based access control (ABAC) model. The new model provides more flexibility and supports fine-grained authorization decisions.

## Breaking Changes

### GetDecisionRequest Structure

**Before (Legacy)**:
```protobuf
message GetDecisionRequest {
    string subject = 1;    // Single string identifier
    string resource = 2;   // Single string identifier
    string action = 3;
    map<string, string> context = 4;
    string policy_id = 5;
}
```

**After (Current)**:
```protobuf
message GetDecisionRequest {
    map<string, string> subject_attributes = 1;   // Attribute map
    map<string, string> resource_attributes = 2;  // Attribute map
    string action = 3;
    map<string, string> context = 4;
    string policy_id = 5;
}
```

## Migration Strategy

### Step 1: Identify Current Usage

Audit your codebase for `GetDecisionRequest` usage:

```bash
# Find all GetDecisionRequest instantiations
grep -r "GetDecisionRequest" --include="*.go" --include="*.java" --include="*.py"

# Find specific field usage
grep -r "Subject:" --include="*.go" -A 2
grep -r "Resource:" --include="*.go" -A 2
```

### Step 2: Update Request Construction

#### Go Migration

**Before**:
```go
req := &pb.GetDecisionRequest{
    Subject:  "alice@example.com",
    Resource: "document-service",
    Action:   "read",
    Context:  map[string]string{
        "ip": "192.168.1.1",
    },
}
```

**After**:
```go
req := &pb.GetDecisionRequest{
    SubjectAttributes: map[string]string{
        "sub": "alice@example.com",
    },
    ResourceAttributes: map[string]string{
        "name": "document-service",
    },
    Action: "read",
    Context: map[string]string{
        "ip": "192.168.1.1",
    },
}
```

#### Python Migration

**Before**:
```python
request = GetDecisionRequest(
    subject="alice@example.com",
    resource="document-service",
    action="read",
    context={"ip": "192.168.1.1"}
)
```

**After**:
```python
request = GetDecisionRequest(
    subject_attributes={
        "sub": "alice@example.com"
    },
    resource_attributes={
        "name": "document-service"
    },
    action="read",
    context={"ip": "192.168.1.1"}
)
```

#### JavaScript/TypeScript Migration

**Before**:
```typescript
const request: GetDecisionRequest = {
    subject: "alice@example.com",
    resource: "document-service",
    action: "read",
    context: { ip: "192.168.1.1" }
};
```

**After**:
```typescript
const request: GetDecisionRequest = {
    subjectAttributes: {
        sub: "alice@example.com"
    },
    resourceAttributes: {
        name: "document-service"
    },
    action: "read",
    context: { ip: "192.168.1.1" }
};
```

### Step 3: Enrich Attributes (Optional)

The new model allows you to add additional attributes for more granular access control:

**Basic Migration** (minimal change):
```go
req := &pb.GetDecisionRequest{
    SubjectAttributes: map[string]string{
        "sub": userID,
    },
    ResourceAttributes: map[string]string{
        "name": resourceID,
    },
    Action: action,
}
```

**Enhanced Migration** (with additional attributes):
```go
req := &pb.GetDecisionRequest{
    SubjectAttributes: map[string]string{
        "sub":            userID,
        "role":           user.Role,
        "department":     user.Department,
        "classification": user.ClearanceLevel,
    },
    ResourceAttributes: map[string]string{
        "name":           resourceID,
        "type":           resource.Type,
        "classification": resource.ClassificationLevel,
        "owner":          resource.OwnerID,
    },
    Action: action,
    Context: map[string]string{
        "ip_address":  requestIP,
        "environment": env,
    },
}
```

## Migration Patterns

### Pattern 1: Simple ID Mapping

**Use Case**: Direct 1:1 mapping from string to attribute map

**Before**:
```go
Subject:  userID
Resource: resourceID
```

**After**:
```go
SubjectAttributes: map[string]string{
    "sub": userID,
}
ResourceAttributes: map[string]string{
    "name": resourceID,
}
```

### Pattern 2: Context Migration

**Use Case**: Moving role/department from context to subject attributes

**Before**:
```go
Subject: userID,
Resource: resourceID,
Context: map[string]string{
    "role":       "admin",
    "department": "engineering",
}
```

**After** (preferred):
```go
SubjectAttributes: map[string]string{
    "sub":        userID,
    "role":       "admin",
    "department": "engineering",
}
ResourceAttributes: map[string]string{
    "name": resourceID,
}
Context: map[string]string{
    // Keep only truly contextual information
    "ip_address": requestIP,
    "timestamp":  time.Now().Format(time.RFC3339),
}
```

**Why?**: `role` and `department` describe WHO the user is (identity), not contextual information about the request. Moving them to `SubjectAttributes` improves semantic clarity and performance.

### Pattern 3: Classification-Based Access (ZTDF)

**Use Case**: Zero Trust Data Format with classification levels

**Before**:
```go
Subject:  userID,
Resource: resourceID,
Context: map[string]string{
    "clearance": "SECRET",
}
```

**After**:
```go
SubjectAttributes: map[string]string{
    "sub":            userID,
    "classification": "SECRET",
}
ResourceAttributes: map[string]string{
    "name":           resourceID,
    "classification": "CONFIDENTIAL",
}
```

The system will automatically compare classification levels using attribute-based matching.

### Pattern 4: Project/Workspace Scoping

**Use Case**: Multi-tenant or project-based access control

**Before**:
```go
Subject:  userID,
Resource: resourceID,
Context: map[string]string{
    "project_id": projectID,
}
```

**After**:
```go
SubjectAttributes: map[string]string{
    "sub":        userID,
    "role":       userRole,
}
ResourceAttributes: map[string]string{
    "name":       resourceID,
    "project_id": resourceProjectID,
}
Context: map[string]string{
    "project_id": currentProjectID, // For matching
}
```

**Note**: `project_id` in context can be used for dynamic resource matching.

## Testing Your Migration

### Test Case Template

```go
func TestMigration_GetDecision(t *testing.T) {
    tests := []struct {
        name           string
        legacySubject  string
        legacyResource string
        newRequest     *GetDecisionRequest
        expectSame     bool
    }{
        {
            name:           "Simple user access",
            legacySubject:  "user123",
            legacyResource: "document-service",
            newRequest: &GetDecisionRequest{
                SubjectAttributes: map[string]string{
                    "sub": "user123",
                },
                ResourceAttributes: map[string]string{
                    "name": "document-service",
                },
                Action: "read",
            },
            expectSame: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test new API returns expected decision
            resp, err := client.GetDecision(ctx, tt.newRequest)
            if err != nil {
                t.Fatalf("GetDecision failed: %v", err)
            }

            // Verify decision is as expected
            if tt.expectSame && resp.Decision != Decision_DECISION_ALLOW {
                t.Errorf("Expected ALLOW, got %v: %s", resp.Decision, resp.Reason)
            }
        })
    }
}
```

### Validation Checklist

- [ ] All `GetDecisionRequest` calls updated to use attribute maps
- [ ] Subject identifier moved to `sub`, `user_id`, or `id` key
- [ ] Resource identifier moved to `name`, `id`, or `resource` key
- [ ] Identity attributes moved from Context to SubjectAttributes
- [ ] Tests passing with new request structure
- [ ] Integration tests verify backward compatibility
- [ ] Admin access patterns updated
- [ ] Audit logs reviewed for proper attribute capture

## Common Migration Issues

### Issue 1: Missing Subject Identifier

**Error**: `"Subject attributes must contain 'sub', 'user_id', or 'id'"`

**Cause**: Empty SubjectAttributes map or missing identifier key

**Fix**:
```go
// Wrong
SubjectAttributes: map[string]string{}

// Correct
SubjectAttributes: map[string]string{
    "sub": userID,
}
```

### Issue 2: Empty Maps Causing Unexpected Behavior

**Behavior**: Empty resource attributes result in ALLOW (no requirements to satisfy)

**Expected**: If you want to require resource validation, include attributes:
```go
// This will ALLOW (no resource requirements)
ResourceAttributes: map[string]string{}

// This will require matching
ResourceAttributes: map[string]string{
    "name": "specific-resource",
}
```

### Issue 3: Admin Role in Wrong Location

**Problem**: Admin role in Context instead of SubjectAttributes

**Wrong**:
```go
SubjectAttributes: map[string]string{
    "sub": adminUser,
},
Context: map[string]string{
    "role": "admin",  // Won't trigger admin check
}
```

**Correct**:
```go
SubjectAttributes: map[string]string{
    "sub":  adminUser,
    "role": "admin",  // Will trigger admin check
}
```

### Issue 4: Attribute Key Case Sensitivity

**Problem**: Attribute matching is case-sensitive for keys in entitlements/policies

**Best Practice**: Use consistent lowercase keys:
```go
// Consistent
SubjectAttributes: map[string]string{
    "sub":        userID,
    "role":       "developer",
    "department": "engineering",
}

// Inconsistent (avoid)
SubjectAttributes: map[string]string{
    "Sub":        userID,
    "Role":       "developer",
    "Department": "engineering",
}
```

**Note**: The ABAC evaluation uses case-insensitive matching internally, but consistency improves readability.

## Rollback Strategy

If issues arise, you can temporarily maintain compatibility by:

1. **Feature Flag**: Use a feature flag to toggle between old and new behavior
2. **Adapter Pattern**: Create an adapter that converts old format to new:

```go
func LegacyToAttributeBased(subject, resource, action string, context map[string]string) *GetDecisionRequest {
    return &GetDecisionRequest{
        SubjectAttributes: map[string]string{
            "sub": subject,
        },
        ResourceAttributes: map[string]string{
            "name": resource,
        },
        Action:  action,
        Context: context,
    }
}
```

3. **Parallel Deployment**: Run both versions in parallel during migration period

## Timeline Recommendations

### Phase 1: Preparation (Week 1-2)
- [ ] Audit current GetDecisionRequest usage
- [ ] Update proto definitions and regenerate client libraries
- [ ] Create migration utilities/helpers
- [ ] Set up feature flags

### Phase 2: Development (Week 3-4)
- [ ] Update application code to new API
- [ ] Add/enrich attributes as needed
- [ ] Write migration tests
- [ ] Update integration tests

### Phase 3: Testing (Week 5)
- [ ] Functional testing in dev/staging
- [ ] Performance testing
- [ ] Security review of attribute exposure
- [ ] Audit log verification

### Phase 4: Deployment (Week 6)
- [ ] Deploy to production with feature flag off
- [ ] Enable for small percentage of traffic
- [ ] Monitor metrics and errors
- [ ] Gradual rollout to 100%
- [ ] Remove legacy code

## Support and Resources

### Documentation
- [API Documentation](./api-attribute-based-access-control.md)
- [ZTDF Attribute Conventions](./ztdf-attribute-conventions.md)
- [Best Practices Guide](./best-practices-abac.md)

### Tools
- Proto validation: `buf lint`
- Code generation: `buf generate`
- Testing: See [Testing Guide](./testing-guide-abac.md)

### Getting Help
- Review audit logs for migration issues
- Check PDP logs for evaluation details
- Consult security team for classification attributes
- See examples in integration test suite

## Appendix: Full Example Migration

### Before (Legacy Code)

```go
package main

import (
    "context"
    "fmt"
    "log"

    pb "stratium/services/platform"
    "google.golang.org/grpc"
)

func checkUserAccess(client pb.PlatformClient, userID, resourceID, action string) (bool, error) {
    req := &pb.GetDecisionRequest{
        Subject:  userID,
        Resource: resourceID,
        Action:   action,
        Context: map[string]string{
            "role": "developer",
        },
    }

    resp, err := client.GetDecision(context.Background(), req)
    if err != nil {
        return false, err
    }

    return resp.Decision == pb.Decision_DECISION_ALLOW, nil
}
```

### After (Migrated Code)

```go
package main

import (
    "context"
    "fmt"
    "log"

    pb "stratium/services/platform"
    "google.golang.org/grpc"
)

func checkUserAccess(client pb.PlatformClient, userID, resourceID, action string, user *User) (bool, string, error) {
    req := &pb.GetDecisionRequest{
        SubjectAttributes: map[string]string{
            "sub":        userID,
            "role":       user.Role,        // Moved from context
            "department": user.Department,  // New attribute
        },
        ResourceAttributes: map[string]string{
            "name": resourceID,
            "type": "api",  // New attribute
        },
        Action: action,
        Context: map[string]string{
            "ip_address":  user.CurrentIP,
            "environment": "production",
        },
    }

    resp, err := client.GetDecision(context.Background(), req)
    if err != nil {
        return false, "", fmt.Errorf("decision request failed: %w", err)
    }

    allowed := resp.Decision == pb.Decision_DECISION_ALLOW
    return allowed, resp.Reason, nil
}

type User struct {
    Role       string
    Department string
    CurrentIP  string
}
```

## Conclusion

The migration to attribute-based access control provides:
- **More Flexibility**: Rich attribute-based policies
- **Better Semantics**: Clear separation of identity, resource, and context
- **Enhanced Security**: Fine-grained authorization decisions
- **ZTDF Support**: Native support for classification-based access control

Follow this guide step-by-step for a smooth migration. Start with simple ID mapping, then progressively enrich attributes to leverage the full power of ABAC.
