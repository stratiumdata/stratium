# ABAC API Integration Example

This document shows how to integrate the Platform Service's ABAC capabilities (`GetDecision` and `GetEntitlements`) into your API endpoints.

## Overview

The Platform Service provides two main ABAC methods:
1. **`GetDecision`** - Makes a single authorization decision for a specific action on a resource
2. **`GetEntitlements`** - Returns all entitlements (permissions) for a subject

## Example 1: Using GetDecision for API Authorization

### Scenario: Document API Endpoint

```go
package api

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"

    "stratium/services/platform"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/protobuf/types/known/structpb"
)

// DocumentAPI handles document operations with ABAC enforcement
type DocumentAPI struct {
    platformClient platform.PlatformServiceClient
}

// NewDocumentAPI creates a new document API with Platform service connection
func NewDocumentAPI(platformAddr string) (*DocumentAPI, error) {
    conn, err := grpc.NewClient(platformAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        return nil, fmt.Errorf("failed to connect to platform service: %w", err)
    }

    return &DocumentAPI{
        platformClient: platform.NewPlatformServiceClient(conn),
    }, nil
}

// Document represents a document resource
type Document struct {
    ID             string            `json:"id"`
    Title          string            `json:"title"`
    Content        string            `json:"content"`
    Classification string            `json:"classification"`
    Owner          string            `json:"owner"`
    Department     string            `json:"department"`
}

// GetDocumentHandler handles GET /api/documents/:id with ABAC enforcement
func (api *DocumentAPI) GetDocumentHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Extract document ID from URL
    documentID := r.URL.Query().Get("id")
    if documentID == "" {
        http.Error(w, "document ID required", http.StatusBadRequest)
        return
    }

    // Step 1: Extract user claims from JWT token (assume middleware already validated)
    userClaims := extractUserClaims(r) // Your JWT extraction logic

    // Step 2: Fetch document metadata to get resource attributes
    doc, err := api.fetchDocumentMetadata(ctx, documentID)
    if err != nil {
        http.Error(w, "document not found", http.StatusNotFound)
        return
    }

    // Step 3: Call Platform Service GetDecision for authorization
    decision, err := api.checkAccess(ctx, userClaims, doc, "read")
    if err != nil {
        http.Error(w, "authorization check failed", http.StatusInternalServerError)
        return
    }

    // Step 4: Enforce decision
    if decision.Decision != platform.Decision_ALLOW {
        http.Error(w, fmt.Sprintf("Access denied: %s", decision.Reason), http.StatusForbidden)
        return
    }

    // Step 5: Access granted - return document
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(doc)
}

// checkAccess calls Platform Service to make an ABAC decision
func (api *DocumentAPI) checkAccess(ctx context.Context, userClaims map[string]interface{}, doc *Document, action string) (*platform.GetDecisionResponse, error) {
    // Convert user claims to protobuf Value map
    subjectAttributes, err := convertToValueMap(userClaims)
    if err != nil {
        return nil, fmt.Errorf("failed to convert subject attributes: %w", err)
    }

    // Build resource attributes from document metadata
    resourceAttributes := map[string]string{
        "resource_type":   "document",
        "resource_id":     doc.ID,
        "classification":  doc.Classification,
        "owner":           doc.Owner,
        "department":      doc.Department,
    }

    // Build context attributes (e.g., request metadata)
    contextAttributes := map[string]string{
        "client_ip":   extractClientIP(ctx),
        "user_agent":  extractUserAgent(ctx),
        "time_of_day": getCurrentTime(),
    }

    // Call Platform Service GetDecision
    req := &platform.GetDecisionRequest{
        SubjectAttributes:  subjectAttributes,
        ResourceAttributes: resourceAttributes,
        Action:             action,
        Context:            contextAttributes,
    }

    return api.platformClient.GetDecision(ctx, req)
}

// Helper function to convert map to protobuf Value map
func convertToValueMap(attrs map[string]interface{}) (map[string]*structpb.Value, error) {
    result := make(map[string]*structpb.Value)
    for k, v := range attrs {
        val, err := structpb.NewValue(v)
        if err != nil {
            return nil, err
        }
        result[k] = val
    }
    return result, nil
}
```

### Example Request/Response Flow

```
1. User makes request: GET /api/documents/doc-123
   Headers: Authorization: Bearer <JWT>

2. API extracts JWT claims:
   {
     "sub": "user123",
     "email": "user@example.com",
     "roles": ["engineer"],
     "department": "engineering",
     "clearance": "confidential"
   }

3. API fetches document metadata:
   {
     "id": "doc-123",
     "classification": "confidential",
     "owner": "user456",
     "department": "engineering"
   }

4. API calls Platform GetDecision:
   Request:
   {
     "subject_attributes": {
       "sub": "user123",
       "roles": ["engineer"],
       "department": "engineering",
       "clearance": "confidential"
     },
     "resource_attributes": {
       "resource_type": "document",
       "classification": "confidential",
       "department": "engineering"
     },
     "action": "read"
   }

5. Platform returns decision:
   Response:
   {
     "decision": "ALLOW",
     "reason": "Entitlement match: user in engineering can read engineering docs",
     "applied_rules": ["entitlement:eng-read-access"]
   }

6. API returns document content to user
```

## Example 2: Using GetEntitlements for UI Permissions

### Scenario: User Dashboard Showing Available Actions

```go
// UserDashboardHandler shows what resources/actions the user can access
func (api *DocumentAPI) UserDashboardHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Extract user claims from JWT
    userClaims := extractUserClaims(r)

    // Convert to protobuf Value map
    subjectAttributes, err := convertToValueMap(userClaims)
    if err != nil {
        http.Error(w, "failed to process user attributes", http.StatusInternalServerError)
        return
    }

    // Call Platform Service GetEntitlements
    req := &platform.GetEntitlementsRequest{
        Subject: subjectAttributes,
        // Optional filters
        ResourceType: "document", // Only get document entitlements
        Action:       "",         // Get all actions
        PageSize:     100,
        PageToken:    "",
    }

    resp, err := api.platformClient.GetEntitlements(ctx, req)
    if err != nil {
        http.Error(w, "failed to fetch entitlements", http.StatusInternalServerError)
        return
    }

    // Build dashboard data from entitlements
    dashboard := buildDashboard(resp.Entitlements)

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(dashboard)
}

// Dashboard represents the user's permissions view
type Dashboard struct {
    User         string              `json:"user"`
    Capabilities []Capability        `json:"capabilities"`
    Entitlements []*EntitlementView  `json:"entitlements"`
}

type Capability struct {
    Resource string   `json:"resource"`
    Actions  []string `json:"actions"`
}

type EntitlementView struct {
    ID          string   `json:"id"`
    Name        string   `json:"name"`
    Description string   `json:"description"`
    Actions     []string `json:"actions"`
    ExpiresAt   string   `json:"expires_at,omitempty"`
}

func buildDashboard(entitlements []*platform.Entitlement) *Dashboard {
    dashboard := &Dashboard{
        Capabilities: make([]Capability, 0),
        Entitlements: make([]*EntitlementView, 0),
    }

    // Group entitlements by resource type
    resourceActions := make(map[string][]string)

    for _, ent := range entitlements {
        // Add to entitlements list
        entView := &EntitlementView{
            ID:          ent.Id,
            Name:        ent.Name,
            Description: ent.Description,
            Actions:     ent.Actions,
        }
        if ent.ExpiresAt != nil {
            entView.ExpiresAt = ent.ExpiresAt.AsTime().Format("2006-01-02")
        }
        dashboard.Entitlements = append(dashboard.Entitlements, entView)

        // Group by resource for capabilities
        resourceType := getResourceType(ent)
        resourceActions[resourceType] = append(resourceActions[resourceType], ent.Actions...)
    }

    // Build capabilities from grouped actions
    for resource, actions := range resourceActions {
        dashboard.Capabilities = append(dashboard.Capabilities, Capability{
            Resource: resource,
            Actions:  deduplicate(actions),
        })
    }

    return dashboard
}
```

### Example Dashboard Response

```json
{
  "user": "user123",
  "capabilities": [
    {
      "resource": "document",
      "actions": ["read", "write", "delete"]
    },
    {
      "resource": "project",
      "actions": ["read", "create"]
    }
  ],
  "entitlements": [
    {
      "id": "ent-123",
      "name": "Engineering Document Access",
      "description": "Read/write access to engineering documents",
      "actions": ["read", "write"],
      "expires_at": "2025-12-31"
    },
    {
      "id": "ent-456",
      "name": "Senior Engineer Privileges",
      "description": "Additional privileges for senior engineers",
      "actions": ["delete"],
      "expires_at": ""
    }
  ]
}
```

## Example 3: Batch Authorization Check

### Scenario: List Documents with Access Filtering

```go
// ListDocumentsHandler returns documents the user can access
func (api *DocumentAPI) ListDocumentsHandler(w http.ResponseWriter, r *http.Request) {
    ctx := r.Context()

    // Extract user claims
    userClaims := extractUserClaims(r)
    subjectAttributes, _ := convertToValueMap(userClaims)

    // Fetch all documents (or a page)
    allDocs, err := api.fetchAllDocuments(ctx)
    if err != nil {
        http.Error(w, "failed to fetch documents", http.StatusInternalServerError)
        return
    }

    // Filter documents based on access
    accessibleDocs := make([]*Document, 0)

    for _, doc := range allDocs {
        // Check access for each document
        resourceAttributes := map[string]string{
            "resource_type":  "document",
            "classification": doc.Classification,
            "department":     doc.Department,
        }

        req := &platform.GetDecisionRequest{
            SubjectAttributes:  subjectAttributes,
            ResourceAttributes: resourceAttributes,
            Action:             "read",
            Context:            map[string]string{},
        }

        resp, err := api.platformClient.GetDecision(ctx, req)
        if err != nil {
            // Log error but continue
            continue
        }

        if resp.Decision == platform.Decision_ALLOW {
            accessibleDocs = append(accessibleDocs, doc)
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(accessibleDocs)
}
```

## Example 4: Middleware for Route Protection

```go
// ABACMiddleware enforces ABAC at the middleware level
func (api *DocumentAPI) ABACMiddleware(requiredAction string, extractResource func(*http.Request) map[string]string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            ctx := r.Context()

            // Extract user claims
            userClaims := extractUserClaims(r)
            if userClaims == nil {
                http.Error(w, "unauthorized", http.StatusUnauthorized)
                return
            }

            subjectAttributes, _ := convertToValueMap(userClaims)

            // Extract resource attributes
            resourceAttributes := extractResource(r)

            // Check access
            req := &platform.GetDecisionRequest{
                SubjectAttributes:  subjectAttributes,
                ResourceAttributes: resourceAttributes,
                Action:             requiredAction,
                Context:            map[string]string{},
            }

            resp, err := api.platformClient.GetDecision(ctx, req)
            if err != nil || resp.Decision != platform.Decision_ALLOW {
                reason := "access denied"
                if resp != nil {
                    reason = resp.Reason
                }
                http.Error(w, reason, http.StatusForbidden)
                return
            }

            // Access granted - continue to handler
            next.ServeHTTP(w, r)
        })
    }
}

// Usage example:
func (api *DocumentAPI) SetupRoutes(mux *http.ServeMux) {
    // Protect document routes with ABAC middleware
    documentResource := func(r *http.Request) map[string]string {
        return map[string]string{
            "resource_type": "document",
            "document_id":   r.URL.Query().Get("id"),
        }
    }

    mux.Handle("/api/documents",
        api.ABACMiddleware("read", documentResource)(
            http.HandlerFunc(api.GetDocumentHandler),
        ),
    )
}
```

## Policies and Entitlements Configuration

To enable the examples above, you need to configure policies and entitlements in the Platform Service. This section shows how to create the necessary ABAC rules.

### Entitlements for Document Access

Entitlements define what actions a subject can perform on resources. Here are the entitlements needed for the examples:

#### 1. Engineering Document Access (Read/Write)

```json
{
  "id": "ent-eng-doc-rw",
  "name": "Engineering Document Access",
  "description": "Read/write access to engineering documents",
  "actions": ["read", "write"],
  "subject_conditions": [
    {
      "attribute": "department",
      "operator": "equals",
      "value": "engineering"
    },
    {
      "attribute": "roles",
      "operator": "contains",
      "value": "engineer"
    }
  ],
  "resource_conditions": [
    {
      "attribute": "resource_type",
      "operator": "equals",
      "value": "document"
    },
    {
      "attribute": "department",
      "operator": "equals",
      "value": "engineering"
    }
  ],
  "context_conditions": [],
  "expires_at": "2025-12-31T23:59:59Z"
}
```

#### 2. Senior Engineer Delete Privileges

```json
{
  "id": "ent-senior-eng-delete",
  "name": "Senior Engineer Delete Privileges",
  "description": "Delete privileges for senior engineers",
  "actions": ["delete"],
  "subject_conditions": [
    {
      "attribute": "roles",
      "operator": "contains",
      "value": "senior-engineer"
    }
  ],
  "resource_conditions": [
    {
      "attribute": "resource_type",
      "operator": "equals",
      "value": "document"
    }
  ],
  "context_conditions": [],
  "expires_at": null
}
```

#### 3. Clearance-Based Document Access

```json
{
  "id": "ent-clearance-access",
  "name": "Clearance-Based Document Access",
  "description": "Access documents based on security clearance level",
  "actions": ["read"],
  "subject_conditions": [
    {
      "attribute": "clearance",
      "operator": "in",
      "value": ["confidential", "secret", "top-secret"]
    }
  ],
  "resource_conditions": [
    {
      "attribute": "resource_type",
      "operator": "equals",
      "value": "document"
    },
    {
      "attribute": "classification",
      "operator": "hierarchical_match",
      "value": "clearance"
    }
  ],
  "context_conditions": [],
  "expires_at": null
}
```

#### 4. Document Owner Full Access

```json
{
  "id": "ent-owner-full-access",
  "name": "Document Owner Full Access",
  "description": "Document owners have full control over their documents",
  "actions": ["read", "write", "delete", "share"],
  "subject_conditions": [],
  "resource_conditions": [
    {
      "attribute": "resource_type",
      "operator": "equals",
      "value": "document"
    },
    {
      "attribute": "owner",
      "operator": "equals_subject",
      "value": "sub"
    }
  ],
  "context_conditions": [],
  "expires_at": null
}
```

### JSON Policies for Simple Rules

For straightforward authorization rules, JSON policies provide a simple, declarative format:

#### 1. Admin Document Access (JSON)

```json
{
  "rules": [
    {
      "id": "allow-admin-full-access",
      "description": "Administrators have full access to all documents",
      "effect": "allow",
      "subject": {
        "role": {
          "operator": "equals",
          "value": "admin"
        }
      },
      "resource": {
        "type": {
          "operator": "equals",
          "value": "document"
        }
      },
      "action": {
        "operator": "in",
        "value": ["read", "write", "delete", "share"]
      }
    }
  ],
  "combineRules": "first-applicable",
  "version": "1"
}
```

#### 2. Department-Based Access (JSON)

```json
{
  "rules": [
    {
      "id": "allow-same-department-read",
      "description": "Users can read documents from their own department",
      "effect": "allow",
      "subject": {
        "department": {
          "operator": "equals",
          "value": "{{resource.department}}"
        }
      },
      "resource": {
        "type": {
          "operator": "equals",
          "value": "document"
        }
      },
      "action": {
        "operator": "equals",
        "value": "read"
      }
    },
    {
      "id": "allow-engineer-write",
      "description": "Engineers can write documents in their department",
      "effect": "allow",
      "subject": {
        "role": {
          "operator": "contains",
          "value": "engineer"
        },
        "department": {
          "operator": "equals",
          "value": "{{resource.department}}"
        }
      },
      "resource": {
        "type": {
          "operator": "equals",
          "value": "document"
        }
      },
      "action": {
        "operator": "in",
        "value": ["read", "write"]
      }
    }
  ],
  "combineRules": "deny-overrides",
  "version": "1"
}
```

#### 3. Clearance-Based Access (JSON)

```json
{
  "rules": [
    {
      "id": "allow-clearance-level",
      "description": "Users with sufficient clearance can access documents",
      "effect": "allow",
      "subject": {
        "clearance": {
          "operator": "in",
          "value": ["confidential", "secret", "top-secret"]
        }
      },
      "resource": {
        "type": {
          "operator": "equals",
          "value": "document"
        },
        "classification": {
          "operator": "hierarchical_match",
          "value": "{{subject.clearance}}"
        }
      },
      "action": {
        "operator": "equals",
        "value": "read"
      }
    }
  ],
  "combineRules": "first-applicable",
  "version": "1"
}
```

### OPA Policies for Advanced Rules

For more complex authorization logic, use OPA policies. Here's an OPA policy that implements the document access rules:

#### Document Access Policy (Rego)

```rego
package stratium.document

import future.keywords.if
import future.keywords.in

# Default deny
default allow = false

# Classification hierarchy
classification_levels := {
    "unclassified": 0,
    "confidential": 1,
    "secret": 2,
    "top-secret": 3
}

# Allow if user's clearance is >= document classification
allow if {
    input.action == "read"
    input.resource.resource_type == "document"
    user_clearance := classification_levels[lower(input.subject.clearance)]
    doc_classification := classification_levels[lower(input.resource.classification)]
    user_clearance >= doc_classification
}

# Allow if user is in the same department and has engineer role
allow if {
    input.action in ["read", "write"]
    input.resource.resource_type == "document"
    input.subject.department == input.resource.department
    "engineer" in input.subject.roles
}

# Allow if user is the document owner
allow if {
    input.resource.resource_type == "document"
    input.resource.owner == input.subject.sub
}

# Allow senior engineers to delete documents in their department
allow if {
    input.action == "delete"
    input.resource.resource_type == "document"
    "senior-engineer" in input.subject.roles
    input.subject.department == input.resource.department
}

# Time-based access control (business hours only for certain classifications)
allow if {
    input.action == "read"
    input.resource.classification == "secret"
    input.context.time_of_day >= "09:00"
    input.context.time_of_day <= "17:00"
    user_has_clearance
}

# Helper rules
user_has_clearance if {
    input.subject.clearance in ["secret", "top-secret"]
}

# Deny access from certain IP ranges
deny_ip_ranges := ["192.168.100.0/24", "10.0.0.0/8"]

deny if {
    some ip_range in deny_ip_ranges
    net.cidr_contains(ip_range, input.context.client_ip)
}

# Final decision (explicit deny overrides allow)
decision := "allow" if {
    allow
    not deny
}

decision := "deny" if {
    not allow
}

decision := "deny" if {
    deny
}
```

### Policy Registration via Platform Service API

To register these policies and entitlements, use the Platform Service gRPC API:

#### Registering an Entitlement

```go
func registerEntitlements(client platform.PlatformServiceClient) error {
    ctx := context.Background()

    // Engineering Document Access entitlement
    entitlement := &platform.Entitlement{
        Id:          "ent-eng-doc-rw",
        Name:        "Engineering Document Access",
        Description: "Read/write access to engineering documents",
        Actions:     []string{"read", "write"},
        SubjectConditions: []*platform.Condition{
            {
                Attribute: "department",
                Operator:  platform.Operator_EQUALS,
                Value:     structpb.NewStringValue("engineering"),
            },
            {
                Attribute: "roles",
                Operator:  platform.Operator_CONTAINS,
                Value:     structpb.NewStringValue("engineer"),
            },
        },
        ResourceConditions: []*platform.Condition{
            {
                Attribute: "resource_type",
                Operator:  platform.Operator_EQUALS,
                Value:     structpb.NewStringValue("document"),
            },
            {
                Attribute: "department",
                Operator:  platform.Operator_EQUALS,
                Value:     structpb.NewStringValue("engineering"),
            },
        },
        ContextConditions: []*platform.Condition{},
        ExpiresAt:         timestamppb.New(time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)),
    }

    _, err := client.RegisterEntitlement(ctx, &platform.RegisterEntitlementRequest{
        Entitlement: entitlement,
    })
    if err != nil {
        return fmt.Errorf("failed to register entitlement: %w", err)
    }

    log.Printf("Entitlement registered: %s", entitlement.Name)
    return nil
}
```

#### Registering an OPA Policy

```go
func registerOPAPolicy(client platform.PlatformServiceClient) error {
    ctx := context.Background()

    // Read the OPA policy from file
    policyContent, err := os.ReadFile("policies/document-access.rego")
    if err != nil {
        return fmt.Errorf("failed to read policy file: %w", err)
    }

    policy := &platform.Policy{
        Id:          "policy-document-access",
        Name:        "Document Access Policy",
        Description: "OPA policy for document access control",
        PolicyType:  platform.PolicyType_POLICY_TYPE_OPA,
        Content:     string(policyContent),
        Enabled:     true,
        Priority:    100, // Higher priority policies are evaluated first
        Metadata: map[string]string{
            "resource_type": "document",
            "version":       "1.0",
        },
    }

    _, err = client.RegisterPolicy(ctx, &platform.RegisterPolicyRequest{
        Policy: policy,
    })
    if err != nil {
        return fmt.Errorf("failed to register policy: %w", err)
    }

    log.Printf("OPA policy registered: %s", policy.Name)
    return nil
}
```

### Complete Setup Script

Here's a complete setup script that registers all necessary policies and entitlements:

```go
package main

import (
    "context"
    "log"
    "time"

    "stratium/services/platform"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
    "google.golang.org/protobuf/types/known/structpb"
    "google.golang.org/protobuf/types/known/timestamppb"
)

func main() {
    // Connect to Platform Service
    conn, err := grpc.NewClient("localhost:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
    if err != nil {
        log.Fatalf("Failed to connect: %v", err)
    }
    defer conn.Close()

    client := platform.NewPlatformServiceClient(conn)

    // Register entitlements
    if err := registerAllEntitlements(client); err != nil {
        log.Fatalf("Failed to register entitlements: %v", err)
    }

    // Register OPA policies
    if err := registerAllPolicies(client); err != nil {
        log.Fatalf("Failed to register policies: %v", err)
    }

    log.Println("ABAC configuration completed successfully")
}

func registerAllEntitlements(client platform.PlatformServiceClient) error {
    ctx := context.Background()

    entitlements := []*platform.Entitlement{
        // Engineering Document Access
        {
            Id:          "ent-eng-doc-rw",
            Name:        "Engineering Document Access",
            Description: "Read/write access to engineering documents",
            Actions:     []string{"read", "write"},
            SubjectConditions: []*platform.Condition{
                {
                    Attribute: "department",
                    Operator:  platform.Operator_EQUALS,
                    Value:     structpb.NewStringValue("engineering"),
                },
            },
            ResourceConditions: []*platform.Condition{
                {
                    Attribute: "resource_type",
                    Operator:  platform.Operator_EQUALS,
                    Value:     structpb.NewStringValue("document"),
                },
                {
                    Attribute: "department",
                    Operator:  platform.Operator_EQUALS,
                    Value:     structpb.NewStringValue("engineering"),
                },
            },
            ExpiresAt: timestamppb.New(time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC)),
        },
        // Senior Engineer Delete Privileges
        {
            Id:          "ent-senior-eng-delete",
            Name:        "Senior Engineer Delete Privileges",
            Description: "Delete privileges for senior engineers",
            Actions:     []string{"delete"},
            SubjectConditions: []*platform.Condition{
                {
                    Attribute: "roles",
                    Operator:  platform.Operator_CONTAINS,
                    Value:     structpb.NewStringValue("senior-engineer"),
                },
            },
            ResourceConditions: []*platform.Condition{
                {
                    Attribute: "resource_type",
                    Operator:  platform.Operator_EQUALS,
                    Value:     structpb.NewStringValue("document"),
                },
            },
        },
        // Document Owner Full Access
        {
            Id:          "ent-owner-full-access",
            Name:        "Document Owner Full Access",
            Description: "Document owners have full control",
            Actions:     []string{"read", "write", "delete", "share"},
            ResourceConditions: []*platform.Condition{
                {
                    Attribute: "resource_type",
                    Operator:  platform.Operator_EQUALS,
                    Value:     structpb.NewStringValue("document"),
                },
            },
        },
    }

    for _, ent := range entitlements {
        _, err := client.RegisterEntitlement(ctx, &platform.RegisterEntitlementRequest{
            Entitlement: ent,
        })
        if err != nil {
            return err
        }
        log.Printf("Registered entitlement: %s", ent.Name)
    }

    return nil
}

func registerAllPolicies(client platform.PlatformServiceClient) error {
    // Implementation for registering OPA policies
    // Similar to registerOPAPolicy example above
    return nil
}
```

### Testing the Configuration

After registering policies and entitlements, test them using the Platform Service:

```bash
# Test GetDecision for an engineer accessing engineering documents
grpcurl -plaintext -d '{
  "subject_attributes": {
    "sub": {"string_value": "user123"},
    "department": {"string_value": "engineering"},
    "roles": {"list_value": {"values": [{"string_value": "engineer"}]}},
    "clearance": {"string_value": "confidential"}
  },
  "resource_attributes": {
    "resource_type": "document",
    "classification": "confidential",
    "department": "engineering"
  },
  "action": "read"
}' localhost:50051 platform.PlatformService/GetDecision
```

```bash
# Test GetEntitlements for a user
grpcurl -plaintext -d '{
  "subject": {
    "sub": {"string_value": "user123"},
    "department": {"string_value": "engineering"},
    "roles": {"list_value": {"values": [{"string_value": "engineer"}]}}
  },
  "resource_filter": "document"
}' localhost:50051 platform.PlatformService/GetEntitlements
```

```bash
grpcurl -plaintext -d '{
  "subject": {
    "department": {"string_value": "engineering"}
  },
  "action_filter": "read"
}' localhost:50051 platform.PlatformService/GetEntitlements
```

## Key Points

### When to Use GetDecision
- **Real-time authorization checks** for specific actions
- **API endpoint protection** (check before granting access)
- **Fine-grained access control** based on resource attributes
- **Audit logging** of authorization decisions

### When to Use GetEntitlements
- **UI rendering** - show/hide buttons based on permissions
- **Dashboard views** - display what user can access
- **Bulk permission checks** - pre-fetch all permissions
- **Permission discovery** - help users understand their access

### Best Practices

1. **Cache Decisions Appropriately**
   - GetDecision results can be cached for short periods (1-5 minutes)
   - GetEntitlements results can be cached longer (5-15 minutes)
   - Invalidate cache on user attribute changes

2. **Include Rich Context**
   - Add request metadata (IP, user agent, time)
   - Include resource-specific attributes
   - Provide action-specific context

3. **Handle Errors Gracefully**
   - Default to DENY on errors
   - Log authorization failures for audit
   - Return meaningful error messages

4. **Optimize Batch Checks**
   - Use GetEntitlements for bulk filtering
   - Consider async authorization for lists
   - Implement cursor-based pagination

5. **Audit All Decisions**
   - Platform service automatically audits
   - Log application-level details
   - Track authorization patterns