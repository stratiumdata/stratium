# PRD: Cedar Policy Language Integration

**Status:** Draft
**Author:** Benjamin Parrish
**Date:** 2026-04-02
**Feature Flag:** None (gradual per-policy rollout)

---

## Design Decisions

Key architectural decisions made during PRD development:

| Decision | Choice | Alternatives Considered |
|----------|--------|------------------------|
| Engine role | Peer engine (add alongside OPA/XACML/JSON) | Primary engine (preferred), replacement (migrate away) |
| Classification hierarchy | Cedar entity hierarchy with `in` operator | Attribute-based numeric comparison, hybrid approach |
| Agent authorization | Deferred to later phase | Model delegations in Cedar now, not applicable |
| SDK impact | Server-side evaluation; PAP API + UI get Cedar awareness | SDK policy helpers, client-side evaluation |
| Schema management | Admin-managed via PAP API | Stratium-defined only, schema per namespace |
| PAP features | Full authoring: CRUD + validation + testing + templates | CRUD + validation only, full authoring without templates |
| Entity population | Hybrid (cache static entities + on-the-fly per-request) | Build entirely on-the-fly, dedicated entity store |
| Performance strategy | Per-request compilation | Compile-once evaluate-many, tiered caching |
| ZTDF manifest policy | Cedar policy reference by ID | Embedded Cedar policy, both reference + fallback |
| Migration from OPA | Not in scope for V1 | Documentation guide, CLI migration tool |
| Audit trail | Same as existing audit path | Extend with Cedar-specific fields, separate Cedar audit table |
| Rollout strategy | Gradual per-policy (no global flag) | Single feature flag, shadow mode first |
| Namespace model | Tenant-scoped namespaces | Single namespace, hierarchy-scoped namespaces |
| Action scope | Full operation set (ZTDF + PAP + admin) | ZTDF operations only, ZTDF + PAP operations |
| Testing strategy | TDD with Stratium-specific policy corpus | Unit + integration, unit + integration + conformance |
| V1 feature scope | Core + templates + batch authorization | Core only, core + templates |

---

## 1. Problem Statement

Stratium's current policy engine supports three policy languages: OPA/Rego (production), XACML (basic implementation), and a custom JSON format. While OPA/Rego is powerful, it presents challenges for enterprise customers:

- **Rego is developer-centric** — its Datalog-derived syntax is unfamiliar to security administrators and compliance officers who need to author and audit access policies.
- **No built-in entity hierarchy** — Stratium's classification hierarchies (NATO: TOP-SECRET→UNCLASSIFIED, Commercial: HIGHLY-CONFIDENTIAL→PUBLIC) are implemented in Go code (`HierarchyMatcher`) rather than expressed declaratively in the policy language. Policy and enforcement logic are coupled.
- **No schema validation at authoring time** — OPA policies are validated at evaluation time, not when they are created. Malformed policies can be persisted and only fail at runtime.
- **Limited policy reuse** — OPA has no native concept of policy templates with parameterized placeholders. Customers with hundreds of similar policies must duplicate Rego modules.
- **No formal authorization model** — OPA evaluates arbitrary Rego queries. There is no structured principal/action/resource authorization model enforced by the engine itself.

Cedar addresses all of these gaps. It is a purpose-built authorization policy language created by AWS, with a human-readable syntax, a formal principal/action/resource/context model, schema-based validation at policy creation time, entity hierarchies, and policy templates. A production-ready native Go implementation (`cedar-go` v1.6.0) is available under Apache-2.0.

### Core Principle

> Cedar policies express *who* can do *what* to *which resource* under *what conditions* — using Stratium's domain vocabulary, validated against a schema, with classification hierarchies modeled as first-class entity relationships.

---

## 2. Goals

1. **Add Cedar as a peer policy engine** — implement `CedarEngine` conforming to the existing `PolicyEngine` interface, registered in `EngineFactory` alongside OPA, XACML, and JSON engines.
2. **Model classification hierarchies as Cedar entities** — express NATO/DoD and Commercial classification taxonomies as Cedar entity parent relationships, enabling the `in` operator for clearance checks.
3. **Tenant-scoped namespaces** — each tenant/org gets a Cedar namespace (e.g., `Acme::User::"alice"`) to prevent entity collisions in multi-tenant deployments.
4. **Full PAP authoring experience** — Cedar policy CRUD, schema-based validation, policy testing sandbox, and policy template support via the PAP REST API.
5. **Admin-managed schemas** — administrators upload and edit Cedar schemas via PAP API, with Stratium-provided starter schemas for the ZTDF domain.
6. **Hybrid entity resolution** — cache static entities (org hierarchy, classifications, groups) with on-the-fly construction of request-specific entities (user claims, resource attributes) from JWT and gRPC context.
7. **Full action coverage** — model all platform operations as Cedar actions: ZTDF crypto operations, PAP policy management, and administrative actions.
8. **Cedar policy templates** — support parameterized policy templates that can be instantiated for specific principals/resources via the PAP API.
9. **Batch authorization** — leverage `cedar-go`'s experimental batch authorization API for high-throughput scenarios (bulk entitlement checks).
10. **ZTDF manifest policy references** — ZTDF manifests reference Cedar policies by ID rather than embedding policy text.

### Non-Goals (V1)

- OPA→Cedar migration tooling (customers adopt Cedar for new policies; existing OPA policies continue to work).
- Agent authorization delegation chains in Cedar (deferred to a follow-up PRD once Cedar engine is stable).
- Client-side Cedar evaluation in SDKs (evaluation is server-side only).
- Cedar-specific audit trail fields (Cedar results flow through existing audit path).
- Shadow mode / parallel evaluation with OPA (no comparison infrastructure).
- Compile-once caching (V1 uses per-request compilation; optimization is a fast-follow).

---

## 3. Architecture Overview

### 3.1 Cedar Engine in the Policy Engine Stack

Cedar slots into the existing `PolicyEngine` interface and `EngineFactory`:

```
┌─────────────────────────────────────────────────────────┐
│                    EngineFactory                          │
│                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │OPAEngine │ │XACMLEngine│ │JSONEngine│ │CedarEngine│  │
│  │(rego)    │ │(xml)      │ │(json)    │ │(cedar-go) │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘   │
│                                                          │
│  All implement: Evaluate() | ValidatePolicy() | TestPolicy()│
└─────────────────────────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────┐
│  PolicyDecisionPoint        │
│  (Platform Service :50051)  │
└─────────────────────────────┘
```

### 3.2 Cedar-Specific Components

```
┌─────────────────────────────────────────────────────────────┐
│                     CedarEngine                              │
│                                                              │
│  ┌─────────────────┐  ┌──────────────────┐                  │
│  │ PolicyCompiler   │  │ EntityResolver    │                 │
│  │ • Parse Cedar    │  │ • Cache (static)  │                 │
│  │ • Build PolicySet│  │ • On-the-fly      │                 │
│  │ • Template inst. │  │   (request ctx)   │                 │
│  └─────────────────┘  └──────────────────┘                  │
│                                                              │
│  ┌─────────────────┐  ┌──────────────────┐                  │
│  │ SchemaManager    │  │ BatchEvaluator    │                 │
│  │ • Load schemas   │  │ • Bulk entitle.   │                 │
│  │ • Validate policy│  │ • Experimental    │                 │
│  │ • Admin CRUD     │  │   cedar-go API    │                 │
│  └─────────────────┘  └──────────────────┘                  │
│                                                              │
│  ┌─────────────────┐  ┌──────────────────┐                  │
│  │ NamespaceManager │  │ TemplateManager   │                │
│  │ • Tenant scoping │  │ • Template CRUD   │                │
│  │ • Entity prefixing│ │ • Instantiation   │                │
│  │ • Schema routing │  │ • Linked policies │                │
│  └─────────────────┘  └──────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Data Flow: Cedar Policy Evaluation

```
Client (SDK) → KAS.WrapDEK(policy_id="cedar:policy-123")
                    │
                    ▼
            KAS extracts subject from JWT
                    │
                    ▼
            KAS calls Platform.GetDecision()
                    │
                    ▼
            Platform loads Policy (language="cedar")
                    │
                    ▼
            EngineFactory.GetEngine("cedar") → CedarEngine
                    │
                    ▼
            CedarEngine.Evaluate():
              1. PolicyCompiler: parse Cedar policy text → PolicySet
              2. EntityResolver:
                 a. Load cached entities (classifications, groups, orgs)
                 b. Build request entities (user from JWT, resource from request)
              3. Build cedar.Request{Principal, Action, Resource, Context}
              4. cedar.Authorize(policySet, entities, request)
              5. Map cedar response → EvaluationResult
                    │
                    ▼
            Platform returns GetDecisionResponse
                    │
                    ▼
            KAS wraps/unwraps DEK based on decision
```

### 3.4 Data Flow: ZTDF Manifest with Cedar Policy Reference

```
ZTDF Manifest (existing):
{
  "policy": "base64-encoded-opa-or-json-policy"
}

ZTDF Manifest (with Cedar reference):
{
  "policy_ref": {
    "engine": "cedar",
    "policy_id": "uuid-of-cedar-policy",
    "schema_version": "1.0"
  }
}
```

When KAS receives a manifest with `policy_ref`, it fetches the Cedar policy from the PAP/policy store by ID and evaluates it server-side. The manifest no longer carries embedded policy text for Cedar — the policy lives in the PAP and can be updated without re-encrypting data.

---

## 4. Cedar Entity Model

### 4.1 Namespace Convention

Each tenant gets a Cedar namespace:

```cedar
namespace Acme {
    // All entity types for tenant "Acme" live here
    entity User in [Group, Role] { ... };
    entity Group in [Group] { ... };
    entity Classification in [Classification] { ... };
    ...
}
```

Stratium provides a **base namespace** (`Stratium`) with starter entity types. Tenants extend or override with their own namespace.

### 4.2 Entity Types

#### Principals

```cedar
entity User in [Group, Role] {
    email: String,
    clearance: Classification,
    department: String,
    mfa_enabled: Bool,
};

entity Group in [Group] {
    description: String,
};

entity Role in [Role] {
    permissions: Set<String>,
};

entity ServiceAccount in [Group, Role] {
    service_name: String,
    trust_level: String,
};
```

#### Resources

```cedar
entity Key {
    key_type: String,       // "RSA-2048", "KYBER-768", etc.
    status: String,         // "active", "pending_rotation", etc.
    classification: Classification,
    owner: User,
};

entity Resource {
    classification: Classification,
    compartments: Set<String>,
    caveats: Set<String>,
    domain: String,
};

entity Policy {
    language: String,
    effect: String,
    owner: User,
};

entity Schema {
    version: String,
    namespace: String,
};

entity Entitlement {
    scope: String,
};
```

#### Classification Hierarchy (Cedar Entity Hierarchy)

NATO/DoD hierarchy modeled as Cedar entity parent relationships:

```cedar
entity Classification in [Classification] {
    level: Long,
    hierarchy: String,  // "nato" or "commercial"
};
```

Entity instances with parent relationships:

```
Classification::"UNCLASSIFIED"
  in Classification::"RESTRICTED"
    in Classification::"CONFIDENTIAL"
      in Classification::"SECRET"
        in Classification::"TOP-SECRET"

Classification::"PUBLIC"
  in Classification::"INTERNAL"
    in Classification::"CONFIDENTIAL-COMMERCIAL"
      in Classification::"RESTRICTED-COMMERCIAL"
        in Classification::"HIGHLY-CONFIDENTIAL"
```

This enables policies like:

```cedar
// Anyone with SECRET clearance can access SECRET and below
permit (
    principal,
    action == Action::"UnwrapDEK",
    resource
)
when {
    resource.classification in principal.clearance
};
```

The `in` operator traverses the entity hierarchy — a principal with `Classification::"SECRET"` clearance automatically satisfies checks for `CONFIDENTIAL`, `RESTRICTED`, and `UNCLASSIFIED`.

### 4.3 Actions

Full operation set organized by service:

```cedar
// ZTDF Key Operations
action WrapDEK appliesTo {
    principal: [User, ServiceAccount],
    resource: [Key, Resource],
    context: {
        ip_address: String,
        mfa_verified: Bool,
        request_time: String,
    },
};

action UnwrapDEK appliesTo {
    principal: [User, ServiceAccount],
    resource: [Key, Resource],
    context: { ... },
};

action CreateKey appliesTo {
    principal: [User, ServiceAccount],
    resource: [Key],
};

action RotateKey appliesTo {
    principal: [User, ServiceAccount],
    resource: [Key],
};

action RegisterClientKey appliesTo {
    principal: [User, ServiceAccount],
    resource: [Key],
};

// PAP Policy Management
action CreatePolicy appliesTo {
    principal: [User, ServiceAccount],
    resource: [Policy],
};

action UpdatePolicy appliesTo {
    principal: [User, ServiceAccount],
    resource: [Policy],
};

action DeletePolicy appliesTo {
    principal: [User, ServiceAccount],
    resource: [Policy],
};

action CreateEntitlement appliesTo {
    principal: [User, ServiceAccount],
    resource: [Entitlement],
};

action UpdateEntitlement appliesTo {
    principal: [User, ServiceAccount],
    resource: [Entitlement],
};

action DeleteEntitlement appliesTo {
    principal: [User, ServiceAccount],
    resource: [Entitlement],
};

// Administrative
action ViewAuditLogs appliesTo {
    principal: [User],
    resource: [Resource],
};

action ManageSchemas appliesTo {
    principal: [User],
    resource: [Schema],
};

action RegisterAgent appliesTo {
    principal: [User],
    resource: [Resource],
};

action IssueDelegation appliesTo {
    principal: [User, ServiceAccount],
    resource: [Resource],
};
```

---

## 5. PAP API Extensions

### 5.1 Cedar Schema Management

New REST endpoints on the PAP server:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/cedar/schemas` | Upload a Cedar schema |
| GET | `/api/cedar/schemas` | List all schemas |
| GET | `/api/cedar/schemas/{id}` | Get a schema by ID |
| PUT | `/api/cedar/schemas/{id}` | Update a schema |
| DELETE | `/api/cedar/schemas/{id}` | Delete a schema |
| POST | `/api/cedar/schemas/{id}/validate` | Validate policies against a schema |

### 5.2 Cedar Policy Templates

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/cedar/templates` | Create a policy template |
| GET | `/api/cedar/templates` | List all templates |
| GET | `/api/cedar/templates/{id}` | Get a template by ID |
| PUT | `/api/cedar/templates/{id}` | Update a template |
| DELETE | `/api/cedar/templates/{id}` | Delete a template |
| POST | `/api/cedar/templates/{id}/instantiate` | Create a linked policy from template |

### 5.3 Cedar Policy Testing

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/cedar/test` | Dry-run a Cedar policy against a sample request |
| POST | `/api/cedar/analyze` | Analyze which policies apply to a principal/resource pair |
| POST | `/api/cedar/batch-test` | Batch test multiple requests against a policy set |

### 5.4 Existing Endpoint Updates

The existing `/api/policies` endpoints continue to work. When `language: "cedar"` is specified:
- `POST /api/policies` validates Cedar syntax against the active schema before persisting.
- `POST /api/validation` accepts Cedar policy text and validates against schema.
- `GET /api/policies?language=cedar` filters to Cedar policies only.

---

## 6. Database Changes

### 6.1 New Tables

```sql
-- Cedar schemas (admin-managed)
CREATE TABLE cedar_schemas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace VARCHAR(255) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    schema_content TEXT NOT NULL,           -- Cedar schema in JSON or Cedar format
    schema_format VARCHAR(10) NOT NULL,     -- "json" or "cedar"
    version VARCHAR(50) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    UNIQUE(namespace, name, version)
);

-- Cedar policy templates
CREATE TABLE cedar_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    template_content TEXT NOT NULL,          -- Cedar policy with ?principal/?resource placeholders
    schema_id UUID REFERENCES cedar_schemas(id),
    namespace VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255),
    updated_by VARCHAR(255)
);

-- Template-linked policies (instantiated from templates)
CREATE TABLE cedar_linked_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id UUID NOT NULL REFERENCES cedar_templates(id),
    policy_id UUID NOT NULL REFERENCES policies(id),
    principal_entity VARCHAR(512),           -- e.g., "Acme::User::\"alice\""
    resource_entity VARCHAR(512),            -- e.g., "Acme::Resource::\"doc-123\""
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255)
);

-- Cached Cedar entities (static hierarchy data)
CREATE TABLE cedar_entities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_uid VARCHAR(512) NOT NULL UNIQUE, -- e.g., "Acme::Classification::\"SECRET\""
    entity_type VARCHAR(255) NOT NULL,
    namespace VARCHAR(255) NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}',
    parents JSONB NOT NULL DEFAULT '[]',     -- Array of parent entity UIDs
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cedar_entities_namespace ON cedar_entities(namespace);
CREATE INDEX idx_cedar_entities_type ON cedar_entities(entity_type);
CREATE INDEX idx_cedar_schemas_namespace ON cedar_schemas(namespace, is_active);
```

### 6.2 Existing Table Changes

```sql
-- Add "cedar" to the policies table language constraint
-- (if using CHECK constraint; otherwise handled in application validation)
ALTER TABLE policies
    DROP CONSTRAINT IF EXISTS policies_language_check,
    ADD CONSTRAINT policies_language_check
    CHECK (language IN ('opa', 'xacml', 'json', 'cedar'));

-- Add optional schema_id reference for Cedar policies
ALTER TABLE policies ADD COLUMN schema_id UUID REFERENCES cedar_schemas(id);

-- Add optional template reference
ALTER TABLE policies ADD COLUMN template_id UUID REFERENCES cedar_templates(id);
```

---

## 7. Go Implementation

### 7.1 New Package: `go/pkg/policy_engine/cedar_engine.go`

```go
// CedarEngine implements PolicyEngine for Cedar policies
type CedarEngine struct {
    schemaManager    *CedarSchemaManager
    entityResolver   *CedarEntityResolver
    templateManager  *CedarTemplateManager
    namespaceManager *CedarNamespaceManager
}
```

Key methods:
- `Evaluate()` — parse Cedar policy, resolve entities, build `cedar.Request`, call `cedar.Authorize()`
- `ValidatePolicy()` — parse Cedar policy and validate against the active schema for the namespace
- `TestPolicy()` — evaluate a Cedar policy against test data without persisting

### 7.2 New Package: `go/pkg/cedar/`

Cedar-specific domain logic, separate from the engine interface:

```
go/pkg/cedar/
├── schema_manager.go      // Schema CRUD and validation
├── entity_resolver.go     // Hybrid entity resolution (cache + on-the-fly)
├── entity_cache.go        // In-memory cache for static entities
├── template_manager.go    // Template CRUD and instantiation
├── namespace_manager.go   // Tenant namespace scoping
├── batch_evaluator.go     // Experimental batch authorization
├── hierarchy.go           // Classification hierarchy → Cedar entities
└── mappers.go             // Map Stratium models ↔ Cedar types
```

### 7.3 Model Changes: `go/pkg/models/policy.go`

```go
const (
    PolicyLanguageXACML PolicyLanguage = "xacml"
    PolicyLanguageOPA   PolicyLanguage = "opa"
    PolicyLanguageJSON  PolicyLanguage = "json"
    PolicyLanguageCedar PolicyLanguage = "cedar"  // NEW
)
```

Update `Policy.Validate()` to accept `PolicyLanguageCedar`.

### 7.4 EngineFactory Update: `go/pkg/policy_engine/engine.go`

```go
type EngineFactory struct {
    opaEngine   PolicyEngine
    xacmlEngine PolicyEngine
    jsonEngine  PolicyEngine
    cedarEngine PolicyEngine  // NEW
}

func (f *EngineFactory) GetEngine(language models.PolicyLanguage) (PolicyEngine, error) {
    switch language {
    // ... existing cases ...
    case models.PolicyLanguageCedar:
        return f.cedarEngine, nil
    }
}
```

### 7.5 Dependencies

```
github.com/cedar-policy/cedar-go v1.6.0+
```

Key `cedar-go` APIs used:
- `cedar.NewPolicySet()` / `cedar.Policy.UnmarshalCedar()` — policy parsing
- `cedar.Authorize(policySet, entities, request)` — authorization
- `cedar.NewEntityUID(type, id)` — entity construction
- `cedar.Request{Principal, Action, Resource, Context}` — request building
- `x/exp/batch` — batch authorization (experimental)
- `x/exp/schema` — schema validation (experimental)

---

## 8. Example Cedar Policies for Stratium

### 8.1 Classification-Based Access

```cedar
// Users with sufficient clearance can unwrap DEKs for matching classifications
permit (
    principal is Acme::User,
    action == Acme::Action::"UnwrapDEK",
    resource is Acme::Resource
)
when {
    resource.classification in principal.clearance
};
```

### 8.2 Role-Based Key Management

```cedar
// Key administrators can rotate keys
permit (
    principal is Acme::User in Acme::Role::"key-admin",
    action == Acme::Action::"RotateKey",
    resource is Acme::Key
);

// Only security officers can create keys with TOP-SECRET classification
permit (
    principal is Acme::User in Acme::Role::"security-officer",
    action == Acme::Action::"CreateKey",
    resource is Acme::Key
)
when {
    resource.classification == Acme::Classification::"TOP-SECRET"
};
```

### 8.3 Context-Aware Access

```cedar
// Deny access from non-MFA sessions for classified resources
forbid (
    principal,
    action == Acme::Action::"UnwrapDEK",
    resource
)
when {
    resource.classification in Acme::Classification::"CONFIDENTIAL"
}
unless {
    context.mfa_verified == true
};
```

### 8.4 Policy Template

```cedar
// Template: Grant a specific user access to a specific resource
@id("user-resource-access-template")
permit (
    principal == ?principal,
    action in [Acme::Action::"WrapDEK", Acme::Action::"UnwrapDEK"],
    resource == ?resource
);
```

Instantiated via PAP API:
```json
POST /api/cedar/templates/{template-id}/instantiate
{
    "principal": "Acme::User::\"alice\"",
    "resource": "Acme::Resource::\"project-alpha-docs\""
}
```

### 8.5 Compartmented Access

```cedar
// Users must have matching compartments for compartmented resources
permit (
    principal is Acme::User,
    action == Acme::Action::"UnwrapDEK",
    resource is Acme::Resource
)
when {
    resource.classification in principal.clearance &&
    resource.compartments.containsAll(principal.compartments)
};
```

### 8.6 Meta-Policy: Policy Management

```cedar
// Only policy administrators can create/update policies
permit (
    principal is Acme::User in Acme::Role::"policy-admin",
    action in [
        Acme::Action::"CreatePolicy",
        Acme::Action::"UpdatePolicy",
        Acme::Action::"DeletePolicy"
    ],
    resource is Acme::Policy
);
```

---

## 9. Entity Resolution Strategy

### 9.1 Static Entities (Cached)

Loaded at startup and refreshed on change (DB polling or notification):

| Entity Type | Source | Cache TTL |
|-------------|--------|-----------|
| Classification hierarchy | `cedar_entities` table (seeded from config) | Until schema change |
| Groups | Keycloak groups sync or `cedar_entities` table | 5 minutes |
| Roles | Keycloak roles sync or `cedar_entities` table | 5 minutes |
| Action definitions | Cedar schema | Until schema change |

### 9.2 Request-Specific Entities (On-the-Fly)

Constructed per-request from available context:

| Entity Type | Source |
|-------------|--------|
| User (principal) | JWT claims from `Authorization` header |
| Resource | gRPC request fields (resource attributes, classification) |
| Key | Key metadata from Key Manager (if evaluating key operations) |
| Context | gRPC metadata, request timestamp, client IP, MFA status |

### 9.3 Entity Resolver Pipeline

```
JWT Claims ─────────────────┐
                             │
gRPC Request Fields ────────┤
                             ▼
                    ┌─────────────────┐
                    │  EntityResolver  │
                    │                  │
                    │  1. Build User   │◄── Keycloak claims
                    │  2. Build Resource│◄── Request fields
                    │  3. Load cached  │◄── cedar_entities table
                    │     hierarchy    │
                    │  4. Merge into   │
                    │     EntityMap    │
                    └────────┬────────┘
                             │
                             ▼
                    cedar.EntityMap (complete)
```

---

## 10. Testing Strategy

### 10.1 TDD with Policy Corpus

Build a corpus of Stratium-specific Cedar policies and write tests first:

**Policy corpus categories:**
1. Classification access (NATO hierarchy, Commercial hierarchy, cross-hierarchy denial)
2. Key operations (WrapDEK, UnwrapDEK, CreateKey, RotateKey with various clearances)
3. Context-aware access (MFA requirements, IP restrictions, time-based access)
4. Role-based management (key admin, policy admin, security officer)
5. Compartmented access (compartment matching, caveat enforcement)
6. Deny policies (explicit deny overrides, default deny)
7. Template instantiation (template creation, linking, evaluation)
8. Multi-tenant isolation (cross-namespace denial, namespace scoping)
9. Batch authorization (bulk entitlement checks)
10. Edge cases (empty policy set, missing entities, schema validation failures)

### 10.2 Test Structure

```
go/pkg/policy_engine/cedar_engine_test.go       // CedarEngine interface tests
go/pkg/cedar/schema_manager_test.go              // Schema CRUD and validation
go/pkg/cedar/entity_resolver_test.go             // Entity resolution
go/pkg/cedar/template_manager_test.go            // Template instantiation
go/pkg/cedar/hierarchy_test.go                   // Classification hierarchy modeling
go/pkg/cedar/batch_evaluator_test.go             // Batch authorization
go/services/pap/cedar_handlers_test.go           // PAP REST API integration tests
go/services/platform/cedar_integration_test.go   // End-to-end policy evaluation
testdata/cedar/policies/                         // Policy corpus files
testdata/cedar/schemas/                          // Test schemas
testdata/cedar/entities/                         // Test entity data
```

### 10.3 Coverage Target

80%+ code coverage across all Cedar packages, consistent with project standards.

---

## 11. Implementation Phases

### Phase 1: Core Cedar Engine (2-3 weeks)

1. Add `cedar-go` dependency
2. Add `PolicyLanguageCedar` to models
3. Implement `CedarEngine` (Evaluate, ValidatePolicy, TestPolicy)
4. Register in `EngineFactory`
5. Build classification hierarchy → Cedar entity mapping (`hierarchy.go`)
6. Implement `EntityResolver` with hybrid cache + on-the-fly resolution
7. Write TDD policy corpus (classification access, key operations, deny policies)
8. Integration test with Platform Service `GetDecision`

### Phase 2: Schema and Namespace Management (1-2 weeks)

1. Create `cedar_schemas` table and migration
2. Implement `SchemaManager` (CRUD, validation)
3. Implement `NamespaceManager` (tenant scoping, entity prefixing)
4. Add PAP REST endpoints for schema management
5. Integrate schema validation into policy creation flow
6. Write starter schemas for ZTDF domain

### Phase 3: Templates and PAP Experience (1-2 weeks)

1. Create `cedar_templates` and `cedar_linked_policies` tables
2. Implement `TemplateManager` (CRUD, instantiation)
3. Add PAP REST endpoints for templates
4. Add Cedar policy testing endpoint (dry-run)
5. Add Cedar policy analysis endpoint (which policies apply)
6. Update existing PAP endpoints for Cedar awareness

### Phase 4: Batch Authorization and ZTDF Integration (1 week)

1. Implement `BatchEvaluator` using `cedar-go` experimental batch API
2. Add batch test endpoint to PAP
3. Implement ZTDF manifest `policy_ref` support in KAS
4. Update `WrapDEK`/`UnwrapDEK` to resolve Cedar policy references
5. Create `cedar_entities` table and seed classification hierarchies

### Phase 5: Testing and Hardening (1 week)

1. Complete policy corpus (all 10 categories)
2. Multi-tenant isolation tests
3. Performance benchmarks (per-request compilation latency)
4. Error handling and edge cases
5. Documentation (Cedar policy authoring guide, schema reference, example policies)

---

## 12. Security Considerations

- **Schema validation prevents policy injection** — all Cedar policies are validated against a schema before persistence. Malformed or type-unsafe policies are rejected at creation time.
- **Namespace isolation** — tenant-scoped namespaces prevent cross-tenant entity references. The `NamespaceManager` enforces that policies can only reference entities within their namespace.
- **No embedded policy execution** — Cedar policies are stored server-side and referenced by ID from ZTDF manifests. This prevents clients from injecting arbitrary policy text.
- **Entity integrity** — cached entities are loaded from trusted sources (DB, Keycloak). Request-specific entities are built from authenticated JWT claims only.
- **Deny overrides permit** — Cedar's evaluation model ensures that any `forbid` policy takes precedence over `permit` policies, consistent with zero-trust principles.
- **Audit trail** — all Cedar policy evaluations flow through the existing audit logging path, capturing the decision, evaluated policy, and request context.

---

## 13. Open Questions

1. **cedar-go `x/exp` stability** — The batch authorization and schema validation APIs are experimental. Should we pin to a specific commit or accept the semver-exempt risk?
2. **Entity cache invalidation** — What notification mechanism for cache invalidation? DB polling (simple) vs. PostgreSQL LISTEN/NOTIFY (real-time) vs. application-level pub/sub?
3. **Schema versioning** — when a schema is updated, should existing policies be re-validated? What happens to policies that no longer pass validation?
4. **Multi-hierarchy classification** — can a resource belong to both NATO and Commercial hierarchies simultaneously? How does Cedar model this?
5. **Performance baseline** — what is acceptable latency for per-request Cedar compilation on the KAS hot path? At what point should we invest in compile-once caching?

---

## 14. Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| `github.com/cedar-policy/cedar-go` | v1.6.0+ | Cedar policy evaluation, entity handling, schema support |
| PostgreSQL | existing | Cedar schemas, templates, entities, linked policies |
| Keycloak | existing | JWT claims for User entity construction |
| `cedar-go/x/exp/batch` | experimental | Batch authorization API |
| `cedar-go/x/exp/schema` | experimental | Schema validation |

---

## 15. Success Metrics

1. **Functional** — Cedar policies can be authored, validated, and evaluated through the same `GetDecision` flow as OPA policies.
2. **Correctness** — Classification hierarchy checks via Cedar `in` operator produce identical results to the existing `HierarchyMatcher` for all test cases.
3. **Coverage** — 80%+ test coverage across all Cedar packages.
4. **Latency** — per-request Cedar compilation + evaluation adds <10ms to the KAS wrap/unwrap path for typical policy sets (<100 policies).
5. **Adoption** — PAP API supports full Cedar lifecycle: schema upload, policy CRUD with validation, template instantiation, and dry-run testing.
