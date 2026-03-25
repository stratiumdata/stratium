<!-- Generated: 2026-03-12 | Codemaps Index | Token estimate: ~450 -->

# Stratium Codemaps

**Last Updated:** 2026-03-12

## Overview

Stratium codemaps provide architectural reference documentation for the Zero-Trust Data Format (ZTDF) cryptographic key management platform. These documents capture the structure of services, data models, APIs, and SDKs for developers working with the codebase.

**Goal**: Serve as the single source of truth for code architecture that stays synchronized with the actual implementation.

## Codemaps at a Glance

### 1. Architecture (`architecture.md`)

**Purpose**: System-wide view of services and data flow

**Covers**:
- Service boundaries (Platform, Key Manager, Key Access, PAP)
- gRPC port assignments and entry points
- Data flow for encrypt/decrypt operations
- mTLS certificate structure
- Configuration management

**Audience**: Service operators, system designers, new team members

**Key sections**:
- Service Boundaries diagram
- Data Flow: ZTDF Encryption/Decryption
- mTLS Communication setup

**File sizes**: Go services, config structures

### 2. Backend (`backend.md`)

**Purpose**: Detailed API reference and service implementation

**Covers**:
- gRPC service APIs (protobuf messages)
- RPC method signatures and implementations
- Database schema (inferred)
- Core packages: PolicyDecisionPoint, ZTDF Validators, Auth
- Key management operations

**Audience**: Backend engineers, API integration developers

**Key sections**:
- Platform Service (GetDecision, GetEntitlements)
- Key Manager Service (UnwrapDEK, RotateKey, RegisterClientKey)
- Key Access Service (WrapDEK, UnwrapDEK)
- PAP REST API endpoints
- Database schema and tables

**File paths**: Proto definitions, service implementations

### 3. Data Models (`data.md`)

**Purpose**: Canonical definitions of domain models

**Covers**:
- Go struct definitions (Entitlement, Policy, Manifest)
- Protobuf message types
- Key material models (KEK, DEK)
- Attribute models (Subject, Resource, Context)
- Hierarchical classification (NATO/DoD/Commercial)
- Audit log models

**Audience**: Data modelers, database engineers, API consumers

**Key sections**:
- Core Domain Models (with Go code snippets)
- Key Material (KEK/DEK lifecycle)
- Attribute Models (Standard attributes, URIs)
- Hierarchy Classification (Levels, matching logic)
- Protobuf Message Hierarchy

**Database**: PostgreSQL table schemas (inferred from code)

### 4. Dependencies (`dependencies.md`)

**Purpose**: External dependencies, crypto primitives, security frameworks

**Covers**:
- Go module dependencies (versions)
- Cryptographic primitives (KYBER, RSA, ECC, AES-GCM)
- FIPS 140-3 compliance framework
- Hardware Security Module (HSM) integration
- Smart Card / YubiKey support
- SDK-specific dependencies
- Build tools and version constraints

**Audience**: Security officers, DevOps, SDK maintainers

**Key sections**:
- Critical Runtime Dependencies (gRPC, OIDC, Database)
- Cryptographic Primitives (with algorithm support)
- FIPS 140-3 Framework and constraints
- HSM and YubiKey integration
- SDK dependencies (Java, Python, JavaScript)

**Versions**: See go.mod, gradle, pyproject.toml

### 5. SDKs (`sdks.md`)

**Purpose**: Client library architecture and patterns

**Covers**:
- SDK matrix (Go/Java/Python/JavaScript)
- Client API signatures
- Configuration patterns (OIDC, key storage)
- FIPS mode behavior
- Streaming support
- Cross-SDK compatibility testing
- Common patterns (token management, key store)

**Audience**: SDK users, SDK maintainers, integrators

**Key sections**:
- SDK Matrix (feature comparison)
- Go SDK (with code examples)
- Java SDK (Gradle, BCFIPS integration)
- Python SDK (3.14+, AI/ML support)
- JavaScript SDK (Node.js dual build)
- Common Patterns (OIDC, Key Store, Wrap/Unwrap)

**Locations**: `/sdk/go/`, `/sdk/java/`, `/sdk/python/`, `/sdk/js/`

## Navigation

### By Responsibility

**Service Operator**:
1. Start: `architecture.md` → Understand services and ports
2. Then: `dependencies.md` → Know what's installed
3. Reference: `backend.md` → API endpoints for troubleshooting

**Backend Engineer**:
1. Start: `backend.md` → Understand APIs and implementations
2. Then: `data.md` → Learn domain models
3. Extend: `/go/services/` → Implement new features

**SDK Developer**:
1. Start: `sdks.md` → Learn client patterns
2. Then: `data.md` → Understand data types
3. Test: Cross-SDK compatibility tests in `/sdk/*/integration/`

**Security Officer**:
1. Start: `dependencies.md` → Review security dependencies
2. Then: `architecture.md` → Understand key flow
3. Verify: `/docs/SECURITY_FIPS.md` → FIPS compliance

**DevOps / Infra**:
1. Start: `architecture.md` → Service ports and dependencies
2. Then: `dependencies.md` → Build tools and versions
3. Deploy: `/deployment/docker/`, `/deployment/kubernetes/`

### By Feature

**ZTDF Encryption/Decryption**:
- Flow diagram: `architecture.md`
- APIs: `backend.md` (KAS.WrapDEK, KAS.UnwrapDEK)
- Manifest model: `data.md`
- SDK usage: `sdks.md`

**ABAC Policy Evaluation**:
- Platform Service: `backend.md` (GetDecision RPC)
- Decision model: `data.md`
- Policy engine: Backend.md (PolicyDecisionPoint section)

**Key Management**:
- Key Manager Service: `backend.md` (all operations)
- Key models: `data.md` (KEK, DEK, Key metadata)
- Crypto: `dependencies.md` (algorithms, HSM, YubiKey)

**Hierarchical Classification**:
- Matching logic: `data.md` (Hierarchy section)
- Validators: Backend.md (ZTDF Validators package)
- Examples: `architecture.md`, `data.md`

## File Paths Reference

### Proto Definitions
```
proto/
├── services/
│   ├── platform/platform.proto
│   ├── key-manager/key-manager.proto
│   └── key-access/key-access.proto
└── models/
    ├── ztdf.proto
    └── stanag4774.proto
```

### Service Implementations
```
go/services/
├── platform/server.go
├── key-manager/server.go
├── key-access/server.go
└── pap/server.go
```

### Core Packages
```
go/pkg/
├── validators/       # ZTDF validation, hierarchy matching
├── policy_engine/    # OPA/Rego policy evaluation
├── models/          # Domain models
├── security/        # Encryption, FIPS, TLS
├── auth/            # OIDC, JWT, auth services
└── ztdf/            # ZTDF client SDK
```

### SDKs
```
sdk/
├── go/              # Go SDK (ztdf.Client)
├── java/            # Java SDK (StratiumClient)
├── python/          # Python SDK (StratiumClient)
└── js/              # JavaScript SDK (ZtdfClient)
```

## Codemaps Format

Each codemap follows this structure:

1. **Freshness header**: Generated date, scope, token estimate
2. **Overview**: What this area covers
3. **Diagrams**: ASCII diagrams of structure/flow
4. **Details**: File paths, code signatures, key components
5. **Tables**: API reference or comparison matrices
6. **Related links**: Cross-references to other codemaps

**Token budget**: Each codemap kept under 1000 tokens for AI context efficiency.

## Maintenance

### When to Update Codemaps

**MUST update**:
- New gRPC service added
- New API RPC added/removed
- Data model structure changes
- Major package reorganization
- Crypto algorithm changes
- FIPS constraints change
- New SDK added

**SHOULD update**:
- Service implementation significant refactoring
- New key provider type
- New configuration option
- Documentation links change

**OPTIONAL update**:
- Internal function refactoring
- Bug fixes (non-breaking)
- Code comment improvements

### Update Process

1. Review code changes: `git log --oneline <file>`
2. Update affected codemap(s)
3. Verify file paths exist
4. Check code examples compile
5. Test links (internal cross-references)
6. Update freshness header: `<!-- Generated: YYYY-MM-DD -->`
7. Commit with message: `docs(codemaps): update <area> for <feature>`

### Example Update Checklist

```markdown
- [ ] Code changes understood
- [ ] File paths verified: `ls -la /path/to/file`
- [ ] Code examples reviewed in editor
- [ ] Cross-references still valid
- [ ] Diagrams reflect current state
- [ ] Freshness header updated
- [ ] README.md updated if structure changed
- [ ] Commit message clear and follows conventions
```

## Contributing

When adding new features or services:

1. **Code-first**: Write service code
2. **Proto-second**: Update protobuf definitions
3. **Docs-third**: Update relevant codemaps
   - New service → Update `architecture.md`
   - New RPC → Update `backend.md`
   - New data model → Update `data.md`
   - New dependency → Update `dependencies.md`
   - SDK changes → Update `sdks.md`

## Quick Links

- **Git History**: `git log --oneline docs/CODEMAPS/`
- **Protobuf Compiler**: `make proto-gen` (from `/go/`)
- **Configuration Guide**: `/docs/CONFIGURATION.md`
- **FIPS Compliance**: `/docs/SECURITY_FIPS.md`
- **Deployment**: `/deployment/README.md`
- **Main README**: `/README.md`

## Version History

| Date | Changes |
|------|---------|
| 2026-03-12 | Initial codemaps generated (architecture, backend, data, dependencies, sdks) |

---

**Note**: These codemaps are generated from the actual codebase. If you find discrepancies between codemaps and code, the **code is the source of truth**. Please update the codemaps accordingly.
