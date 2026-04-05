# CLAUDE.md

## Project Overview

Stratium is an enterprise Zero-Trust Data Format (ZTDF) cryptographic key management platform with Attribute-Based Access Control (ABAC). It uses a distributed microservice architecture with gRPC/mTLS inter-service communication and PostgreSQL as the primary data store.

## First Steps Every Session

Before working on any task, read the architectural codemaps to understand the system:

1. **Architecture overview** — `docs/CODEMAPS/architecture.md` (service boundaries, ports, data flow, mTLS)
2. **Backend APIs** — `docs/CODEMAPS/backend.md` (gRPC RPCs, protobuf messages, REST endpoints, core packages)
3. **Data models** — `docs/CODEMAPS/data.md` (Go structs, protobuf types, key material, attribute models, hierarchy classification)
4. **Dependencies** — `docs/CODEMAPS/dependencies.md` (Go modules, crypto primitives, FIPS 140-3, HSM/YubiKey)
5. **SDKs** — `docs/CODEMAPS/sdks.md` (Go/Java/Python/JavaScript client libraries, common patterns)

The codemaps index is at `docs/CODEMAPS/README.md` with navigation guides by role and feature.

## Service Architecture

Four microservices communicate via gRPC with mTLS:

| Service | Port | Purpose |
|---------|------|---------|
| Platform Server | :50051 (gRPC) | ABAC policy evaluation (GetDecision, GetEntitlements) |
| Key Manager | :50052 (gRPC) | KEK/DEK management, key rotation, HSM/YubiKey |
| Key Access Service (KAS) | :50053 (gRPC) | DEK wrap/unwrap with ABAC enforcement |
| PAP Server | :8080 (REST) | Policy and entitlement CRUD via Gin |

## Key File Paths

### Proto definitions
- `proto/services/platform/platform.proto`
- `proto/services/key-manager/key-manager.proto`
- `proto/services/key-access/key-access.proto`

### Service implementations
- `go/services/platform/server.go`
- `go/services/key-manager/server.go`
- `go/services/key-access/server.go`
- `go/services/pap/server.go`

### Core packages
- `go/pkg/validators/` — ZTDF validation, hierarchy matching
- `go/pkg/policy_engine/` — OPA/Rego policy evaluation
- `go/pkg/models/` — Domain models
- `go/pkg/security/` — Encryption, FIPS, TLS
- `go/pkg/auth/` — OIDC, JWT, auth services

### SDKs
- `sdk/go/` — Go SDK (`ztdf.Client`)
- `sdk/java/` — Java SDK (`StratiumClient`)
- `sdk/python/` — Python SDK (`StratiumClient`)
- `sdk/js/` — JavaScript SDK (`ZtdfClient`)

### Configuration
- `go/config/config.go` — Central config struct
- `deployment/docker/` — Docker setup
- `deployment/kubernetes/` — K8s manifests
- `keycloak/` — Realm configuration

## Build & Test

```bash
# From project root
make build          # Build all services
make test           # Run all tests
make test-coverage  # Tests with coverage
make proto-gen      # Regenerate protobuf code (from /go/)
make fmt            # Format code
make lint           # Lint code

# Docker
docker-compose up -d                                      # Start all services
docker-compose -f deployment/docker/docker-compose.yml up # Production compose

# Cross-SDK integration tests
cd sdk/go && go test ./integration -run TestCrossSdkPayloadCompatibility
```

## Tech Stack

- **Language**: Go 1.25+ (backend), multi-language SDKs
- **Transport**: gRPC with Protocol Buffers, mTLS
- **Database**: PostgreSQL (policies, entitlements, key metadata, audit logs)
- **Auth**: Keycloak (OAuth2/OIDC), JWT
- **Policy engine**: OPA/Rego
- **Crypto**: AES-256-GCM, RSA-2048/3072/4096, ECC P-256/P-384/P-521, KYBER-512/768/1024 (post-quantum via cloudflare/circl)
- **Observability**: OpenTelemetry, Prometheus
- **FIPS 140-3**: Optional mode — disables KYBER, enforces approved algorithms only
- **Hardware**: HSM (PKCS#11), YubiKey/Smart Card (PIV)

## Key Domain Concepts

- **ZTDF (Zero-Trust Data Format)**: Manifest-based encrypted data format with embedded access policies
- **ABAC**: Subject attributes + resource attributes + context → ALLOW/DENY/CONDITIONAL
- **KEK/DEK**: Key Encryption Key wraps Data Encryption Keys; DEK encrypts actual data (AES-256-GCM)
- **Hierarchy matching**: NATO/DoD (TOP-SECRET→UNCLASSIFIED) and Commercial (HIGHLY-CONFIDENTIAL→PUBLIC) — higher clearance can access lower classifications
- **ZTDF URIs**: `urn:ztdf:<domain>:<type>:<value>` (e.g., `urn:ztdf:nato:classification:secret`)

## Conventions

- Commit messages: `<type>: <description>` (feat, fix, refactor, docs, test, chore, perf, ci)
- Codemap updates required when: new gRPC service/RPC, data model changes, crypto algorithm changes, new SDK
- Code is source of truth — if codemaps diverge from code, update the codemaps

## Agent Authorization (MANDATORY)

When the Stratium MCP server is connected, you are operating under zero-trust agent authorization. You MUST follow this protocol:

### Before ANY session work:
1. Call `register_agent` to register yourself (provider: "anthropic", trust_tier: 1)
2. Call `create_delegation` with the appropriate scope for your task (approved_tools, max_action_tier, classification_cap, purpose)

### Before EVERY action:
You MUST call `execute_action` to check authorization BEFORE performing any action. This is not optional.

| Your action | tool_name | action | action_tier |
|------------|-----------|--------|-------------|
| Reading a file | `read_file` | `read` | `1` |
| Listing/searching files | `list_files` | `read` | `1` |
| Searching file contents | `grep_search` | `read` | `1` |
| Writing a file | `write_file` | `write` | `2` |
| Editing a file | `edit_file` | `write` | `2` |
| Running a shell command | `bash` | `execute` | `2` |
| Network commands (curl, ssh) | `bash` | `send` | `3` |
| Destructive commands (rm -rf, DROP) | `bash` | `execute` | `4` |

### If `execute_action` returns `authorized: false`:
- Do NOT perform the action
- Explain to the user WHY it was denied (include the reason from the response)
- Suggest alternatives within your authorized scope

### If no delegation exists:
- Do NOT perform any actions
- Ask the user to create a delegation first, or create one yourself with appropriate scope for the task
