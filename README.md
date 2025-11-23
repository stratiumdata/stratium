# Stratium

**Enterprise-grade Zero Trust Data Format (ZTDF) platform with Attribute-Based Access Control (ABAC)**

Stratium is a comprehensive access control and data protection platform that implements the Zero Trust Data Format specification with advanced attribute-based policy evaluation. It provides fine-grained authorization decisions based on subject attributes, resource attributes, contextual information, and hierarchical classification levels.

## Features

### Core Capabilities

- **Attribute-Based Access Control (ABAC)**: Fine-grained authorization using rich attribute maps
- **Hierarchical Classification Matching**: Automatic evaluation of classification hierarchies (NATO/DoD, Commercial)
- **Zero Trust Data Format (ZTDF) Support**: Native support for ZTDF manifests and encryption
- **Policy Decision Point (PDP)**: Centralized policy evaluation engine with entitlements and policies
- **Key Access Service (KAS)**: Secure key management for ZTDF encryption/decryption
- **Context-Aware Decisions**: Dynamic access control based on request context (IP, time, environment)
- **Multi-Hierarchy Support**: NATO/DoD classification, Commercial sensitivity, and custom hierarchies
- **Audit Logging**: Comprehensive audit trail for all access decisions

### Advanced Features

- **Policy Caching**: In-memory caching with TTL for high-performance policy evaluation
- **Multiple Policy Languages**: Support for JSON policy language with extensible engine architecture
- **Priority-Based Policy Evaluation**: Policies evaluated in priority order with explicit ALLOW/DENY
- **Entitlement Management**: Subject-specific access grants with time-based conditions
- **STANAG 4774 Compliance**: Support for NATO STANAG 4774 TDF specification
- **gRPC API**: High-performance gRPC interface with Protocol Buffers
- **Keycloak Integration**: OAuth2/OIDC authentication and authorization

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Stratium Platform                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐      ┌──────────────────┐            │
│  │  Platform Server │      │   Key Manager    │            │
│  │                  │      │                  │            │
│  │  • GetDecision   │      │  • KEK Storage   │            │
│  │  • Entitlements  │      │  • DEK Service   │            │
│  │  • ABAC Engine   │      │  • HSM Support   │            │
│  └────────┬─────────┘      └────────┬─────────┘            │
│           │                         │                        │
│           │                         │                        │
│  ┌────────▼─────────────────────────▼─────────┐            │
│  │     Policy Decision Point (PDP)             │            │
│  │                                             │            │
│  │  • Entitlement Evaluation                  │            │
│  │  • Policy Engine (JSON/Rego)               │            │
│  │  • Hierarchical Classification Matching     │            │
│  │  • Context Merging                         │            │
│  │  • Audit Logging                           │            │
│  └─────────────────────────────────────────────┘            │
│                                                               │
│  ┌───────────────────────────────────────────┐              │
│  │     ZTDF Validators & Crypto              │              │
│  │                                           │              │
│  │  • Manifest Validation                   │              │
│  │  • Attribute Extraction                  │              │
│  │  • AES-256-GCM Encryption                │              │
│  │  • Hierarchy Matching                    │              │
│  └───────────────────────────────────────────┘              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.21 or later
- PostgreSQL 14+ (for production)
- Docker & Docker Compose (optional, for local development)
- Protocol Buffers compiler (`protoc`) with Go plugins

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/stratium.git
cd stratium

# Install dependencies
cd go
go mod download

# Generate Protocol Buffer code
make proto-gen

# Build the services
make build

# Run tests
make test
```

### Running with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

Services will be available at:
- Platform Server: `localhost:9090` (gRPC)
- Key Manager Server: `localhost:9091` (gRPC)
- Keycloak: `localhost:8080` (HTTP)
- PostgreSQL: `localhost:5432`

## Usage Examples

### Basic Access Decision

```go
import (
    "context"
    pb "stratium/services/platform"
    "google.golang.org/grpc"
)

// Create client
conn, _ := grpc.Dial("localhost:9090", grpc.WithInsecure())
client := pb.NewPlatformServiceClient(conn)

// Make access decision request
req := &pb.GetDecisionRequest{
    SubjectAttributes: map[string]string{
        "sub":        "alice@example.com",
        "role":       "developer",
        "department": "engineering",
    },
    ResourceAttributes: map[string]string{
        "name": "api-gateway",
        "type": "api",
    },
    Action: "read",
    Context: map[string]string{
        "ip_address":  "192.168.1.100",
        "environment": "production",
    },
}

resp, _ := client.GetDecision(context.Background(), req)

if resp.Decision == pb.Decision_DECISION_ALLOW {
    fmt.Printf("Access granted: %s\n", resp.Reason)
} else {
    fmt.Printf("Access denied: %s\n", resp.Reason)
}
```

### Hierarchical Classification (ZTDF)

```go
// SECRET clearance can access CONFIDENTIAL documents
req := &pb.GetDecisionRequest{
    SubjectAttributes: map[string]string{
        "sub":            "user@nato.int",
        "classification": "SECRET",
    },
    ResourceAttributes: map[string]string{
        "classification": "CONFIDENTIAL",
    },
    Action: "read",
}

resp, _ := client.GetDecision(context.Background(), req)
// → ALLOW (hierarchical match: SECRET ≥ CONFIDENTIAL)
```

### ZTDF File Encryption

```go
import "stratium/pkg/ztdf"

// Create ZTDF client
client := ztdf.NewClient("https://kas.example.com")

// Encrypt data
manifest, ciphertext, err := client.Encrypt(plaintext, &ztdf.Policy{
    Attributes: []string{
        "urn:ztdf:nato:classification:secret",
        "urn:ztdf:nato:handling:nato-releasable",
    },
})

// Decrypt data
plaintext, err := client.Decrypt(manifest, ciphertext, userAttributes)
```

## Project Structure

```
stratium/
├── go/                          # Go implementation
│   ├── cmd/                     # Command-line applications
│   │   ├── key-manager-server/  # Key Manager gRPC server
│   │   ├── key-manager-client/  # Key Manager CLI client
│   │   └── ztdf-client/         # ZTDF encryption/decryption CLI
│   ├── services/                # gRPC service implementations
│   │   ├── platform/            # Platform service (GetDecision, Entitlements)
│   │   ├── key-manager/         # Key Manager service (KEK, DEK)
│   │   └── key-access/          # Key Access service (KAS)
│   ├── pkg/                     # Shared packages
│   │   ├── validators/          # ZTDF validators & hierarchy matching
│   │   ├── policy_engine/       # Policy evaluation engines
│   │   ├── crypto/              # Cryptographic operations
│   │   ├── models/              # Data models
│   │   ├── repository/          # Database repositories
│   │   └── auth/                # Authentication & authorization
│   └── config/                  # Configuration management
├── proto/                       # Protocol Buffer definitions
│   └── services/
│       ├── platform/            # Platform service proto
│       ├── key-manager/         # Key Manager service proto
│       └── key-access/          # Key Access service proto
├── docs/                        # Documentation
│   ├── api-attribute-based-access-control.md
│   ├── migration-guide-attribute-based.md
│   ├── ztdf-attribute-conventions.md
│   └── manifest.json            # ZTDF manifest schema
├── deployment/                  # Deployment configurations
│   ├── docker-compose.yml       # Docker Compose setup
│   └── kubernetes/              # Kubernetes manifests
├── keycloak/                    # Keycloak configuration
│   └── realm-export.json        # Realm configuration
└── Makefile                     # Build automation
```

## Configuration

### Environment Variables

#### Platform Server

```bash
# Server configuration
PLATFORM_GRPC_PORT=9090
PLATFORM_ADMIN_KEYS=admin,superuser

# Database
DATABASE_URL=postgres://user:pass@localhost:5432/stratium

# Keycloak
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_REALM=stratium
KEYCLOAK_CLIENT_ID=platform-service
```

#### Key Manager Server

```bash
# Server configuration
KEY_MANAGER_GRPC_PORT=9091
KEY_MANAGER_STORAGE_TYPE=postgres  # or: vault, hsm

# HSM configuration (optional)
HSM_ENABLED=false
HSM_LIBRARY_PATH=/usr/lib/pkcs11/libsofthsm2.so
HSM_PIN=1234
```

## API Reference

### Platform Service

#### GetDecision

Evaluates an access decision request.

**Request**:
```protobuf
message GetDecisionRequest {
    map<string, string> subject_attributes = 1;
    map<string, string> resource_attributes = 2;
    string action = 3;
    map<string, string> context = 4;
    string policy_id = 5;  // Optional
}
```

**Response**:
```protobuf
message GetDecisionResponse {
    Decision decision = 1;          // ALLOW, DENY, CONDITIONAL
    string reason = 2;
    map<string, string> details = 3;
    google.protobuf.Timestamp timestamp = 4;
    string evaluated_policy = 5;
}
```

#### GetEntitlements

Retrieves entitlements for a subject.

**Request**:
```protobuf
message GetEntitlementsRequest {
    map<string, string> subject = 1;
    string resource_filter = 2;     // Optional
    string action_filter = 3;       // Optional
    int32 page_size = 4;
    string page_token = 5;
}
```

See [API Documentation](docs/api-attribute-based-access-control.md) for complete reference.

## Classification Hierarchies

Stratium supports multiple classification hierarchies for hierarchical attribute matching:

### NATO/DoD Hierarchy

```
TOP-SECRET (4)
    ↓
SECRET (3)
    ↓
CONFIDENTIAL (2)
    ↓
RESTRICTED (1)
    ↓
UNCLASSIFIED (0)
```

**Principle**: Higher clearance can access lower classifications

### Commercial Hierarchy

```
HIGHLY-CONFIDENTIAL (4)
    ↓
RESTRICTED (3)
    ↓
CONFIDENTIAL (2)
    ↓
INTERNAL (1)
    ↓
PUBLIC (0)
```

### ZTDF URI Format

```
urn:ztdf:<domain>:<type>:<value>
```

**Examples**:
- `urn:ztdf:nato:classification:secret`
- `urn:ztdf:dod:handling:noforn`
- `urn:ztdf:commercial:sensitivity:confidential`

See [ZTDF Attribute Conventions](docs/ztdf-attribute-conventions.md) for details.

## Development

### Building

```bash
# Build all binaries
make build

# Build specific service
make build-platform
make build-key-manager

# Build with race detector
make build-race
```

### Testing

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific test package
go test ./services/platform/... -v

# Run benchmarks
go test ./pkg/validators/... -bench=.
```

### Code Generation

```bash
# Generate Protocol Buffer code
make proto-gen

# Generate mocks
make mocks

# Format code
make fmt

# Lint code
make lint
```

## Deployment

### Docker Deployment

```bash
# Build Docker images
make docker-build

# Push to registry
make docker-push

# Deploy with Docker Compose
docker-compose -f deployment/docker/docker-compose.yml up -d
```

### Kubernetes Deployment

```bash
# Apply Kubernetes manifests
kubectl apply -f deployment/kubernetes/

# Check deployment status
kubectl get pods -n stratium

# View logs
kubectl logs -f deployment/platform-server -n stratium
```

### Production Considerations

1. **Database**: Use PostgreSQL with connection pooling
2. **TLS**: Enable TLS for all gRPC connections
3. **Authentication**: Configure Keycloak with proper realm settings
4. **HSM**: Use hardware security module for key storage
5. **Monitoring**: Set up Prometheus metrics and Grafana dashboards
6. **Logging**: Configure structured logging with log aggregation
7. **Backup**: Regular database backups and key escrow procedures

## Security

### Authentication

Stratium supports multiple authentication methods:

- **OAuth2/OIDC** via Keycloak
- **mTLS** for service-to-service communication
- **API Keys** for programmatic access

### Authorization

- **Policy-based**: JSON policy language for complex rules
- **Entitlement-based**: Direct subject-resource grants
- **Attribute-based**: ABAC with hierarchical classification
- **Time-based**: Temporal conditions (valid before/after)

### Encryption

- **At-rest**: AES-256-GCM for ZTDF payloads
- **In-transit**: TLS 1.3 for all network communication
- **Key Management**: KEK/DEK architecture with HSM support

### Audit

All access decisions are logged with:
- Subject attributes
- Resource attributes
- Action
- Context
- Decision result
- Timestamp
- Policy evaluated

## Performance

### Benchmarks

```
BenchmarkHierarchyMatcher_MatchesHierarchical/URI_Match-8              5000000    242 ns/op
BenchmarkHierarchyMatcher_MatchesHierarchical/Simplified_Match-8       8000000    198 ns/op
BenchmarkPDP_EvaluateDecision-8                                         100000   12450 ns/op
```

### Optimization Tips

1. **Enable Policy Caching**: Use in-memory cache with appropriate TTL
2. **Connection Pooling**: Configure database connection pools
3. **Batch Requests**: Use batch APIs for multiple decisions
4. **Index Optimization**: Ensure proper database indexes on attribute columns
5. **gRPC Streaming**: Use streaming for bulk operations

## Troubleshooting

### Common Issues

#### Decision Returns DENY When Expected ALLOW

1. Check attribute names match exactly (case-insensitive)
2. Verify classification hierarchy matches
3. Check audit logs for detailed reason
4. Ensure entitlement/policy is enabled and not expired

#### Hierarchical Matching Not Working

1. Verify attribute name is `classification`, `clearance`, or `sensitivity`
2. Check that both values are in the same hierarchy (NATO, DoD, Commercial)
3. Use full URIs or consistent simplified names
4. Review logs for fallback to exact matching

#### Key Manager Connection Failed

1. Verify KEY_MANAGER_GRPC_PORT is correct
2. Check TLS certificates if TLS is enabled
3. Ensure HSM is properly configured (if using HSM)
4. Check network connectivity and firewall rules

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run tests and linters (`make test lint`)
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

## Documentation

- [API Documentation](docs/api-attribute-based-access-control.md) - Complete API reference with examples
- [Migration Guide](docs/migration-guide-attribute-based.md) - Migrating to attribute-based access control
- [ZTDF Conventions](docs/ztdf-attribute-conventions.md) - ZTDF attribute URI conventions and hierarchies
- [Architecture Guide](docs/architecture.md) - System architecture and design decisions
- [Deployment Guide](docs/deployment.md) - Production deployment best practices