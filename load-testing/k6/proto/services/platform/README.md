# Platform gRPC Service

A gRPC service that provides decision-making and entitlement management capabilities for the Stratium platform.

## Overview

The Platform gRPC Service offers two main endpoints:

1. **GetDecision** - Evaluates whether a subject is allowed to perform an action on a resource
2. **GetEntitlements** - Retrieves the entitlements (permissions) for a given subject

## Service Definition

The service is defined in `platform.proto` and provides the following functionality:

### GetDecision

Evaluates access decisions based on:
- Subject (user/service making the request)
- Resource (what is being accessed)
- Action (what operation is being performed)
- Context (additional metadata for decision-making)

Returns:
- Decision (ALLOW, DENY, or CONDITIONAL)
- Reason for the decision
- Additional details
- Evaluated policy information

### GetEntitlements

Retrieves entitlements for a subject with support for:
- Resource filtering
- Action filtering
- Pagination
- Context-based evaluation

Returns:
- List of entitlements
- Pagination tokens
- Total count
- Timestamp information

## Project Structure

```
services/platform/
├── platform.proto           # Protocol Buffer definition
├── README.md                # This file
└── go/
    ├── platform.pb.go       # Generated protobuf code
    ├── platform_grpc.pb.go  # Generated gRPC code
    ├── server.go            # gRPC server implementation
    ├── server_test.go       # Comprehensive tests
    ├── main.go              # Server startup logic
    └── client_example.go    # Example client usage
```

## Getting Started

### Prerequisites

- Go 1.21 or later
- Protocol Buffers compiler (`protoc`)
- Go gRPC plugins

### Installation

1. Install dependencies:
```bash
go mod download
```

2. Generate protobuf code (if needed):
```bash
protoc --go_out=go --go_opt=paths=source_relative \
       --go-grpc_out=go --go-grpc_opt=paths=source_relative \
       services/platform/platform.proto
```

### Running the Server

```bash
cd go/services/platform
go run main.go
```

The server will start on port 50051 by default. You can specify a different port:

```bash
go run main.go -port=8080
```

### Running the Example Client

```bash
cd go/services/platform
go run client_example.go
```

To connect to a different server address:

```bash
go run client_example.go -addr=localhost:8080
```

### Running Tests

```bash
cd go/services/platform
go test -v
```

For benchmarks:

```bash
go test -bench=.
```

## API Examples

### GetDecision Example

```go
req := &platform.GetDecisionRequest{
    Subject:  "user123",
    Resource: "document-service",
    Action:   "read",
    Context: map[string]string{
        "department": "engineering",
    },
}

resp, err := client.GetDecision(ctx, req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Decision: %s\n", resp.Decision.String())
fmt.Printf("Reason: %s\n", resp.Reason)
```

### GetEntitlements Example

```go
req := &platform.GetEntitlementsRequest{
    Subject:        "user123",
    ResourceFilter: "document-service",
    PageSize:       10,
}

resp, err := client.GetEntitlements(ctx, req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Total entitlements: %d\n", resp.TotalCount)
for _, ent := range resp.Entitlements {
    fmt.Printf("Resource: %s, Actions: %v\n", ent.Resource, ent.Actions)
}
```

## Sample Data

The server comes pre-loaded with sample data for testing:

### Users
- **user123**: Regular user with limited entitlements
- **admin456**: Administrator with full access

### Sample Entitlements
- Document service access for user123 (read/write)
- User service access for user123 (read only)
- Full wildcard access for admin456

## Testing with grpcurl

You can test the service using `grpcurl`:

```bash
# List available services
grpcurl -plaintext localhost:50051 list

# Get decision
grpcurl -plaintext -d '{
  "subject": "user123",
  "resource": "document-service",
  "action": "read",
  "context": {"department": "engineering"}
}' localhost:50051 platform.PlatformService/GetDecision

# Get entitlements
grpcurl -plaintext -d '{
  "subject": "user123",
  "page_size": 10
}' localhost:50051 platform.PlatformService/GetEntitlements
```

## Features

### Decision Engine
- Role-based access control (admin privileges)
- Entitlement-based access control
- Condition evaluation (time-based, attribute-based)
- Default deny policy
- Detailed decision reasoning

### Entitlement Management
- Subject-based entitlement retrieval
- Resource and action filtering
- Pagination support
- Condition evaluation
- Metadata support

### Security Features
- Input validation
- Error handling
- Structured logging
- Timestamp tracking

## Configuration

The server supports the following configuration options:

- **Port**: Server port (default: 50051)
- **Log Level**: Logging verbosity
- **Sample Data**: Enable/disable sample data loading

## Production Considerations

This implementation includes sample data and simplified logic for demonstration purposes. For production use, consider:

1. **Database Integration**: Replace in-memory storage with proper databases
2. **Authentication**: Add authentication and authorization middleware
3. **Policy Engine**: Implement a more sophisticated policy evaluation engine
4. **Caching**: Add caching for frequently accessed decisions and entitlements
5. **Monitoring**: Add metrics, tracing, and health checks
6. **Configuration**: Externalize configuration management
7. **Security**: Add TLS, rate limiting, and input sanitization

## Contributing

1. Make changes to the protocol buffer definition if needed
2. Regenerate Go code: `make generate`
3. Update implementation in `server.go`
4. Add tests in `server_test.go`
5. Update documentation

## License

This code is part of the Stratium platform and follows the project's licensing terms.