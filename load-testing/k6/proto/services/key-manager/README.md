# Key Manager gRPC Service

A comprehensive gRPC service for managing encryption keys with multiple key provider technologies, automated key rotation, and secure Data Encryption Key (DEK) unwrapping with Attribute-Based Access Control (ABAC) verification.

## Overview

The Key Manager Service provides enterprise-grade key management capabilities with support for multiple key technologies and comprehensive security features:

### Core Features

1. **Multi-Technology Key Providers**
   - Software-defined key pairs (RSA, ECC)
   - Hardware Security Module (HSM) integration
   - Smart card support
   - USB token support

2. **Automated Key Rotation**
   - Time-based rotation policies
   - Usage-based rotation policies
   - Combined rotation policies
   - Retry logic and failure handling

3. **Secure DEK Unwrapping**
   - ABAC-based access control
   - Comprehensive audit logging
   - Subject-based key encryption
   - Context-aware access decisions

4. **Key Management Operations**
   - Create, read, update, delete keys
   - List keys with filtering and pagination
   - Provider-agnostic key operations
   - Comprehensive metadata support

## Service Definition

The service is defined in `key-manager.proto` and provides the following endpoints:

### Key Management
- **CreateKey** - Creates a new encryption key with specified provider
- **GetKey** - Retrieves key information and optionally public key
- **ListKeys** - Lists keys with filtering and pagination support
- **DeleteKey** - Deletes a key (with safety checks)
- **RotateKey** - Manually rotates a key

### DEK Operations
- **UnwrapDEK** - Unwraps a DEK with ABAC verification and re-encrypts for subject

### Provider Management
- **ListProviders** - Lists available key providers
- **GetProviderInfo** - Gets detailed information about a provider

## Project Structure

```
services/key-manager/
├── key-manager.proto           # Protocol Buffer definition
├── README.md                   # This file
└── go/
    ├── key-manager.pb.go       # Generated protobuf code
    ├── key-manager_grpc.pb.go  # Generated gRPC code
    ├── server.go               # Main gRPC server implementation
    ├── server_test.go          # Comprehensive test suite
    ├── provider.go             # Key provider interface
    ├── software_provider.go    # Software key provider
    ├── hsm_provider.go         # HSM key provider
    ├── smartcard_provider.go   # Smart card/USB token provider
    ├── rotation_manager.go     # Automated key rotation
    ├── abac_evaluator.go       # ABAC access control
    ├── dek_service.go          # DEK unwrapping service
    ├── key_store.go            # Key persistence layer
    └── provider_factory.go     # Provider factory
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
       services/key-manager/key-manager.proto
```

### Running the Server

```bash
cd go/services/key-manager
go run ../../cmd/key-manager-server/main.go
```

The server will start on port 50052 by default. You can specify a different port:

```bash
go run ../../cmd/key-manager-server/main.go -port=8080
```

### Running the Example Client

```bash
cd go/services/key-manager
go run ../../cmd/key-manager-client/main.go
```

To connect to a different server address:

```bash
go run ../../cmd/key-manager-client/main.go -addr=localhost:8080
```

### Running Tests

```bash
cd go/services/key-manager
go test -v
```

For benchmarks:

```bash
go test -bench=.
```

## Key Provider Technologies

### 1. Software Provider
- **Type**: `KEY_PROVIDER_TYPE_SOFTWARE`
- **Features**: Pure software key generation and storage
- **Security**: Application-level security
- **Performance**: High performance, low latency
- **Use Cases**: Development, testing, non-critical applications

**Supported Key Types**:
- RSA-2048, RSA-3072, RSA-4096
- ECC-P256, ECC-P384, ECC-P521

### 2. HSM Provider
- **Type**: `KEY_PROVIDER_TYPE_HSM`
- **Features**: Hardware-backed key generation and operations
- **Security**: FIPS 140-2 Level 3/4 compliance
- **Performance**: Medium performance, higher latency
- **Use Cases**: Production environments, regulatory compliance

**Configuration**:
```yaml
hsm_endpoint: "https://hsm.example.com:443"
hsm_user: "key-manager-service"
hsm_slot: "0"
```

### 3. Smart Card Provider
- **Type**: `KEY_PROVIDER_TYPE_SMART_CARD`
- **Features**: Smart card-based key operations
- **Security**: Hardware-backed, tamper-resistant
- **Performance**: Lower performance, user interaction required
- **Use Cases**: High-security environments, user-specific keys

**Configuration**:
```yaml
device_id: "smart-card-reader-1"
pin: "1234"
```

### 4. USB Token Provider
- **Type**: `KEY_PROVIDER_TYPE_USB_TOKEN`
- **Features**: USB token-based key operations
- **Security**: Hardware-backed, portable
- **Performance**: Lower performance, device-dependent
- **Use Cases**: Portable security, development with hardware tokens

**Configuration**:
```yaml
device_id: "usb-token-1"
pin: "test"
```

## Key Rotation

### Rotation Policies

1. **Manual Rotation** (`ROTATION_POLICY_MANUAL`)
   - Keys are rotated only when explicitly requested
   - No automatic scheduling

2. **Time-Based Rotation** (`ROTATION_POLICY_TIME_BASED`)
   - Keys are rotated after a specified time interval
   - Example: Rotate every 90 days

3. **Usage-Based Rotation** (`ROTATION_POLICY_USAGE_BASED`)
   - Keys are rotated after a specified number of operations
   - Example: Rotate after 1,000,000 uses

4. **Combined Rotation** (`ROTATION_POLICY_COMBINED`)
   - Keys are rotated based on either time or usage thresholds
   - First condition met triggers rotation

### Rotation Configuration

```go
createKeyReq := &CreateKeyRequest{
    Name:                 "auto-rotate-key",
    KeyType:              KeyType_KEY_TYPE_RSA_2048,
    ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
    RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
    RotationIntervalDays: 90,      // Rotate every 90 days
    MaxUsageCount:        1000000, // Or after 1M uses
}
```

## ABAC Access Control

### Access Control Rules

The service uses Attribute-Based Access Control (ABAC) to determine access to DEK unwrapping operations. Access decisions are based on:

- **Subject**: The entity requesting access
- **Resource**: The resource being accessed
- **Action**: The operation being performed
- **Context**: Additional attributes (time, location, etc.)

### Default ABAC Rules

1. **Admin Full Access**
   - Subjects with `role=admin` have unlimited access
   - All actions allowed

2. **Business Hours DEK Access**
   - Users can unwrap DEKs during business hours (9 AM - 5 PM)
   - Weekdays only
   - Requires `department` attribute

3. **Service Account Access**
   - Service accounts can access keys with proper environment validation
   - Must have `service_name` and `environment` attributes

4. **Engineering Development Access**
   - Engineering department can access development resources
   - Resources must start with `dev-`

### Custom ABAC Rules

```go
rule := &ABACRule{
    RuleId:             "custom-rule-1",
    Name:               "Custom Access Rule",
    RequiredAttributes: []string{"clearance_level"},
    Conditions: []*Condition{
        {
            Type:     "attribute",
            Operator: "equals",
            Value:    "secret",
            Parameters: map[string]string{
                "attribute": "clearance_level",
            },
        },
    },
    AllowedActions: []string{"unwrap_dek"},
    Enabled:        true,
}
```

## DEK Unwrapping Workflow

1. **Request Validation**
   - Validate required parameters (subject, resource, key_id, encrypted_dek)
   - Set default action if not specified

2. **ABAC Evaluation**
   - Evaluate access rules against request context
   - Return detailed decision with applied rules

3. **Service Key Retrieval**
   - Get the service key used to encrypt the DEK
   - Validate key exists and is active

4. **DEK Decryption**
   - Use the service key to decrypt the DEK
   - Validate decryption operation

5. **Subject Key Lookup**
   - Get the subject's public key for re-encryption
   - Validate subject key exists

6. **DEK Re-encryption**
   - Encrypt the DEK with the subject's public key
   - Return encrypted DEK to subject

7. **Audit Logging**
   - Log all access attempts (successful and failed)
   - Include detailed context and decision reasoning

## API Examples

### Creating a Key

```go
req := &CreateKeyRequest{
    Name:         "production-service-key",
    KeyType:      KeyType_KEY_TYPE_RSA_4096,
    ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_HSM,
    RotationPolicy: RotationPolicy_ROTATION_POLICY_TIME_BASED,
    RotationIntervalDays: 180,
    AuthorizedSubjects: []string{
        "payment-service",
        "user-service",
    },
    AuthorizedResources: []string{
        "payment-data",
        "user-profiles",
    },
    Metadata: map[string]string{
        "environment": "production",
        "compliance":  "pci-dss",
        "cost-center": "engineering",
    },
}

resp, err := client.CreateKey(ctx, req)
```

### Unwrapping a DEK

```go
req := &UnwrapDEKRequest{
    Subject:      "payment-service",
    Resource:     "payment-data",
    EncryptedDek: encryptedDEKBytes,
    KeyId:        serviceKeyID,
    Action:       "unwrap_dek",
    Context: map[string]string{
        "client_ip":     "10.0.1.100",
        "user_agent":    "payment-service/2.1.0",
        "environment":   "production",
        "service_name":  "payment-processor",
    },
}

resp, err := client.UnwrapDEK(ctx, req)
if err != nil {
    log.Fatal(err)
}

if resp.AccessGranted {
    // Use resp.EncryptedDekForSubject
    log.Printf("DEK unwrapped successfully")
} else {
    log.Printf("Access denied: %s", resp.AccessReason)
}
```

### Listing Keys with Filters

```go
req := &ListKeysRequest{
    SubjectFilter:       "payment-service",
    ProviderTypeFilter:  KeyProviderType_KEY_PROVIDER_TYPE_HSM,
    StatusFilter:        KeyStatus_KEY_STATUS_ACTIVE,
    PageSize:            50,
}

resp, err := client.ListKeys(ctx, req)
```

## Testing with grpcurl

You can test the service using `grpcurl`:

```bash
# List available services
grpcurl -plaintext localhost:50052 list

# Create a key
grpcurl -plaintext -d '{
  "name": "test-key",
  "key_type": "KEY_TYPE_RSA_2048",
  "provider_type": "KEY_PROVIDER_TYPE_SOFTWARE",
  "authorized_subjects": ["test-user"],
  "metadata": {"environment": "test"}
}' localhost:50052 key_manager.KeyManagerService/CreateKey

# List providers
grpcurl -plaintext -d '{}' localhost:50052 key_manager.KeyManagerService/ListProviders

# Unwrap DEK
grpcurl -plaintext -d '{
  "subject": "test-user",
  "resource": "test-resource",
  "encrypted_dek": "dGVzdC1lbmNyeXB0ZWQtZGVr",
  "key_id": "your-key-id",
  "context": {"role": "admin"}
}' localhost:50052 key_manager.KeyManagerService/UnwrapDEK
```

## Security Considerations

### Production Deployment

1. **Authentication & Authorization**
   - Implement mutual TLS (mTLS) for client authentication
   - Use JWT tokens for fine-grained authorization
   - Integrate with enterprise identity providers

2. **Network Security**
   - Deploy behind a load balancer with TLS termination
   - Use private networks or VPN for HSM connectivity
   - Implement rate limiting and DDoS protection

3. **Data Protection**
   - Enable encryption at rest for key metadata
   - Use secure key derivation for DEK encryption
   - Implement key escrow for disaster recovery

4. **Monitoring & Alerting**
   - Monitor key usage patterns and anomalies
   - Alert on failed authentication attempts
   - Track key rotation compliance

5. **Compliance**
   - Implement audit trails for regulatory compliance
   - Support key lifecycle management policies
   - Provide data residency controls

### HSM Integration

For production HSM integration:

1. **PKCS#11 Integration**
```go
// Example HSM configuration
hsmConfig := map[string]string{
    "pkcs11_library": "/usr/lib/libCryptoki2_64.so",
    "slot_id":        "0",
    "pin":            os.Getenv("HSM_PIN"),
    "label":          "key-manager-slot",
}
```

2. **Network HSM**
```go
// Example network HSM configuration
networkHSMConfig := map[string]string{
    "server_host":    "hsm.internal.company.com",
    "server_port":    "1792",
    "client_cert":    "/etc/ssl/certs/client.crt",
    "client_key":     "/etc/ssl/private/client.key",
    "ca_cert":        "/etc/ssl/certs/ca.crt",
}
```

## Performance Characteristics

### Benchmarks

Based on benchmark tests with software providers:

- **CreateKey**: ~1,000 operations/second
- **UnwrapDEK**: ~5,000 operations/second
- **GetKey**: ~10,000 operations/second
- **ListKeys**: ~8,000 operations/second

*Note: HSM operations are typically 10-100x slower due to hardware latency*

### Scalability

- **Horizontal Scaling**: Multiple service instances with shared key store
- **Caching**: In-memory caching of frequently accessed keys
- **Connection Pooling**: gRPC connection pooling for HSM providers
- **Async Operations**: Background key rotation and cleanup

## Contributing

1. Make changes to the protocol buffer definition if needed
2. Regenerate Go code: `make generate`
3. Update implementation in relevant provider files
4. Add tests for new functionality
5. Update documentation

## License

This code is part of the Stratium platform and follows the project's licensing terms.