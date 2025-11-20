# Key Access Service

The Key Access Service is a dedicated gRPC service that provides secure Data Encryption Key (DEK) wrapping and unwrapping operations with ABAC (Attribute-Based Access Control) verification.

## Features

- **DEK Wrapping**: Encrypts data encryption keys using the current encryption key from the Key Manager
- **DEK Unwrapping**: Decrypts wrapped DEKs and re-encrypts them with the subject's public key
- **ABAC Integration**: Verifies that subjects have proper entitlements, conditions, and actions before allowing operations
- **Security First**: Only exposes wrap/unwrap endpoints - no key management operations
- **Subject Key Management**: Manages public keys for subjects to enable secure DEK delivery

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client App    │───▶│  Key Access     │───▶│  Key Manager    │
│                 │    │   Service       │    │   Service       │
│                 │    │  (Port 50053)   │    │  (Port 50052)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │ ABAC Evaluator  │
                       │  (Platform)     │
                       └─────────────────┘
```

## API Endpoints

### WrapDEK
Processes a Data Encryption Key that was encrypted with the subject's private key, decrypts it using the subject's public key, then re-encrypts it with the Key Manager's encryption key for secure storage.

**Request:**
- `subject`: The subject requesting the wrap operation
- `resource`: The resource the DEK will protect
- `dek`: The DEK encrypted with the subject's private key
- `key_id`: Optional key ID (not used for encryption, but tracked for auditing)
- `action`: Action being performed (defaults to "wrap_dek")
- `context`: Additional context for ABAC evaluation

**Response:**
- `wrapped_dek`: The DEK encrypted with the Key Manager's encryption key
- `key_id`: The key ID tracked for this operation
- `access_granted`: Whether access was granted
- `access_reason`: Reason for the access decision
- `applied_rules`: ABAC rules that were applied

**Note:** The service accepts a DEK that was encrypted with the subject's private key. It uses the subject's public key to decrypt the DEK, then re-encrypts it with the current Key Manager encryption key for secure storage.

### UnwrapDEK
Unwraps a Data Encryption Key and returns it encrypted with the subject's public key.

**Request:**
- `subject`: The subject requesting the unwrap operation
- `resource`: The resource the DEK protects
- `wrapped_dek`: The encrypted DEK to be unwrapped
- `key_id`: The key ID used for wrapping
- `action`: Action being performed (defaults to "unwrap_dek")
- `context`: Additional context for ABAC evaluation

**Response:**
- `dek_for_subject`: The DEK encrypted with the subject's public key
- `subject_key_id`: The subject's key ID used for encryption
- `access_granted`: Whether access was granted
- `access_reason`: Reason for the access decision
- `applied_rules`: ABAC rules that were applied

## ABAC Rules

The service includes default ABAC rules:

1. **Admin Full Access**: Admin users (`admin456`) have full access to all operations
2. **User DEK Access**: Regular users (`user123`, `test-user`) can wrap/unwrap DEKs for specific resources
3. **Service Account Access**: Service accounts have access to wrap/unwrap operations

## Security Features

1. **Minimal Attack Surface**: Only exposes wrap/unwrap endpoints
2. **ABAC Verification**: All operations require proper authorization
3. **Subject Key Encryption**: Unwrapped DEKs are encrypted with subject's public key
4. **Audit Logging**: All access decisions are logged
5. **Request Validation**: Comprehensive input validation

## Usage

### Starting the Service

```bash
# Start Key Manager first (required dependency)
make run-key-manager-server

# Start Key Access Service
make run-key-access-server
```

### Running the Example Client

```bash
make run-key-access-client
```

### Building

```bash
# Build just the key access service
make build-key-access

# Build all services
make build
```

### Testing

```bash
# Test just the key access service
make test-key-access

# Test all services
make test
```

## Configuration

The service can be configured with the following flags:

- `--port`: Server port (default: 50053)
- `--key-manager`: Key Manager service address (default: "localhost:50052")

## Example Usage

```go
// Connect to the service
conn, err := grpc.NewClient("localhost:50053", grpc.WithTransportCredentials(insecure.NewCredentials()))
client := keyAccess.NewKeyAccessServiceClient(conn)

// Generate a DEK and encrypt it with subject's private key
// (In practice, the client would use their private key to encrypt the DEK)
dek := make([]byte, 32)
rand.Read(dek)
// encryptedDEK := encryptWithPrivateKey(subjectPrivateKey, dek) // Client-side operation

// Wrap the DEK (service decrypts with subject's public key, then re-encrypts with Key Manager key)
wrapResp, err := client.WrapDEK(ctx, &keyAccess.WrapDEKRequest{
    Subject:  "user123",
    Resource: "document-service",
    Dek:      encryptedDEK, // DEK encrypted with subject's private key
    Action:   "wrap_dek",
    Context: map[string]string{
        "department": "engineering",
    },
})

if wrapResp.AccessGranted {
    // The wrapped DEK is now encrypted with the Key Manager's encryption key
    // It can be unwrapped by authorized subjects through the UnwrapDEK operation
    wrappedDek := wrapResp.WrappedDek

    // Optional: UnwrapDEK can be used for key sharing scenarios
    // where you want to decrypt and re-encrypt for another subject
    unwrapResp, err := client.UnwrapDEK(ctx, &keyAccess.UnwrapDEKRequest{
        Subject:    "user123",
        Resource:   "document-service",
        WrappedDek: wrapResp.WrappedDek,
        KeyId:      wrapResp.KeyId,
        Action:     "unwrap_dek",
    })

    if unwrapResp.AccessGranted {
        // DEK is decrypted and re-encrypted with subject's public key
        reEncryptedDek := unwrapResp.DekForSubject
    }
}
```

## Dependencies

- **Key Manager Service**: Must be running for DEK operations
- **gRPC**: Communication protocol
- **Protocol Buffers**: Message serialization

## Ports

- Key Access Service: 50053
- Key Manager Service: 50052 (dependency)
- Platform Service: 50051 (for ABAC in production)