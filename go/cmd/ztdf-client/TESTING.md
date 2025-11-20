# ZTDF Client Testing Guide

This guide explains how to test the ZTDF client with your running services.

## Prerequisites

Before testing, ensure you have the following services running:

1. **Keycloak** - Authentication server
2. **Key Manager Server** - Manages encryption keys
3. **Key Access Server (KAS)** - Wraps/unwraps DEKs with ABAC policy enforcement
4. **Platform Server** - Provides ABAC policy evaluation (optional, KAS has a default client)

## Build the Client

```bash
cd /Users/benjaminparrish/Development/stratium/go
go build -o ztdf-client ./cmd/ztdf-client
```

## Test Scenarios

### Scenario 1: Basic Flow with Mock Authentication

If you're using the mock authentication in the Key Access Server:

```bash
# Create a ZTDF file using mock token
./ztdf-client wrap \
  --keycloak-url "https://mock-issuer.example.com" \
  --text "This is my secret message" \
  --output "test.ztdf" \
  --resource "test-resource" \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy"

# Decrypt the ZTDF file
./ztdf-client unwrap test.ztdf \
  --keycloak-url "https://mock-issuer.example.com" \
  --resource "test-resource" \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy"
```

### Scenario 2: Full Flow with Real Keycloak

```bash
# 1. Login to Keycloak
./ztdf-client login \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --client-id "ztdf-client" \
  --username "user123" \
  --password "yourpassword" \
  --kas-addr "localhost:8081"

# 2. Create encrypted ZTDF
./ztdf-client wrap \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --text "Confidential business data that needs protection" \
  --output "confidential.ztdf" \
  --resource "document-service" \
  --kas-addr "localhost:8081"

# 3. Decrypt ZTDF
./ztdf-client unwrap confidential.ztdf \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --resource "document-service" \
  --kas-addr "localhost:8081"
```

### Scenario 3: File-based Encryption

```bash
# Create a test file
echo "This is a long document with multiple lines
Line 2
Line 3
Confidential information here" > plaintext.txt

# Encrypt the file
./ztdf-client wrap \
  --keycloak-url "https://mock-issuer.example.com" \
  --input plaintext.txt \
  --output document.ztdf \
  --resource "file-storage" \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy"

# Decrypt and save to file
./ztdf-client unwrap document.ztdf \
  --keycloak-url "https://mock-issuer.example.com" \
  --resource "file-storage" \
  --save decrypted.txt \
  --print=false \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy"

# Compare files
diff plaintext.txt decrypted.txt
```

### Scenario 4: Test Access Control

```bash
# Create ZTDF as user123
./ztdf-client wrap \
  --keycloak-url "https://mock-issuer.example.com" \
  --text "Only user123 can read this" \
  --output restricted.ztdf \
  --resource "test-resource" \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy"

# Try to decrypt as different user (should fail if policies are configured)
./ztdf-client unwrap restricted.ztdf \
  --keycloak-url "https://mock-issuer.example.com" \
  --resource "test-resource" \
  --kas-addr "localhost:8081" \
  --username "other-user" \
  --password "dummy"
```

### Scenario 5: Verbose Output

Use `--verbose` flag to see detailed information:

```bash
./ztdf-client wrap \
  --keycloak-url "https://mock-issuer.example.com" \
  --text "Debug mode test" \
  --output debug.ztdf \
  --resource "test-resource" \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy" \
  --verbose

./ztdf-client unwrap debug.ztdf \
  --keycloak-url "https://mock-issuer.example.com" \
  --resource "test-resource" \
  --kas-addr "localhost:8081" \
  --username "user123" \
  --password "dummy" \
  --verbose
```

## Inspecting ZTDF Files

ZTDF files are ZIP archives. You can inspect them:

```bash
# Extract ZTDF contents
unzip -d ztdf-extracted test.ztdf

# View manifest
cat ztdf-extracted/manifest.json | jq .

# View encrypted payload (binary)
ls -lh ztdf-extracted/0.payload
```

## Expected Output

### Successful Wrap
```
Read 24 bytes from input
Using authentication token: eyJhbGciOi...
Key Access Server: localhost:8081
Resource: test-resource
Encrypting payload and wrapping DEK...
✓ Generated DEK: 32 bytes
✓ Encrypted payload: 40 bytes
✓ Wrapped DEK with Key Access Server
Saving ZTDF to test.ztdf...
✓ ZTDF file created successfully! (1234 bytes)

╭─────────────────────────────────────────╮
│  ZTDF Creation Successful!              │
╰─────────────────────────────────────────╯

File: test.ztdf
Resource: test-resource
Plaintext size: 24 bytes
Encrypted size: 40 bytes
```

### Successful Unwrap
```
Loading ZTDF from test.ztdf...
✓ ZTDF loaded successfully
  Encrypted payload: 40 bytes
  Encryption algorithm: AES-256-GCM
Using authentication token: eyJhbGciOi...
Key Access Server: localhost:8081
Resource: test-resource
Unwrapping DEK and decrypting payload...
✓ DEK unwrapped successfully
✓ Payload decrypted successfully
✓ Plaintext size: 24 bytes

╭─────────────────────────────────────────╮
│  ZTDF Decryption Successful!            │
╰─────────────────────────────────────────╯

Plaintext Content:
─────────────────────────────────────────
This is my secret message
─────────────────────────────────────────
```

### Access Denied
```
Loading ZTDF from restricted.ztdf...
✓ ZTDF loaded successfully
Using authentication token: eyJhbGciOi...
Unwrapping DEK and decrypting payload...
Error: failed to unwrap ZTDF: failed to unwrap DEK: access denied: Access denied: user not authorized for resource
```

## Troubleshooting

### "failed to get authentication token"
- Run `ztdf-client login` first to authenticate
- Or provide `--username` and `--password` flags
- Check Keycloak URL is correct

### "failed to connect to key access service"
- Ensure KAS is running on the specified address
- Check `--kas-addr` flag (default: localhost:8081)
- Verify network connectivity

### "access denied"
- Check ABAC policies are configured correctly
- Verify user has access to the specified resource
- Ensure JWT token is valid (not expired)
- Check KAS logs for policy evaluation details

### "policy binding verification failed"
- The ZTDF file may have been tampered with
- The policy in the manifest doesn't match the HMAC
- This is a security feature to prevent policy modification

### "payload integrity verification failed"
- The encrypted payload has been modified
- The file may be corrupted
- Re-create the ZTDF from the original source

## Integration with Other Services

### Starting the Services

1. **Key Manager Server**:
```bash
cd /Users/benjaminparrish/Development/stratium/go
go run ./cmd/key-manager-server
```

2. **Key Access Server**:
```bash
cd /Users/benjaminparrish/Development/stratium/go
go run ./cmd/key-access-server
```

3. **Platform Server** (optional):
```bash
cd /Users/benjaminparrish/Development/stratium/go
go run ./cmd/platform-server
```

### Environment Variables

You can use environment variables instead of flags:

```bash
export KEYCLOAK_URL="https://keycloak.example.com/realms/myrealm"
export KEYCLOAK_CLIENT_ID="ztdf-client"
export KAS_ADDR="localhost:8081"

./ztdf-client wrap --text "Hello" --output test.ztdf --username user123 --password secret
```

## Automated Testing Script

Save this as `test-ztdf.sh`:

```bash
#!/bin/bash
set -e

echo "=== ZTDF Client Test Script ==="

# Configuration
KEYCLOAK_URL="https://mock-issuer.example.com"
KAS_ADDR="localhost:8081"
USERNAME="user123"
PASSWORD="dummy"
RESOURCE="test-resource"

# Test 1: Basic wrap/unwrap
echo ""
echo "Test 1: Basic text wrap/unwrap"
./ztdf-client wrap \
  --keycloak-url "$KEYCLOAK_URL" \
  --text "Test message 123" \
  --output test1.ztdf \
  --resource "$RESOURCE" \
  --kas-addr "$KAS_ADDR" \
  --username "$USERNAME" \
  --password "$PASSWORD"

./ztdf-client unwrap test1.ztdf \
  --keycloak-url "$KEYCLOAK_URL" \
  --resource "$RESOURCE" \
  --kas-addr "$KAS_ADDR" \
  --username "$USERNAME" \
  --password "$PASSWORD" \
  --save test1-decrypted.txt \
  --print=false

if [ "$(cat test1-decrypted.txt)" = "Test message 123" ]; then
  echo "✓ Test 1 PASSED"
else
  echo "✗ Test 1 FAILED"
  exit 1
fi

# Test 2: File wrap/unwrap
echo ""
echo "Test 2: File wrap/unwrap"
echo "Multi-line test file
Line 2
Line 3" > test2-input.txt

./ztdf-client wrap \
  --keycloak-url "$KEYCLOAK_URL" \
  --input test2-input.txt \
  --output test2.ztdf \
  --resource "$RESOURCE" \
  --kas-addr "$KAS_ADDR" \
  --username "$USERNAME" \
  --password "$PASSWORD"

./ztdf-client unwrap test2.ztdf \
  --keycloak-url "$KEYCLOAK_URL" \
  --resource "$RESOURCE" \
  --kas-addr "$KAS_ADDR" \
  --username "$USERNAME" \
  --password "$PASSWORD" \
  --save test2-decrypted.txt \
  --print=false

if diff test2-input.txt test2-decrypted.txt; then
  echo "✓ Test 2 PASSED"
else
  echo "✗ Test 2 FAILED"
  exit 1
fi

# Cleanup
rm -f test1.ztdf test1-decrypted.txt
rm -f test2.ztdf test2-input.txt test2-decrypted.txt

echo ""
echo "=== All tests PASSED ==="
```

Make it executable and run:
```bash
chmod +x test-ztdf.sh
./test-ztdf.sh
```

## Notes

- The client uses mock authentication by default if the Key Access Server can't connect to a real Keycloak instance
- Token files are saved in `~/.ztdf/token.json` by default
- ZTDF files are standard ZIP archives containing `manifest.json` and `0.payload`
- The implementation follows the OpenTDF 4.0.0 specification
