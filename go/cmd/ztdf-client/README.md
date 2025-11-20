# ZTDF Client

A command-line client for creating and managing Zero Trust Data Format (ZTDF) files with integrated encryption and access control.

## Features

- **Keycloak Authentication**: Login and manage JWT tokens for authentication
- **ZTDF Creation**: Encrypt plaintext data and create ZTDF files with wrapped DEKs
- **ZTDF Decryption**: Unwrap DEKs and decrypt ZTDF files with ABAC policy enforcement
- **OpenTDF Compatible**: Implements the OpenTDF specification for interoperability

## Architecture

The ZTDF client integrates with:
- **Keycloak**: For user authentication and JWT token generation
- **Key Access Server (KAS)**: For DEK wrapping/unwrapping with ABAC policy enforcement
- **Platform Service**: For attribute-based access control (ABAC) policy evaluation

## Installation

Build the client:

```bash
cd /Users/benjaminparrish/Development/stratium/go
go build -o ztdf-client ./cmd/ztdf-client
```

## Usage

### 1. Login to Keycloak

First, authenticate with Keycloak to obtain a JWT token. When you are
targeting the local Helm deployment (Minikube, kind, Docker Desktop),
make sure the Key Manager and Key Access services are reachable. The CLI
uses native gRPC, so either port-forward the services directly:

```bash
kubectl port-forward -n stratium svc/stratium-key-manager 50052:50052
kubectl port-forward -n stratium svc/stratium-key-access 50053:50053
```

or expose them through the Envoy ingress/port-forward (e.g.
`grpc.stratium.local:80`). Without one of these options, the default
addresses on `localhost` will refuse the connection.

Now login:

```bash
./ztdf-client login \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --client-id "ztdf-client" \
  --username "user123" \
  --password "mypassword" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

The token will be saved to `~/.ztdf/token.json` and automatically refreshed when needed.

### 2. Create a ZTDF File (Wrap)

Encrypt plaintext and create a ZTDF file:

**From text:**
```bash
./ztdf-client wrap \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --text "This is my sensitive data" \
  --output "data.ztdf" \
  --resource "document-service" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

**From file:**
```bash
./ztdf-client wrap \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --input "plaintext.txt" \
  --output "data.ztdf" \
  --resource "document-service" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

### Local Helm Deployment Quick Start

When following `deployment/helm/LOCAL_DEVELOPMENT.md`, start the provided
port-forward script or forward the Key Manager/Key Access services as
shown above. Then run:

```bash
./ztdf-client wrap \
  --keycloak-url "http://localhost:8080/realms/stratium" \
  --username "<username>" \
  --password "<password>" \
  --resource "pap-api" \
  --input "./samples/hello.txt" \
  --output "./samples/hello.txt.ztdf" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

If you enabled the ingress overlay and mapped
`grpc.stratium.local -> $(minikube ip)`, you can instead point both
addresses at Envoy:

```bash
./ztdf-client wrap \
  --keycloak-url "http://auth.stratium.local/realms/stratium" \
  --username "<username>" \
  --password "<password>" \
  --resource "pap-api" \
  --text "hello from minikube" \
  --km-addr "grpc.stratium.local:80" \
  --kas-addr "grpc.stratium.local:80"
```

Make sure the ingress or `kubectl port-forward` session stays running
while you execute the CLI—otherwise you will see `connection refused`
errors like the one shown at the top of this issue. The Helm chart now
creates a native gRPC listener behind the ingress, so HTTP/2 clients can
use `grpc.stratium.local:80` without going through the gRPC-Web bridge.

### Remote (EKS) Deployment

When accessing the demo EKS cluster, traffic goes through an AWS ALB that
terminates TLS. Point both gRPC addresses at `grpc.demostratium.com:443`
and enable TLS:

```bash
./ztdf-client wrap \
  --keycloak-url "https://auth.demostratium.com/realms/stratium" \
  --username "<username>" \
  --password "<password>" \
  --resource "pap-api" \
  --input "./samples/hello.txt" \
  --output "./samples/hello.txt.ztdf" \
  --km-addr "grpc.demostratium.com:443" \
  --kas-addr "grpc.demostratium.com:443" \
  --use-tls
```

### 3. Decrypt a ZTDF File (Unwrap)

Decrypt a ZTDF file and extract the plaintext:

**Print to stdout:**
```bash
./ztdf-client unwrap data.ztdf \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --resource "document-service" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

**Save to file:**
```bash
./ztdf-client unwrap data.ztdf \
  --keycloak-url "https://keycloak.example.com/realms/myrealm" \
  --resource "document-service" \
  --save "decrypted.txt" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053"
```

## Global Flags

- `--keycloak-url`: Keycloak issuer URL (required)
- `--client-id`: Keycloak client ID (default: "ztdf-client")
- `--client-secret`: Keycloak client secret (optional)
- `--username`: Username for authentication
- `--password`: Password for authentication
- `--token-file`: Path to store/load token (default: `~/.ztdf/token.json`)
- `--km-addr`: Key Manager Server address (default: "localhost:50052")
- `--kas-addr`: Key Access Server address (default: "localhost:50053")
- `--use-tls`: Enable TLS when connecting to the Key Manager and Key Access servers (required when the endpoints are exposed through HTTPS load balancers)
- `--verbose, -v`: Verbose output

## How It Works

### Wrap (Create ZTDF)

1. **Generate DEK**: A random 256-bit AES key is generated
2. **Encrypt Payload**: The plaintext is encrypted with AES-256-GCM using the DEK
3. **Create Policy**: A ZTDF policy is created with data attributes
4. **Calculate Policy Binding**: HMAC(DEK, Base64(policy)) is computed to prevent tampering
5. **Wrap DEK**: The DEK is sent to the Key Access Server, which:
   - Authenticates the user via JWT token
   - Evaluates ABAC policies (subject=JWT, resource=specified, action=wrap_dek)
   - Wraps the DEK with the service encryption key
6. **Create Manifest**: A manifest is created with encryption metadata
7. **Package ZTDF**: The manifest and encrypted payload are packaged into a ZIP file

### Unwrap (Decrypt ZTDF)

1. **Load ZTDF**: The ZIP file is opened and manifest + payload are extracted
2. **Extract Wrapped Key**: The wrapped DEK is retrieved from the manifest
3. **Unwrap DEK**: The wrapped DEK is sent to the Key Access Server, which:
   - Authenticates the user via JWT token
   - Evaluates ABAC policies (subject=JWT, resource=specified, action=unwrap_dek)
   - Unwraps the DEK using the service private key
   - Re-encrypts the DEK for the subject (or returns plaintext for demo)
4. **Verify Policy Binding**: HMAC verification ensures the policy wasn't tampered with
5. **Decrypt Payload**: The encrypted payload is decrypted using AES-256-GCM with the DEK
6. **Verify Integrity**: SHA-256 hash verification ensures payload wasn't modified
7. **Return Plaintext**: The decrypted plaintext is returned to the user

## ZTDF Structure

A ZTDF file is a ZIP archive containing:

### manifest.json
```json
{
  "assertions": [...],
  "encryptionInformation": {
    "type": "SPLIT",
    "keyAccess": [{
      "type": "WRAPPED",
      "url": "localhost:50053",
      "protocol": "KAS",
      "wrappedKey": "base64-encoded-wrapped-dek",
      "policyBinding": {
        "alg": "HS256",
        "hash": "base64-encoded-hmac"
      }
    }],
    "method": {
      "algorithm": "AES-256-GCM",
      "iv": "base64-encoded-iv"
    },
    "integrityInformation": {...},
    "policy": "base64-encoded-policy"
  },
  "payload": {
    "type": "reference",
    "url": "0.payload",
    "protocol": "zip",
    "isEncrypted": true
  }
}
```

### 0.payload
Binary encrypted payload (AES-256-GCM ciphertext)

## Security Features

- **Zero Trust**: Access control is enforced at unwrap time by the KAS
- **Attribute-Based Access Control**: Policies evaluate subject, resource, action, and context
- **Policy Binding**: HMAC prevents policy tampering after ZTDF creation
- **Integrity Verification**: SHA-256 hashes ensure payload hasn't been modified
- **Token Management**: JWT tokens are securely stored and automatically refreshed

## Environment Variables

Instead of command-line flags, you can use environment variables:

- `KEYCLOAK_URL`: Keycloak issuer URL
- `KEYCLOAK_CLIENT_ID`: Client ID
- `KEYCLOAK_CLIENT_SECRET`: Client secret
- `KAS_ADDR`: Key Access Server address

## Troubleshooting

### Authentication Failed
- Verify Keycloak URL is correct and accessible
- Check username and password
- Ensure client ID is configured in Keycloak

### Access Denied
- Check that your user has appropriate ABAC policies configured
- Verify the resource name matches the policy
- Check token expiration with `--verbose`

### DEK Wrap/Unwrap Failed
- Ensure Key Access Server is running and accessible
- Verify KAS address with `--kas-addr`
- Check KAS logs for policy evaluation details

## Example Workflow

```bash
# 1. Login
./ztdf-client login \
  --keycloak-url "https://keycloak.example.com/realms/test" \
  --username "user123" \
  --password "secret"

# 2. Create encrypted file
./ztdf-client wrap \
  --keycloak-url "https://keycloak.example.com/realms/test" \
  --text "Confidential business data" \
  --output "confidential.ztdf" \
  --resource "business-docs"

# 3. Decrypt file
./ztdf-client unwrap confidential.ztdf \
  --keycloak-url "https://keycloak.example.com/realms/test" \
  --resource "business-docs"
```

## Development

Run tests:
```bash
go test ./cmd/ztdf-client/...
```

Build:
```bash
go build -o ztdf-client ./cmd/ztdf-client
```

## OpenTDF Compliance

This client implements the OpenTDF/ZTDF specification version 4.0.0, including:
- Manifest structure with assertions, encryption information, and payload reference
- Policy binding using HMAC
- AES-256-GCM payload encryption
- Key Access Protocol (KAS) for DEK wrapping/unwrapping
- Integrity verification using SHA-256

## License

Copyright © 2024 Stratium
