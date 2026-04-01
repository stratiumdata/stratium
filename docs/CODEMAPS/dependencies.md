<!-- Generated: 2026-03-28 | External Dependencies & Crypto Primitives | Files scanned: 275 Go | Token estimate: ~850 -->

# Dependencies Codemap

**Last Updated:** 2026-03-28

## Critical Runtime Dependencies

### Go Module Dependencies

**Source**: `/Users/benjaminparrish/Development/stratium/go/go.mod`

**Crypto & TLS**:
- `google.golang.org/grpc` v1.75.0 - gRPC framework
- `google.golang.org/protobuf` v1.36.8 - Protocol Buffers
- `github.com/cloudflare/circl` v1.6.1 - Post-quantum cryptography (KYBER)
- `golang.org/x/crypto` - Standard crypto library
- No explicit TLS lib (uses stdlib crypto/tls)

**OIDC & Authentication**:
- `github.com/coreos/go-oidc/v3` v3.16.0 - OIDC provider
- `github.com/golang-jwt/jwt/v5` v5.3.0 - JWT parsing
- `golang.org/x/oauth2` v0.31.0 - OAuth2 token handling

**Database**:
- `github.com/lib/pq` v1.10.9 - PostgreSQL driver
- `github.com/jmoiron/sqlx` v1.4.0 - SQL utilities

**Policy Engine**:
- `github.com/open-policy-agent/opa` v1.0.0 - OPA/Rego policy evaluation

**Observability**:
- `go.opentelemetry.io/otel` v1.38.0 - Distributed tracing
- `go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc` v0.63.0 - gRPC instrumentation
- `go.opentelemetry.io/otel/exporters/prometheus` v0.55.0 - Prometheus metrics
- `github.com/prometheus/client_golang` v1.20.5 - Prometheus client

**Cache & Cache**:
- `github.com/redis/go-redis/v9` v9.14.0 - Optional Redis caching
- `github.com/alicebob/miniredis/v2` v2.35.0 - In-memory Redis for testing

**CLI & Config**:
- `github.com/spf13/cobra` v1.10.1 - CLI command framework
- `github.com/spf13/viper` v1.18.2 - Configuration management
- `gopkg.in/yaml.v3` v3.0.1 - YAML parsing

**Utilities**:
- `github.com/google/uuid` v1.6.0 - UUID generation
- `github.com/samber/lo` v1.52.0 - Functional utilities
- `github.com/stretchr/testify` v1.11.1 - Testing assertions

**Web Framework** (vendored):
- `third_party/gin/` - Vendored Gin web framework for PAP REST API

**AWS Integration** (optional):
- `github.com/aws/aws-sdk-go-v2` v1.30.5 - AWS SDK
- `github.com/aws/aws-sdk-go-v2/service/secretsmanager` v1.31.1 - AWS Secrets Manager

## Cryptographic Primitives

### Post-Quantum Key Encapsulation

**KYBER Implementation**:
- Package: `/Users/benjaminparrish/Development/stratium/go/pkg/security/encryption/kem/`
- Algorithms:
  - KYBER-512 (128-bit quantum security)
  - KYBER-768 (192-bit quantum security)
  - KYBER-1024 (256-bit quantum security)
- Source: NIST standardized ML-KEM
- Library: `cloudflare/circl` v1.6.1

**FIPS Mode handling** (KYBER disabled in FIPS):
- File: `/Users/benjaminparrish/Development/stratium/go/pkg/security/encryption/kem/kyber_disabled_fips.go`
- In FIPS mode: RSA-only for key wrapping

### Elliptic Curve Cryptography

**Curves supported**:
- P-256 (NIST secp256r1)
- P-384 (NIST secp384r1)
- P-521 (NIST secp521r1)
- Source: stdlib `crypto/ecdsa`

**ECIES usage**:
- Envelope encryption using ECC public keys
- File: `/Users/benjaminparrish/Development/stratium/go/services/key-manager/ecies.go`

### RSA Key Wrapping

**Implementations**:
- RSA-2048 (minimum)
- RSA-3072
- RSA-4096 (recommended)
- Padding: PKCS#1 v1.5 (standard)
- FIPS mode: PKCS#1 v2.1 (OAEP)

**Files**:
- Core: stdlib `crypto/rsa`
- Key management: `/go/services/key-manager/server.go`

### Symmetric Encryption

**AES-256-GCM**:
- Key size: 256 bits
- Mode: Galois/Counter Mode (authenticated encryption)
- IV: 96 bits (random per encryption)
- Authentication tag: 128 bits
- Source: stdlib `crypto/cipher`

**Usage**:
- ZTDF payload encryption
- Key derivation: HKDF with SHA-256

## Security Framework: FIPS 140-3

**Enabled via**: `FIPS_ENABLED=true` environment variable

**Build artifacts**:
- `/Users/benjaminparrish/Development/stratium/go/pkg/security/fipsbuild/`
- `/Users/benjaminparrish/Development/stratium/go/pkg/security/fipsruntime/`

**FIPS constraints**:
- Approved algorithms only (RSA, ECC, AES-256-GCM)
- No KYBER in FIPS mode
- No PKCS#1 v1.5 RSA padding
- DEK sent plaintext over TLS (server-side wrapping disabled)

**Validation**:
- Script: `/Users/benjaminparrish/Development/stratium/scripts/validate_fips_runtime.sh`

## Hardware Security Module (HSM)

**Optional integration**:
- PKCS#11 interface (SoftHSM2, YubiKey, etc.)
- Library path: `HSM_LIBRARY_PATH=/usr/lib/pkcs11/libsofthsm2.so`
- PIN: `HSM_PIN=1234`

**Provider interface**:
- `/Users/benjaminparrish/Development/stratium/go/services/key-manager/server.go`
- `KeyProvider` interface for HSM operations

## Smart Card / YubiKey Support

**YubiKey integration**:
- Files:
  - `/Users/benjaminparrish/Development/stratium/go/pkg/ztdf/yubikey_keymanager.go`
  - `/Users/benjaminparrish/Development/stratium/go/services/key-manager/yubikey_card_reader.go`
  - `/Users/benjaminparrish/Development/stratium/go/services/key-manager/yubikey_card_reader_test.go`

**PIV (Personal Identity Verification)**:
- Slot configuration: `YubiKeySlot=9c` (default: signature key)
- PIN management: `YubiKeyPIN`
- Touch requirement: `YubiKeyRequireTouch=true`

**Tools used**:
- `yubico-piv-tool` (key operations)
- `ykman` (YubiKey Manager)

## SDK Dependencies

### Go SDK

**Base**: `/Users/benjaminparrish/Development/stratium/sdk/go/`

**Module**: `go.mod` with same core deps as server

**Unique deps**:
- None additional beyond server deps

### Java SDK

**Build**: `build.gradle.kts` Gradle build

**Key dependencies**:
- `com.google.protobuf:protobuf-java` - Protocol Buffers
- `io.grpc:grpc-netty-shaded` - gRPC
- `org.bouncycastle:bcprov-jdk15on` - Bouncy Castle crypto
- `org.bouncycastle:bc-fips` - FIPS provider (optional)

**FIPS support**:
- BCFIPS provider auto-registration
- Validation via `FipsMode.java`

**File**: `/Users/benjaminparrish/Development/stratium/sdk/java/build.gradle.kts`

### Python SDK

**Base**: `/Users/benjaminparrish/Development/stratium/sdk/python/`

**Build**: `pyproject.toml`

**Key dependencies**:
- `grpcio` - gRPC client
- `grpcio-tools` - Protocol Buffer code generation
- `cryptography` - Cryptographic operations (OpenSSL backend)
- `pydantic` - Configuration validation
- `requests-oauthlib` - OAuth2 client
- `pyopenssl` - Python SSL wrapper

**FIPS mode**:
- Validates OpenSSL FIPS mode via cryptography APIs
- Falls back to command-line `openssl` if APIs unavailable

### JavaScript SDK

**Base**: `/Users/benjaminparrish/Development/stratium/sdk/js/`

**Package manager**: npm

**Node.js specific** (`src/nodejs/`):
- `@connectrpc/connect-node` - Connect/gRPC library
- `crypto` (built-in) - Node.js Web Crypto API
- `grpc-js` - gRPC JavaScript

**Browser/Deno** (`src/`):
- `@connectrpc/connect-web` - Browser gRPC
- `@noble/curves` - Pure JS curve implementation
- `tweetnacl-js` - NaCl cryptography

## Build Tools

**Go toolchain**: Go 1.25+

**Protocol Buffers**:
- `protoc` - Protocol Buffer compiler
- `protoc-gen-go` - Go code generator
- `protoc-gen-go-grpc` - gRPC code generator

**Java**:
- Gradle wrapper: `/sdk/java/gradlew`
- JDK 21+ required

**Python**:
- Python 3.14+
- `venv` for virtual environments

**JavaScript**:
- Node.js 18+
- npm 9+

## Deployment Dependencies

**Docker**:
- Base images: See `/Users/benjaminparrish/Development/stratium/deployment/docker/Dockerfile`
- PostgreSQL image for data store

**Kubernetes**:
- Manifests: `/Users/benjaminparrish/Development/stratium/deployment/kubernetes/`

**Secrets**:
- Kubernetes `secret` for mTLS certificates
- Environment variables for config

## Version Constraints

**Critical upgrades**:
- gRPC: Stays on v1.75+ for security patches
- Protobuf: v1.36+ for compatibility
- Cloudflare circl: v1.6+ for KYBER support
- OPA: v1.0.0+ for policy evaluation

## Vulnerability Scanning

**Tools** (inferred):
- golangci-lint for Go linting
- Vulnerability scanner in CI/CD

## Related Documentation

- **Architecture**: `/docs/CODEMAPS/architecture.md`
- **Security (FIPS)**: `/docs/SECURITY_FIPS.md`
- **Configuration**: `/docs/CONFIGURATION.md`
- **SDK docs**: Individual SDK READMEs
