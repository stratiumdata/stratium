<!-- Generated: 2026-03-12 | SDK Implementations & Client Patterns | Token estimate: ~950 -->

# SDKs Codemap

**Last Updated:** 2026-03-12

## SDK Matrix

| Language | Location | Client | Status | ZTDF Support | FIPS Support | Key Providers |
|----------|----------|--------|--------|--------------|--------------|---------------|
| **Go** | `/sdk/go/` | `ztdf.Client` | Production | Full | Yes | Software, HSM, YubiKey |
| **Java** | `/sdk/java/` | `StratiumClient` | Production | Full | BCFIPS | Software, HSM |
| **Python** | `/sdk/python/` | `StratiumClient` | Production | Full | Yes | Software, YubiKey |
| **JavaScript** | `/sdk/js/` | `ZtdfClient` | Production | Full | Web Crypto | Software |

## Go SDK

**Location**: `/Users/benjaminparrish/Development/stratium/sdk/go/`

**Module**: `stratium/sdk/go` (see `go.mod`)

**Main client**:
```go
type Client struct {
  keyAccessAddr string
  kasClient     keyAccess.KeyAccessServiceClient
  kmClient      keyManagerService.KeyManagerServiceClient
  kasConn       *grpc.ClientConn
  kmConn        *grpc.ClientConn
  keyManager    models.KeyManager
  authProvider  auth.AuthProvider
  authConfig    *auth.AuthConfig
}

func NewClient(config *ZtdfClientConfig) (*Client, error)
```

**File**: `/Users/benjaminparrish/Development/stratium/sdk/go/ztdf/client.go`

**Configuration**:
```go
type ZtdfClientConfig struct {
  KeyAccessAddr       string
  KeyManagerAddr      string
  KeyStorePath        string
  ClientKeyProvider   string  // "software", "yubikey", "smartcard"
  FIPSEnabled         *bool
  YubiKeySlot         string
  YubiKeyPIN          string
  YubiKeyRequireTouch bool
  YubiKeyPIVToolPath  string
  YubiKeyYKManPath    string
  AuthConfig          *auth.AuthConfig
  UseTLS              bool
}
```

**Core operations**:

```go
// Encrypt plaintext → ZTDF manifest
func (c *Client) Wrap(ctx context.Context, plaintext []byte, options *WrapOptions) (*WrapResult, error)

// Decrypt ZTDF manifest → plaintext
func (c *Client) Unwrap(ctx context.Context, ztdfBlob []byte, userAttributes map[string]string) ([]byte, error)

// Streaming support
func (c *Client) WrapStream(ctx context.Context, reader io.Reader, options *WrapOptions) (*WrapStreamResult, error)
```

**Key providers**:
- Software: File-based key storage (`.ztdf-keys/`)
- YubiKey: PIV smart card support
- HSM: PKCS#11 interface (optional)

**Cross-SDK compatibility**:
- Test: `/Users/benjaminparrish/Development/stratium/sdk/go/integration/`
- Payload encryption compatible with Java/Python/JavaScript

## Java SDK

**Location**: `/Users/benjaminparrish/Development/stratium/sdk/java/`

**Build**: Gradle with protobuf plugin

**Main client**:
```java
public class StratiumClient {
  private final StratiumClientConfig config;
  private final KeyAccessServiceStub kasStub;
  private final KeyManagerServiceStub kmStub;
  private final StratiumKeyStore keyStore;

  public static StratiumClient initialize(StratiumClientConfig config)
  public WrapResult wrap(byte[] plaintext, WrapOptions options)
  public byte[] unwrap(byte[] ztdfBlob, Map<String, String> userAttrs)
}
```

**File**: `/Users/benjaminparrish/Development/stratium/sdk/java/src/main/java/com/stratium/sdk/client/StratiumClient.java`

**Configuration**:
```java
StratiumClientConfig config = StratiumClientConfig.builder()
    .keyAccessUri(URI.create("http://localhost:8081"))
    .keyManagerUri(URI.create("http://localhost:8082"))
    .clientId("my-app")
    .fipsEnabled(true)
    .oicdConfig(OIDCConfig.builder()
        .issuerUrl("https://keycloak.local/realms/stratium")
        .clientId("my-app")
        .clientSecret("secret")
        .build())
    .build();
```

**FIPS mode**:
- Auto-detects FIPS-capable JCE provider (BCFIPS)
- Validates AES-GCM provider: `Security.getProvider("BCFIPS") != null`
- Falls back to default if BCFIPS not available

**Crypto utils**:
- File: `/sdk/java/src/main/java/com/stratium/sdk/crypto/CryptoUtils.java`
- DEK wrapping: RSA or plaintext (FIPS mode)
- Manifest parsing: `ZtdfParser`

**Testing**:
- Cross-SDK tests: `cross-sdk-tool.jar`
- Integration tests verify Go↔Java payload compatibility

## Python SDK

**Location**: `/Users/benjaminparrish/Development/stratium/sdk/python/`

**Main client**:
```python
class StratiumClient:
  def __init__(self, config: StratiumConfig) -> None: ...
  def initialize(self) -> None: ...

  def wrap(
    self,
    plaintext: bytes,
    options: WrapOptions
  ) -> WrapResult: ...

  def unwrap(
    self,
    ztdf_blob: bytes,
    user_attributes: dict[str, str] | None = None
  ) -> bytes: ...
```

**File**: `/Users/benjaminparrish/Development/stratium/sdk/python/stratium_sdk/client.py`

**Configuration**:
```python
config = StratiumConfig(
    platform_address="platform.stratium.local:50051",
    key_manager_address="key-manager.stratium.local:50052",
    key_access_address="kas.stratium.local:50053",
    client_id="training-app",
    fips_enabled=False,
    oidc=OIDCConfig(
        issuer_url="https://keycloak.stratium.local/realms/stratium",
        client_id="training-app",
        client_secret="super-secret",
    ),
)
```

**FIPS validation**:
```python
# Validates OpenSSL FIPS mode
if fips_enabled:
  openssl_binary = os.environ.get("OPENSSL_BIN", "openssl")
  result = subprocess.run([openssl_binary, "version"], capture_output=True)
  if "FIPS" not in result.stdout.decode():
    raise ValidationError("OpenSSL not in FIPS mode")
```

**Key provider interface**:
- Software (file-based, `.ztdf-keys/`)
- YubiKey (via `pcsclite` daemon)

**AI/ML workload support**:
- In-memory ZTDF decryption for training pipelines
- No subprocess calls (pure Python)

**Python requirements**:
- Python 3.14+
- `grpcio`, `cryptography`, `pydantic`, `requests-oauthlib`

## JavaScript SDK

**Location**: `/Users/benjaminparrish/Development/stratium/sdk/js/`

**Dual build**:
- `/src/nodejs/` - Node.js with native crypto
- `/src/ztdf/` - Universal (browser/Node.js/Deno)

**Main client (Node.js)**:
```javascript
class ZtdfClient {
  constructor(config: ZtdfClientConfig) { ... }
  async initialize(): Promise<void> { ... }

  async wrap(
    plaintext: Uint8Array,
    options: WrapOptions
  ): Promise<WrapResult> { ... }

  async unwrap(
    ztdfBlob: Uint8Array,
    userAttributes?: Record<string, string>
  ): Promise<Uint8Array> { ... }
}
```

**File**: `/Users/benjaminparrish/Development/stratium/sdk/js/src/nodejs/ztdf-client.js`

**Configuration**:
```javascript
const client = new ZtdfClient({
  keyAccessUrl: 'http://localhost:8081',
  keyManagerUrl: 'http://localhost:8082',
  clientId: 'my-server-app',
  clientKeyExpirationMs: 24 * 60 * 60 * 1000,
  getToken: async () => await getMyAuthToken(),
  debug: true,
  fipsEnabled: false
});

await client.initialize();
```

**Crypto provider**:
- Node.js: `crypto.webcrypto` (native)
- Browser: `window.crypto` (Web Crypto API)

**File storage**:
- Default: `.ztdf-keys/` directory
- Configurable via `keyStorePath`

**Key operations**:
- RSA-based DEK wrapping (PKCS#1 v1.5)
- AES-256-GCM for payload encryption
- ECDH key agreement (future)

**Testing**:
- Cross-SDK tests: `cross-sdk-tool.mjs`

## Common Patterns Across SDKs

### OIDC Token Management

**Flow** (all SDKs):
1. Get token from OIDC provider (Keycloak)
2. Token refresh: Automatic if expiring
3. Pass token in gRPC metadata: `Authorization: Bearer <token>`

**SDK pattern**:
```go
type AuthConfig struct {
  IssuerURL    string
  ClientID     string
  ClientSecret string
}

token, err := provider.Token(ctx)  // Keycloak
```

### Key Store Interface

**Semantics** (all SDKs):
- Store client private key locally
- Load on initialization
- Support multiple keys (rotation)
- File format: PEM (standardized)

**Directory structure**:
```
.ztdf-keys/
├── active-key-id.pem     # Current signing key
├── history/
│   ├── old-key-1.pem     # Rotated keys
│   └── old-key-2.pem
└── metadata.json         # Key IDs, timestamps
```

### Wrap/Unwrap Operations

**Wrap flow** (identical across all SDKs):
```
1. Generate random 256-bit DEK
2. Encrypt plaintext with AES-256-GCM(DEK)
3. Wrap DEK with KAS public key (via WrapDEK RPC)
4. Package: manifest + wrapped-dek + ciphertext → ZTDF blob
```

**Unwrap flow** (identical across all SDKs):
```
1. Parse ZTDF blob → extract wrapped-dek, ciphertext
2. Call KAS.UnwrapDEK() → server returns plaintext DEK
3. Decrypt ciphertext with AES-256-GCM(DEK)
4. Return plaintext
```

### FIPS Mode Behavior

**All SDKs**:
- When `fipsEnabled=true`:
  - DEK NOT wrapped with RSA (client-side)
  - DEK sent plaintext over TLS
  - Server performs RSA wrapping
  - Validate FIPS-approved algorithms only

**Validation** (SDK-specific):
- Go: Validates `encryption.IsFIPSApproved()`
- Java: Checks BCFIPS provider registered
- Python: Validates OpenSSL FIPS mode
- JavaScript: No FIPS validation (TLS handles it)

## Streaming Support

**Go SDK**:
```go
func (c *Client) WrapStream(ctx context.Context, reader io.Reader, options *WrapOptions) (*WrapStreamResult, error)
func (c *Client) UnwrapStream(ctx context.Context, reader io.Reader) (io.Reader, error)
```

**Java SDK**:
```java
public StreamingWrapResult wrapStream(InputStream input, WrapOptions options)
public InputStream unwrapStream(InputStream ztdfInput)
```

**Python SDK**:
```python
def wrap_stream(self, file_path: Path, options: WrapOptions) -> WrapResult: ...
```

**JavaScript SDK**:
- File-based streaming via `fs.createReadStream()`

## Related Documentation

- **Architecture**: `/docs/CODEMAPS/architecture.md`
- **Backend**: `/docs/CODEMAPS/backend.md`
- **Data Models**: `/docs/CODEMAPS/data.md`
- **SDK READMEs**:
  - Go: `/sdk/go/README.md`
  - Java: `/sdk/java/README.md`
  - Python: `/sdk/python/README.md`
  - JavaScript: `/sdk/js/src/nodejs/README.md`
