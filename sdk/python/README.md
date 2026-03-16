# Stratium Python SDK

The Python SDK provides the same opinionated workflows as the Go, Java, and JavaScript SDKs:

- High-level `StratiumClient` facade for wrapping/unwrapping Zero Trust Data Format (ZTDF) blobs
- gRPC clients for the Platform, Key Manager, and Key Access services
- OIDC/Keycloak-aware token provider with automatic refresh
- File-system backed key store compatible with the existing SDKs
- AES‑256‑GCM/ZTDF helpers for AI/ML training pipelines that need to decrypt encrypted corpora on demand

Requires Python 3.14 or newer.

## Quick start

```bash
cd sdk/python
python3.14 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### Usage

```python
from stratium_sdk import (
    OIDCConfig,
    StratiumClient,
    StratiumConfig,
    WrapOptions,
)

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

client = StratiumClient(config)
client.initialize()

wrap_result = client.wrap(
    plaintext=b"training-set",
    options=WrapOptions(
        resource="model-weights",
        filename="weights.bin",
        content_type="application/octet-stream",
    ),
)

plaintext = client.unwrap(wrap_result.ztdf_blob)
```

Set `fips_enabled=True` to disable client-side RSA PKCS#1 v1.5 wrapping and send the DEK in plaintext over TLS.
The SDK validates that the linked OpenSSL runtime is in FIPS mode and raises a `ValidationError` if it is not.
If the OpenSSL FIPS APIs are not exposed by `cryptography`, set `OPENSSL_BIN` to a compatible `openssl`
binary and ensure `OPENSSL_CONF`/`OPENSSL_MODULES` point at the FIPS provider configuration.

### Running tests

```bash
cd sdk/python
source .venv/bin/activate
pip install .[dev]
pytest
```

### Regenerating protobuf stubs

```bash
cd sdk/python
.venv/bin/python -m grpc_tools.protoc \
    -I ../../proto \
    --python_out=stratium_sdk/proto/services \
    --grpc_python_out=stratium_sdk/proto/services \
    ../../proto/services/{platform,key-manager,key-access}/*.proto

.venv/bin/python -m grpc_tools.protoc \
    -I ../../proto \
    --python_out=stratium_sdk/proto/models \
    ../../proto/models/{ztdf,stanag4774}.proto
```

The generated files under `stratium_sdk/proto` are committed so application builds do not require `protoc`.
