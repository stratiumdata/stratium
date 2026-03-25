# FIPS 140-3 Compliance Plan (Stratium)

This document outlines the steps needed to align Stratium services and SDKs with
FIPS 140-3 requirements. FIPS compliance is achieved by using validated
cryptographic modules in validated operating environments, and by restricting
algorithms/flows to those covered by the validation.

## Scope
- In scope: Go services, Go SDK, Java SDK, Node.js SDK, Python SDK, key manager
  services.
- Out of scope for FIPS validation: Browser WebCrypto (cannot be FIPS validated).
  Browser SDKs can be supported but must be documented as non-FIPS and reject `fipsEnabled`.

## Cryptographic Boundary
- In-scope components:
  - Go services that perform key wrapping, payload encryption, policy binding, and
    integrity checks (Key Access, Key Manager, Platform, PAP).
  - Go, Java, Node.js, and Python SDK crypto utilities used for ZTDF payload
    encryption, integrity checks, and DEK handling.
  - Key Manager providers that generate, wrap, and store keys.
- In-scope crypto modules:
  - Go standard library when built with `GOFIPS140` (validated module).
  - Java provider configured for FIPS (BCFIPS or a vendor FIPS JDK).
  - OpenSSL FIPS provider for Node.js and Python.
- Out of scope:
  - Browser WebCrypto.
  - External TLS termination (LB/proxy) when it terminates TLS before Stratium.
  - Databases, storage, and OS-level services outside the validated runtime.

## Current Gaps (Summary)
- Go builds must be consistently verified to ensure `GOFIPS140` is in use.
- TLS policy enforcement and evidence collection are not standardized.
- Provider validation evidence is not consistently captured for audits.

## Target State
- All server-side cryptography uses validated modules and approved algorithms.
- A global FIPS mode enforces approved algorithms and blocks non-compliant flows.
- Deployments are restricted to validated or vendor-affirmed environments.
- Documentation and CI verify module use and algorithm compliance.

## Go Track (Native Go FIPS 140-3 Module)
- Build all Go services/SDKs with:
  - `GOFIPS140=v1.0.0 go build`
- Makefile defaults to FIPS builds; use `make build` (FIPS on), `make build FIPS=0` to disable, and `GOFIPS140=v1.0.0` to override the module.
- Verify binaries in CI:
  - `go version -m <binary>` includes the expected `GOFIPS140` module.
- Enforce runtime FIPS mode in production:
  - `GODEBUG=fips140=on` (default for GOFIPS140 builds, but enforce explicitly).
- Deployment policy:
  - Restrict to validated or vendor-affirmed OS/arch combinations listed by the
    Go module validation.
- Upgrade policy:
  - Track module version updates and align Go upgrades to validated modules.

## Configuration Knobs
```yaml
security:
  fips:
    enabled: false
    go_module: v1.0.0
```
- `security.fips.enabled`: Fail startup if the runtime is not in FIPS mode.
- `security.fips.go_module`: Required `GOFIPS140` build setting when FIPS is enabled.

## Algorithm Policy (All Runtimes)
- Approved only: AES-256-GCM, HMAC-SHA256/384/512, SHA-256/384/512,
  RSA-OAEP with SHA-256, RSA-PSS with SHA-256, TLS 1.2/1.3 with approved ciphersuites.
- ECC (P-256/P-384) is approved by FIPS, but current Stratium ECIES flows are
  not validated and are disabled in FIPS mode.
- Blocked in all modes:
  - Kyber KEM, RSA PKCS#1 v1.5 key transport, SHA-1 OAEP fallbacks, custom ECIES/ECC key wrapping.
- Add an SDK/service-level algorithm gate that rejects non-approved algorithms
  when `FIPS_MODE=1`.
- In FIPS mode, SDKs do not attempt SHA-1 OAEP or PKCS#1 v1.5 fallback decryptions.

## Language-Specific Actions
### Go
- Replace any non-FIPS crypto primitives with standard library equivalents.
- If using `golang.org/x/crypto` (e.g., HKDF), confirm the validated module
  covers the algorithm for the intended use and switch to approved KDF paths.

### Java
- Use a validated crypto provider (e.g., BouncyCastle FIPS or vendor FIPS JDK).
- Disable non-approved providers and remove SHA-1/PKCS1Padding fallbacks.
- In FIPS mode, SDK startup validates the default AES/GCM provider is FIPS-capable.
- When BCFIPS is on the classpath, the SDK registers it at highest priority and sets
  `org.bouncycastle.fips.approved_only=true` by default.
- For JVM-level enforcement, configure `java.security` to prioritize BCFIPS
  (see `sdk/java/config/java.security.fips`).

### Node.js
- Use Node built against an OpenSSL FIPS provider.
- Enforce `--enable-fips` and `crypto.setFips(1)` in production.
- Remove RSA PKCS#1 v1.5 wrapping and non-approved fallbacks.
- In FIPS mode, SDK calls `crypto.setFips(1)` and fails if FIPS support is unavailable.

### Python
- Ensure OpenSSL FIPS provider is used and `cryptography` is linked to it.
- FIPS is acceptable only when the runtime enforces the FIPS provider:
  - Set `OPENSSL_CONF` and `OPENSSL_MODULES` (or rely on a vendor FIPS OpenSSL
    build that loads the provider by default).
- Use a stable Python runtime for SDK tests (3.13+). Python 3.14 alpha builds may
  crash with native extensions (e.g., `grpcio`).
- Remove SHA-1/PKCS1Padding fallbacks and non-approved algorithms.
- In FIPS mode, SDK validates OpenSSL FIPS mode via `cryptography` bindings.
- If the OpenSSL FIPS APIs are unavailable in `cryptography`, set `OPENSSL_BIN` plus
  `OPENSSL_CONF`/`OPENSSL_MODULES` to point at the FIPS provider configuration.

## Key Management and HSM
- Prefer HSM/KMS for key generation and storage in FIPS mode.
- Store only wrapped keys at rest; ensure key generation occurs inside validated
  modules.
- Update Key Manager to allow FIPS-only key types and providers.
- In FIPS mode, Stratium currently allows only RSA key types for DEK wrapping.

## Client DEK Handling (FIPS Mode)
- Client-side RSA PKCS#1 v1.5 DEK wrapping is disabled in all modes.
- Clients send the DEK in plaintext over TLS to Key Access, and services perform
  server-side wrapping using approved algorithms.
- SDK toggles:
  - Java: `StratiumClientConfig.builder().fipsEnabled(true)`
  - Node.js: `new ZtdfClient({ fipsEnabled: true })`
  - Python: `StratiumConfig(fips_enabled=True)`

## TLS and Transport
- Restrict TLS to approved cipher suites and TLS 1.2/1.3.
- Ensure the TLS stack is provided by the validated module for each runtime.

## Testing and CI
- Add CI checks to confirm:
  - Go binaries are built with `GOFIPS140=v1.0.0`.
  - Runtime FIPS mode is enabled in production configs.
  - Non-approved algorithms are not used in FIPS mode.
- Add integration tests that run with FIPS mode enabled.

## FIPS Mode Verification Checklist
- Go services/SDK built with `GOFIPS140=v1.0.0` and runtime `GODEBUG=fips140=on`.
- Java SDK uses a FIPS provider (e.g., BCFIPS or vendor FIPS JDK) and throws if not active.
- Node.js SDK runs on OpenSSL FIPS builds and `crypto.setFips(1)` succeeds.
- Python SDK links to OpenSSL FIPS provider and `ensure_fips_mode()` succeeds.
- `OPENSSL_CONF` and `OPENSSL_MODULES` are set unless the OpenSSL build reports
  FIPS mode by default.
- TLS endpoints restricted to approved TLS 1.2/1.3 ciphersuites.
- Non-approved algorithms (Kyber, PKCS#1 v1.5, SHA-1 OAEP) are blocked in FIPS mode.

## Release Checklist (FIPS Builds)
- Go:
  - `GOFIPS140=v1.0.0 GODEBUG=fips140=on go build ./go/cmd/...`
  - `go version -m <binary>` shows `GOFIPS140=v1.0.0`
- Java:
  - Run with a FIPS provider configured as highest priority (e.g., BCFIPS).
  - Set `fipsEnabled=true` and verify startup fails without FIPS provider.
- Node.js:
  - Use a FIPS-enabled OpenSSL build and start with `--enable-fips`.
  - `fipsEnabled=true` and verify `crypto.getFips() === 1`.
- Python:
  - Use a Python build linked to OpenSSL FIPS provider.
  - `fips_enabled=True` and verify `ensure_fips_mode()` succeeds.

## Documentation and Operations
- Document the supported deployment environments for FIPS mode.
- Document the algorithm policy and what is disabled in FIPS mode.
- Provide a “FIPS Mode” runbook for enabling and validating compliance.

## Evidence and Runbook
### Approved Algorithm List (FIPS Mode)
- Symmetric encryption: AES-256-GCM (payload encryption and key material at rest).
- Key transport: RSA-OAEP with SHA-256 (DEK wrapping).
- Signatures: RSA-PSS with SHA-256 (key management signing operations).
- Integrity: HMAC-SHA256 and SHA-256 (policy binding and payload hashing).
- Transport: TLS 1.2/1.3 with approved cipher suites from the validated module.

### Provider Configuration (By Runtime)
- Go:
  - Build with `GOFIPS140=v1.0.0`.
  - Run with `GODEBUG=fips140=on` and `security.fips.enabled=true`.
  - Verify with `go version -m <binary>`.
- Java:
  - Use `sdk/java/config/java.security.fips` to prioritize BCFIPS.
  - Set `-Djava.security.properties=/path/to/java.security.fips`.
  - Ensure `org.bouncycastle.fips.approved_only=true`.
- Node.js:
  - Run a Node build linked against OpenSSL FIPS.
  - Start with `--enable-fips` and verify `crypto.setFips(1)` succeeds.
- Python:
  - Use a Python build linked against OpenSSL FIPS provider.
  - Provide `OPENSSL_CONF` and `OPENSSL_MODULES` if needed to load the FIPS provider.
  - Use Python 3.13+ for SDK tests (3.14 alpha builds are not supported).
  - Verify via the SDK `ensure_fips_mode()` call.

### Evidence Artifacts
- Build provenance:
  - Go: `go version -m <binary>` output showing `GOFIPS140=v1.0.0`.
  - Java: `java -XshowSettings:security -version` output with BCFIPS at highest priority.
  - Node: `node -p "require('crypto').getFips()"` output equals `1`.
  - Python: `python -c "from stratium_sdk.crypto import ensure_fips_mode; ensure_fips_mode(); print('ok')"` output.
- Runtime checks:
  - `make fips-validate` output stored alongside build artifacts.
- Configuration snapshots:
  - `config/*` files showing `security.fips.enabled=true` and runtime flags.

### Operational Checklist for Audits
- Pre-audit:
  - Confirm all production binaries are built with `GOFIPS140=v1.0.0`.
  - Capture `make fips-validate` output for each runtime environment.
  - Verify TLS termination layer and record its TLS policy if outside Stratium.
- Deployment:
  - Ensure `security.fips.enabled=true` in service configs.
  - Enforce `GODEBUG=fips140=on` and runtime flags for Java/Node/Python.
  - Validate providers are active at startup (fail closed if not).
- Post-deployment:
  - Archive build logs, validation outputs, and config snapshots per release.
  - Review key access and policy decision audit logs for anomalies.
  - Confirm algorithm policy rejects non-approved algorithms in runtime logs.

## Phased Rollout
1. Define FIPS mode and algorithm policy; add runtime gates.
2. Enable Go native FIPS module in CI and production builds.
3. Remove or gate non-FIPS algorithms (Kyber, PKCS#1 v1.5, SHA-1 OAEP).
4. Align Java/Node/Python SDKs with validated providers.
5. Validate deployment environments and document compliance evidence.

## Full E2E Test (FIPS Mode)
Run this after building FIPS-enabled binaries and starting the required dependencies (DB, Keycloak, etc.).

1. Build FIPS binaries and validate runtime crypto modules:
   - `make full`
   - `make fips-validate`
2. Start services with FIPS mode enabled:
   - Set `security.fips.enabled=true` in each service config file (for example: `config/examples/platform-server.yaml`, `config/examples/key-manager.yaml`, `config/examples/key-access-server.yaml`, `config/examples/pap-server.yaml`).
   - Set `security.fips.go_module` to match the **exact** build setting (for example: `v1.0.0-c2097c7c` when `go version -m <binary>` shows that value). The setting may include a commit suffix even if you built with `GOFIPS140=v1.0.0`.
   - Export `GODEBUG=fips140=on` in the shell that launches the services (or set it in your container environment).
   - Confirm the binary is a FIPS build: `go version -m bin/platform-server` should show `GOFIPS140=v1.0.0`.
   - Ensure TLS is enabled for all service endpoints and certificates are configured (`server.tls.enabled=true`, `server.tls.cert_file`, `server.tls.key_file`, and CA settings as needed).
3. Run Go service integration tests:
   - `make tests-all`
4. Run SDK integration tests:
   - Go SDK: `cd sdk/go && go test ./...`
   - Java SDK: `cd sdk/java && ./gradlew test -Pfips=true`
   - Python SDK:
     - `cd sdk/python`
     - `python -m venv .venv && source .venv/bin/activate`
     - `python -m pip install -U pip`
     - `python -m pip install -e ".[dev]"`
     - `python -m pytest`
   - Node SDK: `cd sdk/js && npm test`
5. Run a real end-to-end flow:
   Use the Go `ztdf-client` CLI so a new user can see the complete auth → wrap → unwrap path. The example below assumes the local docker-compose stack, Keycloak at `http://localhost:8080`, and services on ports `50052/50053`. If you are using self-signed certs, export a trusted CA file and pass `--use-tls`.

   Build the CLI:
   ```bash
   cd go
   go build -o ../bin/ztdf-client ./cmd/ztdf-client
   ```
   If you get `unknown flag: --use-tls`, you are running an older binary. Re-run the
   build above and confirm `./bin/ztdf-client --help` shows the `--use-tls` flag.

   Ensure you have a test user in Keycloak. If you are brand new, open the Keycloak admin console at `http://localhost:8080`, log in as `admin/admin`, select the `stratium` realm, create a user (for example `user123`), and set a password.

   Export connection settings and (if needed) the local CA:
   ```bash
   export KEYCLOAK_URL="http://localhost:8080/realms/stratium"
   export KM_ADDR="localhost:50052"
   export KAS_ADDR="localhost:50053"
   export CLIENT_ID="stratium-ztdf-client"
   export STRATIUM_GRPC_CA_FILE="$PWD/config/examples/certs/ca.crt"  # only if using self-signed TLS
   # GRPC_DEFAULT_SSL_ROOTS_FILE_PATH also works for Go clients
   ```

   Log in (token is stored in `~/.ztdf/token.json`):
   ```bash
   ./bin/ztdf-client login \
     --keycloak-url "$KEYCLOAK_URL" \
     --client-id "$CLIENT_ID" \
     --username "user123" \
     --password "mypassword" \
     --km-addr "$KM_ADDR" \
     --kas-addr "$KAS_ADDR" \
     --use-tls
   ```

   Wrap a plaintext file into a ZTDF:
   ```bash
   echo "hello stratium" > /tmp/hello.txt
   ./bin/ztdf-client wrap \
     --keycloak-url "$KEYCLOAK_URL" \
     --input "/tmp/hello.txt" \
     --output "/tmp/hello.ztdf" \
     --resource "document-service" \
     --km-addr "$KM_ADDR" \
     --kas-addr "$KAS_ADDR" \
     --use-tls
   ```

   Unwrap the ZTDF and verify the plaintext matches:
   ```bash
   ./bin/ztdf-client unwrap /tmp/hello.ztdf \
     --keycloak-url "$KEYCLOAK_URL" \
     --resource "document-service" \
     --save "/tmp/hello.out" \
     --km-addr "$KM_ADDR" \
     --kas-addr "$KAS_ADDR" \
     --use-tls
   diff /tmp/hello.txt /tmp/hello.out
   ```

   Confirm service logs show FIPS mode enabled and no non-approved algorithm fallback.
6. Archive evidence:
   - Save test output logs and `make fips-validate` output with the release artifacts.
