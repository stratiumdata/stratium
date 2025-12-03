## Cross-SDK Payload Integration Test

The `integration` package hosts an end‑to‑end test suite that exercises the Go, Java, and JavaScript SDKs against the same Stratium stack. The goal is to guarantee that each SDK can encrypt a payload that any other SDK can decrypt. The test is invoked from Go (`go test ./integration`), but every SDK performs real network calls to your running Key Access, Key Manager, and Keycloak instances.

### What the test validates

`cross_sdk_test.go` spins up an interoperability matrix covering all ordered pairs of SDKs:

| Encryptor | Decryptor |
|-----------|-----------|
| Java      | JavaScript |
| Java      | Go |
| JavaScript | Java |
| JavaScript | Go |
| Go | Java |
| Go | JavaScript |

Each row generates a random plaintext blob, asks the encryptor SDK to produce a ZTDF, persists that ciphertext to `artifacts/cross-sdk/<combo>_ciphertext.ztdf`, and finally asks the decryptor SDK to unwrap the payload. The test asserts that the decrypted bytes match the original plaintext and writes every intermediate file (plaintext, ciphertext, decrypted plaintext) to the same artifacts directory for manual inspection.

### How it works

1. **Harness** – The Go test harness marshals small JSON requests into each SDK’s command-line helper:
   - Go: `go run ./cmd/crosssdk <encrypt|decrypt>`
   - Java: `./gradlew runCrossSdkTool --args='<mode>'`
   - JavaScript: `node scripts/cross-sdk-tool.mjs <mode>`

   Each helper reads a JSON request on `stdin` and emits a JSON response on `stdout`. This keeps the test language-agnostic while still running inside a single `go test`.

2. **Artifacts** – Before running combinations, the harness prints key environment values (endpoints, policy length, client-key directories) and ensures the directories `artifacts/client-keys/{go,js}` and `artifacts/cross-sdk` exist. Every helper writes its client keys into those directories so retries reuse the same registered key IDs.

3. **Environment** – The helpers rely on shared configuration exported in `scripts/cross-sdk.env`. Important variables:
   - `STRATIUM_KEY_ACCESS_URL / _URI` and `STRATIUM_KEY_MANAGER_URL / _URI` – gRPC endpoints for the services.
   - `STRATIUM_KEYCLOAK_URL` and `STRATIUM_KEYCLOAK_REALM` – used to build the issuer URL when the helpers need to mint tokens.
   - `STRATIUM_BEARER_TOKEN` **or** `STRATIUM_CLIENT_ID`/`STRATIUM_CLIENT_SECRET` credentials – a user-scoped token is preferred so policies can reference subject attributes.
   - `STRATIUM_POLICY_BASE64` – Base64-encoded resource policy that is embedded in every ZTDF.
   - `STRATIUM_RESOURCE_ATTRIBUTES` – Comma-separated `key=value` pairs asserted when requesting/wrapping DEKs.
   - Optional overrides (`STRATIUM_RESOURCE`, `STRATIUM_FILENAME`, `STRATIUM_CONTENT_TYPE`, `STRATIUM_GO_KEY_DIR`, `STRATIUM_JS_KEY_DIR`, `STRATIUM_JAVA_KEY_DIR`) customize the payload metadata and client-key storage locations. By default every helper writes to `artifacts/client-keys/<lang>` under the repo (Go: `go`, JS: `js`, Java: `java`), so set these when you need a different directory.

   Copy `scripts/cross-sdk.env.example` to `scripts/cross-sdk.env`, fill in the values that make sense for your local stack, and keep the file out of version control.

4. **Execution** – Run the suite via:

```bash
scripts/run-cross-sdk-tests.sh           # reads scripts/cross-sdk.env
# or
scripts/run-cross-sdk-tests.sh /path/to/custom-env
```

The script exports the environment file, ensures client-key directories exist, and runs `go test ./integration`. Helper output is streamed directly to your terminal (prefixed with `[cross-sdk]`) so you can see which command is running and where artifacts are being written.

5. **Artifacts and diagnostics** – After every encrypt/decrypt cycle the harness emits lines such as:

```
[cross-sdk] testing java_to_go
[cross-sdk] wrote artifacts/cross-sdk/java_to_go_plaintext.txt (30 bytes)
[cross-sdk] wrote artifacts/cross-sdk/java_to_go_ciphertext.ztdf (1165 bytes)
[cross-sdk] java_to_go produced ZTDF (1165 bytes)
```

If a helper returns a non-zero exit code the Go test captures `stderr`, surfaces it in the failure output, and aborts the current combination. Because artifacts persist under `artifacts/cross-sdk`, you can inspect the generated ZTDFs and plaintext files even when a later step fails.

### Requirements and tips

- **Running Stratium stack** – The test expects a Docker Compose (or equivalent) deployment with Key Access, Key Manager, and Keycloak reachable at the endpoints specified in your env file.
- **Shared credentials** – Provide a bearer token or client credentials with access to the same subject/policy data across SDKs. The Go helper can reuse `STRATIUM_SUBJECT_ID` to register client keys on behalf of a user token.
- **Fresh client keys** – Each SDK will generate and register its own RSA client key the first time it runs. Clearing `artifacts/client-keys/*` forces the helpers to re-register keys (useful when the Key Manager database has been reset).
- **Debugging** – Enable verbose logging in individual helpers by setting `STRATIUM_SDK_DEBUG=1` (respected by JS and Go) or by running Java’s Gradle task with `--info` or `--stacktrace`.

### When to run it

Run the cross-SDK integration test whenever you touch:

- ZTDF manifest structure or integrity metadata.
- Policy-binding logic or policy serialization.
- SDK authentication flows and client-key registration logic.
- Any code that could introduce compatibility differences between languages (e.g., switching from ECC to RSA keys, changing cipher suites, adding manifest fields).

Because it relies on live services and real tokens, this suite is heavier than unit tests, but it provides high confidence that users can mix and match SDKs without regressions.
