# Deployment Resources

This directory contains everything needed to deploy Stratium in different environments. The content is now organized by deployment method to make it easier to find the correct assets.

## Docker
All Dockerfiles, Compose stacks, and local demo documentation live under [`docker/`](docker/).
- `Dockerfile`, `Dockerfile.pap`, `Dockerfile.postgres`
- `docker-compose*.yml` bundles for RSA, ECC, KEM, and demo scenarios
- Guides such as `README.demo.md` and `ALGORITHMS.md`

Follow the instructions in `docker/README.md` for building images and running the Compose stacks.

## Helm
Helm charts, scripts, and environment-specific guides remain under [`helm/`](helm/). Refer to that directory for deploying to EKS or other Kubernetes clusters using Helm.

## Additional Assets
The deployment root still contains shared infrastructure resources:
- `kubernetes/` manifests and `KUBERNETES.md`
- `dns/`, `certs/`, and other infrastructure helpers
- `postgres/` initialization SQL used by both Docker and Helm scenarios

This layout keeps Docker- and Helm-specific files scoped to their directories while preserving common assets at the root.

## FIPS Runtime Validation
When deploying with FIPS mode enabled, validate each runtime crypto module in the running environment.
For a local, automated check, run `scripts/validate_fips_runtime.sh` or `make fips-validate`. Use `STRICT=1` to fail on skipped checks, set `GO_BIN_PATH` to point at the Go service binary, and `PYTHON_BIN` to select a specific Python interpreter.

### Go services (GOFIPS140)
Confirm binaries were built with the FIPS module and runtime settings match.
- Check build info on the running binary: `go version -m /path/to/stratium-binary | rg GOFIPS140`
- Ensure `security.fips.enabled=true` and `security.fips.go_module` matches the build setting.
- Ensure `GODEBUG` does not disable FIPS (`fips140=off`).

### Java SDK (BCFIPS or FIPS-enabled JDK)
The SDK checks the default provider for AES/GCM and fails fast if it is not FIPS-capable.
- Set `STRATIUM_FIPS_ENABLED=true` (or `-Dstratium.fips.enabled=true`) and initialize the SDK.
- Verify provider order with `java -XshowSettings:security -version` or a `jshell` snippet:
  - `Cipher.getInstance("AES/GCM/NoPadding").getProvider().getName()`
- Ensure the provider name/info contains `FIPS` (BCFIPS or a FIPS-enabled JDK).

### Python SDK (OpenSSL FIPS provider)
The SDK calls `ensure_fips_mode()` and raises if the linked OpenSSL is not in FIPS mode.
- Run: `python -c "from stratium_sdk.crypto import ensure_fips_mode; ensure_fips_mode(); print('FIPS OK')"`
- Confirm `ssl.OPENSSL_VERSION` points at a FIPS-capable build.

### Node SDK (OpenSSL FIPS)
The Node SDK enables FIPS via `crypto.setFips(1)` and throws if unsupported.
- Run: `node -e "const {setFips,getFips}=require('crypto'); setFips(1); console.log(getFips())"`
- Ensure it prints `1` and does not throw; otherwise use a Node build linked to FIPS OpenSSL.
