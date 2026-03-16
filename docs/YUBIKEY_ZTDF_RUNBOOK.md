# Stratium + YubiKey Runbook (User Client Key Mode)

This runbook is for your intended model: the YubiKey belongs to the user, and `ztdf-client` uses that YubiKey keypair as the client key for ZTDF wrap/unwrap.

In this mode:
- Stratium services run in Docker.
- YubiKey is only used by the host-side `ztdf-client` process.
- You do not need USB passthrough into containers.

## 1. Prerequisites

Install tooling on your host (macOS example):

```bash
brew install go docker grpcurl jq ykman yubico-piv-tool opensc
```

Verify YubiKey visibility on the host:

```bash
ykman list
yubico-piv-tool -a status
```

You also need:
- A YubiKey with PIV enabled.
- PIV PIN/PUK known.
- Stratium repo at `/Users/benjaminparrish/Development/stratium`.

## 2. Provision user key on YubiKey slot 9d

Generate user keypair on YubiKey slot `9d` and install a cert:

```bash
cd /Users/benjaminparrish/Development/stratium

yubico-piv-tool -a generate -s 9d -A RSA2048 -o /tmp/yubikey-user-pubkey.pem
yubico-piv-tool -a selfsign-certificate -s 9d -S '/CN=stratium-user/' -i /tmp/yubikey-user-pubkey.pem -o /tmp/yubikey-user-cert.pem
yubico-piv-tool -a import-certificate -s 9d -i /tmp/yubikey-user-cert.pem
```

Optional (recommended for user-presence): require touch for slot `9d`.
Check policy:

```bash
ykman piv keys info 9d
```

If `Touch policy` is not `ALWAYS`, re-provision the slot with touch policy:

```bash
yubico-piv-tool -a generate -s 9d -A RSA2048 --touch-policy always -o /tmp/yubikey-user-pubkey.pem
```

## 3. Build Stratium and `ztdf-client`

YubiKey client wrap+unwrap now works in both standard and FIPS builds.

```bash
cd /Users/benjaminparrish/Development/stratium

make build
cd go
go build -o ztdf-client ./cmd/ztdf-client
```

Optional FIPS build:

```bash
export GOFIPS140=${GOFIPS140:-v1.0.0-c2097c7c}
go build -tags fips -o ztdf-client ./cmd/ztdf-client
```

## 4. Start Stratium services in Docker (standard compose)

Create admin key if needed:

```bash
mkdir -p /Users/benjaminparrish/.stratium
openssl rand -base64 32 > /Users/benjaminparrish/.stratium/admin-key
chmod 600 /Users/benjaminparrish/.stratium/admin-key
```

Start services:

```bash
cd /Users/benjaminparrish/Development/stratium/deployment/docker
docker compose up --build -d
docker compose ps
```

Connectivity checks (local docker defaults expose TLS gRPC):

```bash
grpcurl -insecure localhost:50052 list
grpcurl -insecure localhost:50053 list
```

## 5. Execute end-to-end user-key wrap/unwrap

Use seeded test user from realm export:
- Username: `admin456`
- Password: `admin123`

```bash
cd /Users/benjaminparrish/Development/stratium/go

export YK_PIN="<YUBIKEY_PIN>"
export STRATIUM_GRPC_CA_FILE="/Users/benjaminparrish/Development/stratium/config/examples/certs/ca.crt"

# Wrap using user's YubiKey private key
./ztdf-client wrap \
  --keycloak-url "http://localhost:8080/realms/stratium" \
  --username "admin456" \
  --password "admin123" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053" \
  --use-tls \
  --client-key-provider yubikey \
  --yk-require-touch \
  --yk-slot 9d \
  --yk-pin "$YK_PIN" \
  --resource "document-service" \
  --text "ZTDF test with user-held YubiKey key" \
  --output "/tmp/yubikey-user-test.ztdf"

# Unwrap with the same user's YubiKey private key
./ztdf-client unwrap /tmp/yubikey-user-test.ztdf \
  --keycloak-url "http://localhost:8080/realms/stratium" \
  --username "admin456" \
  --password "admin123" \
  --km-addr "localhost:50052" \
  --kas-addr "localhost:50053" \
  --use-tls \
  --client-key-provider yubikey \
  --yk-require-touch \
  --yk-slot 9d \
  --yk-pin "$YK_PIN" \
  --resource "document-service" \
  --save /tmp/yubikey-user-test.txt \
  --print=false

cat /tmp/yubikey-user-test.txt
```

Expected result: `/tmp/yubikey-user-test.txt` contains the original plaintext.

## 6. Validate that user client key registration happened

Check local client metadata:

```bash
cat ~/.ztdf/yubikey-client-key/key_metadata.json | jq
```

The `key_id` in this file should match the client key ID used in wrap/unwrap requests.

## 7. Troubleshooting

- `Failed to dial target host "localhost:50052"`:
  - Confirm container is up and healthy: `docker compose ps`.
  - Confirm service ports are exposed: `50052`, `50053`.
  - Check logs: `docker logs stratium-key-manager` and `docker logs stratium-key-access`.
- `error reading server preface: EOF`:
  - This usually means plaintext gRPC was sent to a TLS endpoint.
  - Use `--use-tls` in `ztdf-client`.
  - For local self-signed certs, export `STRATIUM_GRPC_CA_FILE=/Users/benjaminparrish/Development/stratium/config/examples/certs/ca.crt`.
- `failed to verify touch policy for slot ...`:
  - Run `ykman piv keys info 9d` and verify slot metadata is available.
  - Upgrade YubiKey tooling if metadata is missing (`brew upgrade ykman yubico-piv-tool`).
  - Ensure `yubico-piv-tool` is installed; client uses it as an additional touch-policy source.
  - In `--yk-require-touch` mode, wrap/unwrap is fail-closed unless touch policy is verifiably `ALWAYS`.
- `failed to connect to yubikey: Error in PCSC call`:
  - Remove/reinsert YubiKey.
  - Restart PC/SC service (`pcscd`) and rerun `ykman list`.
  - Ensure no other app has exclusive smartcard access.
- `AUTH_FAILED` with YubiKey:
  - Verify PIN with `ykman piv info`.
  - If retries are low, stop and recover with PUK before lockout.

## 8. Production hardening checklist

1. Enable TLS/mTLS for Key Manager and Key Access.
2. Never pass `--yk-pin` directly in shell history in production; use environment or secret injection.
3. Use least-privilege users and enforce ABAC policies per resource/action.
4. Enable audit logging for client key registration and DEK operations.
5. Rotate service keys and define a user key revocation process.
