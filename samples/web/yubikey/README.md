# Stratium Web YubiKey Sample

This sample is a client-side web UI where YubiKey touch is handled in the browser using WebAuthn.

It demonstrates:
1. Registering a YubiKey-backed WebAuthn credential.
2. Requiring YubiKey touch for wrap.
3. Requiring YubiKey touch for unwrap.
4. Doing encrypt/decrypt in browser WebCrypto (no backend crypto flow).
5. Emitting a `.ztdf` ZIP container (`manifest.json` + `0.payload`).

## Location

- `samples/web/yubikey/main.go` - static file server only
- `samples/web/yubikey/public/index.html` - UI
- `samples/web/yubikey/public/app.js` - UI behavior
- `samples/web/yubikey/public/styles.css` - styling

## Prerequisites

1. Chromium-based browser or Safari/Firefox with WebAuthn enabled.
2. YubiKey configured for FIDO2/WebAuthn usage.
3. Serve over `http://localhost` or HTTPS (WebAuthn secure context requirement).

## Run

```bash
cd /Users/benjaminparrish/Development/stratium/samples/web/yubikey
go run .
```

Alternative from repo root:

```bash
cd /Users/benjaminparrish/Development/stratium
go run ./samples/web/yubikey/main.go
```

Open:

```text
http://localhost:8099
```

Optional:

```bash
export YUBIKEY_WEB_SAMPLE_ADDR=":8099"
```

## Test Flow (UI)

1. Click **Register / Rotate YubiKey Credential**.
2. Touch YubiKey when prompted by the browser.
3. Enter plaintext and click **Wrap (Requires Touch)**.
4. Touch YubiKey when prompted.
5. Upload the generated `.ztdf` package (or paste its Base64 content).
6. Click **Unwrap (Requires Touch)** and touch YubiKey again.
7. Confirm decrypted text matches original text.

## Notes

- This sample intentionally keeps YubiKey workflow on the client.
- This sample uses WebAuthn touch as proof-of-user-presence and browser WebCrypto for encryption.
- The sample writes a `.ztdf` ZIP container with a minimal manifest and encrypted payload.
- The key-wrap path is still browser-local (IndexedDB master key), so it is not wire-compatible with server-side KAS unwrap.
- The browser stores a local master key in IndexedDB; unwrap works only in the same browser profile unless you add key portability.
- Browser WebAuthn cannot directly execute YubiKey PIV RSA decrypt/sign operations used by `ztdf-client`.
- For full Stratium ZTDF + PIV key flow, continue using `docs/YUBIKEY_ZTDF_RUNBOOK.md`.
