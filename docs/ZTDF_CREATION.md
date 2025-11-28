# ZTDF Creation Walkthrough

The Stratium Go SDK (`sdk/go/ztdf`) encodes plaintext into a
Zero Trust Data Format (ZTDF) package through a series of deterministic steps.
This document walks through the process implemented by `Client.Wrap`, showing
how each field and file of the final `.ztdf` archive is produced.

## 1. Generate a Data Encryption Key (DEK)

File: `sdk/go/ztdf/crypto.go`, function `GenerateDEK`

```go
dek, err := GenerateDEK()
```

- Produces 32 random bytes (AES‑256 key) using `crypto/rand`.
- All downstream encryption and bindings derive from this key.

## 2. Encrypt the Plaintext Payload

File: `sdk/go/ztdf/crypto.go`, function `EncryptPayload`

```go
encryptedPayload, iv, err := EncryptPayload(plaintext, dek)
```

- Uses AES‑256‑GCM with a fresh nonce (`iv`) to encrypt the plaintext.
- Output:
  - `encryptedPayload` → stored later in `0.payload`.
  - `iv` → recorded in the manifest’s encryption method block.

## 3. Build or Load a Policy

File: `sdk/go/ztdf/client.go`, function `createPolicy`

```go
policy := c.createPolicy(opts)
policyJSON, _ := protojson.Marshal(policy)
```

- If the caller provided a `WrapOptions.Policy` it is reused; otherwise
  defaults are built from the supplied attributes.
- The protobuf is marshaled to JSON and `base64` encoded for embedding inside
  the manifest.
- Important policy fields:
  - `Body.DataAttributes` – the list of attribute URIs (with display names)
    that describe access requirements.
  - `Uuid` and `TdfSpecVersion` – metadata for clients to validate.

## 4. Bind Policy to the DEK

File: `sdk/go/ztdf/crypto.go`, function `CalculatePolicyBinding`

```go
policyBindingHash := CalculatePolicyBinding(dek, policyBase64)
```

- HMAC‑SHA256 using the DEK as the key.
- Prevents tampering with the policy: any change invalidates the binding.
- Stored under `Manifest.EncryptionInformation.KeyAccess[].PolicyBinding`.

## 5. Wrap the DEK via Key Access

File: `sdk/go/ztdf/client.go`, method `wrapDEK`

```go
wrappedDEK, keyID, err := c.wrapDEK(ctx, dek, resource, policyBase64)
```

This call performs several operations:
1. **Authenticate** to the Key Access service (OIDC token).
2. **Client wraps** the DEK locally with its private key:
   ```go
   clientWrappedDEK, _ := c.keyManager.WrapDEK(dek)
   ```
3. **Invoke `WrapDEK` RPC** (`go/services/key-access/server.go`):
   - ABAC evaluation occurs inside Key Access using the
     policy attributes.
   - Key Access decrypts the client-wrapped DEK using Key Manager,
     rewraps it with the current service key, and returns:
     - `wrappedDEK` – opaque bytes encrypted for the service key.
     - `keyID` – identifier of the service key used.

## 6. Compute Payload Integrity

File: `sdk/go/ztdf/crypto.go`, function `CalculatePayloadHash`

```go
payloadHash := CalculatePayloadHash(encryptedPayload)
```

- SHA‑256 over the ciphertext.
- Added to `Manifest.EncryptionInformation.IntegrityInformation` so
  consumers can ensure the payload is intact.

## 7. Assemble the Manifest Structure

File: `sdk/go/ztdf/client.go`, function `createManifest`

Key sections:

- `Assertions` – example handling assertion stored as JSON.
- `EncryptionInformation`:
  - `KeyAccess[0]`:
    - `Url` – Key Access endpoint used.
    - `Kid` – key ID returned by Key Access.
    - `WrappedKey` – base64 of `wrappedDEK`.
    - `PolicyBinding` – algorithm + hash from Step 4.
  - `Method` – algorithm (`AES-256-GCM`) and base64-encoded IV.
  - `IntegrityInformation` – root hash and segment metadata based on `payloadHash`.
  - `Policy` – base64 policy JSON from Step 3.
- `Payload` – pointer to `0.payload`.

## 8. Produce the Trusted Data Object

File: `sdk/go/ztdf/client.go`, function `Wrap`

```go
tdo := &models.TrustedDataObject{
    Manifest: manifest,
    Payload: &models.Payload{Data: encryptedPayload},
}
```

- `Manifest` contains the metadata built above.
- `Payload.Data` holds the encrypted bytes ready to be serialized.

## 9. Package into a ZTDF ZIP

File: `sdk/go/ztdf/file.go`, function `SaveToFile`

Contents of the `.ztdf` archive:

```
manifest.json   # JSON form of models.Manifest
0.payload       # Raw encryptedPayload bytes
```

Steps performed:
1. Opens a ZIP writer.
2. Writes `manifest.json` via `protojson.Marshal(tdo.Manifest)`.
3. Writes `0.payload` from `tdo.Payload.Data`.
4. Closes the ZIP and saves the resulting bytes to disk.

## Summary

1. Generate DEK → encrypt plaintext and calculate integrity hash.
2. Build policy JSON and bind it to the DEK via HMAC.
3. Client wraps DEK, Key Access rewraps it with a service key.
4. Manifest captures all metadata (policy, encryption method, integrity, key access).
5. Final `TrustedDataObject` is serialized into a ZIP containing
   `manifest.json` and `0.payload`.

Understanding each step helps when customizing wrap options,
debugging policy evaluations, or validating the produced ZTDF artifacts.
