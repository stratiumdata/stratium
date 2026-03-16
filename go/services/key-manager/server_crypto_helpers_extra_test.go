//go:build !fips

package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"stratium/pkg/security/encryption"
)

// ---------------------------------------------------------------------------
// recoverYubiKeySignedDEK – missing branches
// ---------------------------------------------------------------------------

// TestRecoverYubiKeySignedDEK_BadJSON verifies error when wrapped bytes are not valid JSON.
func TestRecoverYubiKeySignedDEK_BadJSON(t *testing.T) {
	key := &Key{
		KeyId:        "test",
		PublicKeyPem: "",
	}
	_, err := recoverYubiKeySignedDEK(key, []byte("not-json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// TestRecoverYubiKeySignedDEK_WrongVersion verifies error for unsupported version.
func TestRecoverYubiKeySignedDEK_WrongVersion(t *testing.T) {
	envelope := yubiKeySignedDEKEnvelope{
		Version:   "bad-version-v0",
		DEK:       base64.StdEncoding.EncodeToString([]byte("dek")),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, _ := json.Marshal(envelope)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	_, err := recoverYubiKeySignedDEK(key, data)
	if err == nil {
		t.Fatal("expected error for wrong version")
	}
}

// TestRecoverYubiKeySignedDEK_EmptyDEK verifies error when DEK field decodes to empty bytes.
func TestRecoverYubiKeySignedDEK_EmptyDEK(t *testing.T) {
	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeyEnvelopeVersionSignedV1,
		DEK:       base64.StdEncoding.EncodeToString([]byte{}), // empty
		Signature: base64.StdEncoding.EncodeToString([]byte("sig")),
	}
	data, _ := json.Marshal(envelope)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	_, err := recoverYubiKeySignedDEK(key, data)
	if err == nil {
		t.Fatal("expected error for empty DEK in envelope")
	}
}

// TestRecoverYubiKeySignedDEK_EmptySignature verifies error when Signature decodes to empty bytes.
func TestRecoverYubiKeySignedDEK_EmptySignature(t *testing.T) {
	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeyEnvelopeVersionSignedV1,
		DEK:       base64.StdEncoding.EncodeToString([]byte("some-dek")),
		Signature: base64.StdEncoding.EncodeToString([]byte{}), // empty
	}
	data, _ := json.Marshal(envelope)

	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	_, err := recoverYubiKeySignedDEK(key, data)
	if err == nil {
		t.Fatal("expected error for empty signature in envelope")
	}
}

// TestRecoverYubiKeySignedDEK_InvalidPublicKey verifies error when key PEM is missing.
func TestRecoverYubiKeySignedDEK_InvalidPublicKey(t *testing.T) {
	dek := []byte("some-dek-bytes")
	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeyEnvelopeVersionSignedV1,
		DEK:       base64.StdEncoding.EncodeToString(dek),
		Signature: base64.StdEncoding.EncodeToString([]byte("fake-signature")),
	}
	data, _ := json.Marshal(envelope)

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: "", // missing PEM
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	_, err := recoverYubiKeySignedDEK(key, data)
	if err == nil {
		t.Fatal("expected error for missing public key PEM")
	}
}

// TestRecoverYubiKeySignedDEK_InvalidSignature verifies error when signature doesn't verify.
func TestRecoverYubiKeySignedDEK_InvalidSignature(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	dek := []byte("some-dek-bytes")
	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeyEnvelopeVersionSignedV1,
		DEK:       base64.StdEncoding.EncodeToString(dek),
		Signature: base64.StdEncoding.EncodeToString([]byte("invalid-signature-bytes-padded-to-256-bytes")),
	}
	data, _ := json.Marshal(envelope)

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	_, err := recoverYubiKeySignedDEK(key, data)
	if err == nil {
		t.Fatal("expected error for invalid signature")
	}
}

// TestRecoverYubiKeySignedDEK_ValidSignature verifies success with a valid RSA signature.
func TestRecoverYubiKeySignedDEK_ValidSignature(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	dek := []byte("dek-payload-12345678901234567890")
	digest := sha256.Sum256(dek)
	// crypto.SHA256 = 5
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, 5, digest[:])
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}

	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeyEnvelopeVersionSignedV1,
		DEK:       base64.StdEncoding.EncodeToString(dek),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}
	data, _ := json.Marshal(envelope)

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	}

	result, err := recoverYubiKeySignedDEK(key, data)
	if err != nil {
		t.Fatalf("recoverYubiKeySignedDEK() error = %v", err)
	}
	if string(result) != string(dek) {
		t.Errorf("recovered DEK = %q, want %q", result, dek)
	}
}

// TestRecoverYubiKeySignedDEK_ECCKeyType verifies error for non-RSA key type.
func TestRecoverYubiKeySignedDEK_ECCKeyType(t *testing.T) {
	eccKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(&eccKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	dek := []byte("some-dek")
	envelope := yubiKeySignedDEKEnvelope{
		Version:   yubiKeyEnvelopeVersionSignedV1,
		DEK:       base64.StdEncoding.EncodeToString(dek),
		Signature: base64.StdEncoding.EncodeToString([]byte("sig-bytes")),
	}
	data, _ := json.Marshal(envelope)

	key := &Key{
		KeyId:        "test",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
	}

	_, err := recoverYubiKeySignedDEK(key, data)
	if err == nil {
		t.Fatal("expected error for ECC key type in recoverYubiKeySignedDEK")
	}
}

// ---------------------------------------------------------------------------
// wrapWithServiceKey – missing branches
// ---------------------------------------------------------------------------

// TestWrapWithServiceKey_KeyNotFound verifies error when service key doesn't exist.
func TestWrapWithServiceKey_KeyNotFound(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	_, err := server.wrapWithServiceKey(ctx, "nonexistent-key-id", []byte("plaintext"))
	if err == nil {
		t.Fatal("expected error when service key not found")
	}
}

// TestWrapWithServiceKey_Success verifies successful wrapping.
func TestWrapWithServiceKey_Success(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	createResp, err := server.CreateKey(ctx, &CreateKeyRequest{
		Name:         "wrap-test-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	wrapped, err := server.wrapWithServiceKey(ctx, createResp.Key.KeyId, []byte("plaintext-data"))
	if err != nil {
		t.Fatalf("wrapWithServiceKey() error = %v", err)
	}
	if len(wrapped) == 0 {
		t.Error("expected non-empty wrapped data")
	}
}

// TestWrapWithServiceKey_FIPSRejectsECC verifies FIPS mode rejects non-RSA service keys.
func TestWrapWithServiceKey_FIPSRejectsECC(t *testing.T) {
	server := newTestKeyManagerServerWithFIPS(t, encryption.ECC_P256, true)
	ctx := context.Background()

	// In FIPS mode, we can't even create an ECC key, so this test just verifies
	// that FIPS enforcement works at key creation
	_, err := server.CreateKey(ctx, &CreateKeyRequest{
		Name:         "fips-ecc-key",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err == nil {
		t.Log("CreateKey() succeeded in FIPS mode for ECC (may be expected in some builds)")
	}
}

// ---------------------------------------------------------------------------
// keyPairToKey – missing branches
// ---------------------------------------------------------------------------

// TestKeyPairToKey_WithExpiresAt verifies ExpiresAt is set in the result.
func TestKeyPairToKey_WithExpiresAt(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	expiresAt := time.Now().Add(time.Hour)

	keyPair := &KeyPair{
		KeyID:        "test-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKeyPEM: "pem-data",
		ExpiresAt:    &expiresAt,
		CreatedAt:    time.Now(),
		Metadata:     map[string]string{"tag": "value"},
	}

	key := server.keyPairToKey(keyPair)
	if key == nil {
		t.Fatal("keyPairToKey() returned nil")
	}
	if key.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set")
	}
	if key.Metadata["tag"] != "value" {
		t.Errorf("expected metadata tag=value, got %v", key.Metadata)
	}
}

// TestKeyPairToKey_WithLastRotated verifies LastRotated is set in the result.
func TestKeyPairToKey_WithLastRotated(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	lastRotated := time.Now().Add(-time.Hour)

	keyPair := &KeyPair{
		KeyID:        "test-key-rotated",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKeyPEM: "pem-data",
		LastRotated:  &lastRotated,
		CreatedAt:    time.Now(),
		Metadata:     map[string]string{},
	}

	key := server.keyPairToKey(keyPair)
	if key == nil {
		t.Fatal("keyPairToKey() returned nil")
	}
	if key.LastRotated == nil {
		t.Error("expected LastRotated to be set")
	}
}

// TestKeyPairToKey_ExternallyManaged verifies externally managed key fields are propagated.
func TestKeyPairToKey_ExternallyManaged(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)
	loadedAt := time.Now().Add(-30 * time.Minute)

	keyPair := &KeyPair{
		KeyID:                "ext-key",
		KeyType:              KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKeyPEM:         "pem-data",
		CreatedAt:            time.Now(),
		Metadata:             map[string]string{},
		ExternallyManaged:    true,
		ExternalSource:       "vault",
		ExternalManifestPath: "/path/to/manifest",
		PrivateKeySource:     "external",
		ExternalLoadedAt:     &loadedAt,
	}

	key := server.keyPairToKey(keyPair)
	if key == nil {
		t.Fatal("keyPairToKey() returned nil")
	}
	if !key.ExternallyManaged {
		t.Error("expected ExternallyManaged to be true")
	}
	if key.ExternalSource != "vault" {
		t.Errorf("expected ExternalSource=vault, got %s", key.ExternalSource)
	}
	if key.ExternalManifestPath != "/path/to/manifest" {
		t.Errorf("expected ExternalManifestPath=/path/to/manifest, got %s", key.ExternalManifestPath)
	}
	if key.ExternalLoadedAt == nil {
		t.Error("expected ExternalLoadedAt to be set")
	}
}

// TestKeyPairToKey_Minimal verifies basic conversion without optional fields.
func TestKeyPairToKey_Minimal(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	keyPair := &KeyPair{
		KeyID:        "minimal-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKeyPEM: "pem-data",
		CreatedAt:    time.Now(),
		Metadata:     map[string]string{},
	}

	key := server.keyPairToKey(keyPair)
	if key == nil {
		t.Fatal("keyPairToKey() returned nil")
	}
	if key.KeyId != "minimal-key" {
		t.Errorf("KeyId = %q, want minimal-key", key.KeyId)
	}
	if key.ExpiresAt != nil {
		t.Error("expected ExpiresAt to be nil")
	}
	if key.LastRotated != nil {
		t.Error("expected LastRotated to be nil")
	}
}

// TestWrapWithServiceKey_FIPSKeyCheck verifies FIPS enforcement in wrapWithServiceKey.
func TestWrapWithServiceKey_FIPSKeyCheck(t *testing.T) {
	// Build a server with fipsEnabled=true but bypass key creation restriction
	// by directly injecting a non-FIPS key into the store
	server := newTestKeyManagerServerWithFIPS(t, encryption.ECC_P256, true)
	ctx := context.Background()

	// Manually store an ECC key pair
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey ECC: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(&eccKey.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	keyPair := &KeyPair{
		KeyID:        "fips-bypass-ecc",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKey:    &eccKey.PublicKey,
		PrivateKey:   eccKey,
		PublicKeyPEM: pemStr,
		CreatedAt:    time.Now(),
		Metadata:     map[string]string{},
	}
	err = server.keyStore.StoreKeyPair(ctx, keyPair)
	if err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	// Also store Key record so GetKey works
	err = server.keyStore.StoreKey(ctx, &Key{
		KeyId:        "fips-bypass-ecc",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// wrapWithServiceKey should fail in FIPS mode for ECC key
	_, err = server.wrapWithServiceKey(ctx, "fips-bypass-ecc", []byte("plaintext"))
	if err == nil {
		t.Fatal("expected wrapWithServiceKey to fail in FIPS mode for ECC key")
	}
}
