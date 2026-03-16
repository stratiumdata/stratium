//go:build !fips

package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"stratium/pkg/security/encryption"
)

// ---------------------------------------------------------------------------
// ecies.go: line 107-109 — "ciphertext missing nonce"
// Provide a valid ephemeral point (on curve) but ciphertext shorter than nonce
// ---------------------------------------------------------------------------

func TestDecryptDEKWithECCPrivateKey_ShortNonce(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P256 key: %v", err)
	}
	ephemeral, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ephemeral key: %v", err)
	}

	coordSize := (key.Curve.Params().BitSize + 7) / 8
	xBytes := ephemeral.PublicKey.X.FillBytes(make([]byte, coordSize))
	yBytes := ephemeral.PublicKey.Y.FillBytes(make([]byte, coordSize))
	// Valid 64-byte header (P256 ephemeral point) + only 3 bytes of "ciphertext" < 12-byte GCM nonce
	data := append(append(xBytes, yBytes...), 0x01, 0x02, 0x03)

	_, err = decryptDEKWithECCPrivateKey(key, data)
	if err == nil {
		t.Fatal("expected error for ciphertext missing nonce")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Errorf("expected 'nonce' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// dek_service.go: publicKeyToPEM — unsupported RSA size (covers line 315-316)
// ---------------------------------------------------------------------------

func TestDEKPublicKeyToPEM_RSA1024(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	_, _, err = publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024 (unsupported size)")
	}
	if !strings.Contains(err.Error(), "unsupported RSA") {
		t.Errorf("expected unsupported RSA error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// dek_service.go: publicKeyToPEM — unsupported ECC curve (covers line 343-344)
// ---------------------------------------------------------------------------

func TestDEKPublicKeyToPEM_ECCP224(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P224: %v", err)
	}
	_, _, err = publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224 (unsupported curve)")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected unsupported ECC curve error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// dek_service.go: RegisterClientPublicKey with invalid PEM (covers line 393-395)
// ---------------------------------------------------------------------------

func TestRegisterClientPublicKey_InvalidPEM(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	err := srv.dekService.RegisterClientPublicKey(context.Background(), "user1", "not-a-valid-pem")
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

// ---------------------------------------------------------------------------
// dek_service.go: RegisterClientPublicKey with RSA-1024 (covers line 399-401)
// publicKeyToPEM fails for RSA-1024 which covers the conversion error path
// ---------------------------------------------------------------------------

func TestRegisterClientPublicKey_RSA1024PEM(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	// Manually build a PEM (bypassing our publicKeyToPEM size check) so that
	// RegisterClientPublicKey can parse the PEM but then fails on conversion.
	derBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA-1024 public key DER: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))
	err = srv.dekService.RegisterClientPublicKey(context.Background(), "user1", pemStr)
	if err == nil {
		t.Fatal("expected error for RSA-1024 (unsupported size in RegisterClientPublicKey)")
	}
}

// ---------------------------------------------------------------------------
// server_client_keys.go: GetClientKey with no auth (covers line 121-128)
// ---------------------------------------------------------------------------

func TestGetClientKey_NoAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	resp, err := srv.GetClientKey(context.Background(), &GetClientKeyRequest{
		KeyId:    "any-key",
		ClientId: "app-1",
	})
	if err != nil {
		t.Fatalf("GetClientKey unexpected gRPC error: %v", err)
	}
	if resp.Found {
		t.Error("GetClientKey should return Found=false without auth")
	}
}

// ---------------------------------------------------------------------------
// server_client_keys.go: GetClientKey integrity failure (covers line 175-182)
// Tamper with the stored key's integrity hash after registration
// ---------------------------------------------------------------------------

func TestGetClientKey_IntegrityFailure(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Register a key
	regResp, err := srv.RegisterClientKey(ctxWithUser("tamper-user"), &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})
	if err != nil || !regResp.Success {
		t.Fatalf("RegisterClientKey failed: %v %v", err, regResp.GetErrorMessage())
	}
	keyID := regResp.Key.KeyId

	// Tamper: access the internal store and corrupt the hash
	store := srv.clientKeyStore.(*InMemoryClientKeyStore)
	store.mu.Lock()
	if k, ok := store.keys[keyID]; ok {
		k.KeyIntegrityHash = "corrupted-hash"
	}
	store.mu.Unlock()

	// GetClientKey should now fail integrity check
	getResp, err := srv.GetClientKey(ctxWithUser("tamper-user"), &GetClientKeyRequest{
		KeyId:    keyID,
		ClientId: "app-1",
	})
	if err != nil {
		t.Fatalf("GetClientKey unexpected gRPC error: %v", err)
	}
	if getResp.Found {
		t.Error("GetClientKey should return Found=false for tampered key")
	}
}
