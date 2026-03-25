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
	"testing"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// admin_key.go: CompositeAdminKeyProvider.GetAdminKey —
// "no admin key provider succeeded" branch (lastErr == nil, but key wrong len)
// ---------------------------------------------------------------------------

// TestCompositeAdminKeyProvider_GetAdminKey_WrongLengthNoError covers the branch
// where every provider succeeds (err==nil) but returns a key of the wrong length,
// so lastErr stays nil and we hit the "no admin key provider succeeded" return.
func TestCompositeAdminKeyProvider_GetAdminKey_WrongLengthNoError(t *testing.T) {
	provider1 := NewMockAdminKeyProvider()
	provider1.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return make([]byte, 16), nil // wrong length, no error
	}

	composite := NewCompositeAdminKeyProvider(provider1)
	_, err := composite.GetAdminKey(context.Background())
	if err == nil {
		t.Fatal("expected error for wrong-length key with no provider error")
	}
}

// ---------------------------------------------------------------------------
// hsm_provider.go: NewHSMKeyProvider with non-nil config
// ---------------------------------------------------------------------------

// TestNewHSMKeyProvider_WithConfig exercises the `if config != nil` branch.
func TestNewHSMKeyProvider_WithConfig(t *testing.T) {
	p := NewHSMKeyProvider(map[string]string{
		"hsm_endpoint": "mock",
	})
	if p == nil {
		t.Fatal("NewHSMKeyProvider returned nil")
	}
	if !p.IsAvailable() {
		t.Fatal("expected provider to be available when config is supplied")
	}
	cfg := p.GetConfiguration()
	if cfg["hsm_endpoint"] != "mock" {
		t.Errorf("expected hsm_endpoint=mock in config, got %v", cfg)
	}
}

// Note: HSMKeyProvider.DeleteKeyPair, GenerateKeyPair, RotateKey have a mutex deadlock
// bug (write lock held while calling IsAvailable which takes read lock), so those are
// not tested here.

// ---------------------------------------------------------------------------
// client_key_store.go: publicKeyToPEM — extra branches
// ---------------------------------------------------------------------------

// TestClientKeyStore_PublicKeyToPEM_RSA3072 covers the RSA-3072 branch.
func TestClientKeyStore_PublicKeyToPEM_RSA3072(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("GenerateKey RSA-3072: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM RSA-3072 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_3072 {
		t.Errorf("expected KEY_TYPE_RSA_3072, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_RSA4096 covers the RSA-4096 branch.
func TestClientKeyStore_PublicKeyToPEM_RSA4096(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("GenerateKey RSA-4096: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM RSA-4096 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_RSA_4096 {
		t.Errorf("expected KEY_TYPE_RSA_4096, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_ECCP384 covers the ECC P-384 branch.
func TestClientKeyStore_PublicKeyToPEM_ECCP384(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P384: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P384 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P384 {
		t.Errorf("expected KEY_TYPE_ECC_P384, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_ECCP521 covers the ECC P-521 branch.
func TestClientKeyStore_PublicKeyToPEM_ECCP521(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey P521: %v", err)
	}
	pemStr, kt, err := store.publicKeyToPEM(&priv.PublicKey)
	if err != nil {
		t.Fatalf("publicKeyToPEM P521 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_ECC_P521 {
		t.Errorf("expected KEY_TYPE_ECC_P521, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_KyberKey covers the Kyber public key branch.
func TestClientKeyStore_PublicKeyToPEM_KyberKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	pub512, _, err := kyber512.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512: %v", err)
	}

	pemStr, kt, err := store.publicKeyToPEM(pub512)
	if err != nil {
		t.Fatalf("publicKeyToPEM Kyber512 error = %v", err)
	}
	if kt != KeyType_KEY_TYPE_KYBER_512 {
		t.Errorf("expected KEY_TYPE_KYBER_512, got %v", kt)
	}
	if pemStr == "" {
		t.Error("expected non-empty PEM")
	}
}

// TestClientKeyStore_PublicKeyToPEM_UnsupportedType covers the unsupported key type branch.
func TestClientKeyStore_PublicKeyToPEM_UnsupportedType(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	type weirdKey struct{}
	_, _, err := store.publicKeyToPEM(weirdKey{})
	if err == nil {
		t.Fatal("expected error for unsupported public key type")
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go: StoreClientPublicKey
// ---------------------------------------------------------------------------

// TestStoreClientPublicKey_RSA exercises StoreClientPublicKey with RSA key.
func TestStoreClientPublicKey_RSA(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	err = store.StoreClientPublicKey(ctx, "alice-store-rsa", &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreClientPublicKey: %v", err)
	}

	// Retrieve back
	pubKey, err := store.GetClientPublicKey(ctx, "alice-store-rsa")
	if err != nil {
		t.Fatalf("GetClientPublicKey: %v", err)
	}
	if pubKey == nil {
		t.Fatal("expected non-nil public key")
	}
}

// TestStoreClientPublicKey_ECC exercises StoreClientPublicKey with ECC key.
func TestStoreClientPublicKey_ECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	err = store.StoreClientPublicKey(ctx, "bob-store-ecc", &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreClientPublicKey ECC: %v", err)
	}
}

// TestStoreClientPublicKey_Kyber exercises StoreClientPublicKey with Kyber key.
func TestStoreClientPublicKey_Kyber(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	pub, _, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768: %v", err)
	}

	err = store.StoreClientPublicKey(ctx, "charlie-store-kyber", pub)
	if err != nil {
		t.Fatalf("StoreClientPublicKey Kyber768: %v", err)
	}
}

// TestStoreClientPublicKey_EmptySubject covers the empty subject branch.
func TestStoreClientPublicKey_EmptySubject(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	err := store.StoreClientPublicKey(ctx, "", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for empty subject")
	}
}

// TestStoreClientPublicKey_NilKey covers the nil key branch.
func TestStoreClientPublicKey_NilKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	err := store.StoreClientPublicKey(ctx, "dave-nil-key", nil)
	if err == nil {
		t.Fatal("expected error for nil public key")
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go: GetClientPublicKey — cache miss (parsed key not cached)
// ---------------------------------------------------------------------------

// TestGetClientPublicKey_CacheMiss covers the "not cached → parse" path.
func TestGetClientPublicKey_CacheMiss(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	key := &Key{
		KeyId:        "cache-miss-key",
		ClientId:     "alice-cache",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := store.RegisterKey(ctx, key); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	// Delete from cache to force re-parse
	store.mu.Lock()
	delete(store.parsedKeyCache, "cache-miss-key")
	store.mu.Unlock()

	pub, err := store.GetClientPublicKey(ctx, "alice-cache")
	if err != nil {
		t.Fatalf("GetClientPublicKey (cache miss): %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
}

// ---------------------------------------------------------------------------
// key_encryption.go: ConvertPrivateKeyToPEM — unsupported type
// ---------------------------------------------------------------------------

// TestConvertPrivateKeyToPEM_CompletelyUnsupportedKeyType covers the final unsupported branch.
func TestConvertPrivateKeyToPEM_CompletelyUnsupportedKeyType(t *testing.T) {
	type weirdKey struct{}
	_, err := ConvertPrivateKeyToPEM(&weirdKey{}, KeyType_KEY_TYPE_UNSPECIFIED)
	if err == nil {
		t.Fatal("expected error for unsupported key type in ConvertPrivateKeyToPEM")
	}
}

// TestConvertPrivateKeyToPEM_KyberDisabledPath covers the Kyber "disabled" fallback.
// Passing a non-Kyber concrete type to ConvertPrivateKeyToPEM with a Kyber key type causes
// convertKyberPrivateKeyToPEM to return handled=false, hitting the "disabled" branch.
func TestConvertPrivateKeyToPEM_KyberDisabledPath(t *testing.T) {
	type fakeKyberKey struct{}
	_, err := ConvertPrivateKeyToPEM(&fakeKyberKey{}, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for fake Kyber key type in ConvertPrivateKeyToPEM")
	}
}

// ---------------------------------------------------------------------------
// key_encryption.go: deserializePrivateKey — parse error and wrong type
// ---------------------------------------------------------------------------

// TestDeserializePrivateKey_RSAParseError covers the RSA "parse fails" branch.
func TestDeserializePrivateKey_RSAParseError(t *testing.T) {
	_, err := deserializePrivateKey([]byte("garbage-not-a-key"), KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error for invalid RSA private key bytes")
	}
}

// TestDeserializePrivateKey_ECCParseError covers the ECC "parse fails" branch.
func TestDeserializePrivateKey_ECCParseError(t *testing.T) {
	_, err := deserializePrivateKey([]byte("garbage-not-a-key"), KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error for invalid ECC private key bytes")
	}
}

// TestDeserializePrivateKey_RSAWrongKeyType covers the case where PKCS8 parses
// but the resulting key is not RSA (contains an ECC key instead).
func TestDeserializePrivateKey_RSAWrongKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	_, err = deserializePrivateKey(der, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error when ECC bytes are parsed as RSA key type")
	}
}

// TestDeserializePrivateKey_ECCWrongKeyType covers the case where PKCS8 parses
// but the resulting key is not ECC (contains an RSA key instead).
func TestDeserializePrivateKey_ECCWrongKeyType(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	_, err = deserializePrivateKey(der, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error when RSA bytes are parsed as ECC key type")
	}
}

// ---------------------------------------------------------------------------
// software_provider_kyber.go: decryptWithKyber / encryptWithKyber — default branch
// ---------------------------------------------------------------------------

// TestDecryptWithKyber_UnknownPrivateKeyType covers the default (false) branch.
func TestDecryptWithKyber_UnknownPrivateKeyType(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	type notAKyberKey struct{}
	plaintext, handled, err := provider.decryptWithKyber(&notAKyberKey{}, []byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatal("expected handled=false for unknown private key type")
	}
	if plaintext != nil {
		t.Fatal("expected nil plaintext for unhandled type")
	}
}

// TestEncryptWithKyber_UnknownPublicKeyType covers the default (false) branch.
func TestEncryptWithKyber_UnknownPublicKeyType(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	type notAKyberKey struct{}
	ct, handled, err := provider.encryptWithKyber(&notAKyberKey{}, []byte("data"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if handled {
		t.Fatal("expected handled=false for unknown public key type")
	}
	if ct != nil {
		t.Fatal("expected nil ciphertext for unhandled type")
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go: GetActiveKeyForClient — expired key skip
// ---------------------------------------------------------------------------

// TestGetActiveKeyForClient_ExpiredKey covers the "key is expired" skip path.
func TestGetActiveKeyForClient_ExpiredKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	pastTime := time.Now().Add(-1 * time.Hour)
	key := &Key{
		KeyId:        "expired-client-key-final",
		ClientId:     "expiry-user-final",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		ExpiresAt:    timestamppb.New(pastTime), // already expired
	}
	if err := store.RegisterKey(ctx, key); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}

	_, err := store.GetActiveKeyForClient(ctx, "expiry-user-final")
	if err == nil {
		t.Fatal("expected error: no active key because only key is expired")
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go: GetActiveKeyForClient — key exists in clientKeys but
// not in keys map (orphan key ID)
// ---------------------------------------------------------------------------

// TestGetActiveKeyForClient_OrphanKeyID covers the `if !exists { continue }` branch
// where a keyID is in clientKeys but the corresponding key is missing from keys.
func TestGetActiveKeyForClient_OrphanKeyID(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Directly insert an orphan keyID into clientKeys without a corresponding key record
	store.mu.Lock()
	store.clientKeys["orphan-user"] = []string{"missing-key-id"}
	store.mu.Unlock()

	_, err := store.GetActiveKeyForClient(ctx, "orphan-user")
	if err == nil {
		t.Fatal("expected error when orphan key ID exists without corresponding key record")
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go: ListKeysForClient — orphan key ID branch
// ---------------------------------------------------------------------------

// TestListKeysForClient_OrphanKeyID covers the `if !exists { continue }` branch.
func TestListKeysForClient_OrphanKeyID(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Insert orphan keyID
	store.mu.Lock()
	store.clientKeys["orphan-list-user"] = []string{"missing-key-id"}
	store.mu.Unlock()

	keys, err := store.ListKeysForClient(ctx, "orphan-list-user", true)
	if err != nil {
		t.Fatalf("ListKeysForClient unexpected error: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for orphan user, got %d", len(keys))
	}
}
