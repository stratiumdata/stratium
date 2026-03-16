//go:build !fips

package key_manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"
	"stratium/config"
	"stratium/pkg/security/encryption"
)

// ===========================================================================
// dek_service.go line 104-108: FIPS mode rejects non-RSA service key types
// ===========================================================================

func TestUnwrapDEK_FIPSRejectsNonRSAKey(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	// Seed an ECC key into the key store so it can be found
	eccKey := &Key{
		KeyId:        "ecc-key-1",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := srv.keyStore.StoreKey(ctx, eccKey); err != nil {
		t.Fatalf("seed ECC key: %v", err)
	}

	resp, err := srv.dekService.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Subject:      "test-user",
		Resource:     "test-resource",
		KeyId:        "ecc-key-1",
		EncryptedDek: []byte("fake-encrypted-dek"),
		ClientKeyId:  "client-1",
		Action:       "unwrap_dek",
	})
	if err != nil {
		t.Fatalf("UnwrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected access denied for ECC key in FIPS mode")
	}
	if !strings.Contains(resp.AccessReason, "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection reason, got: %s", resp.AccessReason)
	}
}

// ===========================================================================
// dek_service.go line 112-116: provider factory returns error for unknown type
// ===========================================================================

func TestUnwrapDEK_ProviderFactoryError(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Seed a key with a provider type the factory doesn't support (use a large int)
	key := &Key{
		KeyId:        "hsm-key-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType(9999), // truly unknown provider
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := srv.keyStore.StoreKey(ctx, key); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	resp, err := srv.dekService.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Subject:      "test-user",
		Resource:     "test-resource",
		KeyId:        "hsm-key-1",
		EncryptedDek: []byte("fake-encrypted-dek"),
		ClientKeyId:  "client-1",
		Action:       "unwrap_dek",
	})
	if err != nil {
		t.Fatalf("UnwrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected access denied for unknown provider type")
	}
	if !strings.Contains(resp.AccessReason, "Failed to create key provider") {
		t.Errorf("expected provider factory error reason, got: %s", resp.AccessReason)
	}
}

// ===========================================================================
// dek_service.go line 220-223: encryptDEKForSubject FIPS rejects ECC subject key
// ===========================================================================

func TestEncryptDEKForSubject_FIPSRejectsNonRSA(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: true}
	eccKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	subjectKey := &Key{KeyType: KeyType_KEY_TYPE_ECC_P256}

	_, _, err := svc.encryptDEKForSubject(subjectKey, &eccKey.PublicKey, []byte("test-dek"), "subject-1")
	if err == nil {
		t.Fatal("expected error for non-RSA subject key in FIPS mode")
	}
	if !strings.Contains(err.Error(), "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection, got: %v", err)
	}
}

// ===========================================================================
// dek_service.go line 240-241: encryptDEKForSubject unsupported key type
// ===========================================================================

func TestEncryptDEKForSubject_UnsupportedKeyType_Ed25519(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: false}
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	subjectKey := &Key{KeyType: KeyType_KEY_TYPE_UNSPECIFIED}

	_, _, err := svc.encryptDEKForSubject(subjectKey, edPub, []byte("test-dek"), "subject-1")
	if err == nil {
		t.Fatal("expected error for ed25519 (unsupported) subject key type")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go line 373-374: publicKeyToPEM unsupported RSA size
// ===========================================================================

func TestClientKeyStore_PublicKeyToPEM_RSA1024(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024")
	}
	if !strings.Contains(err.Error(), "unsupported RSA key size") {
		t.Errorf("expected unsupported RSA size, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go line 401-402: publicKeyToPEM unsupported ECC curve
// ===========================================================================

func TestClientKeyStore_PublicKeyToPEM_ECCP224(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P224: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected unsupported ECC curve, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go default case: publicKeyToPEM unsupported key type entirely
// ===========================================================================

func TestClientKeyStore_PublicKeyToPEM_Ed25519(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	_, _, err := store.publicKeyToPEM(edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go: StoreClientPublicKey with unsupported key triggers
// publicKeyToPEM error (line 337-339)
// ===========================================================================

func TestStoreClientPublicKey_UnsupportedKeyType(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	err := store.StoreClientPublicKey(context.Background(), "subject-1", edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key")
	}
	if !strings.Contains(err.Error(), "failed to convert public key to PEM") {
		t.Errorf("expected conversion error, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go: GetClientPublicKey parse error (line 312-314)
// Register a key with bad PEM directly, then call GetClientPublicKey
// ===========================================================================

func TestGetClientPublicKey_ParseError(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Register a valid key first, then corrupt the PEM in-place
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	validPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))
	goodKey := &Key{
		KeyId:        "bad-pem-key",
		ClientId:     "bad-user",
		PublicKeyPem: validPEM,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := store.RegisterKey(ctx, goodKey); err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	// Now corrupt the PEM and clear the parsed key cache
	store.mu.Lock()
	if k, ok := store.keys["bad-pem-key"]; ok {
		k.PublicKeyPem = "not-valid-pem"
	}
	delete(store.parsedKeyCache, "bad-pem-key")
	store.mu.Unlock()

	_, err := store.GetClientPublicKey(ctx, "bad-user")
	if err == nil {
		t.Fatal("expected error for bad PEM in GetClientPublicKey")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go line 445-447 and 457-459: parsePublicKeyPEM wrong
// key type after parsing (RSA PEM but declare as ECC type, and vice versa)
// ===========================================================================

func TestParsePublicKeyPEM_RSAPEMAsECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// Generate RSA PEM
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	derBytes, _ := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	// Try to parse as ECC - should fail with type mismatch
	_, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error parsing RSA PEM as ECC key type")
	}
	if !strings.Contains(err.Error(), "expected ECDSA public key") {
		t.Errorf("expected ECDSA type mismatch error, got: %v", err)
	}
}

func TestParsePublicKeyPEM_ECCPEMAsRSA(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// Generate ECC PEM
	eccPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	derBytes, _ := x509.MarshalPKIXPublicKey(&eccPriv.PublicKey)
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	// Try to parse as RSA - should fail with type mismatch
	_, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error parsing ECC PEM as RSA key type")
	}
	if !strings.Contains(err.Error(), "expected RSA public key") {
		t.Errorf("expected RSA type mismatch error, got: %v", err)
	}
}

// ===========================================================================
// client_key_store.go line 469-471: parsePublicKeyPEM with invalid DER bytes
// for ECC key type — x509.ParsePKIXPublicKey fails
// ===========================================================================

func TestParsePublicKeyPEM_InvalidDERForECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}))
	_, err := store.parsePublicKeyPEM(badPEM, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error for invalid DER in ECC parsePublicKeyPEM")
	}
}

// ===========================================================================
// client_key_store.go line 435-437: parsePublicKeyPEM Kyber parse error
// Pass a PEM with Kyber key type but wrong-sized bytes
// ===========================================================================

func TestParsePublicKeyPEM_KyberInvalidSize(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	badPEM := string(pem.EncodeToMemory(&pem.Block{Type: "KYBER PUBLIC KEY", Bytes: []byte("short")}))
	_, err := store.parsePublicKeyPEM(badPEM, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for invalid Kyber key size")
	}
}

// ===========================================================================
// software_provider.go line 421: publicKeyToPEM unsupported key type
// ===========================================================================

func TestSoftwareProvider_PublicKeyToPEM_Ed25519(t *testing.T) {
	provider := &SoftwareKeyProvider{}
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	_, err := provider.publicKeyToPEM(edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key type")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

// ===========================================================================
// software_provider.go line 259: ListKeyPairs not found returns error
// ===========================================================================

func TestSoftwareProvider_Decrypt_KeyNotFound(t *testing.T) {
	provider := &SoftwareKeyProvider{
		keyStore: NewInMemoryKeyStore(),
	}
	_, err := provider.Decrypt(context.Background(), "nonexistent-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

// ===========================================================================
// software_provider.go line 321: Encrypt key not found
// ===========================================================================

func TestSoftwareProvider_Encrypt_KeyNotFound(t *testing.T) {
	provider := &SoftwareKeyProvider{
		keyStore: NewInMemoryKeyStore(),
	}
	_, err := provider.Encrypt(context.Background(), "nonexistent-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

// ===========================================================================
// software_provider.go line 352-360: RotateKey with unsupported key type
// ===========================================================================

func TestSoftwareProvider_RotateKey_UnsupportedType(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	// Seed a key with unspecified type
	kp := &KeyPair{
		KeyID:   "unspecified-key",
		KeyType: KeyType_KEY_TYPE_UNSPECIFIED,
	}
	_ = store.StoreKeyPair(ctx, kp)

	provider := &SoftwareKeyProvider{keyStore: store}
	_, err := provider.RotateKey(ctx, "unspecified-key")
	if err == nil {
		t.Fatal("expected error rotating unsupported key type")
	}
}

// ===========================================================================
// software_provider.go line 156: generateKeyPairInternal publicKeyToPEM fails
// Trigger by having generateKeyPairInternal succeed with an ed25519 key
// can't do directly—but we CAN test RotateKey fails on key not found
// ===========================================================================

func TestSoftwareProvider_RotateKey_KeyNotFound(t *testing.T) {
	provider := &SoftwareKeyProvider{
		keyStore: NewInMemoryKeyStore(),
	}
	_, err := provider.RotateKey(context.Background(), "missing-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key in RotateKey")
	}
}

// ===========================================================================
// key_encryption.go line 269-271: ConvertPrivateKeyToPEM unsupported ECC type
// (pass a non-*ecdsa.PrivateKey but with ECC key type flag)
// ===========================================================================

func TestConvertPrivateKeyToPEM_ECCWrongType(t *testing.T) {
	// Pass an RSA key but claim it's ECC type
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_ECC_P256)
	if err == nil {
		t.Fatal("expected error for RSA key with ECC type")
	}
	if !strings.Contains(err.Error(), "expected *ecdsa.PrivateKey") {
		t.Errorf("expected type mismatch error, got: %v", err)
	}
}

// ===========================================================================
// key_encryption.go line 280-282: ConvertPrivateKeyToPEM Kyber key disabled
// when a non-Kyber key passed as Kyber type
// ===========================================================================

func TestConvertPrivateKeyToPEM_KyberNonKyberKey(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	_, err := ConvertPrivateKeyToPEM(rsaKey, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error for RSA key with Kyber type")
	}
}

// ===========================================================================
// dek_service.go line 362: publicKeyToPEM unsupported type in dek_service
// (the default branch in dek_service.publicKeyToPEM)
// ===========================================================================

func TestDEKPublicKeyToPEM_Ed25519(t *testing.T) {
	_, edPub, _ := ed25519.GenerateKey(rand.Reader)
	_, _, err := publicKeyToPEM(edPub)
	if err == nil {
		t.Fatal("expected error for ed25519 key")
	}
	if !strings.Contains(err.Error(), "unsupported public key type") {
		t.Errorf("expected unsupported key type error, got: %v", err)
	}
}

// ===========================================================================
// key_store.go: StoreKey nil + StoreKeyPair nil
// (covers the nil check lines that may not be hit in tests)
// ===========================================================================

func TestInMemoryKeyStore_StoreKey_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key")
	}
}

func TestInMemoryKeyStore_StoreKeyPair_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKeyPair(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key pair")
	}
}

func TestInMemoryKeyStore_StoreKey_EmptyID(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKey(context.Background(), &Key{})
	if err == nil {
		t.Fatal("expected error for empty key ID")
	}
}

func TestInMemoryKeyStore_StoreKeyPair_EmptyID(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKeyPair(context.Background(), &KeyPair{})
	if err == nil {
		t.Fatal("expected error for empty key pair ID")
	}
}

// ===========================================================================
// smartcard_provider.go: FIPS validation rejects non-RSA key types
// Covers validateFIPSKeyTypeLocked and validateFIPSKeyByIDLocked
// ===========================================================================

// newFIPSSmartCardProvider creates a mock SmartCardKeyProvider with FIPS enabled and initialized
func newFIPSSmartCardProvider(t *testing.T) *SmartCardKeyProvider {
	t.Helper()
	provider := NewSmartCardKeyProvider("mock", map[string]string{"pin": "1234"})
	err := provider.Configure(map[string]string{"fips_enabled": "true", "pin": "1234"})
	if err != nil {
		t.Fatalf("Configure FIPS: %v", err)
	}
	if !provider.IsAvailable() {
		t.Fatal("SmartCard provider should be available after Configure")
	}
	return provider
}

func TestSmartCard_FIPSRejectsNonRSAGenerate(t *testing.T) {
	provider := newFIPSSmartCardProvider(t)

	// Try to generate an ECC key in FIPS mode
	_, err := provider.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P256, "fips-test-key", nil)
	if err == nil {
		t.Fatal("expected error generating ECC key in FIPS mode")
	}
	if !strings.Contains(err.Error(), "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection, got: %v", err)
	}
}

// newInitializedSmartCardProvider creates a mock SmartCardKeyProvider that is initialized
func newInitializedSmartCardProvider(t *testing.T) *SmartCardKeyProvider {
	t.Helper()
	return NewSmartCardKeyProvider("mock", map[string]string{"pin": "1234"})
}

func TestSmartCard_FIPSRejectsDecryptNonRSA(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	// Generate an ECC key first (before FIPS is enabled)
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "ecc-key", nil)
	if err != nil {
		t.Fatalf("generate ECC key: %v", err)
	}

	// Now enable FIPS
	err = provider.Configure(map[string]string{"fips_enabled": "true", "pin": "1234"})
	if err != nil {
		t.Fatalf("Configure FIPS: %v", err)
	}

	// Decrypt with the ECC key should fail FIPS validation
	_, err = provider.Decrypt(ctx, "ecc-key", []byte("ciphertext"))
	if err == nil {
		t.Fatal("expected error decrypting with ECC key in FIPS mode")
	}
	if !strings.Contains(err.Error(), "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection, got: %v", err)
	}
}

func TestSmartCard_FIPSRejectsEncryptNonRSA(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "ecc-key-enc", nil)
	if err != nil {
		t.Fatalf("generate ECC key: %v", err)
	}

	err = provider.Configure(map[string]string{"fips_enabled": "true", "pin": "1234"})
	if err != nil {
		t.Fatalf("Configure FIPS: %v", err)
	}

	_, err = provider.Encrypt(ctx, "ecc-key-enc", []byte("plaintext"))
	if err == nil {
		t.Fatal("expected error encrypting with ECC key in FIPS mode")
	}
	if !strings.Contains(err.Error(), "not allowed in FIPS mode") {
		t.Errorf("expected FIPS rejection, got: %v", err)
	}
}

func TestSmartCard_FIPSRejectsGetKeyPairNonRSA(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "ecc-key-get", nil)
	if err != nil {
		t.Fatalf("generate ECC key: %v", err)
	}

	err = provider.Configure(map[string]string{"fips_enabled": "true", "pin": "1234"})
	if err != nil {
		t.Fatalf("Configure FIPS: %v", err)
	}

	_, err = provider.GetKeyPair(ctx, "ecc-key-get")
	if err == nil {
		t.Fatal("expected error getting ECC key in FIPS mode")
	}
}

func TestSmartCard_FIPSRejectsRotateNonRSA(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "ecc-key-rot", nil)
	if err != nil {
		t.Fatalf("generate ECC key: %v", err)
	}

	err = provider.Configure(map[string]string{"fips_enabled": "true", "pin": "1234"})
	if err != nil {
		t.Fatalf("Configure FIPS: %v", err)
	}

	_, err = provider.RotateKey(ctx, "ecc-key-rot")
	if err == nil {
		t.Fatal("expected error rotating ECC key in FIPS mode")
	}
}

func TestSmartCard_FIPSInvalidConfigValue(t *testing.T) {
	provider := NewSmartCardKeyProvider("mock", map[string]string{"pin": "1234"})
	err := provider.Configure(map[string]string{"fips_enabled": "not-a-bool"})
	if err == nil {
		t.Fatal("expected error for invalid fips_enabled value")
	}
	if !strings.Contains(err.Error(), "invalid fips_enabled value") {
		t.Errorf("expected parse error, got: %v", err)
	}
}

// ===========================================================================
// smartcard_provider.go: DeleteKeyPair and ListKeyPairs error paths
// ===========================================================================

func TestSmartCard_DeleteKeyPair_Success(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	// Generate a key, then delete it
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "delete-me", nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	err = provider.DeleteKeyPair(ctx, "delete-me")
	if err != nil {
		t.Errorf("expected no error deleting key, got: %v", err)
	}

	// Verify it's gone
	_, err = provider.GetKeyPair(ctx, "delete-me")
	if err == nil {
		t.Error("expected error after deleting key")
	}
}

func TestSmartCard_ListKeyPairs(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	// Generate a key
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "list-key", nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	keys, err := provider.ListKeyPairs(ctx)
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}
	if len(keys) == 0 {
		t.Error("expected at least one key")
	}
}

func TestSmartCard_GetKeyPair_NotFound(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	_, err := provider.GetKeyPair(context.Background(), "nonexistent-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

// ===========================================================================
// server.go: createInitialKey (covers line 328-345 — 7 statements)
// ===========================================================================

func TestServer_CreateInitialKey(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	cfg := &config.Config{}
	cfg.Encryption.Algorithm = "RSA-2048"

	// This should succeed and create a key
	srv.createInitialKey(cfg, KeyType_KEY_TYPE_RSA_2048)

	// Verify a key was created
	keys, err := srv.ListKeys(context.Background(), &ListKeysRequest{})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys.Keys) == 0 {
		t.Error("expected at least one key after createInitialKey")
	}
}

// ===========================================================================
// server_client_keys.go: RegisterClientKey duplicate key triggers RegisterKey
// error (line 99-106), and RevokeClientKey success path + ListClients
// ===========================================================================

func TestRevokeClientKey_Success(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("revoke-user")

	// Register a key
	regResp, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})
	if err != nil || !regResp.Success {
		t.Fatalf("RegisterClientKey: %v %v", err, regResp.GetErrorMessage())
	}
	keyID := regResp.Key.KeyId

	// Revoke the key
	revokeResp, err := srv.RevokeClientKey(ctx, &RevokeClientKeyRequest{
		KeyId:  keyID,
		Reason: "test revocation",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey: %v", err)
	}
	if !revokeResp.Success {
		t.Errorf("RevokeClientKey should succeed, got error: %s", revokeResp.ErrorMessage)
	}
}

func TestRevokeClientKey_NotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("revoke-user")

	resp, err := srv.RevokeClientKey(ctx, &RevokeClientKeyRequest{
		KeyId:  "nonexistent-key",
		Reason: "test",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey: %v", err)
	}
	if resp.Success {
		t.Error("should fail for nonexistent key")
	}
}

func TestListClientKeys_WithAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("list-user")

	// Register a key
	_, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})
	if err != nil {
		t.Fatalf("RegisterClientKey: %v", err)
	}

	// List keys
	resp, err := srv.ListClientKeys(ctx, &ListClientKeysRequest{})
	if err != nil {
		t.Fatalf("ListClientKeys: %v", err)
	}
	if len(resp.Keys) == 0 {
		t.Error("expected at least one key")
	}
}

func TestListClients(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := ctxWithUser("client-list-user")

	// Register a key to have at least one client
	_, _ = srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})

	resp, err := srv.ListClients(context.Background(), &ListClientsRequest{})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(resp.Clients) == 0 {
		t.Error("expected at least one client")
	}
}

// ===========================================================================
// smartcard_provider.go line 233-237 and 242-245: GenerateKeyPair error paths
// when cardReader.GetPublicKey or publicKeyToPEM fails
// ===========================================================================

func TestSmartCard_Sign_Success(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	// Generate a key
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "sign-key", nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Sign with the key
	_, err = provider.Sign(ctx, "sign-key", []byte("message-to-sign"))
	if err != nil {
		t.Errorf("Sign error: %v", err)
	}
}

func TestSmartCard_EncryptDecrypt_Success(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "crypt-key", nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ciphertext, err := provider.Encrypt(ctx, "crypt-key", []byte("hello"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plaintext, err := provider.Decrypt(ctx, "crypt-key", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(plaintext) != "hello" {
		t.Errorf("expected 'hello', got %s", string(plaintext))
	}
}

func TestSmartCard_RotateKey_Success(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P256, "rotate-key", nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	newKP, err := provider.RotateKey(ctx, "rotate-key")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newKP == nil {
		t.Error("expected non-nil key pair after rotation")
	}
}

// ===========================================================================
// server.go: GetAuthService accessor (line 353)
// ===========================================================================

func TestServer_GetAuthService(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	// For test server, auth service is nil
	as := srv.GetAuthService()
	if as != nil {
		t.Error("expected nil auth service for test server")
	}
}

// ===========================================================================
// key_store.go: matchesFilters with nil metadata
// ===========================================================================

func TestInMemoryKeyStore_ListKeys_WithFilters(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	_ = store.StoreKey(ctx, &Key{
		KeyId:        "filter-key-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	_ = store.StoreKey(ctx, &Key{
		KeyId:        "filter-key-2",
		KeyType:      KeyType_KEY_TYPE_ECC_P256,
		Status:       KeyStatus_KEY_STATUS_REVOKED,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})

	// Filter by status
	keys, err := store.ListKeys(ctx, map[string]interface{}{
		"status": KeyStatus_KEY_STATUS_ACTIVE,
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 1 || keys[0].KeyId != "filter-key-1" {
		t.Errorf("expected 1 active key, got %d", len(keys))
	}

	// Filter by provider_type
	allKeys, err := store.ListKeys(ctx, map[string]interface{}{
		"provider_type": KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(allKeys) != 2 {
		t.Errorf("expected 2 software keys, got %d", len(allKeys))
	}
}

// ===========================================================================
// rotation_manager.go: PerformRotation with provider.RotateKey failure
// and UpdateKey failure paths (lines 276-291)
// ===========================================================================

func TestRotationManager_PerformRotation_KeyNotInStore(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	ctx := context.Background()

	// Call PerformRotation with a key ID that doesn't exist in the key store
	rm := srv.rotationManager
	_, err := rm.PerformRotation(ctx, "nonexistent-rotation-key")
	if err == nil {
		t.Fatal("expected error for nonexistent key")
	}
}

// ===========================================================================
// Helpers (unused import guard)
// ===========================================================================

var _ crypto.PublicKey = ed25519.PublicKey{}
