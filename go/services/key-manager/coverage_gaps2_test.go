//go:build !fips

package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"
	"time"

	"stratium/pkg/security/encryption"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// failingProviderFactory is a minimal ProviderFactory that always fails GetProvider.
// ---------------------------------------------------------------------------

type failingProviderFactory struct{}

func (f *failingProviderFactory) CreateProvider(providerType KeyProviderType, config map[string]string) (KeyProviderInterface, error) {
	return nil, fmt.Errorf("no provider available")
}

func (f *failingProviderFactory) GetProvider(providerType KeyProviderType) (KeyProviderInterface, error) {
	return nil, fmt.Errorf("no provider available for %v", providerType)
}

func (f *failingProviderFactory) GetAvailableProviders() []KeyProviderType {
	return nil
}

// ---------------------------------------------------------------------------
// client_key_store.go:373-374 and :337
// InMemoryClientKeyStore.publicKeyToPEM with RSA-1024 (unsupported size)
// Also covers StoreClientPublicKey error path (line 337).
// ---------------------------------------------------------------------------

func TestCoverageGaps2_ClientKeyStore_StoreRSA1024(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	// StoreClientPublicKey calls publicKeyToPEM internally – RSA-1024 must fail.
	err = store.StoreClientPublicKey(context.Background(), "user1", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024 in StoreClientPublicKey")
	}
	if !strings.Contains(err.Error(), "unsupported RSA") {
		t.Errorf("expected 'unsupported RSA' error, got: %v", err)
	}
}

// Also test publicKeyToPEM directly for RSA-1024.
func TestCoverageGaps2_ClientKeyStore_PublicKeyToPEM_RSA1024(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for RSA-1024 in publicKeyToPEM")
	}
	if !strings.Contains(err.Error(), "unsupported RSA") {
		t.Errorf("expected 'unsupported RSA' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go:401-402 and :337
// InMemoryClientKeyStore.publicKeyToPEM with P-224 (unsupported curve)
// Also covers StoreClientPublicKey error path (line 337).
// ---------------------------------------------------------------------------

func TestCoverageGaps2_ClientKeyStore_StoreECCP224(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	err = store.StoreClientPublicKey(context.Background(), "user2", &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224 in StoreClientPublicKey")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected 'unsupported ECC curve' error, got: %v", err)
	}
}

// Also test publicKeyToPEM directly for P-224.
func TestCoverageGaps2_ClientKeyStore_PublicKeyToPEM_P224(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	_, _, err = store.publicKeyToPEM(&priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for P-224 in publicKeyToPEM")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected 'unsupported ECC curve' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go:435-437
// parsePublicKeyPEM calls parseKyberPublicKeyFromPEM which returns (_, true, err)
// when the block bytes are garbage for a Kyber key type.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_ClientKeyStore_ParsePublicKeyPEM_KyberBadBytes(t *testing.T) {
	store := NewInMemoryClientKeyStore()

	// Encode garbage bytes as a PEM block so pem.Decode succeeds
	// but parseKyberPublicKeyFromPEM fails (bad Kyber bytes).
	garbageBytes := []byte("this-is-not-a-real-kyber-public-key")
	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "KYBER-512 PUBLIC KEY",
		Bytes: garbageBytes,
	}))

	_, err := store.parsePublicKeyPEM(pemData, KeyType_KEY_TYPE_KYBER_512)
	if err == nil {
		t.Fatal("expected error parsing invalid Kyber public key PEM")
	}
}

// ---------------------------------------------------------------------------
// client_key_store.go:312
// GetClientPublicKey hits the parsePublicKeyPEM error path.
// Register a key, tamper its PEM to invalid bytes, then call GetClientPublicKey.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_ClientKeyStore_GetClientPublicKey_ParseError(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Register a valid RSA-2048 key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA-2048: %v", err)
	}
	err = store.StoreClientPublicKey(ctx, "parse-error-subject", &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreClientPublicKey: %v", err)
	}

	// Find the stored key and tamper with its PublicKeyPem to be invalid
	activeKey, err := store.GetActiveKeyForClient(ctx, "parse-error-subject")
	if err != nil {
		t.Fatalf("GetActiveKeyForClient: %v", err)
	}

	store.mu.Lock()
	if k, ok := store.keys[activeKey.KeyId]; ok {
		k.PublicKeyPem = string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: []byte("not-valid-der-bytes"),
		}))
	}
	// Clear the parsed key cache so it must re-parse
	delete(store.parsedKeyCache, activeKey.KeyId)
	store.mu.Unlock()

	// GetClientPublicKey should now fail when trying to parse the tampered PEM
	_, err = store.GetClientPublicKey(ctx, "parse-error-subject")
	if err == nil {
		t.Fatal("expected error when parsing tampered public key PEM")
	}
}

// ---------------------------------------------------------------------------
// dek_service.go:104-108
// FIPS mode rejects non-FIPS key type (Kyber-512) in UnwrapDEK.
// Seed the key directly into the keyStore bypassing CreateKey FIPS check.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_DEKService_FIPS_RejectsKyberServiceKey(t *testing.T) {
	ctx := context.Background()

	// Create a FIPS-enabled server
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	// Seed a Kyber-512 key directly into the key store (bypassing FIPS validation)
	kyberKey := &Key{
		KeyId:        "kyber-fips-test-key",
		KeyType:      KeyType_KEY_TYPE_KYBER_512,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := srv.keyStore.StoreKey(ctx, kyberKey); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// UnwrapDEK should return denied because Kyber is not FIPS-allowed
	req := &UnwrapDEKRequest{
		Subject:      "user1",
		Resource:     "resource1",
		KeyId:        "kyber-fips-test-key",
		ClientKeyId:  "client-key-1",
		EncryptedDek: []byte("dummy-dek"),
	}
	resp, err := srv.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK unexpected error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK should deny access for Kyber key in FIPS mode")
	}
	if !strings.Contains(resp.AccessReason, "not allowed in FIPS mode") {
		t.Errorf("expected FIPS denial reason, got: %s", resp.AccessReason)
	}
}

// ---------------------------------------------------------------------------
// dek_service.go:112-116
// Provider factory GetProvider failure path.
// Use a DEKUnwrappingService with a failingProviderFactory.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_DEKService_ProviderFactoryFailure(t *testing.T) {
	ctx := context.Background()

	keyStore := NewInMemoryKeyStore()
	clientKeyStore := NewInMemoryClientKeyStore()

	// Seed a key into the store
	serviceKey := &Key{
		KeyId:        "no-provider-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	if err := keyStore.StoreKey(ctx, serviceKey); err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// Create DEKUnwrappingService with a factory that always fails GetProvider
	dekSvc := NewDEKUnwrappingService(keyStore, &failingProviderFactory{}, clientKeyStore, false)

	req := &UnwrapDEKRequest{
		Subject:      "user1",
		Resource:     "resource1",
		KeyId:        "no-provider-key",
		ClientKeyId:  "ck1",
		EncryptedDek: []byte("dummy-encrypted-dek"),
	}
	resp, err := dekSvc.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK unexpected error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK should deny access when provider factory fails")
	}
	if !strings.Contains(resp.AccessReason, "Failed to create key provider") {
		t.Errorf("expected provider failure reason, got: %s", resp.AccessReason)
	}
}

// ---------------------------------------------------------------------------
// key_store.go:27 — StoreKey with nil key
// key_store.go:102-104 — UpdateKey with nil key
// key_store.go:106-108 — UpdateKey with empty key ID
// key_store.go:124-126 — StoreKeyPair with nil key pair
// ---------------------------------------------------------------------------

func TestCoverageGaps2_KeyStore_StoreKey_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key in StoreKey")
	}
}

func TestCoverageGaps2_KeyStore_UpdateKey_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.UpdateKey(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key in UpdateKey")
	}
}

func TestCoverageGaps2_KeyStore_UpdateKey_EmptyID(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.UpdateKey(context.Background(), &Key{KeyId: ""})
	if err == nil {
		t.Fatal("expected error for empty key ID in UpdateKey")
	}
}

func TestCoverageGaps2_KeyStore_StoreKeyPair_Nil(t *testing.T) {
	store := NewInMemoryKeyStore()
	err := store.StoreKeyPair(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil key pair in StoreKeyPair")
	}
}

// ---------------------------------------------------------------------------
// key_store.go:181 — matchesFilters returns false for non-matching provider_type
// ListKeys with a provider_type filter that doesn't match any stored key.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_KeyStore_ListKeys_ProviderTypeMismatch(t *testing.T) {
	store := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store a SOFTWARE key
	err := store.StoreKey(ctx, &Key{
		KeyId:        "sw-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	// Filter for HSM — the SOFTWARE key should NOT match, triggering return false
	keys, err := store.ListKeys(ctx, map[string]interface{}{
		"provider_type": KeyProviderType_KEY_PROVIDER_TYPE_HSM,
	})
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for HSM filter, got %d", len(keys))
	}
}

// ---------------------------------------------------------------------------
// dek_service.go:393-395 — RegisterClientPublicKey with valid PEM block
// but DER bytes that x509.ParsePKIXPublicKey rejects.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_DEKService_RegisterClientPublicKey_BadDER(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// A PEM block that decodes successfully but contains garbage DER bytes
	badDERPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("this-is-not-valid-der-asn1-data"),
	}))

	err := srv.dekService.RegisterClientPublicKey(context.Background(), "user1", badDERPEM)
	if err == nil {
		t.Fatal("expected error for bad DER in RegisterClientPublicKey")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("expected 'failed to parse public key' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// dek_service.go:159-163 — encryptDEKForSubject failure path in UnwrapDEK.
// Use an Ed25519 client public key, which parses fine via x509 but falls
// through to the default (unsupported) case in encryptDEKForSubject.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_DEKService_UnwrapDEK_EncryptForSubjectFails(t *testing.T) {
	ctx := context.Background()
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a service key that can actually decrypt a DEK
	createResp, err := srv.CreateKey(ctx, &CreateKeyRequest{
		Name:         "service-key-for-ed25519-test",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	keyID := createResp.Key.KeyId

	// Encrypt a DEK with the service key
	provider, err := srv.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	plainDEK := []byte("test-dek-32-bytes-padding-xyz123")
	encryptedDEK, err := provider.Encrypt(ctx, keyID, plainDEK)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Generate an Ed25519 public key — x509.ParsePKIXPublicKey returns ed25519.PublicKey
	// which is not *rsa.PublicKey or *ecdsa.PublicKey, so encryptDEKForSubject hits default.
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	edDERBytes, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal Ed25519 public key: %v", err)
	}
	edPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: edDERBytes}))

	// Register the Ed25519 key as a client key directly (bypassing type checks)
	clientKeyID := "ed25519-client-key"
	clientKey := &Key{
		KeyId:        clientKeyID,
		ClientId:     "ed25519-user",
		PublicKeyPem: edPEM,
		KeyType:      KeyType_KEY_TYPE_UNSPECIFIED, // unknown so parsePublicKeyPEM hits default fallback
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		Metadata:     make(map[string]string),
	}
	if err := srv.clientKeyStore.RegisterKey(ctx, clientKey); err != nil {
		t.Fatalf("RegisterKey (Ed25519 client): %v", err)
	}

	req := &UnwrapDEKRequest{
		Subject:      "ed25519-user",
		Resource:     "resource1",
		KeyId:        keyID,
		ClientKeyId:  clientKeyID,
		EncryptedDek: encryptedDEK,
	}
	resp, err := srv.dekService.UnwrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("UnwrapDEK unexpected error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("UnwrapDEK should deny when encryptDEKForSubject fails for Ed25519 key")
	}
}

// ---------------------------------------------------------------------------
// seed_data.go:92-94 — applyKeyManagerSeedData warns on invalid provider_type
// seed_data.go:97-99 — applyKeyManagerSeedData warns on invalid rotation_policy
// ---------------------------------------------------------------------------

func TestCoverageGaps2_SeedData_InvalidProviderType(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:         "test-key-bad-provider",
				KeyType:      "RSA_2048",
				ProviderType: "NONEXISTENT_PROVIDER_TYPE",
			},
		},
	}
	// applyKeyManagerSeedData should warn about invalid provider_type but not return error
	err := srv.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("applyKeyManagerSeedData unexpected error: %v", err)
	}
}

func TestCoverageGaps2_SeedData_InvalidRotationPolicy(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:           "test-key-bad-rotation",
				KeyType:        "RSA_2048",
				RotationPolicy: "NONEXISTENT_ROTATION_POLICY",
			},
		},
	}
	err := srv.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("applyKeyManagerSeedData unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// seed_data.go:121-123 — applyKeyManagerSeedData logs error when CreateKey fails.
// Use FIPS server and try to seed an ECC key which is rejected in FIPS mode.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_SeedData_CreateKeyFails(t *testing.T) {
	srv := newTestKeyManagerServerWithFIPS(t, encryption.RSA2048, true)

	seed := &KeyManagerSeedData{
		Keys: []KeySeed{
			{
				Name:    "ecc-key-fips-should-fail",
				KeyType: "ECC_P256",
			},
		},
	}
	// In FIPS mode CreateKey for ECC should fail, triggering the error log path
	err := srv.applyKeyManagerSeedData(seed, KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("applyKeyManagerSeedData unexpected top-level error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// rotation_manager.go:513-514 — UpdateRotationJob with TIME_BASED policy.
// This exercises the specific switch-case branch that was missed.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_RotationManager_UpdateRotationJob_TimeBased(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	// Schedule a rotation job first so UpdateRotationJob finds it
	ctx := context.Background()
	err := keyStore.StoreKey(ctx, &Key{
		KeyId:        "rotate-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	err = rm.ScheduleRotation("rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// UpdateRotationJob with TIME_BASED hits the specific uncovered switch branch
	err = rm.UpdateRotationJob("rotate-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 48*time.Hour)
	if err != nil {
		t.Fatalf("UpdateRotationJob: %v", err)
	}
}

// ---------------------------------------------------------------------------
// rotation_manager.go:258-261 — PerformRotation fails when GetKey returns error.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_RotationManager_PerformRotation_GetKeyError(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	rm := NewDefaultKeyRotationManager(keyStore, factory)

	ctx := context.Background()

	// First store the key so ScheduleRotation succeeds
	err := keyStore.StoreKey(ctx, &Key{
		KeyId:        "ephemeral-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	err = rm.ScheduleRotation("ephemeral-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// Now delete the key so PerformRotation's GetKey call fails
	if err := keyStore.DeleteKey(ctx, "ephemeral-key"); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}

	// PerformRotation will try GetKey("ephemeral-key") → not found → error path (line 258-261)
	_, err = rm.PerformRotation(ctx, "ephemeral-key")
	if err == nil {
		t.Fatal("expected error from PerformRotation for deleted key")
	}
}

// ---------------------------------------------------------------------------
// rotation_manager.go:269-271 — PerformRotation fails when GetProvider returns error.
// Use a rotation manager with a failing provider factory.
// ---------------------------------------------------------------------------

func TestCoverageGaps2_RotationManager_PerformRotation_ProviderError(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	rm := NewDefaultKeyRotationManager(keyStore, &failingProviderFactory{})

	ctx := context.Background()

	// Store the key so GetKey succeeds
	err := keyStore.StoreKey(ctx, &Key{
		KeyId:        "prov-fail-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	})
	if err != nil {
		t.Fatalf("StoreKey: %v", err)
	}

	err = rm.ScheduleRotation("prov-fail-key", RotationPolicy_ROTATION_POLICY_TIME_BASED, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScheduleRotation: %v", err)
	}

	// PerformRotation: GetKey succeeds, then GetProvider fails (line 269-271)
	_, err = rm.PerformRotation(ctx, "prov-fail-key")
	if err == nil {
		t.Fatal("expected error from PerformRotation when provider is unavailable")
	}
}

// ---------------------------------------------------------------------------
// server_crypto_helpers.go — inferKeyTypeFromPEM with Ed25519 (unsupported type)
// Covers the default branch that returns "unsupported key type".
// ---------------------------------------------------------------------------

func TestCoverageGaps2_InferKeyTypeFromPEM_Ed25519(t *testing.T) {
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		t.Fatalf("marshal Ed25519: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	_, err = inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for Ed25519 in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("expected 'unsupported key type' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// server_crypto_helpers.go — inferKeyTypeFromPEM with RSA-1024 (unsupported size)
// Covers the RSA default branch returning "unsupported RSA key size".
// ---------------------------------------------------------------------------

func TestCoverageGaps2_InferKeyTypeFromPEM_RSA1024(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate RSA-1024: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA-1024: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	_, err = inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for RSA-1024 in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "unsupported RSA key size") {
		t.Errorf("expected 'unsupported RSA key size' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// server_crypto_helpers.go — inferKeyTypeFromPEM with P-224 (unsupported ECC curve)
// Covers the ECDSA default branch returning "unsupported ECC curve".
// ---------------------------------------------------------------------------

func TestCoverageGaps2_InferKeyTypeFromPEM_ECCP224(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-224: %v", err)
	}
	derBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-224: %v", err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes}))

	_, err = inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for P-224 in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "unsupported ECC curve") {
		t.Errorf("expected 'unsupported ECC curve' error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// server_crypto_helpers.go — inferKeyTypeFromPEM with bad DER (ParsePKIXPublicKey fails)
// ---------------------------------------------------------------------------

func TestCoverageGaps2_InferKeyTypeFromPEM_BadDER(t *testing.T) {
	pemStr := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("garbage-not-valid-asn1"),
	}))
	_, err := inferKeyTypeFromPEM(pemStr)
	if err == nil {
		t.Fatal("expected error for bad DER in inferKeyTypeFromPEM")
	}
	if !strings.Contains(err.Error(), "failed to parse public key") {
		t.Errorf("expected 'failed to parse public key' error, got: %v", err)
	}
}
