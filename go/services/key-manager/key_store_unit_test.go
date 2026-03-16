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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
	"stratium/pkg/auth"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func generateRSA2048Key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return k
}

func generateECCP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return k
}

func generateECCP384Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	return k
}

func rsaPublicKeyPEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func eccPublicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func validUserClaims() *auth.UserClaims {
	return &auth.UserClaims{Sub: "user-123", Email: "user@example.com"}
}

// ---------------------------------------------------------------------------
// parsePublicKeyPEM
// ---------------------------------------------------------------------------

func TestKeyStore_ParsePublicKeyPEM_RSA(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	rsaKey := generateRSA2048Key(t)
	pemStr := rsaPublicKeyPEM(t, rsaKey)

	parsed, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_RSA_2048)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	rsaParsed, ok := parsed.(*rsa.PublicKey)
	require.True(t, ok, "expected *rsa.PublicKey")
	assert.Equal(t, rsaKey.PublicKey.N, rsaParsed.N)
}

func TestKeyStore_ParsePublicKeyPEM_ECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	eccKey := generateECCP256Key(t)
	pemStr := eccPublicKeyPEM(t, eccKey)

	parsed, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_ECC_P256)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	_, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok, "expected *ecdsa.PublicKey")
}

func TestKeyStore_ParsePublicKeyPEM_ECC_P384(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	eccKey := generateECCP384Key(t)
	pemStr := eccPublicKeyPEM(t, eccKey)

	parsed, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_ECC_P384)
	require.NoError(t, err)
	require.NotNil(t, parsed)

	_, ok := parsed.(*ecdsa.PublicKey)
	require.True(t, ok, "expected *ecdsa.PublicKey")
}

func TestKeyStore_ParsePublicKeyPEM_InvalidPEM(t *testing.T) {
	store := NewInMemoryClientKeyStore()

	_, err := store.parsePublicKeyPEM("not-a-pem", KeyType_KEY_TYPE_RSA_2048)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode PEM block")
}

func TestKeyStore_ParsePublicKeyPEM_WrongKeyType(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	// Provide an ECC PEM but declare it as RSA – x509 parse will return an
	// *ecdsa.PublicKey which fails the RSA type assertion.
	eccKey := generateECCP256Key(t)
	pemStr := eccPublicKeyPEM(t, eccKey)

	_, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_RSA_2048)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected RSA public key")
}

func TestKeyStore_ParsePublicKeyPEM_RSA_WrongTypeAsECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	rsaKey := generateRSA2048Key(t)
	pemStr := rsaPublicKeyPEM(t, rsaKey)

	_, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_ECC_P256)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "expected ECDSA public key")
}

func TestKeyStore_ParsePublicKeyPEM_Unspecified_FallsBackToGeneric(t *testing.T) {
	// KEY_TYPE_UNSPECIFIED hits the default branch which tries generic parsing
	store := NewInMemoryClientKeyStore()
	rsaKey := generateRSA2048Key(t)
	pemStr := rsaPublicKeyPEM(t, rsaKey)

	parsed, err := store.parsePublicKeyPEM(pemStr, KeyType_KEY_TYPE_UNSPECIFIED)
	require.NoError(t, err)
	require.NotNil(t, parsed)
}

// ---------------------------------------------------------------------------
// publicKeyToPEM
// ---------------------------------------------------------------------------

func TestPublicKey_ToPEM_RSA2048(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	rsaKey := generateRSA2048Key(t)

	pemStr, keyType, err := store.publicKeyToPEM(&rsaKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, KeyType_KEY_TYPE_RSA_2048, keyType)

	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block, "expected valid PEM block")
	assert.Equal(t, "PUBLIC KEY", block.Type)
}

func TestPublicKey_ToPEM_RSA3072(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	k, err := rsa.GenerateKey(rand.Reader, 3072)
	require.NoError(t, err)

	_, keyType, err := store.publicKeyToPEM(&k.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, KeyType_KEY_TYPE_RSA_3072, keyType)
}

func TestPublicKey_ToPEM_RSA4096(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	k, err := rsa.GenerateKey(rand.Reader, 4096)
	require.NoError(t, err)

	_, keyType, err := store.publicKeyToPEM(&k.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, KeyType_KEY_TYPE_RSA_4096, keyType)
}

func TestPublicKey_ToPEM_ECCP256(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	eccKey := generateECCP256Key(t)

	pemStr, keyType, err := store.publicKeyToPEM(&eccKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, KeyType_KEY_TYPE_ECC_P256, keyType)

	block, _ := pem.Decode([]byte(pemStr))
	require.NotNil(t, block)
	assert.Equal(t, "PUBLIC KEY", block.Type)
}

func TestPublicKey_ToPEM_ECCP384(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	eccKey := generateECCP384Key(t)

	_, keyType, err := store.publicKeyToPEM(&eccKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, KeyType_KEY_TYPE_ECC_P384, keyType)
}

func TestPublicKey_ToPEM_ECCP521(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	k, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	_, keyType, err := store.publicKeyToPEM(&k.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, KeyType_KEY_TYPE_ECC_P521, keyType)
}

func TestPublicKey_ToPEM_UnsupportedType(t *testing.T) {
	store := NewInMemoryClientKeyStore()

	// Pass a type that is not RSA/ECC/Kyber — a plain string implements no
	// key interface but satisfies crypto.PublicKey (empty interface).
	type unknownKey struct{}
	_, _, err := store.publicKeyToPEM(unknownKey{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public key type")
}

// ---------------------------------------------------------------------------
// StoreClientPublicKey
// ---------------------------------------------------------------------------

func TestKeyStore_StoreClientPublicKey_RSA(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKey := generateRSA2048Key(t)
	err := store.StoreClientPublicKey(ctx, "subject-rsa", &rsaKey.PublicKey)
	require.NoError(t, err)

	// The key should be retrievable via GetClientPublicKey
	pub, err := store.GetClientPublicKey(ctx, "subject-rsa")
	require.NoError(t, err)
	require.NotNil(t, pub)

	_, ok := pub.(*rsa.PublicKey)
	assert.True(t, ok, "expected *rsa.PublicKey back from store")
}

func TestKeyStore_StoreClientPublicKey_ECC(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	eccKey := generateECCP256Key(t)
	err := store.StoreClientPublicKey(ctx, "subject-ecc", &eccKey.PublicKey)
	require.NoError(t, err)

	pub, err := store.GetClientPublicKey(ctx, "subject-ecc")
	require.NoError(t, err)
	require.NotNil(t, pub)

	_, ok := pub.(*ecdsa.PublicKey)
	assert.True(t, ok, "expected *ecdsa.PublicKey back from store")
}

func TestKeyStore_StoreClientPublicKey_EmptySubject(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKey := generateRSA2048Key(t)
	err := store.StoreClientPublicKey(ctx, "", &rsaKey.PublicKey)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject cannot be empty")
}

func TestKeyStore_StoreClientPublicKey_NilKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	err := store.StoreClientPublicKey(ctx, "subject-nil", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key cannot be nil")
}

// ---------------------------------------------------------------------------
// GetClientPublicKey
// ---------------------------------------------------------------------------

func TestKeyStore_GetClientPublicKey_EmptySubject(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	_, err := store.GetClientPublicKey(ctx, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject cannot be empty")
}

func TestKeyStore_GetClientPublicKey_NoKeys(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	_, err := store.GetClientPublicKey(ctx, "unknown-subject")
	require.Error(t, err)
}

func TestKeyStore_GetClientPublicKey_UsesCachedKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKey := generateRSA2048Key(t)
	err := store.StoreClientPublicKey(ctx, "cached-subject", &rsaKey.PublicKey)
	require.NoError(t, err)

	// First call populates the cache (or uses it if already populated).
	pub1, err := store.GetClientPublicKey(ctx, "cached-subject")
	require.NoError(t, err)

	// Second call should also succeed and return the same key.
	pub2, err := store.GetClientPublicKey(ctx, "cached-subject")
	require.NoError(t, err)

	// Both should be the same underlying RSA key.
	rsa1, ok1 := pub1.(*rsa.PublicKey)
	rsa2, ok2 := pub2.(*rsa.PublicKey)
	require.True(t, ok1)
	require.True(t, ok2)
	assert.Equal(t, rsa1.N, rsa2.N)
}

func TestKeyStore_GetClientPublicKey_ParsesUncachedKey(t *testing.T) {
	// Register key via RegisterKey (which caches), then manually clear the cache
	// so GetClientPublicKey has to re-parse the PEM.
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKey := generateRSA2048Key(t)
	pemStr := rsaPublicKeyPEM(t, rsaKey)
	key := &Key{
		KeyId:        "uncached-key",
		ClientId:     "uncached-subject",
		PublicKeyPem: pemStr,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	require.NoError(t, store.RegisterKey(ctx, key))

	// Clear the parsed key cache.
	store.mu.Lock()
	delete(store.parsedKeyCache, "uncached-key")
	store.mu.Unlock()

	pub, err := store.GetClientPublicKey(ctx, "uncached-subject")
	require.NoError(t, err)
	require.NotNil(t, pub)

	_, ok := pub.(*rsa.PublicKey)
	assert.True(t, ok)
}

// ---------------------------------------------------------------------------
// cloneKey
// ---------------------------------------------------------------------------

func TestClone_Key_Nil(t *testing.T) {
	result := cloneKey(nil)
	assert.Nil(t, result)
}

func TestClone_Key_DeepCopy(t *testing.T) {
	original := &Key{
		KeyId:    "key-1",
		ClientId: "client-1",
		KeyType:  KeyType_KEY_TYPE_RSA_2048,
		Status:   KeyStatus_KEY_STATUS_ACTIVE,
		Metadata: map[string]string{"env": "prod"},
	}

	clone := cloneKey(original)
	require.NotNil(t, clone)
	assert.Equal(t, original.KeyId, clone.KeyId)
	assert.Equal(t, original.ClientId, clone.ClientId)
	assert.Equal(t, original.KeyType, clone.KeyType)
	assert.Equal(t, original.Status, clone.Status)
	assert.Equal(t, "prod", clone.Metadata["env"])

	// Mutating the clone should not affect the original.
	clone.KeyId = "mutated"
	clone.Metadata["env"] = "dev"

	assert.Equal(t, "key-1", original.KeyId)
	assert.Equal(t, "prod", original.Metadata["env"])
}

func TestClone_Key_WithAllFields(t *testing.T) {
	now := timestamppb.Now()
	original := &Key{
		KeyId:              "full-key",
		ClientId:           "client-full",
		PublicKeyPem:       "pem-data",
		KeyType:            KeyType_KEY_TYPE_ECC_P256,
		Status:             KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:          now,
		KeyIntegrityHash:   "hash-abc",
		Metadata:           map[string]string{"k": "v"},
	}

	clone := cloneKey(original)
	require.NotNil(t, clone)
	assert.Equal(t, original.KeyId, clone.KeyId)
	assert.Equal(t, original.PublicKeyPem, clone.PublicKeyPem)
	assert.Equal(t, original.KeyIntegrityHash, clone.KeyIntegrityHash)
}

// ---------------------------------------------------------------------------
// VerifyKeyIntegrity
// ---------------------------------------------------------------------------

func TestKeyStore_VerifyKeyIntegrity_NilClaims(t *testing.T) {
	kim := NewKeyIntegrityManager()
	key := &Key{
		KeyId:            "key-1",
		PublicKeyPem:     "pem",
		KeyType:          KeyType_KEY_TYPE_RSA_2048,
		KeyIntegrityHash: "some-hash",
	}

	err := kim.VerifyKeyIntegrity(key, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user claims are required")
}

func TestKeyStore_VerifyKeyIntegrity_CorrectHash(t *testing.T) {
	kim := NewKeyIntegrityManager()
	claims := validUserClaims()

	pemData := "-----BEGIN PUBLIC KEY-----\nfakedata\n-----END PUBLIC KEY-----"
	keyType := KeyType_KEY_TYPE_RSA_2048

	// Generate the expected hash using the same manager.
	expectedHash := kim.CreateKeyIntegrityHash(pemData, keyType, claims)

	key := &Key{
		KeyId:            "key-ok",
		PublicKeyPem:     pemData,
		KeyType:          keyType,
		KeyIntegrityHash: expectedHash,
	}

	err := kim.VerifyKeyIntegrity(key, claims)
	require.NoError(t, err)
}

func TestKeyStore_VerifyKeyIntegrity_TamperedHash(t *testing.T) {
	kim := NewKeyIntegrityManager()
	claims := validUserClaims()

	key := &Key{
		KeyId:            "key-bad",
		PublicKeyPem:     "real-pem",
		KeyType:          KeyType_KEY_TYPE_RSA_2048,
		KeyIntegrityHash: "deadbeef",
	}

	err := kim.VerifyKeyIntegrity(key, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tampered")
}

func TestKeyStore_VerifyKeyIntegrity_WrongKeyTypeInHash(t *testing.T) {
	kim := NewKeyIntegrityManager()
	claims := validUserClaims()

	pemData := "some-pem"
	// Hash computed with ECC type but key stored with RSA type.
	wrongHash := kim.CreateKeyIntegrityHash(pemData, KeyType_KEY_TYPE_ECC_P256, claims)

	key := &Key{
		KeyId:            "key-mismatch",
		PublicKeyPem:     pemData,
		KeyType:          KeyType_KEY_TYPE_RSA_2048,
		KeyIntegrityHash: wrongHash,
	}

	err := kim.VerifyKeyIntegrity(key, claims)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tampered")
}

// ---------------------------------------------------------------------------
// validateUnwrapRequest
// ---------------------------------------------------------------------------

func TestDEK_ValidateUnwrapRequest_Valid(t *testing.T) {
	svc := &DEKUnwrappingService{}
	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		KeyId:        "key-1",
		EncryptedDek: []byte("encrypted"),
	}

	err := svc.validateUnwrapRequest(req)
	require.NoError(t, err)
	// Default action should have been set.
	assert.Equal(t, "unwrap_dek", req.Action)
}

func TestDEK_ValidateUnwrapRequest_ExistingAction(t *testing.T) {
	svc := &DEKUnwrappingService{}
	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		KeyId:        "key-1",
		EncryptedDek: []byte("encrypted"),
		Action:       "custom_action",
	}

	err := svc.validateUnwrapRequest(req)
	require.NoError(t, err)
	// Pre-existing action should not be overwritten.
	assert.Equal(t, "custom_action", req.Action)
}

func TestDEK_ValidateUnwrapRequest_MissingSubject(t *testing.T) {
	svc := &DEKUnwrappingService{}
	req := &UnwrapDEKRequest{
		Resource:     "resource-1",
		KeyId:        "key-1",
		EncryptedDek: []byte("encrypted"),
	}

	err := svc.validateUnwrapRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subject is required")
}

func TestDEK_ValidateUnwrapRequest_MissingResource(t *testing.T) {
	svc := &DEKUnwrappingService{}
	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		KeyId:        "key-1",
		EncryptedDek: []byte("encrypted"),
	}

	err := svc.validateUnwrapRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resource is required")
}

func TestDEK_ValidateUnwrapRequest_MissingKeyID(t *testing.T) {
	svc := &DEKUnwrappingService{}
	req := &UnwrapDEKRequest{
		Subject:      "user-1",
		Resource:     "resource-1",
		EncryptedDek: []byte("encrypted"),
	}

	err := svc.validateUnwrapRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key ID is required")
}

func TestDEK_ValidateUnwrapRequest_MissingEncryptedDEK(t *testing.T) {
	svc := &DEKUnwrappingService{}
	req := &UnwrapDEKRequest{
		Subject:  "user-1",
		Resource: "resource-1",
		KeyId:    "key-1",
	}

	err := svc.validateUnwrapRequest(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypted DEK is required")
}

// ---------------------------------------------------------------------------
// encryptDEKForSubject
// ---------------------------------------------------------------------------

func TestDEK_EncryptDEKForSubject_RSA(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: false}
	rsaKey := generateRSA2048Key(t)
	dek := []byte("0123456789abcdef0123456789abcdef")

	subjectKey := &Key{
		KeyId:    "rsa-subject-key",
		KeyType:  KeyType_KEY_TYPE_RSA_2048,
		Metadata: map[string]string{},
	}

	encrypted, keyID, err := svc.encryptDEKForSubject(subjectKey, &rsaKey.PublicKey, dek, "alice")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.Contains(t, keyID, "alice")
	assert.Contains(t, keyID, "rsa")
}

func TestDEK_EncryptDEKForSubject_ECC(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: false}
	eccKey := generateECCP256Key(t)
	dek := []byte("0123456789abcdef0123456789abcdef")

	subjectKey := &Key{
		KeyId:    "ecc-subject-key",
		KeyType:  KeyType_KEY_TYPE_ECC_P256,
		Metadata: map[string]string{},
	}

	encrypted, keyID, err := svc.encryptDEKForSubject(subjectKey, &eccKey.PublicKey, dek, "bob")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.Contains(t, keyID, "bob")
	assert.Contains(t, keyID, "ecc")
}

func TestDEK_EncryptDEKForSubject_UnsupportedKeyType(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: false}
	dek := []byte("0123456789abcdef")

	subjectKey := &Key{
		KeyId:    "unsupported-subject-key",
		Metadata: map[string]string{},
	}

	type unsupportedKey struct{}
	_, _, err := svc.encryptDEKForSubject(subjectKey, unsupportedKey{}, dek, "charlie")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported public key type")
}

func TestDEK_EncryptDEKForSubject_FIPS_RejectsECC(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: true}
	eccKey := generateECCP256Key(t)
	dek := []byte("0123456789abcdef0123456789abcdef")

	subjectKey := &Key{
		KeyId:    "ecc-subject-key-fips",
		KeyType:  KeyType_KEY_TYPE_ECC_P256,
		Metadata: map[string]string{},
	}

	_, _, err := svc.encryptDEKForSubject(subjectKey, &eccKey.PublicKey, dek, "dave")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not allowed in FIPS mode")
}

func TestDEK_EncryptDEKForSubject_FIPS_AllowsRSA(t *testing.T) {
	svc := &DEKUnwrappingService{fipsEnabled: true}
	rsaKey := generateRSA2048Key(t)
	dek := []byte("0123456789abcdef0123456789abcdef")

	subjectKey := &Key{
		KeyId:    "rsa-subject-key-fips",
		KeyType:  KeyType_KEY_TYPE_RSA_2048,
		Metadata: map[string]string{},
	}

	encrypted, keyID, err := svc.encryptDEKForSubject(subjectKey, &rsaKey.PublicKey, dek, "eve")
	require.NoError(t, err)
	assert.NotEmpty(t, encrypted)
	assert.Contains(t, keyID, "eve")
}
