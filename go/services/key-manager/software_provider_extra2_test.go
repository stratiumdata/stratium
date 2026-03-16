//go:build !fips

package key_manager

import (
	"context"
	"testing"
)

// ---------------------------------------------------------------------------
// generateKeyPairInternal / GenerateKeyPair – uncovered branches
// ---------------------------------------------------------------------------

// TestSoftwareKeyProvider_GenerateKeyPair_RSA3072 exercises the RSA-3072 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_RSA3072(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_3072, "rsa3072-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA-3072 error = %v", err)
	}
	if keyPair.KeyType != KeyType_KEY_TYPE_RSA_3072 {
		t.Errorf("unexpected key type: %v", keyPair.KeyType)
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_RSA4096 exercises the RSA-4096 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_RSA4096(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_4096, "rsa4096-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA-4096 error = %v", err)
	}
	if keyPair.KeyType != KeyType_KEY_TYPE_RSA_4096 {
		t.Errorf("unexpected key type: %v", keyPair.KeyType)
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_ECC_P384 exercises the ECC-P384 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_ECC_P384(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P384, "ecc-p384-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair ECC-P384 error = %v", err)
	}
	if keyPair.KeyType != KeyType_KEY_TYPE_ECC_P384 {
		t.Errorf("unexpected key type: %v", keyPair.KeyType)
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_ECC_P521 exercises the ECC-P521 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_ECC_P521(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_ECC_P521, "ecc-p521-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair ECC-P521 error = %v", err)
	}
	if keyPair.KeyType != KeyType_KEY_TYPE_ECC_P521 {
		t.Errorf("unexpected key type: %v", keyPair.KeyType)
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_Unsupported exercises the default/error branch.
func TestSoftwareKeyProvider_GenerateKeyPair_Unsupported(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_UNSPECIFIED, "unsupported-key", nil)
	if err == nil {
		t.Fatal("expected error for unsupported key type")
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_WithMaxAge exercises the max_age_hours config path.
func TestSoftwareKeyProvider_GenerateKeyPair_WithMaxAge(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	config := map[string]string{
		"max_age_hours": "24",
		"env":           "test",
	}
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "aged-key", config)
	if err != nil {
		t.Fatalf("GenerateKeyPair with max_age_hours error = %v", err)
	}
	if keyPair.ExpiresAt == nil {
		t.Error("expected ExpiresAt to be set when max_age_hours is configured")
	}
	// Also check that non-age metadata was copied
	if keyPair.Metadata["env"] != "test" {
		t.Errorf("expected metadata env=test, got %v", keyPair.Metadata)
	}
}

// TestSoftwareKeyProvider_Configure_WithMaxAge exercises the default_max_age_hours config path.
func TestSoftwareKeyProvider_Configure_WithMaxAge(t *testing.T) {
	provider := NewSoftwareKeyProvider(map[string]string{
		"default_max_age_hours": "8760", // 1 year in hours
	})

	// Verify configuration is stored
	config := provider.GetConfiguration()
	if config["default_max_age_hours"] != "8760" {
		t.Errorf("expected default_max_age_hours=8760 in config, got %v", config)
	}
}

// TestSoftwareKeyProvider_Configure_InvalidMaxAge exercises the invalid duration path.
func TestSoftwareKeyProvider_Configure_InvalidMaxAge(t *testing.T) {
	// Non-numeric value for hours - should be silently ignored (no error)
	provider := NewSoftwareKeyProvider(nil)
	err := provider.Configure(map[string]string{
		"default_max_age_hours": "not-a-number",
	})
	if err != nil {
		t.Fatalf("Configure() with invalid max age should not return error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// encryptDEKWithSharedSecret – short secret error path
// ---------------------------------------------------------------------------

// TestEncryptDEKWithSharedSecret_ShortSecret verifies error when shared secret is too short.
func TestEncryptDEKWithSharedSecret_ShortSecret(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.encryptDEKWithSharedSecret(
		[]byte("dek"),
		[]byte("short"), // only 5 bytes, need >= 32
		[]byte("kem-ciphertext"),
	)
	if err == nil {
		t.Fatal("expected error for shared secret shorter than 32 bytes")
	}
}

// TestEncryptDEKWithSharedSecret_Success verifies successful encryption.
func TestEncryptDEKWithSharedSecret_Success(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i)
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	kemCiphertext := []byte("kem-ct-prefix")

	result, err := provider.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	if err != nil {
		t.Fatalf("encryptDEKWithSharedSecret() error = %v", err)
	}
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

// ---------------------------------------------------------------------------
// decryptDEKWithSharedSecret – error paths
// ---------------------------------------------------------------------------

// TestDecryptDEKWithSharedSecret_ShortSecret verifies error when shared secret is too short.
func TestDecryptDEKWithSharedSecret_ShortSecret(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	_, err := provider.decryptDEKWithSharedSecret(
		[]byte("encrypted-dek"),
		[]byte("short"), // only 5 bytes
	)
	if err == nil {
		t.Fatal("expected error for shared secret shorter than 32 bytes")
	}
}

// TestDecryptDEKWithSharedSecret_ShortEncryptedDEK verifies error when encrypted DEK is too short.
func TestDecryptDEKWithSharedSecret_ShortEncryptedDEK(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	sharedSecret := make([]byte, 32)
	_, err := provider.decryptDEKWithSharedSecret(
		[]byte("tiny"), // shorter than GCM nonce size (12 bytes)
		sharedSecret,
	)
	if err == nil {
		t.Fatal("expected error for encrypted DEK shorter than nonce size")
	}
}

// TestEncryptDecryptDEKWithSharedSecret_RoundTrip verifies encrypt→decrypt roundtrip.
func TestEncryptDecryptDEKWithSharedSecret_RoundTrip(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}
	dek := []byte("the-dek-payload-12345678901234")
	kemCiphertext := []byte("kem-ct")

	combined, err := provider.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	if err != nil {
		t.Fatalf("encryptDEKWithSharedSecret() error = %v", err)
	}

	// The combined result is: kemCiphertext + nonce + ciphertext
	// Strip the kemCiphertext prefix to get just the encrypted DEK portion
	encryptedDEK := combined[len(kemCiphertext):]

	decrypted, err := provider.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
	if err != nil {
		t.Fatalf("decryptDEKWithSharedSecret() error = %v", err)
	}
	if string(decrypted) != string(dek) {
		t.Errorf("decrypted = %q, want %q", decrypted, dek)
	}
}

// TestDecryptDEKWithSharedSecret_BadCiphertext verifies error when ciphertext is tampered.
func TestDecryptDEKWithSharedSecret_BadCiphertext(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	sharedSecret := make([]byte, 32)

	// Create valid-length but garbage encrypted DEK (nonce size = 12, plus garbage)
	garbage := make([]byte, 12+16) // nonce + garbage data
	for i := range garbage {
		garbage[i] = byte(i)
	}

	_, err := provider.decryptDEKWithSharedSecret(garbage, sharedSecret)
	if err == nil {
		t.Fatal("expected error when decrypting tampered ciphertext")
	}
}

// ---------------------------------------------------------------------------
// GenerateKeyPair – Kyber variants (covered indirectly via Kyber files)
// ---------------------------------------------------------------------------

// TestSoftwareKeyProvider_GenerateKeyPair_Kyber512 exercises Kyber-512 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_Kyber512(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_512, "kyber512-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair Kyber-512 error = %v", err)
	}
	if keyPair == nil {
		t.Fatal("expected non-nil key pair")
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_Kyber768 exercises Kyber-768 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_Kyber768(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_768, "kyber768-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair Kyber-768 error = %v", err)
	}
	if keyPair == nil {
		t.Fatal("expected non-nil key pair")
	}
}

// TestSoftwareKeyProvider_GenerateKeyPair_Kyber1024 exercises Kyber-1024 branch.
func TestSoftwareKeyProvider_GenerateKeyPair_Kyber1024(t *testing.T) {
	ctx := context.Background()
	provider := NewSoftwareKeyProvider(nil)
	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_1024, "kyber1024-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair Kyber-1024 error = %v", err)
	}
	if keyPair == nil {
		t.Fatal("expected non-nil key pair")
	}
}

// TestSoftwareKeyProvider_Encrypt_Kyber verifies Kyber key encryption path.
func TestSoftwareKeyProvider_Encrypt_Kyber(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_512, "kyber-enc-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair Kyber-512 error = %v", err)
	}
	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	plaintext := []byte("kyber-secret-data")
	ciphertext, err := provider.Encrypt(ctx, "kyber-enc-key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt with Kyber key error = %v", err)
	}
	if len(ciphertext) == 0 {
		t.Error("expected non-empty ciphertext")
	}
}

// TestSoftwareKeyProvider_Decrypt_Kyber verifies Kyber key decryption path.
func TestSoftwareKeyProvider_Decrypt_Kyber(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_KYBER_512, "kyber-dec-key", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair Kyber-512 error = %v", err)
	}
	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	plaintext := []byte("kyber-roundtrip-data")
	ciphertext, err := provider.Encrypt(ctx, "kyber-dec-key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt with Kyber key error = %v", err)
	}

	decrypted, err := provider.Decrypt(ctx, "kyber-dec-key", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt with Kyber key error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

// TestSoftwareKeyProvider_Sign_UnsupportedKeyType exercises error branch for unsupported private key type.
func TestSoftwareKeyProvider_Sign_UnsupportedKeyType(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	// Inject a key with an unsupported private key type
	keyPair := &KeyPair{
		KeyID:        "unsupported-sign-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKey:    nil,
		PrivateKey:   "not-a-real-key", // unsupported type
		PublicKeyPEM: "pem-data",
		Metadata:     map[string]string{},
	}
	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	_, err := provider.Sign(ctx, "unsupported-sign-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error when signing with unsupported private key type")
	}
}

// TestSoftwareKeyProvider_Encrypt_UnsupportedKeyType exercises error branch for unsupported public key type.
func TestSoftwareKeyProvider_Encrypt_UnsupportedKeyType(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	// Inject a key with an unsupported public key type
	keyPair := &KeyPair{
		KeyID:        "unsupported-enc-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKey:    "not-a-real-key", // unsupported type
		PrivateKey:   "not-a-real-key",
		PublicKeyPEM: "pem-data",
		Metadata:     map[string]string{},
	}
	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	_, err := provider.Encrypt(ctx, "unsupported-enc-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error when encrypting with unsupported public key type")
	}
}

// TestSoftwareKeyProvider_Decrypt_UnsupportedKeyType exercises error branch for unsupported private key type.
func TestSoftwareKeyProvider_Decrypt_UnsupportedKeyType(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair := &KeyPair{
		KeyID:        "unsupported-dec-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		PublicKey:    "not-a-real-key",
		PrivateKey:   "not-a-real-key", // unsupported type
		PublicKeyPEM: "pem-data",
		Metadata:     map[string]string{},
	}
	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	_, err := provider.Decrypt(ctx, "unsupported-dec-key", []byte("data"))
	if err == nil {
		t.Fatal("expected error when decrypting with unsupported private key type")
	}
}

// TestSoftwareKeyProvider_GetKeyPair_Expired verifies error for expired key.
func TestSoftwareKeyProvider_GetKeyPair_Expired(t *testing.T) {
	ctx := context.Background()
	keyStore := NewInMemoryKeyStore()
	provider := NewSoftwareKeyProvider(nil)
	provider.SetKeyStore(keyStore)

	keyPair, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "exp-key", map[string]string{
		"max_age_hours": "0", // 0 hours = already expired
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	// ExpiresAt should be set but may be in the past (0h from now)
	if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
		t.Fatalf("StoreKeyPair: %v", err)
	}

	// Only test if key was actually expired
	if keyPair.ExpiresAt != nil {
		// Manually set to past
		past := keyPair.CreatedAt.Add(-1)
		keyPair.ExpiresAt = &past
		// Re-store
		if err := keyStore.StoreKeyPair(ctx, keyPair); err != nil {
			t.Fatalf("StoreKeyPair re-store: %v", err)
		}

		_, err = provider.GetKeyPair(ctx, "exp-key")
		if err == nil {
			t.Fatal("expected error for expired key")
		}
	}
}
