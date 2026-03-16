package key_manager

import (
	"context"
	"testing"
	"time"
)

// Note: GenerateKeyPair, DeleteKeyPair, and RotateKey in HSMKeyProvider have a known
// mutex deadlock bug (they hold the write lock then call IsAvailable() which takes a
// read lock), so those methods cannot be tested safely.

// TestHSMProvider_GetKeyPair_Expired verifies that an expired key returns an error.
func TestHSMProvider_GetKeyPair_Expired(t *testing.T) {
	p := newConnectedHSMProvider(t)

	// Inject a key with an expired ExpiresAt
	past := time.Now().Add(-time.Hour)
	mock := p.hsmClient.(*MockHSMClient)
	mock.keys["expired-key"] = map[string]interface{}{"type": KeyType_KEY_TYPE_RSA_2048}
	p.keyMetadata["expired-key"] = &KeyPair{
		KeyID:     "expired-key",
		KeyType:   KeyType_KEY_TYPE_RSA_2048,
		ExpiresAt: &past,
		Metadata:  map[string]string{},
	}

	_, err := p.GetKeyPair(context.Background(), "expired-key")
	if err == nil {
		t.Fatal("expected GetKeyPair to fail for expired key")
	}
}

// TestHSMProvider_Encrypt_UpdatesUsageCount verifies that Encrypt increments usage count.
func TestHSMProvider_Encrypt_UpdatesUsageCount(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "enc-usage-key", KeyType_KEY_TYPE_RSA_2048)
	kp := p.keyMetadata["enc-usage-key"]
	kp.UsageCount = 0

	_, err := p.Encrypt(context.Background(), "enc-usage-key", []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if kp.UsageCount != 1 {
		t.Fatalf("expected usage count 1, got %d", kp.UsageCount)
	}
}

// TestHSMProvider_Decrypt_UpdatesUsageCount verifies that Decrypt increments usage count.
func TestHSMProvider_Decrypt_UpdatesUsageCount(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "dec-usage-key", KeyType_KEY_TYPE_RSA_2048)
	kp := p.keyMetadata["dec-usage-key"]
	kp.UsageCount = 0

	_, err := p.Decrypt(context.Background(), "dec-usage-key", []byte("ciphertext"))
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if kp.UsageCount != 1 {
		t.Fatalf("expected usage count 1, got %d", kp.UsageCount)
	}
}

// TestHSMProvider_ProviderProperties verifies provider metadata methods.
func TestHSMProvider_ProviderProperties(t *testing.T) {
	p := NewHSMKeyProvider(nil)

	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_HSM {
		t.Errorf("GetProviderType() = %v, want HSM", p.GetProviderType())
	}
	if p.GetProviderName() == "" {
		t.Error("GetProviderName() returned empty string")
	}
	if !p.SupportsRotation() {
		t.Error("SupportsRotation() = false, want true")
	}
	if !p.SupportsHardwareSecurity() {
		t.Error("SupportsHardwareSecurity() = false, want true")
	}

	keyTypes := p.GetSupportedKeyTypes()
	if len(keyTypes) == 0 {
		t.Error("GetSupportedKeyTypes() returned empty list")
	}
}

// TestHSMProvider_IsAvailable_BeforeConfigure verifies false before Configure is called.
func TestHSMProvider_IsAvailable_BeforeConfigure(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	if p.IsAvailable() {
		t.Fatal("expected IsAvailable() to return false before Configure()")
	}
}
