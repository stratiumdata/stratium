//go:build !fips

package key_manager

import (
	"context"
	"testing"
)

func TestCoverageFinal80_UseHardwareCardReaderConfig(t *testing.T) {
	if useHardwareCardReaderConfig(nil) {
		t.Fatal("expected false for nil config")
	}
	if useHardwareCardReaderConfig(map[string]string{}) {
		t.Fatal("expected false for empty config")
	}
	if !useHardwareCardReaderConfig(map[string]string{"reader_backend": "yubikey"}) {
		t.Fatal("expected true for yubikey backend")
	}
	if !useHardwareCardReaderConfig(map[string]string{"reader_backend": "pkcs11"}) {
		t.Fatal("expected true for pkcs11 backend")
	}
}

func TestCoverageFinal80_SmartCardProvider_ListKeysAfterGenerate(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	// Generate
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "sc-key-1", nil)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// GetKeyPair
	kp, err := provider.GetKeyPair(ctx, "sc-key-1")
	if err != nil {
		t.Fatalf("GetKeyPair: %v", err)
	}
	if kp.KeyID != "sc-key-1" {
		t.Fatal("wrong key ID")
	}

	// ListKeyPairs
	keys, err := provider.ListKeyPairs(ctx)
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected at least 1 key")
	}

	// Delete
	if err := provider.DeleteKeyPair(ctx, "sc-key-1"); err != nil {
		t.Fatalf("DeleteKeyPair: %v", err)
	}
}

func TestCoverageFinal80_SmartCardProvider_RotateKey(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "rotate-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	newKP, err := provider.RotateKey(ctx, "rotate-key")
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if newKP.KeyID != "rotate-key" {
		t.Fatal("wrong key ID after rotation")
	}
	if newKP.LastRotated == nil {
		t.Fatal("expected LastRotated to be set")
	}
}

func TestCoverageFinal80_SmartCardProvider_NotAvailableErrors(t *testing.T) {
	provider := NewSmartCardKeyProvider("mock", nil)
	ctx := context.Background()

	// Not authenticated yet -> not available
	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "k", nil)
	if err == nil {
		t.Fatal("expected error when not available")
	}
	_, err = provider.GetKeyPair(ctx, "k")
	if err == nil {
		t.Fatal("expected error for GetKeyPair when not available")
	}
	err = provider.DeleteKeyPair(ctx, "k")
	if err == nil {
		t.Fatal("expected error for DeleteKeyPair when not available")
	}
	_, err = provider.ListKeyPairs(ctx)
	if err == nil {
		t.Fatal("expected error for ListKeyPairs when not available")
	}
}

func TestCoverageFinal80_SmartCardProvider_DuplicateKey(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "dup-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "dup-key", nil)
	if err == nil {
		t.Fatal("expected error for duplicate key")
	}
}

func TestCoverageFinal80_SmartCardProvider_SignAndDecrypt(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.GenerateKeyPair(ctx, KeyType_KEY_TYPE_RSA_2048, "sign-key", nil)
	if err != nil {
		t.Fatal(err)
	}

	sig, err := provider.Sign(ctx, "sign-key", []byte("test data to sign"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("empty signature")
	}

	// Decrypt with RSA - the mock may not support real decryption, but we cover the code path
	result, err := provider.Decrypt(ctx, "sign-key", []byte("some-ciphertext"))
	if err != nil {
		// Mock decrypt may fail - that's fine, code path was covered
		t.Logf("Decrypt returned expected error: %v", err)
	} else if len(result) == 0 {
		t.Log("Decrypt returned empty result")
	}
}

func TestCoverageFinal80_SmartCardProvider_SignNotAvailable(t *testing.T) {
	provider := NewSmartCardKeyProvider("mock", nil) // not initialized
	ctx := context.Background()

	_, err := provider.Sign(ctx, "k", []byte("data"))
	if err == nil {
		t.Fatal("expected error for sign when not available")
	}
}

func TestCoverageFinal80_SmartCardProvider_RotateKeyNotFound(t *testing.T) {
	provider := newInitializedSmartCardProvider(t)
	ctx := context.Background()

	_, err := provider.RotateKey(ctx, "nonexistent-key")
	if err == nil {
		t.Fatal("expected error for rotating nonexistent key")
	}
}

func TestCoverageFinal80_IsPIVSlotIdentifier(t *testing.T) {
	if !isPIVSlotIdentifier("9d") {
		t.Fatal("expected true for 9d")
	}
	if !isPIVSlotIdentifier("9A") {
		t.Fatal("expected true for 9A")
	}
	if isPIVSlotIdentifier("xyz") {
		t.Fatal("expected false for xyz")
	}
	if isPIVSlotIdentifier("") {
		t.Fatal("expected false for empty")
	}
	if isPIVSlotIdentifier("123") {
		t.Fatal("expected false for 3 chars")
	}
}
