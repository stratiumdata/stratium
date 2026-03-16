package key_manager

import (
	"context"
	"testing"
)

// newConnectedHSMProvider creates an HSMKeyProvider backed by MockHSMClient,
// with the client already connected and initialized.
func newConnectedHSMProvider(t *testing.T) *HSMKeyProvider {
	t.Helper()
	p := NewHSMKeyProvider(nil)
	if err := p.Configure(map[string]string{"hsm_endpoint": "mock"}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

// injectHSMKey injects a key directly into the MockHSMClient and the provider's
// keyMetadata map so that operations requiring an existing key work without calling
// GenerateKeyPair (which deadlocks in the current implementation because it holds
// the write lock and then calls IsAvailable which tries to acquire the read lock).
func injectHSMKey(p *HSMKeyProvider, keyID string, keyType KeyType) {
	mock := p.hsmClient.(*MockHSMClient)
	mock.keys[keyID] = map[string]interface{}{"type": keyType}
	p.keyMetadata[keyID] = &KeyPair{
		KeyID:    keyID,
		KeyType:  keyType,
		Metadata: map[string]string{},
	}
}

// ---------------------------------------------------------------------------
// Provider Configure / GetConfiguration
// ---------------------------------------------------------------------------

func TestHSMProvider_Configure_AndGetConfig(t *testing.T) {
	p := newConnectedHSMProvider(t)

	cfg := p.GetConfiguration()
	if cfg["hsm_endpoint"] != "mock" {
		t.Fatalf("expected hsm_endpoint=mock in configuration, got %v", cfg)
	}
}

func TestHSMProvider_Configure_ReconnectsClient(t *testing.T) {
	p := newConnectedHSMProvider(t)

	// Disconnect the underlying client.
	p.hsmClient.Disconnect() //nolint:errcheck

	// Calling Configure again should reconnect.
	if err := p.Configure(map[string]string{"hsm_endpoint": "mock"}); err != nil {
		t.Fatalf("Configure (re-connect) failed: %v", err)
	}
	if !p.hsmClient.IsConnected() {
		t.Fatal("expected HSM client to be reconnected after second Configure()")
	}
}

// ---------------------------------------------------------------------------
// IsAvailable
// ---------------------------------------------------------------------------

func TestHSMProvider_IsAvailable_AfterConfigure(t *testing.T) {
	p := newConnectedHSMProvider(t)
	if !p.IsAvailable() {
		t.Fatal("expected provider to be available after Configure")
	}
}

// ---------------------------------------------------------------------------
// GetKeyPair
// ---------------------------------------------------------------------------

func TestHSMProvider_GetKeyPair_NotFound(t *testing.T) {
	p := newConnectedHSMProvider(t)

	_, err := p.GetKeyPair(context.Background(), "missing-key")
	if err == nil {
		t.Fatal("expected GetKeyPair to fail for missing key")
	}
}

func TestHSMProvider_GetKeyPair_Found(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "injected-key", KeyType_KEY_TYPE_RSA_2048)

	kp, err := p.GetKeyPair(context.Background(), "injected-key")
	if err != nil {
		t.Fatalf("GetKeyPair() failed: %v", err)
	}
	if kp.KeyID != "injected-key" {
		t.Fatalf("unexpected key ID: %s", kp.KeyID)
	}
}

func TestHSMProvider_GetKeyPair_NotAvailable(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	_, err := p.GetKeyPair(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected GetKeyPair to fail when not available")
	}
}

// ---------------------------------------------------------------------------
// ListKeyPairs — uses RLock so no deadlock
// ---------------------------------------------------------------------------

func TestHSMProvider_ListKeyPairs(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "list-key-1", KeyType_KEY_TYPE_RSA_2048)
	injectHSMKey(p, "list-key-2", KeyType_KEY_TYPE_ECC_P256)

	keys, err := p.ListKeyPairs(context.Background())
	if err != nil {
		t.Fatalf("ListKeyPairs() failed: %v", err)
	}
	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}
}

func TestHSMProvider_ListKeyPairs_NotAvailable(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	_, err := p.ListKeyPairs(context.Background())
	if err == nil {
		t.Fatal("expected ListKeyPairs to fail when not available")
	}
}

// ---------------------------------------------------------------------------
// Sign — no outer lock so no deadlock
// ---------------------------------------------------------------------------

func TestHSMProvider_Sign(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "sign-key", KeyType_KEY_TYPE_RSA_2048)

	sig, err := p.Sign(context.Background(), "sign-key", []byte("hello"))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}
}

func TestHSMProvider_Sign_NotAvailable(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	_, err := p.Sign(context.Background(), "k1", []byte("data"))
	if err == nil {
		t.Fatal("expected Sign to fail when not available")
	}
}

func TestHSMProvider_Sign_KeyNotFound(t *testing.T) {
	p := newConnectedHSMProvider(t)
	_, err := p.Sign(context.Background(), "missing-key", []byte("data"))
	if err == nil {
		t.Fatal("expected Sign to fail for unknown key")
	}
}

func TestHSMProvider_Sign_UpdatesUsageCount(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "usage-key", KeyType_KEY_TYPE_RSA_2048)
	kp := p.keyMetadata["usage-key"]
	kp.UsageCount = 0

	p.Sign(context.Background(), "usage-key", []byte("data")) //nolint:errcheck

	if kp.UsageCount != 1 {
		t.Fatalf("expected usage count 1, got %d", kp.UsageCount)
	}
}

// ---------------------------------------------------------------------------
// Decrypt — no outer lock so no deadlock
// ---------------------------------------------------------------------------

func TestHSMProvider_Decrypt(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "dec-key", KeyType_KEY_TYPE_RSA_2048)

	plaintext, err := p.Decrypt(context.Background(), "dec-key", []byte("ciphertext"))
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if len(plaintext) == 0 {
		t.Fatal("expected non-empty plaintext from mock decrypt")
	}
}

func TestHSMProvider_Decrypt_NotAvailable(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	_, err := p.Decrypt(context.Background(), "k1", []byte("c"))
	if err == nil {
		t.Fatal("expected Decrypt to fail when not available")
	}
}

func TestHSMProvider_Decrypt_KeyNotFound(t *testing.T) {
	p := newConnectedHSMProvider(t)
	_, err := p.Decrypt(context.Background(), "missing", []byte("c"))
	if err == nil {
		t.Fatal("expected Decrypt to fail for unknown key")
	}
}

// ---------------------------------------------------------------------------
// Encrypt — no outer lock so no deadlock
// ---------------------------------------------------------------------------

func TestHSMProvider_Encrypt(t *testing.T) {
	p := newConnectedHSMProvider(t)
	injectHSMKey(p, "enc-key", KeyType_KEY_TYPE_RSA_2048)

	ciphertext, err := p.Encrypt(context.Background(), "enc-key", []byte("plaintext"))
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("expected non-empty ciphertext from mock encrypt")
	}
}

func TestHSMProvider_Encrypt_NotAvailable(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	_, err := p.Encrypt(context.Background(), "k1", []byte("p"))
	if err == nil {
		t.Fatal("expected Encrypt to fail when not available")
	}
}

func TestHSMProvider_Encrypt_KeyNotFound(t *testing.T) {
	p := newConnectedHSMProvider(t)
	_, err := p.Encrypt(context.Background(), "missing", []byte("p"))
	if err == nil {
		t.Fatal("expected Encrypt to fail for unknown key")
	}
}

// ---------------------------------------------------------------------------
// MockHSMClient direct tests
// ---------------------------------------------------------------------------

func TestMockHSMClient_NotConnected(t *testing.T) {
	m := &MockHSMClient{keys: make(map[string]interface{})}

	if err := m.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "k", nil); err == nil {
		t.Fatal("expected GenerateKey to fail when not connected")
	}
	if _, err := m.GetPublicKey("k"); err == nil {
		t.Fatal("expected GetPublicKey to fail when not connected")
	}
	if err := m.DeleteKey("k"); err == nil {
		t.Fatal("expected DeleteKey to fail when not connected")
	}
	if _, err := m.ListKeys(); err == nil {
		t.Fatal("expected ListKeys to fail when not connected")
	}
	if _, err := m.Sign("k", nil); err == nil {
		t.Fatal("expected Sign to fail when not connected")
	}
	if _, err := m.Decrypt("k", nil); err == nil {
		t.Fatal("expected Decrypt to fail when not connected")
	}
	if _, err := m.Encrypt("k", nil); err == nil {
		t.Fatal("expected Encrypt to fail when not connected")
	}
	if _, err := m.GetKeyInfo("k"); err == nil {
		t.Fatal("expected GetKeyInfo to fail when not connected")
	}
}

func TestMockHSMClient_FullLifecycle(t *testing.T) {
	m := &MockHSMClient{keys: make(map[string]interface{})}

	if err := m.Connect(nil); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}
	if !m.IsConnected() {
		t.Fatal("expected connected after Connect()")
	}

	if err := m.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "k1", nil); err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	pub, err := m.GetPublicKey("k1")
	if err != nil {
		t.Fatalf("GetPublicKey() failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}

	info, err := m.GetKeyInfo("k1")
	if err != nil {
		t.Fatalf("GetKeyInfo() failed: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil key info")
	}

	keys, err := m.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys() failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	sig, err := m.Sign("k1", []byte("data"))
	if err != nil {
		t.Fatalf("Sign() failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	ct, err := m.Encrypt("k1", []byte("plain"))
	if err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if len(ct) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}

	pt, err := m.Decrypt("k1", []byte("cipher"))
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if len(pt) == 0 {
		t.Fatal("expected non-empty plaintext")
	}

	if err := m.DeleteKey("k1"); err != nil {
		t.Fatalf("DeleteKey() failed: %v", err)
	}

	// Key should be gone.
	if _, err := m.GetPublicKey("k1"); err == nil {
		t.Fatal("expected GetPublicKey to fail after delete")
	}
	if _, err := m.GetKeyInfo("k1"); err == nil {
		t.Fatal("expected GetKeyInfo to fail after delete")
	}
	if _, err := m.Sign("k1", nil); err == nil {
		t.Fatal("expected Sign to fail after delete")
	}
	if _, err := m.Encrypt("k1", nil); err == nil {
		t.Fatal("expected Encrypt to fail after delete")
	}
	if _, err := m.Decrypt("k1", nil); err == nil {
		t.Fatal("expected Decrypt to fail after delete")
	}

	if err := m.Disconnect(); err != nil {
		t.Fatalf("Disconnect() failed: %v", err)
	}
	if m.IsConnected() {
		t.Fatal("expected disconnected after Disconnect()")
	}
}

func TestMockHSMClient_GenerateKey_Options(t *testing.T) {
	m := &MockHSMClient{keys: make(map[string]interface{})}
	m.Connect(nil) //nolint:errcheck

	// Generate with non-nil options map.
	if err := m.GenerateKey(KeyType_KEY_TYPE_ECC_P256, "ecc-key", map[string]interface{}{"comment": "test"}); err != nil {
		t.Fatalf("GenerateKey with options failed: %v", err)
	}

	keys, _ := m.ListKeys()
	if len(keys) != 1 {
		t.Fatalf("expected 1 key after generate, got %d", len(keys))
	}
}

// TestMockPublicKey_Equal exercises MockPublicKey.Equal.
func TestMockPublicKey_Equal(t *testing.T) {
	a := &MockPublicKey{keyID: "a"}
	b := &MockPublicKey{keyID: "a"}
	c := &MockPublicKey{keyID: "c"}

	if !a.Equal(b) {
		t.Fatal("expected a.Equal(b) to be true for same key ID")
	}
	if a.Equal(c) {
		t.Fatal("expected a.Equal(c) to be false for different key ID")
	}
	if a.Equal("not-a-mock-key") {
		t.Fatal("expected a.Equal to be false for non-MockPublicKey")
	}
}
