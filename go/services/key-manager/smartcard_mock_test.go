package key_manager

import (
	"context"
	"testing"
)

// newConnectedSmartCardProvider creates a SmartCardKeyProvider using the embedded
// MockCardReader, with Connect + SelectDevice + Authenticate already performed.
func newConnectedSmartCardProvider(t *testing.T) *SmartCardKeyProvider {
	t.Helper()
	p := NewSmartCardKeyProvider("smartcard", nil)
	if err := p.Configure(map[string]string{
		"pin":       "1234",
		"device_id": "mock-device-1",
	}); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Provider metadata / lifecycle
// ---------------------------------------------------------------------------

func TestSmartCardProvider_GetProviderType_SmartCard(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD {
		t.Fatalf("unexpected provider type: %v", p.GetProviderType())
	}
}

func TestSmartCardProvider_GetProviderType_USBToken(t *testing.T) {
	p := NewSmartCardKeyProvider("usb_token", nil)
	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN {
		t.Fatalf("unexpected provider type for usb_token: %v", p.GetProviderType())
	}
}

func TestSmartCardProvider_GetProviderName_SmartCard(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if p.GetProviderName() == "" {
		t.Fatal("expected non-empty provider name")
	}
}

func TestSmartCardProvider_GetProviderName_USBToken(t *testing.T) {
	p := NewSmartCardKeyProvider("usb_token", nil)
	if p.GetProviderName() == "" {
		t.Fatal("expected non-empty provider name for usb_token")
	}
}

func TestSmartCardProvider_SupportsRotation(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if !p.SupportsRotation() {
		t.Fatal("expected smart card provider to support rotation")
	}
}

func TestSmartCardProvider_SupportsHardwareSecurity(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if !p.SupportsHardwareSecurity() {
		t.Fatal("expected smart card provider to support hardware security")
	}
}

func TestSmartCardProvider_IsAvailable_BeforeConfigure(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if p.IsAvailable() {
		t.Fatal("expected provider to be unavailable before Configure")
	}
}

func TestSmartCardProvider_IsAvailable_AfterConfigure(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	if !p.IsAvailable() {
		t.Fatal("expected provider to be available after Configure + Authenticate")
	}
}

// ---------------------------------------------------------------------------
// GetConfiguration – PIN must not be returned
// ---------------------------------------------------------------------------

func TestSmartCardProvider_GetConfiguration_ExcludesPIN(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	cfg := p.GetConfiguration()
	if _, hasPIN := cfg["pin"]; hasPIN {
		t.Fatal("PIN must not appear in GetConfiguration output")
	}
	if cfg["device_id"] != "mock-device-1" {
		t.Fatalf("expected device_id in config, got %v", cfg)
	}
}

// ---------------------------------------------------------------------------
// GenerateKeyPair
// ---------------------------------------------------------------------------

func TestSmartCardProvider_GenerateKeyPair_RSA2048(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	kp, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-rsa-1", map[string]string{})
	if err != nil {
		t.Fatalf("GenerateKeyPair RSA-2048 failed: %v", err)
	}
	if kp.PublicKeyPEM == "" {
		t.Fatal("expected non-empty PublicKeyPEM")
	}
	if kp.KeyID != "sc-rsa-1" {
		t.Fatalf("unexpected key ID: %s", kp.KeyID)
	}
}

func TestSmartCardProvider_GenerateKeyPair_ECC_P256(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	kp, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P256, "sc-ecc-1", map[string]string{})
	if err != nil {
		t.Fatalf("GenerateKeyPair ECC P-256 failed: %v", err)
	}
	if kp.PublicKeyPEM == "" {
		t.Fatal("expected non-empty PublicKeyPEM")
	}
}

func TestSmartCardProvider_GenerateKeyPair_ECC_P384(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	kp, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P384, "sc-ecc384-1", map[string]string{})
	if err != nil {
		t.Fatalf("GenerateKeyPair ECC P-384 failed: %v", err)
	}
	if kp.PublicKeyPEM == "" {
		t.Fatal("expected non-empty PublicKeyPEM")
	}
}

func TestSmartCardProvider_GenerateKeyPair_Unsupported(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	_, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_4096, "sc-rsa4096", map[string]string{})
	if err == nil {
		t.Fatal("expected GenerateKeyPair to fail for unsupported key type RSA-4096")
	}
}

func TestSmartCardProvider_GenerateKeyPair_DuplicateID(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "dup-sc", map[string]string{}); err != nil {
		t.Fatalf("first GenerateKeyPair failed: %v", err)
	}
	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "dup-sc", map[string]string{}); err == nil {
		t.Fatal("expected GenerateKeyPair to fail for duplicate key ID")
	}
}

func TestSmartCardProvider_GenerateKeyPair_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "k1", map[string]string{})
	if err == nil {
		t.Fatal("expected GenerateKeyPair to fail when not available")
	}
}

func TestSmartCardProvider_GenerateKeyPair_WithExpiry(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	kp, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-expiry", map[string]string{
		"max_age_hours": "24",
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair with expiry failed: %v", err)
	}
	if kp.ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set when max_age_hours is provided")
	}
}

// ---------------------------------------------------------------------------
// GetKeyPair
// ---------------------------------------------------------------------------

func TestSmartCardProvider_GetKeyPair_NotFound(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	_, err := p.GetKeyPair(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected GetKeyPair to fail for missing key")
	}
}

func TestSmartCardProvider_GetKeyPair_Found(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-get", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	kp, err := p.GetKeyPair(context.Background(), "sc-get")
	if err != nil {
		t.Fatalf("GetKeyPair failed: %v", err)
	}
	if kp.KeyID != "sc-get" {
		t.Fatalf("unexpected key ID: %s", kp.KeyID)
	}
}

func TestSmartCardProvider_GetKeyPair_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.GetKeyPair(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected GetKeyPair to fail when not available")
	}
}

// ---------------------------------------------------------------------------
// DeleteKeyPair
// ---------------------------------------------------------------------------

func TestSmartCardProvider_DeleteKeyPair(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-del", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if err := p.DeleteKeyPair(context.Background(), "sc-del"); err != nil {
		t.Fatalf("DeleteKeyPair failed: %v", err)
	}

	// Verify metadata is gone.
	if _, exists := p.keyMetadata["sc-del"]; exists {
		t.Fatal("expected key metadata to be removed after delete")
	}
}

func TestSmartCardProvider_DeleteKeyPair_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	err := p.DeleteKeyPair(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected DeleteKeyPair to fail when not available")
	}
}

// ---------------------------------------------------------------------------
// ListKeyPairs
// ---------------------------------------------------------------------------

func TestSmartCardProvider_ListKeyPairs(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-list-1", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P256, "sc-list-2", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	keys, err := p.ListKeyPairs(context.Background())
	if err != nil {
		t.Fatalf("ListKeyPairs failed: %v", err)
	}
	if len(keys) < 2 {
		t.Fatalf("expected at least 2 keys, got %d", len(keys))
	}
}

func TestSmartCardProvider_ListKeyPairs_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.ListKeyPairs(context.Background())
	if err == nil {
		t.Fatal("expected ListKeyPairs to fail when not available")
	}
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

func TestSmartCardProvider_Sign_RSA(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-sign", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	sig, err := p.Sign(context.Background(), "sc-sign", []byte("payload"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}
}

func TestSmartCardProvider_Sign_ECC(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_ECC_P256, "sc-sign-ecc", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	sig, err := p.Sign(context.Background(), "sc-sign-ecc", []byte("payload"))
	if err != nil {
		t.Fatalf("Sign (ECC) failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty ECC signature")
	}
}

func TestSmartCardProvider_Sign_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.Sign(context.Background(), "k1", []byte("data"))
	if err == nil {
		t.Fatal("expected Sign to fail when not available")
	}
}

func TestSmartCardProvider_Sign_KeyNotFound(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	_, err := p.Sign(context.Background(), "missing", []byte("data"))
	if err == nil {
		t.Fatal("expected Sign to fail for unknown key")
	}
}

// ---------------------------------------------------------------------------
// Encrypt / Decrypt round-trip
// ---------------------------------------------------------------------------

func TestSmartCardProvider_EncryptDecrypt_RSA(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-enc", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	plaintext := []byte("smartcard-roundtrip-test")
	ciphertext, err := p.Encrypt(context.Background(), "sc-enc", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	recovered, err := p.Decrypt(context.Background(), "sc-enc", ciphertext)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", string(recovered), string(plaintext))
	}
}

func TestSmartCardProvider_Encrypt_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.Encrypt(context.Background(), "k1", []byte("p"))
	if err == nil {
		t.Fatal("expected Encrypt to fail when not available")
	}
}

func TestSmartCardProvider_Decrypt_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.Decrypt(context.Background(), "k1", []byte("c"))
	if err == nil {
		t.Fatal("expected Decrypt to fail when not available")
	}
}

func TestSmartCardProvider_Encrypt_KeyNotFound(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	_, err := p.Encrypt(context.Background(), "missing", []byte("p"))
	if err == nil {
		t.Fatal("expected Encrypt to fail for unknown key")
	}
}

func TestSmartCardProvider_Decrypt_KeyNotFound(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	_, err := p.Decrypt(context.Background(), "missing", []byte("c"))
	if err == nil {
		t.Fatal("expected Decrypt to fail for unknown key")
	}
}

// ---------------------------------------------------------------------------
// RotateKey
// ---------------------------------------------------------------------------

func TestSmartCardProvider_RotateKey(t *testing.T) {
	p := newConnectedSmartCardProvider(t)

	if _, err := p.GenerateKeyPair(context.Background(), KeyType_KEY_TYPE_RSA_2048, "sc-rot", map[string]string{}); err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	rotated, err := p.RotateKey(context.Background(), "sc-rot")
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	if rotated.LastRotated == nil {
		t.Fatal("expected LastRotated to be set after rotation")
	}
}

func TestSmartCardProvider_RotateKey_NotFound(t *testing.T) {
	p := newConnectedSmartCardProvider(t)
	_, err := p.RotateKey(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected RotateKey to fail for missing key")
	}
}

func TestSmartCardProvider_RotateKey_NotAvailable(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	_, err := p.RotateKey(context.Background(), "k1")
	if err == nil {
		t.Fatal("expected RotateKey to fail when not available")
	}
}

// ---------------------------------------------------------------------------
// MockCardReader – direct tests for additional coverage
// ---------------------------------------------------------------------------

func TestMockCardReader_NotConnected(t *testing.T) {
	m := newMockCardReader()

	if _, err := m.ListDevices(); err == nil {
		t.Fatal("ListDevices should fail when not connected")
	}
	if err := m.SelectDevice("mock-device-1"); err == nil {
		t.Fatal("SelectDevice should fail when not connected")
	}
	if err := m.Authenticate("1234"); err == nil {
		t.Fatal("Authenticate should fail when not connected")
	}
	if err := m.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "k", nil); err == nil {
		t.Fatal("GenerateKey should fail when not connected")
	}
	if _, err := m.GetPublicKey("k"); err == nil {
		t.Fatal("GetPublicKey should fail when not connected")
	}
	if err := m.DeleteKey("k"); err == nil {
		t.Fatal("DeleteKey should fail when not connected")
	}
	if _, err := m.ListKeys(); err == nil {
		t.Fatal("ListKeys should fail when not connected")
	}
	if _, err := m.Sign("k", nil); err == nil {
		t.Fatal("Sign should fail when not connected")
	}
	if _, err := m.Decrypt("k", nil); err == nil {
		t.Fatal("Decrypt should fail when not connected")
	}
	if _, err := m.Encrypt("k", nil); err == nil {
		t.Fatal("Encrypt should fail when not connected")
	}
	if _, err := m.GetKeyInfo("k"); err == nil {
		t.Fatal("GetKeyInfo should fail when not connected")
	}
}

func TestMockCardReader_ConnectAndListDevices(t *testing.T) {
	m := newMockCardReader()
	if err := m.Connect(nil); err != nil {
		t.Fatalf("Connect() failed: %v", err)
	}

	devices, err := m.ListDevices()
	if err != nil {
		t.Fatalf("ListDevices() failed: %v", err)
	}
	if len(devices) == 0 {
		t.Fatal("expected at least one device")
	}
}

func TestMockCardReader_SelectDevice_NotFound(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil) //nolint:errcheck
	if err := m.SelectDevice("nonexistent-device"); err == nil {
		t.Fatal("expected SelectDevice to fail for unknown device")
	}
}

func TestMockCardReader_GetDeviceInfo_NoDeviceSelected(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil) //nolint:errcheck
	// No device selected yet.
	if _, err := m.GetDeviceInfo(); err == nil {
		t.Fatal("expected GetDeviceInfo to fail when no device is selected")
	}
}

func TestMockCardReader_GetDeviceInfo_AfterSelect(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)          //nolint:errcheck
	m.SelectDevice("mock-device-1") //nolint:errcheck

	info, err := m.GetDeviceInfo()
	if err != nil {
		t.Fatalf("GetDeviceInfo() failed: %v", err)
	}
	if info["id"] != "mock-device-1" {
		t.Fatalf("unexpected device id: %v", info)
	}
}

func TestMockCardReader_Authenticate_InvalidPIN(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil) //nolint:errcheck
	if err := m.Authenticate("wrong-pin"); err == nil {
		t.Fatal("expected Authenticate to fail for wrong PIN")
	}
}

func TestMockCardReader_Authenticate_ValidPIN(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)          //nolint:errcheck
	if err := m.Authenticate("1234"); err != nil {
		t.Fatalf("Authenticate with valid PIN failed: %v", err)
	}
	if !m.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated to be true after authentication")
	}
}

func TestMockCardReader_FullLifecycle(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)           //nolint:errcheck
	m.SelectDevice("mock-device-1") //nolint:errcheck
	m.Authenticate("test")          //nolint:errcheck

	if err := m.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "card-key", nil); err != nil {
		t.Fatalf("GenerateKey RSA failed: %v", err)
	}

	pub, err := m.GetPublicKey("card-key")
	if err != nil {
		t.Fatalf("GetPublicKey failed: %v", err)
	}
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}

	info, err := m.GetKeyInfo("card-key")
	if err != nil {
		t.Fatalf("GetKeyInfo failed: %v", err)
	}
	if info == nil {
		t.Fatal("expected non-nil key info")
	}

	keys, err := m.ListKeys()
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}

	sig, err := m.Sign("card-key", []byte("data"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}

	if err := m.DeleteKey("card-key"); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}
	if _, err := m.GetPublicKey("card-key"); err == nil {
		t.Fatal("expected GetPublicKey to fail after delete")
	}

	if err := m.Disconnect(); err != nil {
		t.Fatalf("Disconnect failed: %v", err)
	}
	if m.IsConnected() {
		t.Fatal("expected IsConnected to be false after Disconnect")
	}
	if m.IsAuthenticated() {
		t.Fatal("expected IsAuthenticated to be false after Disconnect")
	}
}

func TestMockCardReader_GenerateKey_ECC_P256(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck

	if err := m.GenerateKey(KeyType_KEY_TYPE_ECC_P256, "ecc-p256", nil); err != nil {
		t.Fatalf("GenerateKey ECC P-256 failed: %v", err)
	}

	sig, err := m.Sign("ecc-p256", []byte("data"))
	if err != nil {
		t.Fatalf("Sign (ECC) failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty ECC signature")
	}
}

func TestMockCardReader_GenerateKey_ECC_P384(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck

	if err := m.GenerateKey(KeyType_KEY_TYPE_ECC_P384, "ecc-p384", nil); err != nil {
		t.Fatalf("GenerateKey ECC P-384 failed: %v", err)
	}
}

func TestMockCardReader_GenerateKey_UnsupportedType(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck

	if err := m.GenerateKey(KeyType_KEY_TYPE_RSA_4096, "unsupported", nil); err == nil {
		t.Fatal("expected GenerateKey to fail for unsupported key type")
	}
}

func TestMockCardReader_EncryptDecrypt_RSA(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck

	if err := m.GenerateKey(KeyType_KEY_TYPE_RSA_2048, "enc-dec-key", nil); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	plaintext := []byte("mock card reader roundtrip")
	ct, err := m.Encrypt("enc-dec-key", plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	pt, err := m.Decrypt("enc-dec-key", ct)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", string(pt), string(plaintext))
	}
}

func TestMockCardReader_Encrypt_KeyNotFound(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck
	if _, err := m.Encrypt("nonexistent", []byte("p")); err == nil {
		t.Fatal("expected Encrypt to fail for nonexistent key")
	}
}

func TestMockCardReader_Decrypt_KeyNotFound(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck
	if _, err := m.Decrypt("nonexistent", []byte("c")); err == nil {
		t.Fatal("expected Decrypt to fail for nonexistent key")
	}
}

func TestMockCardReader_Sign_KeyNotFound(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck
	if _, err := m.Sign("nonexistent", []byte("d")); err == nil {
		t.Fatal("expected Sign to fail for nonexistent key")
	}
}

func TestMockCardReader_GetKeyInfo_NotFound(t *testing.T) {
	m := newMockCardReader()
	m.Connect(nil)       //nolint:errcheck
	m.Authenticate("test") //nolint:errcheck
	if _, err := m.GetKeyInfo("nonexistent"); err == nil {
		t.Fatal("expected GetKeyInfo to fail for nonexistent key")
	}
}
