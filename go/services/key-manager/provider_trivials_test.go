package key_manager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

// HSMKeyProvider trivial method tests

func TestHSMKeyProvider_GetProviderType(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_HSM {
		t.Errorf("GetProviderType() = %v, want KEY_PROVIDER_TYPE_HSM", p.GetProviderType())
	}
}

func TestHSMKeyProvider_GetProviderName(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	name := p.GetProviderName()
	if name == "" {
		t.Error("GetProviderName() returned empty string")
	}
	// Should contain "Hardware Security Module" or similar
	if len(name) < 5 {
		t.Errorf("GetProviderName() returned suspiciously short name: %q", name)
	}
}

func TestHSMKeyProvider_GetSupportedKeyTypes(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	types := p.GetSupportedKeyTypes()
	if len(types) == 0 {
		t.Error("GetSupportedKeyTypes() returned empty slice")
	}
}

func TestHSMKeyProvider_SupportsRotation(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	if !p.SupportsRotation() {
		t.Error("SupportsRotation() = false, want true for HSM provider")
	}
}

func TestHSMKeyProvider_SupportsHardwareSecurity(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	if !p.SupportsHardwareSecurity() {
		t.Error("SupportsHardwareSecurity() = false, want true for HSM provider")
	}
}

func TestHSMKeyProvider_IsAvailable_NotInitialized(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	// Not initialized - should return false
	if p.IsAvailable() {
		t.Error("IsAvailable() = true for uninitialized HSM provider, want false")
	}
}

func TestHSMKeyProvider_GetConfiguration_Empty(t *testing.T) {
	p := NewHSMKeyProvider(nil)
	cfg := p.GetConfiguration()
	if cfg == nil {
		t.Error("GetConfiguration() returned nil map")
	}
}

// SmartCardKeyProvider trivial method tests

func TestSmartCardKeyProvider_isYubiKeyCardReader_NonYubiKey(t *testing.T) {
	// MockCardReader is not a YubiKeyPIVCardReader
	mock := newMockCardReader()
	if isYubiKeyCardReader(mock) {
		t.Error("isYubiKeyCardReader(MockCardReader) = true, want false")
	}
}

func TestSmartCardKeyProvider_isYubiKeyCardReader_YubiKey(t *testing.T) {
	yubiReader := NewYubiKeyPIVCardReader()
	if !isYubiKeyCardReader(yubiReader) {
		t.Error("isYubiKeyCardReader(YubiKeyPIVCardReader) = false, want true")
	}
}

func TestSmartCardKeyProvider_GetProviderType_SmartCard(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD {
		t.Errorf("GetProviderType() = %v, want KEY_PROVIDER_TYPE_SMART_CARD", p.GetProviderType())
	}
}

func TestSmartCardKeyProvider_GetProviderType_USBToken(t *testing.T) {
	p := NewSmartCardKeyProvider("usb_token", nil)
	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN {
		t.Errorf("GetProviderType() = %v, want KEY_PROVIDER_TYPE_USB_TOKEN", p.GetProviderType())
	}
}

func TestSmartCardKeyProvider_GetProviderType_Default(t *testing.T) {
	// Any other device type defaults to smart card
	p := NewSmartCardKeyProvider("other", nil)
	if p.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD {
		t.Errorf("GetProviderType() = %v, want KEY_PROVIDER_TYPE_SMART_CARD for unknown device type", p.GetProviderType())
	}
}

func TestSmartCardKeyProvider_GetProviderName_SmartCard(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	name := p.GetProviderName()
	if name == "" {
		t.Error("GetProviderName() returned empty string")
	}
}

func TestSmartCardKeyProvider_GetProviderName_USBToken(t *testing.T) {
	p := NewSmartCardKeyProvider("usb_token", nil)
	name := p.GetProviderName()
	if name == "" {
		t.Error("GetProviderName() returned empty string for usb_token")
	}
}

func TestSmartCardKeyProvider_GetProviderName_Distinct(t *testing.T) {
	smartCard := NewSmartCardKeyProvider("smartcard", nil)
	usbToken := NewSmartCardKeyProvider("usb_token", nil)
	if smartCard.GetProviderName() == usbToken.GetProviderName() {
		t.Error("GetProviderName() should return different names for smartcard vs usb_token")
	}
}

func TestSmartCardKeyProvider_SupportsRotation(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if !p.SupportsRotation() {
		t.Error("SupportsRotation() = false, want true")
	}
}

func TestSmartCardKeyProvider_SupportsHardwareSecurity(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	if !p.SupportsHardwareSecurity() {
		t.Error("SupportsHardwareSecurity() = false, want true")
	}
}

func TestSmartCardKeyProvider_IsAvailable_NotInitialized(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	// Not initialized - should return false
	if p.IsAvailable() {
		t.Error("IsAvailable() = true for uninitialized SmartCard provider, want false")
	}
}

func TestSmartCardKeyProvider_GetConfiguration_ExcludesPIN(t *testing.T) {
	p := NewSmartCardKeyProvider("smartcard", nil)
	// Use the mock PIN ("1234") so authentication succeeds with the mock card reader
	_ = p.Configure(map[string]string{
		"device_id": "mock-device-1",
		"pin":       "1234",
	})

	cfg := p.GetConfiguration()
	if _, hasPIN := cfg["pin"]; hasPIN {
		t.Error("GetConfiguration() should not expose the PIN")
	}
	if cfg["device_id"] != "mock-device-1" {
		t.Errorf("GetConfiguration() missing device_id, got %v", cfg)
	}
}

// YubiKeyPIVCardReader.keyTypeFromPublicKey tests

func TestKeyTypeFromPublicKey_RSA2048(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA 2048 key: %v", err)
	}
	got := keyTypeFromPublicKey(&priv.PublicKey)
	if got != KeyType_KEY_TYPE_RSA_2048 {
		t.Errorf("keyTypeFromPublicKey(RSA-2048) = %v, want KEY_TYPE_RSA_2048", got)
	}
}

func TestKeyTypeFromPublicKey_RSA4096(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("failed to generate RSA 4096 key: %v", err)
	}
	got := keyTypeFromPublicKey(&priv.PublicKey)
	if got != KeyType_KEY_TYPE_RSA_4096 {
		t.Errorf("keyTypeFromPublicKey(RSA-4096) = %v, want KEY_TYPE_RSA_4096", got)
	}
}

func TestKeyTypeFromPublicKey_ECCP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECC P-256 key: %v", err)
	}
	got := keyTypeFromPublicKey(&priv.PublicKey)
	if got != KeyType_KEY_TYPE_ECC_P256 {
		t.Errorf("keyTypeFromPublicKey(ECC P-256) = %v, want KEY_TYPE_ECC_P256", got)
	}
}

func TestKeyTypeFromPublicKey_ECCP384(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECC P-384 key: %v", err)
	}
	got := keyTypeFromPublicKey(&priv.PublicKey)
	if got != KeyType_KEY_TYPE_ECC_P384 {
		t.Errorf("keyTypeFromPublicKey(ECC P-384) = %v, want KEY_TYPE_ECC_P384", got)
	}
}

func TestKeyTypeFromPublicKey_ECCP521(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECC P-521 key: %v", err)
	}
	got := keyTypeFromPublicKey(&priv.PublicKey)
	if got != KeyType_KEY_TYPE_ECC_P521 {
		t.Errorf("keyTypeFromPublicKey(ECC P-521) = %v, want KEY_TYPE_ECC_P521", got)
	}
}

func TestKeyTypeFromPublicKey_NilReturnsUnspecified(t *testing.T) {
	// Passing a nil interface value - the switch will hit the default case
	got := keyTypeFromPublicKey(nil)
	if got != KeyType_KEY_TYPE_UNSPECIFIED {
		t.Errorf("keyTypeFromPublicKey(nil) = %v, want KEY_TYPE_UNSPECIFIED", got)
	}
}

func TestKeyTypeFromPublicKey_UnknownTypeReturnsUnspecified(t *testing.T) {
	// Pass a non-key type to exercise the default branch
	type unknownKey struct{}
	got := keyTypeFromPublicKey(&unknownKey{})
	if got != KeyType_KEY_TYPE_UNSPECIFIED {
		t.Errorf("keyTypeFromPublicKey(unknownKey) = %v, want KEY_TYPE_UNSPECIFIED", got)
	}
}
