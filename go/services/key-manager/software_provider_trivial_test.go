package key_manager

import (
	"testing"
)

// TestSoftwareKeyProvider_GetSupportedKeyTypes verifies all expected key types are returned.
func TestSoftwareKeyProvider_GetSupportedKeyTypes(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	types := provider.GetSupportedKeyTypes()
	if len(types) == 0 {
		t.Fatal("GetSupportedKeyTypes() returned empty slice")
	}

	expected := map[KeyType]bool{
		KeyType_KEY_TYPE_RSA_2048:    false,
		KeyType_KEY_TYPE_RSA_3072:    false,
		KeyType_KEY_TYPE_RSA_4096:    false,
		KeyType_KEY_TYPE_ECC_P256:    false,
		KeyType_KEY_TYPE_ECC_P384:    false,
		KeyType_KEY_TYPE_ECC_P521:    false,
		KeyType_KEY_TYPE_KYBER_512:   false,
		KeyType_KEY_TYPE_KYBER_768:   false,
		KeyType_KEY_TYPE_KYBER_1024:  false,
	}

	for _, kt := range types {
		if _, ok := expected[kt]; ok {
			expected[kt] = true
		}
	}

	for kt, found := range expected {
		if !found {
			t.Errorf("GetSupportedKeyTypes() missing key type %v", kt)
		}
	}
}

// TestSoftwareKeyProvider_SupportsRotation verifies software provider supports rotation.
func TestSoftwareKeyProvider_SupportsRotation(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	if !provider.SupportsRotation() {
		t.Error("SupportsRotation() = false, want true for software provider")
	}
}

// TestSoftwareKeyProvider_SupportsHardwareSecurity verifies software provider does NOT support hardware security.
func TestSoftwareKeyProvider_SupportsHardwareSecurity(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	if provider.SupportsHardwareSecurity() {
		t.Error("SupportsHardwareSecurity() = true, want false for software provider")
	}
}

// TestSoftwareKeyProvider_GetProviderType verifies the provider type.
func TestSoftwareKeyProvider_GetProviderType(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	if provider.GetProviderType() != KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE {
		t.Errorf("GetProviderType() = %v, want KEY_PROVIDER_TYPE_SOFTWARE", provider.GetProviderType())
	}
}

// TestSoftwareKeyProvider_GetProviderName verifies the provider name is non-empty.
func TestSoftwareKeyProvider_GetProviderName(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	if provider.GetProviderName() == "" {
		t.Error("GetProviderName() returned empty string")
	}
}

// TestSoftwareKeyProvider_IsAvailable verifies software provider is always available.
func TestSoftwareKeyProvider_IsAvailable(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	if !provider.IsAvailable() {
		t.Error("IsAvailable() = false, want true for software provider")
	}
}

// TestSoftwareKeyProvider_Configure verifies configuration is applied.
func TestSoftwareKeyProvider_Configure(t *testing.T) {
	provider := NewSoftwareKeyProvider(nil)
	err := provider.Configure(map[string]string{"default_max_age_hours": "24"})
	if err != nil {
		t.Errorf("Configure() error = %v", err)
	}

	config := provider.GetConfiguration()
	if config["default_max_age_hours"] != "24" {
		t.Errorf("GetConfiguration() missing config key, got %v", config)
	}
}

// TestSoftwareKeyProvider_NewWithConfig verifies provider is initialized with given config.
func TestSoftwareKeyProvider_NewWithConfig(t *testing.T) {
	cfg := map[string]string{"key": "value"}
	provider := NewSoftwareKeyProvider(cfg)
	config := provider.GetConfiguration()
	if config["key"] != "value" {
		t.Errorf("NewSoftwareKeyProvider() config not applied, got %v", config)
	}
}
