package key_manager

import (
	"testing"

	"stratium/pkg/security/encryption"
)

func TestDefaultProviderFactory_NewDefaultProviderFactory(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	if factory == nil {
		t.Fatal("NewDefaultProviderFactory() returned nil")
	}
	if factory.encryptionAlgorithm != encryption.RSA2048 {
		t.Errorf("NewDefaultProviderFactory() algorithm = %v, want RSA2048", factory.encryptionAlgorithm)
	}
}

func TestDefaultProviderFactory_CreateProvider_Software(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	provider, err := factory.CreateProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, nil)
	if err != nil {
		t.Fatalf("CreateProvider(SOFTWARE) error = %v", err)
	}
	if provider == nil {
		t.Fatal("CreateProvider(SOFTWARE) returned nil provider")
	}
}

func TestDefaultProviderFactory_CreateProvider_HSM(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	provider, err := factory.CreateProvider(KeyProviderType_KEY_PROVIDER_TYPE_HSM, nil)
	if err != nil {
		t.Fatalf("CreateProvider(HSM) error = %v", err)
	}
	if provider == nil {
		t.Fatal("CreateProvider(HSM) returned nil provider")
	}
}

func TestDefaultProviderFactory_CreateProvider_SmartCard(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	provider, err := factory.CreateProvider(KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD, nil)
	if err != nil {
		t.Fatalf("CreateProvider(SMART_CARD) error = %v", err)
	}
	if provider == nil {
		t.Fatal("CreateProvider(SMART_CARD) returned nil provider")
	}
}

func TestDefaultProviderFactory_CreateProvider_USBToken(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	provider, err := factory.CreateProvider(KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN, nil)
	if err != nil {
		t.Fatalf("CreateProvider(USB_TOKEN) error = %v", err)
	}
	if provider == nil {
		t.Fatal("CreateProvider(USB_TOKEN) returned nil provider")
	}
}

func TestDefaultProviderFactory_CreateProvider_Invalid(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	_, err := factory.CreateProvider(KeyProviderType(999), nil)
	if err == nil {
		t.Fatal("CreateProvider(invalid) should return error")
	}
}

func TestDefaultProviderFactory_CreateProvider_WithConfig(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	cfg := map[string]string{
		"max_age_hours": "48",
	}
	provider, err := factory.CreateProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, cfg)
	if err != nil {
		t.Fatalf("CreateProvider(SOFTWARE, config) error = %v", err)
	}
	if provider == nil {
		t.Fatal("CreateProvider(SOFTWARE, config) returned nil provider")
	}
}

func TestDefaultProviderFactory_GetAvailableProviders(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	providers := factory.GetAvailableProviders()
	if len(providers) == 0 {
		t.Fatal("GetAvailableProviders() returned empty list")
	}

	// Verify all expected provider types are present
	expected := map[KeyProviderType]bool{
		KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE:   false,
		KeyProviderType_KEY_PROVIDER_TYPE_HSM:        false,
		KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD: false,
		KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN:  false,
	}
	for _, pt := range providers {
		expected[pt] = true
	}
	for pt, found := range expected {
		if !found {
			t.Errorf("GetAvailableProviders() missing provider type %v", pt)
		}
	}
}

func TestDefaultProviderFactory_GetProvider_Valid(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	provider, err := factory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("GetProvider(SOFTWARE) error = %v", err)
	}
	if provider == nil {
		t.Fatal("GetProvider(SOFTWARE) returned nil")
	}
}

func TestDefaultProviderFactory_GetProvider_Invalid(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	_, err := factory.GetProvider(KeyProviderType(999))
	if err == nil {
		t.Fatal("GetProvider(invalid) should return error")
	}
}

func TestDefaultProviderFactory_UpdateProviderConfig_Valid(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	cfg := map[string]string{
		"max_age_hours": "72",
	}
	err := factory.UpdateProviderConfig(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE, cfg)
	if err != nil {
		t.Fatalf("UpdateProviderConfig(SOFTWARE) error = %v", err)
	}
}

func TestDefaultProviderFactory_UpdateProviderConfig_Invalid(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	err := factory.UpdateProviderConfig(KeyProviderType(999), nil)
	if err == nil {
		t.Fatal("UpdateProviderConfig(invalid) should return error")
	}
}

func TestDefaultProviderFactory_GetProviderInfo(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.RSA2048)
	infos := factory.GetProviderInfo()
	if len(infos) == 0 {
		t.Fatal("GetProviderInfo() returned empty list")
	}
	for _, info := range infos {
		if info.Name == "" {
			t.Error("GetProviderInfo() provider has empty name")
		}
	}
}

func TestDefaultProviderFactory_GetEncryptionAlgorithm(t *testing.T) {
	factory := NewDefaultProviderFactory(encryption.ECC_P256)
	algo := factory.GetEncryptionAlgorithm()
	if algo != encryption.ECC_P256 {
		t.Errorf("GetEncryptionAlgorithm() = %v, want ECC_P256", algo)
	}
}

func TestAlgorithmToKeyType(t *testing.T) {
	tests := []struct {
		algo    encryption.Algorithm
		want    KeyType
		wantErr bool
	}{
		{encryption.RSA2048, KeyType_KEY_TYPE_RSA_2048, false},
		{encryption.RSA3072, KeyType_KEY_TYPE_RSA_3072, false},
		{encryption.RSA4096, KeyType_KEY_TYPE_RSA_4096, false},
		{encryption.ECC_P256, KeyType_KEY_TYPE_ECC_P256, false},
		{encryption.ECC_P384, KeyType_KEY_TYPE_ECC_P384, false},
		{encryption.ECC_P521, KeyType_KEY_TYPE_ECC_P521, false},
		{encryption.KYBER512, KeyType_KEY_TYPE_KYBER_512, false},
		{encryption.KYBER768, KeyType_KEY_TYPE_KYBER_768, false},
		{encryption.KYBER1024, KeyType_KEY_TYPE_KYBER_1024, false},
		{encryption.Algorithm("UNKNOWN"), KeyType_KEY_TYPE_UNSPECIFIED, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.algo), func(t *testing.T) {
			got, err := AlgorithmToKeyType(tt.algo)
			if (err != nil) != tt.wantErr {
				t.Errorf("AlgorithmToKeyType(%v) error = %v, wantErr %v", tt.algo, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("AlgorithmToKeyType(%v) = %v, want %v", tt.algo, got, tt.want)
			}
		})
	}
}
