package key_manager

import (
	"fmt"
	"stratium/pkg/security/encryption"
	"sync"
)

// DefaultProviderFactory implements ProviderFactory
type DefaultProviderFactory struct {
	mu                  sync.RWMutex
	providers           map[KeyProviderType]KeyProviderInterface
	encryptionAlgorithm encryption.Algorithm
}

// NewDefaultProviderFactory creates a new provider factory
func NewDefaultProviderFactory(encryptionAlgo encryption.Algorithm) *DefaultProviderFactory {
	factory := &DefaultProviderFactory{
		providers:           make(map[KeyProviderType]KeyProviderInterface),
		encryptionAlgorithm: encryptionAlgo,
	}

	factory.initializeProviders()
	return factory
}

// CreateProvider creates a key provider based on type
func (f *DefaultProviderFactory) CreateProvider(providerType KeyProviderType, config map[string]string) (KeyProviderInterface, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	switch providerType {
	case KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE:
		return NewSoftwareKeyProvider(config), nil

	case KeyProviderType_KEY_PROVIDER_TYPE_HSM:
		return NewHSMKeyProvider(config), nil

	case KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD:
		return NewSmartCardKeyProvider("smartcard", config), nil

	case KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN:
		return NewSmartCardKeyProvider("usb_token", config), nil

	default:
		return nil, fmt.Errorf("unsupported provider type: %v", providerType)
	}
}

// GetAvailableProviders returns all available provider types
func (f *DefaultProviderFactory) GetAvailableProviders() []KeyProviderType {
	return []KeyProviderType{
		KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		KeyProviderType_KEY_PROVIDER_TYPE_HSM,
		KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD,
		KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN,
	}
}

// GetProviderInfo returns information about all providers
func (f *DefaultProviderFactory) GetProviderInfo() []*KeyProvider {
	providers := make([]*KeyProvider, 0)

	// Software Provider
	softwareProvider := &KeyProvider{
		Type:        KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Name:        "Software Key Provider",
		Description: "Software-based key generation and storage",
		Available:   true,
		Configuration: map[string]string{
			"max_age_hours":         "Key expiration time in hours",
			"default_max_age_hours": "Default key expiration time",
		},
		SupportedKeyTypes: []KeyType{
			KeyType_KEY_TYPE_RSA_2048,
			KeyType_KEY_TYPE_RSA_3072,
			KeyType_KEY_TYPE_RSA_4096,
			KeyType_KEY_TYPE_ECC_P256,
			KeyType_KEY_TYPE_ECC_P384,
			KeyType_KEY_TYPE_ECC_P521,
		},
		SupportsRotation:         true,
		SupportsHardwareSecurity: false,
	}
	providers = append(providers, softwareProvider)

	// HSM Provider
	hsmProvider := &KeyProvider{
		Type:        KeyProviderType_KEY_PROVIDER_TYPE_HSM,
		Name:        "Hardware Security Module Provider",
		Description: "Hardware-based key generation and storage",
		Available:   true, // Mock HSM is available
		Configuration: map[string]string{
			"hsm_endpoint": "HSM connection endpoint",
			"hsm_user":     "HSM user credentials",
			"hsm_slot":     "HSM slot number",
		},
		SupportedKeyTypes: []KeyType{
			KeyType_KEY_TYPE_RSA_2048,
			KeyType_KEY_TYPE_RSA_3072,
			KeyType_KEY_TYPE_RSA_4096,
			KeyType_KEY_TYPE_ECC_P256,
			KeyType_KEY_TYPE_ECC_P384,
			KeyType_KEY_TYPE_ECC_P521,
		},
		SupportsRotation:         true,
		SupportsHardwareSecurity: true,
	}
	providers = append(providers, hsmProvider)

	// Smart Card Provider
	smartCardProvider := &KeyProvider{
		Type:        KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD,
		Name:        "Smart Card Provider",
		Description: "Smart card-based key generation and storage",
		Available:   true, // Mock smart card is available
		Configuration: map[string]string{
			"device_id": "Smart card device ID",
			"pin":       "Smart card PIN",
		},
		SupportedKeyTypes: []KeyType{
			KeyType_KEY_TYPE_RSA_2048,
			KeyType_KEY_TYPE_ECC_P256,
			KeyType_KEY_TYPE_ECC_P384,
		},
		SupportsRotation:         true,
		SupportsHardwareSecurity: true,
	}
	providers = append(providers, smartCardProvider)

	// USB Token Provider
	usbTokenProvider := &KeyProvider{
		Type:        KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN,
		Name:        "USB Token Provider",
		Description: "USB token-based key generation and storage",
		Available:   true, // Mock USB token is available
		Configuration: map[string]string{
			"device_id": "USB token device ID",
			"pin":       "USB token PIN",
		},
		SupportedKeyTypes: []KeyType{
			KeyType_KEY_TYPE_RSA_2048,
			KeyType_KEY_TYPE_ECC_P256,
			KeyType_KEY_TYPE_ECC_P384,
		},
		SupportsRotation:         true,
		SupportsHardwareSecurity: true,
	}
	providers = append(providers, usbTokenProvider)

	return providers
}

// initializeProviders initializes all providers
func (f *DefaultProviderFactory) initializeProviders() {
	f.mu.Lock()
	defer f.mu.Unlock()

	// Initialize with default configs
	f.providers[KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE] = NewSoftwareKeyProvider(nil)
	f.providers[KeyProviderType_KEY_PROVIDER_TYPE_HSM] = NewHSMKeyProvider(nil)
	f.providers[KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD] = NewSmartCardKeyProvider("smartcard", nil)
	f.providers[KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN] = NewSmartCardKeyProvider("usb_token", nil)
}

// GetProvider returns a cached provider instance
func (f *DefaultProviderFactory) GetProvider(providerType KeyProviderType) (KeyProviderInterface, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	provider, exists := f.providers[providerType]
	if !exists {
		return nil, fmt.Errorf("provider type %v not found", providerType)
	}

	return provider, nil
}

// UpdateProviderConfig updates the configuration for a provider
func (f *DefaultProviderFactory) UpdateProviderConfig(providerType KeyProviderType, config map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	provider, exists := f.providers[providerType]
	if !exists {
		return fmt.Errorf("provider type %v not found", providerType)
	}

	return provider.Configure(config)
}

// GetEncryptionAlgorithm returns the configured encryption algorithm
func (f *DefaultProviderFactory) GetEncryptionAlgorithm() encryption.Algorithm {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.encryptionAlgorithm
}

// AlgorithmToKeyType converts an encryption algorithm to a KeyType
func AlgorithmToKeyType(algo encryption.Algorithm) (KeyType, error) {
	switch algo {
	case encryption.RSA2048:
		return KeyType_KEY_TYPE_RSA_2048, nil
	case encryption.RSA3072:
		return KeyType_KEY_TYPE_RSA_3072, nil
	case encryption.RSA4096:
		return KeyType_KEY_TYPE_RSA_4096, nil
	case encryption.ECC_P256:
		return KeyType_KEY_TYPE_ECC_P256, nil
	case encryption.ECC_P384:
		return KeyType_KEY_TYPE_ECC_P384, nil
	case encryption.ECC_P521:
		return KeyType_KEY_TYPE_ECC_P521, nil
	case encryption.KYBER512:
		return KeyType_KEY_TYPE_KYBER_512, nil
	case encryption.KYBER768:
		return KeyType_KEY_TYPE_KYBER_768, nil
	case encryption.KYBER1024:
		return KeyType_KEY_TYPE_KYBER_1024, nil
	default:
		return KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported algorithm: %s", algo)
	}
}
