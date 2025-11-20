package key_manager

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// SoftwareKeyProvider implements KeyProvider for software-defined keys
type SoftwareKeyProvider struct {
	mu             sync.RWMutex
	keyStore       KeyStore // Single source of truth for keys
	config         map[string]string
	maxKeyAge      time.Duration
	defaultKeySize int
}

// NewSoftwareKeyProvider creates a new software key provider
func NewSoftwareKeyProvider(config map[string]string) *SoftwareKeyProvider {
	provider := &SoftwareKeyProvider{
		config:         make(map[string]string),
		maxKeyAge:      24 * time.Hour * 365, // Default 1 year
		defaultKeySize: 2048,
	}

	if config != nil {
		provider.Configure(config)
	}

	return provider
}

// SetKeyStore sets the KeyStore to be used by this provider
func (s *SoftwareKeyProvider) SetKeyStore(keyStore KeyStore) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyStore = keyStore
}

// GetProviderType returns the provider type
func (s *SoftwareKeyProvider) GetProviderType() KeyProviderType {
	return KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE
}

// GetProviderName returns the provider name
func (s *SoftwareKeyProvider) GetProviderName() string {
	return "Software Key Provider"
}

// IsAvailable checks if the provider is available
func (s *SoftwareKeyProvider) IsAvailable() bool {
	return true // Software provider is always available
}

// GetSupportedKeyTypes returns supported key types
func (s *SoftwareKeyProvider) GetSupportedKeyTypes() []KeyType {
	return []KeyType{
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
		KeyType_KEY_TYPE_ECC_P521,
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024,
	}
}

// SupportsRotation indicates if the provider supports key rotation
func (s *SoftwareKeyProvider) SupportsRotation() bool {
	return true
}

// SupportsHardwareSecurity indicates hardware security support
func (s *SoftwareKeyProvider) SupportsHardwareSecurity() bool {
	return false
}

// generateKeyPairInternal generates a new key pair without acquiring locks
func (s *SoftwareKeyProvider) generateKeyPairInternal(ctx context.Context, keyType KeyType, keyID string, config map[string]string) (*KeyPair, error) {
	var privateKey any
	var publicKey any
	var err error

	switch keyType {
	case KeyType_KEY_TYPE_RSA_2048:
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA-2048 key: %w", err)
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey

	case KeyType_KEY_TYPE_RSA_3072:
		privateKey, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA-3072 key: %w", err)
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey

	case KeyType_KEY_TYPE_RSA_4096:
		privateKey, err = rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA-4096 key: %w", err)
		}
		publicKey = &privateKey.(*rsa.PrivateKey).PublicKey

	case KeyType_KEY_TYPE_ECC_P256:
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECC-P256 key: %w", err)
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey

	case KeyType_KEY_TYPE_ECC_P384:
		privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECC-P384 key: %w", err)
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey

	case KeyType_KEY_TYPE_ECC_P521:
		privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECC-P521 key: %w", err)
		}
		publicKey = &privateKey.(*ecdsa.PrivateKey).PublicKey

	case KeyType_KEY_TYPE_KYBER_512:
		pub, priv, err := kyber512.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate KYBER-512 key: %w", err)
		}
		publicKey = pub
		privateKey = priv

	case KeyType_KEY_TYPE_KYBER_768:
		pub, priv, err := kyber768.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate KYBER-768 key: %w", err)
		}
		publicKey = pub
		privateKey = priv

	case KeyType_KEY_TYPE_KYBER_1024:
		pub, priv, err := kyber1024.GenerateKeyPair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate KYBER-1024 key: %w", err)
		}
		publicKey = pub
		privateKey = priv

	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	// Convert public key to PEM format
	publicKeyPEM, err := s.publicKeyToPEM(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	// Create key pair
	keyPair := &KeyPair{
		KeyID:         keyID,
		KeyType:       keyType,
		ProviderType:  s.GetProviderType(),
		PublicKey:     publicKey,
		PrivateKey:    privateKey,
		PublicKeyPEM:  publicKeyPEM,
		CreatedAt:     time.Now(),
		UsageCount:    0,
		MaxUsageCount: 0, // No limit by default
		Metadata:      make(map[string]string),
	}

	// Set expiration if configured
	if maxAge, exists := config["max_age_hours"]; exists {
		if hours, err := time.ParseDuration(maxAge + "h"); err == nil {
			expiresAt := time.Now().Add(hours)
			keyPair.ExpiresAt = &expiresAt
		}
	}

	// Copy metadata from config
	for k, v := range config {
		if k != "max_age_hours" {
			keyPair.Metadata[k] = v
		}
	}

	return keyPair, nil
}

// GenerateKeyPair generates a new key pair
func (s *SoftwareKeyProvider) GenerateKeyPair(ctx context.Context, keyType KeyType, keyID string, config map[string]string) (*KeyPair, error) {
	// Generate the key pair (no lock needed here, generateKeyPairInternal doesn't access shared state)
	keyPair, err := s.generateKeyPairInternal(ctx, keyType, keyID, config)
	if err != nil {
		return nil, err
	}

	// Note: KeyPair is returned but NOT stored here
	// The caller (typically server.CreateKey) is responsible for storing via KeyStore
	return keyPair, nil
}

// GetKeyPair retrieves a key pair by ID
func (s *SoftwareKeyProvider) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	s.mu.RLock()
	keyStore := s.keyStore
	s.mu.RUnlock()

	if keyStore == nil {
		return nil, fmt.Errorf("keyStore not initialized")
	}

	// Get key pair from KeyStore (works with both InMemoryKeyStore and PostgresKeyStore)
	keyPair, err := keyStore.GetKeyPair(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("key with ID %s not found: %w", keyID, err)
	}

	// Check if key has expired
	if keyPair.ExpiresAt != nil && time.Now().After(*keyPair.ExpiresAt) {
		return nil, fmt.Errorf("key with ID %s has expired", keyID)
	}

	return keyPair, nil
}

// DeleteKeyPair deletes a key pair
func (s *SoftwareKeyProvider) DeleteKeyPair(ctx context.Context, keyID string) error {
	s.mu.RLock()
	keyStore := s.keyStore
	s.mu.RUnlock()

	if keyStore == nil {
		return fmt.Errorf("keyStore not initialized")
	}

	// Delete from KeyStore (caller is responsible for provider cleanup)
	// Note: This is a no-op for software provider since keys are in KeyStore
	return nil
}

// ListKeyPairs lists all key pair IDs
func (s *SoftwareKeyProvider) ListKeyPairs(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	keyStore := s.keyStore
	s.mu.RUnlock()

	if keyStore == nil {
		return nil, fmt.Errorf("keyStore not initialized")
	}

	// List keys from KeyStore filtered by this provider type
	filters := map[string]interface{}{
		"provider_type": s.GetProviderType(),
	}
	keys, err := keyStore.ListKeys(ctx, filters)
	if err != nil {
		return nil, err
	}

	keyIDs := make([]string, 0, len(keys))
	for _, key := range keys {
		keyIDs = append(keyIDs, key.KeyId)
	}

	return keyIDs, nil
}

// Sign signs data with the specified key
func (s *SoftwareKeyProvider) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	keyPair, err := s.GetKeyPair(ctx, keyID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	keyPair.UsageCount++
	s.mu.Unlock()

	hash := sha256.Sum256(data)

	switch privateKey := keyPair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hash[:])
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	default:
		return nil, fmt.Errorf("unsupported private key type for signing")
	}
}

// Decrypt decrypts data with the specified key
func (s *SoftwareKeyProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	keyPair, err := s.GetKeyPair(ctx, keyID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	keyPair.UsageCount++
	s.mu.Unlock()

	switch privateKey := keyPair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	case *ecdsa.PrivateKey:
		return decryptDEKWithECCPrivateKey(privateKey, ciphertext)
	case *kyber512.PrivateKey:
		return s.decryptWithKyber512(privateKey, ciphertext)
	case *kyber768.PrivateKey:
		return s.decryptWithKyber768(privateKey, ciphertext)
	case *kyber1024.PrivateKey:
		return s.decryptWithKyber1024(privateKey, ciphertext)
	default:
		return nil, fmt.Errorf("unsupported private key type for decryption: %T", privateKey)
	}
}

// Encrypt encrypts data with the specified key
func (s *SoftwareKeyProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	keyPair, err := s.GetKeyPair(ctx, keyID)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	keyPair.UsageCount++
	s.mu.Unlock()

	switch publicKey := keyPair.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
	case *ecdsa.PublicKey:
		return encryptDEKWithECCPublicKey(publicKey, plaintext)
	case *kyber512.PublicKey:
		// Kyber uses KEM - encapsulate generates a shared secret and ciphertext
		// Note: For actual data encryption, the shared secret should be used as a key for symmetric encryption
		ciphertext, _, err := kyber512.Scheme().Encapsulate(publicKey)
		if err != nil {
			return nil, fmt.Errorf("KYBER-512 encapsulation failed: %w", err)
		}
		return ciphertext, nil
	case *kyber768.PublicKey:
		ciphertext, _, err := kyber768.Scheme().Encapsulate(publicKey)
		if err != nil {
			return nil, fmt.Errorf("KYBER-768 encapsulation failed: %w", err)
		}
		return ciphertext, nil
	case *kyber1024.PublicKey:
		ciphertext, _, err := kyber1024.Scheme().Encapsulate(publicKey)
		if err != nil {
			return nil, fmt.Errorf("KYBER-1024 encapsulation failed: %w", err)
		}
		return ciphertext, nil
	default:
		return nil, fmt.Errorf("unsupported public key type for encryption: %T", publicKey)
	}
}

// RotateKey rotates a key by generating a new key pair
func (s *SoftwareKeyProvider) RotateKey(ctx context.Context, keyID string) (*KeyPair, error) {
	// Get old key pair
	oldKeyPair, err := s.GetKeyPair(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("key with ID %s not found: %w", keyID, err)
	}

	// Generate new key pair with same type and config
	config := make(map[string]string)
	for k, v := range oldKeyPair.Metadata {
		config[k] = v
	}

	// Generate new key pair using internal method
	newKeyPair, err := s.generateKeyPairInternal(ctx, oldKeyPair.KeyType, keyID, config)
	if err != nil {
		return nil, fmt.Errorf("failed to rotate key: %w", err)
	}

	now := time.Now()
	newKeyPair.LastRotated = &now

	// Note: Caller is responsible for storing the new key pair via KeyStore
	return newKeyPair, nil
}

// Configure sets provider configuration
func (s *SoftwareKeyProvider) Configure(config map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for k, v := range config {
		s.config[k] = v
	}

	// Apply specific configurations
	if maxAge, exists := config["default_max_age_hours"]; exists {
		if hours, err := time.ParseDuration(maxAge + "h"); err == nil {
			s.maxKeyAge = hours
		}
	}

	return nil
}

// GetConfiguration returns current configuration
func (s *SoftwareKeyProvider) GetConfiguration() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	config := make(map[string]string)
	for k, v := range s.config {
		config[k] = v
	}

	return config
}

// publicKeyToPEM converts a public key to PEM format
func (s *SoftwareKeyProvider) publicKeyToPEM(publicKey any) (string, error) {
	var publicKeyBytes []byte
	var err error

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", err
		}
	case *ecdsa.PublicKey:
		publicKeyBytes, err = x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			return "", err
		}
	case *kyber512.PublicKey:
		publicKeyBytes, err = pub.MarshalBinary()
		if err != nil {
			return "", err
		}
	case *kyber768.PublicKey:
		publicKeyBytes, err = pub.MarshalBinary()
		if err != nil {
			return "", err
		}
	case *kyber1024.PublicKey:
		publicKeyBytes, err = pub.MarshalBinary()
		if err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("unsupported public key type: %T", publicKey)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM), nil
}

// decryptWithKyber512 decrypts data encrypted with KYBER-512 KEM
func (s *SoftwareKeyProvider) decryptWithKyber512(privateKey *kyber512.PrivateKey, ciphertext []byte) ([]byte, error) {
	// KYBER-512 ciphertext size is 768 bytes
	kemCiphertextSize := kyber512.Scheme().CiphertextSize()

	// The ciphertext format is: KEM ciphertext || encrypted DEK
	if len(ciphertext) < kemCiphertextSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", kemCiphertextSize, len(ciphertext))
	}

	// Split the ciphertext
	kemCiphertext := ciphertext[:kemCiphertextSize]
	encryptedDEK := ciphertext[kemCiphertextSize:]

	// Decapsulate to get the shared secret
	sharedSecret, err := kyber512.Scheme().Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KYBER-512 decapsulation failed: %w", err)
	}

	// Decrypt the DEK using the shared secret
	return s.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
}

// decryptWithKyber768 decrypts data encrypted with KYBER-768 KEM
func (s *SoftwareKeyProvider) decryptWithKyber768(privateKey *kyber768.PrivateKey, ciphertext []byte) ([]byte, error) {
	// KYBER-768 ciphertext size is 1088 bytes
	kemCiphertextSize := kyber768.Scheme().CiphertextSize()

	// The ciphertext format is: KEM ciphertext || encrypted DEK
	if len(ciphertext) < kemCiphertextSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", kemCiphertextSize, len(ciphertext))
	}

	// Split the ciphertext
	kemCiphertext := ciphertext[:kemCiphertextSize]
	encryptedDEK := ciphertext[kemCiphertextSize:]

	// Decapsulate to get the shared secret
	sharedSecret, err := kyber768.Scheme().Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KYBER-768 decapsulation failed: %w", err)
	}

	// Decrypt the DEK using the shared secret
	return s.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
}

// decryptWithKyber1024 decrypts data encrypted with KYBER-1024 KEM
func (s *SoftwareKeyProvider) decryptWithKyber1024(privateKey *kyber1024.PrivateKey, ciphertext []byte) ([]byte, error) {
	// KYBER-1024 ciphertext size is 1568 bytes
	kemCiphertextSize := kyber1024.Scheme().CiphertextSize()

	// The ciphertext format is: KEM ciphertext || encrypted DEK
	if len(ciphertext) < kemCiphertextSize {
		return nil, fmt.Errorf("ciphertext too short: expected at least %d bytes, got %d", kemCiphertextSize, len(ciphertext))
	}

	// Split the ciphertext
	kemCiphertext := ciphertext[:kemCiphertextSize]
	encryptedDEK := ciphertext[kemCiphertextSize:]

	// Decapsulate to get the shared secret
	sharedSecret, err := kyber1024.Scheme().Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("KYBER-1024 decapsulation failed: %w", err)
	}

	// Decrypt the DEK using the shared secret
	return s.decryptDEKWithSharedSecret(encryptedDEK, sharedSecret)
}

// decryptDEKWithSharedSecret decrypts a DEK using a KEM shared secret
func (s *SoftwareKeyProvider) decryptDEKWithSharedSecret(encryptedDEK, sharedSecret []byte) ([]byte, error) {
	// Use the shared secret to decrypt the DEK with AES-256-GCM
	aesBlock, err := aes.NewCipher(sharedSecret[:32]) // Use first 32 bytes for AES-256
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedDEK) < nonceSize {
		return nil, fmt.Errorf("encrypted DEK too short")
	}

	// Extract nonce and ciphertext
	nonce := encryptedDEK[:nonceSize]
	ciphertextData := encryptedDEK[nonceSize:]

	// Decrypt the DEK
	dek, err := gcm.Open(nil, nonce, ciphertextData, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	return dek, nil
}
