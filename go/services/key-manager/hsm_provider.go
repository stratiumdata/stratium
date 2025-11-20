package key_manager

import (
	"context"
	"crypto"
	"fmt"
	"sync"
	"time"
)

// HSMKeyProvider implements KeyProvider for Hardware Security Module keys
type HSMKeyProvider struct {
	mu          sync.RWMutex
	config      map[string]string
	initialized bool
	hsmClient   HSMClient
	keyMetadata map[string]*KeyPair
}

// HSMClient defines the interface for HSM operations
type HSMClient interface {
	Connect(config map[string]string) error
	Disconnect() error
	IsConnected() bool
	GenerateKey(keyType KeyType, keyID string, options map[string]interface{}) error
	GetPublicKey(keyID string) (crypto.PublicKey, error)
	DeleteKey(keyID string) error
	ListKeys() ([]string, error)
	Sign(keyID string, data []byte) ([]byte, error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
	Encrypt(keyID string, plaintext []byte) ([]byte, error)
	GetKeyInfo(keyID string) (map[string]interface{}, error)
}

// MockHSMClient provides a mock implementation for testing
type MockHSMClient struct {
	connected bool
	keys      map[string]interface{}
}

// NewHSMKeyProvider creates a new HSM key provider
func NewHSMKeyProvider(config map[string]string) *HSMKeyProvider {
	provider := &HSMKeyProvider{
		config:      make(map[string]string),
		keyMetadata: make(map[string]*KeyPair),
		hsmClient:   &MockHSMClient{keys: make(map[string]interface{})}, // Use mock for demo
	}

	if config != nil {
		provider.Configure(config)
	}

	return provider
}

// GetProviderType returns the provider type
func (h *HSMKeyProvider) GetProviderType() KeyProviderType {
	return KeyProviderType_KEY_PROVIDER_TYPE_HSM
}

// GetProviderName returns the provider name
func (h *HSMKeyProvider) GetProviderName() string {
	return "Hardware Security Module Provider"
}

// IsAvailable checks if the HSM is available and connected
func (h *HSMKeyProvider) IsAvailable() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.initialized {
		return false
	}

	return h.hsmClient != nil && h.hsmClient.IsConnected()
}

// GetSupportedKeyTypes returns supported key types for HSM
func (h *HSMKeyProvider) GetSupportedKeyTypes() []KeyType {
	return []KeyType{
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
		KeyType_KEY_TYPE_ECC_P521,
	}
}

// SupportsRotation indicates if the provider supports key rotation
func (h *HSMKeyProvider) SupportsRotation() bool {
	return true
}

// SupportsHardwareSecurity indicates hardware security support
func (h *HSMKeyProvider) SupportsHardwareSecurity() bool {
	return true
}

// GenerateKeyPair generates a new key pair in the HSM
func (h *HSMKeyProvider) GenerateKeyPair(ctx context.Context, keyType KeyType, keyID string, config map[string]string) (*KeyPair, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	// Check if key already exists
	if _, exists := h.keyMetadata[keyID]; exists {
		return nil, fmt.Errorf("key with ID %s already exists", keyID)
	}

	// Convert config to options
	options := make(map[string]interface{})
	for k, v := range config {
		options[k] = v
	}

	// Generate key in HSM
	err := h.hsmClient.GenerateKey(keyType, keyID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key in HSM: %w", err)
	}

	// Get public key from HSM
	publicKey, err := h.hsmClient.GetPublicKey(keyID)
	if err != nil {
		// Clean up on failure
		h.hsmClient.DeleteKey(keyID)
		return nil, fmt.Errorf("failed to retrieve public key from HSM: %w", err)
	}

	// Convert public key to PEM (using software provider method for consistency)
	softwareProvider := NewSoftwareKeyProvider(nil)
	publicKeyPEM, err := softwareProvider.publicKeyToPEM(publicKey)
	if err != nil {
		h.hsmClient.DeleteKey(keyID)
		return nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	// Create key pair metadata
	keyPair := &KeyPair{
		KeyID:         keyID,
		KeyType:       keyType,
		ProviderType:  h.GetProviderType(),
		PublicKey:     publicKey,
		PrivateKey:    nil, // Private key stays in HSM
		PublicKeyPEM:  publicKeyPEM,
		CreatedAt:     time.Now(),
		UsageCount:    0,
		MaxUsageCount: 0,
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

	// Store metadata
	h.keyMetadata[keyID] = keyPair

	return keyPair, nil
}

// GetKeyPair retrieves a key pair metadata
func (h *HSMKeyProvider) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	keyPair, exists := h.keyMetadata[keyID]
	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}

	// Check if key has expired
	if keyPair.ExpiresAt != nil && time.Now().After(*keyPair.ExpiresAt) {
		return nil, fmt.Errorf("key with ID %s has expired", keyID)
	}

	// Verify key still exists in HSM
	_, err := h.hsmClient.GetKeyInfo(keyID)
	if err != nil {
		return nil, fmt.Errorf("key not found in HSM: %w", err)
	}

	return keyPair, nil
}

// DeleteKeyPair deletes a key pair from HSM and metadata
func (h *HSMKeyProvider) DeleteKeyPair(ctx context.Context, keyID string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.IsAvailable() {
		return fmt.Errorf("HSM is not available")
	}

	// Delete from HSM first
	err := h.hsmClient.DeleteKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to delete key from HSM: %w", err)
	}

	// Remove metadata
	delete(h.keyMetadata, keyID)
	return nil
}

// ListKeyPairs lists all key pair IDs
func (h *HSMKeyProvider) ListKeyPairs(ctx context.Context) ([]string, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	// Get keys from HSM to ensure consistency
	hsmKeys, err := h.hsmClient.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from HSM: %w", err)
	}

	return hsmKeys, nil
}

// Sign signs data using HSM
func (h *HSMKeyProvider) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	// Update usage count
	h.mu.Lock()
	if keyPair, exists := h.keyMetadata[keyID]; exists {
		keyPair.UsageCount++
	}
	h.mu.Unlock()

	return h.hsmClient.Sign(keyID, data)
}

// Decrypt decrypts data using HSM
func (h *HSMKeyProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	// Update usage count
	h.mu.Lock()
	if keyPair, exists := h.keyMetadata[keyID]; exists {
		keyPair.UsageCount++
	}
	h.mu.Unlock()

	return h.hsmClient.Decrypt(keyID, ciphertext)
}

// Encrypt encrypts data using HSM
func (h *HSMKeyProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	// Update usage count
	h.mu.Lock()
	if keyPair, exists := h.keyMetadata[keyID]; exists {
		keyPair.UsageCount++
	}
	h.mu.Unlock()

	return h.hsmClient.Encrypt(keyID, plaintext)
}

// RotateKey rotates a key in the HSM
func (h *HSMKeyProvider) RotateKey(ctx context.Context, keyID string) (*KeyPair, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if !h.IsAvailable() {
		return nil, fmt.Errorf("HSM is not available")
	}

	oldKeyPair, exists := h.keyMetadata[keyID]
	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}

	// Create config from metadata
	config := make(map[string]string)
	for k, v := range oldKeyPair.Metadata {
		config[k] = v
	}

	// Delete old key from HSM
	err := h.hsmClient.DeleteKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old key from HSM: %w", err)
	}

	// Remove old metadata
	delete(h.keyMetadata, keyID)

	// Generate new key
	newKeyPair, err := h.GenerateKeyPair(ctx, oldKeyPair.KeyType, keyID, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key during rotation: %w", err)
	}

	now := time.Now()
	newKeyPair.LastRotated = &now

	return newKeyPair, nil
}

// Configure sets HSM provider configuration
func (h *HSMKeyProvider) Configure(config map[string]string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Update config
	for k, v := range config {
		h.config[k] = v
	}

	// Initialize HSM connection
	if h.hsmClient != nil {
		err := h.hsmClient.Connect(config)
		if err != nil {
			return fmt.Errorf("failed to connect to HSM: %w", err)
		}
		h.initialized = true
	}

	return nil
}

// GetConfiguration returns current configuration
func (h *HSMKeyProvider) GetConfiguration() map[string]string {
	h.mu.RLock()
	defer h.mu.RUnlock()

	config := make(map[string]string)
	for k, v := range h.config {
		config[k] = v
	}

	return config
}

// Mock HSM Client Implementation
func (m *MockHSMClient) Connect(config map[string]string) error {
	m.connected = true
	return nil
}

func (m *MockHSMClient) Disconnect() error {
	m.connected = false
	return nil
}

func (m *MockHSMClient) IsConnected() bool {
	return m.connected
}

func (m *MockHSMClient) GenerateKey(keyType KeyType, keyID string, options map[string]interface{}) error {
	if !m.connected {
		return fmt.Errorf("HSM not connected")
	}

	m.keys[keyID] = map[string]interface{}{
		"type":    keyType,
		"created": time.Now(),
	}
	return nil
}

func (m *MockHSMClient) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	if !m.connected {
		return nil, fmt.Errorf("HSM not connected")
	}

	if _, exists := m.keys[keyID]; !exists {
		return nil, fmt.Errorf("key not found")
	}

	// Return a mock public key (in real implementation, this would come from actual HSM)
	return &MockPublicKey{keyID: keyID}, nil
}

func (m *MockHSMClient) DeleteKey(keyID string) error {
	if !m.connected {
		return fmt.Errorf("HSM not connected")
	}

	delete(m.keys, keyID)
	return nil
}

func (m *MockHSMClient) ListKeys() ([]string, error) {
	if !m.connected {
		return nil, fmt.Errorf("HSM not connected")
	}

	keys := make([]string, 0, len(m.keys))
	for keyID := range m.keys {
		keys = append(keys, keyID)
	}
	return keys, nil
}

func (m *MockHSMClient) Sign(keyID string, data []byte) ([]byte, error) {
	if !m.connected {
		return nil, fmt.Errorf("HSM not connected")
	}

	if _, exists := m.keys[keyID]; !exists {
		return nil, fmt.Errorf("key not found")
	}

	// Mock signature
	return []byte("mock-signature"), nil
}

func (m *MockHSMClient) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if !m.connected {
		return nil, fmt.Errorf("HSM not connected")
	}

	if _, exists := m.keys[keyID]; !exists {
		return nil, fmt.Errorf("key not found")
	}

	// Mock decryption
	return []byte("mock-decrypted-data"), nil
}

func (m *MockHSMClient) Encrypt(keyID string, plaintext []byte) ([]byte, error) {
	if !m.connected {
		return nil, fmt.Errorf("HSM not connected")
	}

	if _, exists := m.keys[keyID]; !exists {
		return nil, fmt.Errorf("key not found")
	}

	// Mock encryption
	return []byte("mock-encrypted-data"), nil
}

func (m *MockHSMClient) GetKeyInfo(keyID string) (map[string]interface{}, error) {
	if !m.connected {
		return nil, fmt.Errorf("HSM not connected")
	}

	if info, exists := m.keys[keyID]; exists {
		return info.(map[string]interface{}), nil
	}

	return nil, fmt.Errorf("key not found")
}

// MockPublicKey for testing
type MockPublicKey struct {
	keyID string
}

func (m *MockPublicKey) Equal(x crypto.PublicKey) bool {
	if other, ok := x.(*MockPublicKey); ok {
		return m.keyID == other.keyID
	}
	return false
}
