package key_manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"stratium/pkg/security/fipsbuild"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SmartCardKeyProvider implements KeyProvider for smart cards and USB tokens
type SmartCardKeyProvider struct {
	mu          sync.RWMutex
	config      map[string]string
	fipsEnabled bool
	initialized bool
	cardReader  CardReader
	keyMetadata map[string]*KeyPair
	deviceType  string // "smartcard" or "usb_token"
}

// CardReader defines the interface for smart card/USB token operations
type CardReader interface {
	Connect(config map[string]string) error
	Disconnect() error
	IsConnected() bool
	ListDevices() ([]string, error)
	SelectDevice(deviceID string) error
	GetDeviceInfo() (map[string]string, error)

	// Authentication
	Authenticate(pin string) error
	IsAuthenticated() bool

	// Key operations
	GenerateKey(keyType KeyType, keyID string, options map[string]interface{}) error
	GetPublicKey(keyID string) (crypto.PublicKey, error)
	DeleteKey(keyID string) error
	ListKeys() ([]string, error)
	Sign(keyID string, data []byte) ([]byte, error)
	Decrypt(keyID string, ciphertext []byte) ([]byte, error)
	Encrypt(keyID string, plaintext []byte) ([]byte, error)
	GetKeyInfo(keyID string) (map[string]interface{}, error)
}

// MockCardReader provides a mock implementation for testing
type MockCardReader struct {
	connected      bool
	authenticated  bool
	devices        map[string]string
	selectedDevice string
	keys           map[string]*mockCardKey
}

type mockCardKey struct {
	keyType      KeyType
	created      time.Time
	rsaPrivate   *rsa.PrivateKey
	ecdsaPrivate *ecdsa.PrivateKey
}

// NewSmartCardKeyProvider creates a new smart card/USB token key provider
func NewSmartCardKeyProvider(deviceType string, config map[string]string) *SmartCardKeyProvider {
	provider := &SmartCardKeyProvider{
		config:      make(map[string]string),
		fipsEnabled: fipsbuild.Enabled,
		keyMetadata: make(map[string]*KeyPair),
		deviceType:  deviceType,
		cardReader:  newMockCardReader(),
	}

	if config != nil {
		if useHardwareCardReaderConfig(config) {
			provider.cardReader = NewYubiKeyPIVCardReader()
		}
		provider.Configure(config)
	}

	return provider
}

func newMockCardReader() *MockCardReader {
	return &MockCardReader{
		devices: map[string]string{
			"mock-device-1": "Mock Smart Card",
			"mock-token-1":  "Mock USB Token",
		},
		keys: make(map[string]*mockCardKey),
	}
}

func useHardwareCardReaderConfig(config map[string]string) bool {
	if len(config) == 0 {
		return false
	}

	backend := strings.ToLower(strings.TrimSpace(config["reader_backend"]))
	if backend == "yubikey" || backend == "pkcs11" || backend == "pcsc" {
		return true
	}

	triggerFields := []string{
		"pkcs11_library",
		"piv_tool_path",
		"ykman_path",
		"slot",
		"key_id",
	}

	for _, key := range triggerFields {
		if strings.TrimSpace(config[key]) != "" {
			return true
		}
	}

	return false
}

func isYubiKeyCardReader(reader CardReader) bool {
	_, ok := reader.(*YubiKeyPIVCardReader)
	return ok
}

func (s *SmartCardKeyProvider) isAvailableLocked() bool {
	if !s.initialized {
		return false
	}
	return s.cardReader != nil && s.cardReader.IsConnected() && s.cardReader.IsAuthenticated()
}

// GetProviderType returns the provider type based on device type
func (s *SmartCardKeyProvider) GetProviderType() KeyProviderType {
	if s.deviceType == "usb_token" {
		return KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN
	}
	return KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD
}

// GetProviderName returns the provider name
func (s *SmartCardKeyProvider) GetProviderName() string {
	if s.deviceType == "usb_token" {
		return "USB Token Key Provider"
	}
	return "Smart Card Key Provider"
}

// IsAvailable checks if the device is available and connected
func (s *SmartCardKeyProvider) IsAvailable() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.isAvailableLocked()
}

// GetSupportedKeyTypes returns supported key types
func (s *SmartCardKeyProvider) GetSupportedKeyTypes() []KeyType {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return s.getSupportedKeyTypesLocked()
}

// SupportsRotation indicates if the provider supports key rotation
func (s *SmartCardKeyProvider) SupportsRotation() bool {
	return true // Depends on device capabilities
}

// SupportsHardwareSecurity indicates hardware security support
func (s *SmartCardKeyProvider) SupportsHardwareSecurity() bool {
	return true
}

// GenerateKeyPair generates a new key pair on the smart card/USB token
func (s *SmartCardKeyProvider) GenerateKeyPair(ctx context.Context, keyType KeyType, keyID string, config map[string]string) (*KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isAvailableLocked() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	return s.generateKeyPairLocked(keyType, keyID, config)
}

func (s *SmartCardKeyProvider) generateKeyPairLocked(keyType KeyType, keyID string, config map[string]string) (*KeyPair, error) {
	if !s.isAvailableLocked() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	if err := s.validateFIPSKeyTypeLocked(keyType); err != nil {
		return nil, err
	}

	// Check if key already exists
	if _, exists := s.keyMetadata[keyID]; exists {
		return nil, fmt.Errorf("key with ID %s already exists", keyID)
	}

	// Validate key type is supported
	supported := false
	for _, supportedType := range s.getSupportedKeyTypesLocked() {
		if keyType == supportedType {
			supported = true
			break
		}
	}
	if !supported {
		return nil, fmt.Errorf("key type %v not supported by %s", keyType, s.GetProviderName())
	}

	// Convert config to options
	options := make(map[string]interface{})
	for k, v := range config {
		options[k] = v
	}

	// Generate key on device
	err := s.cardReader.GenerateKey(keyType, keyID, options)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key on %s: %w", s.GetProviderName(), err)
	}

	// Get public key from device
	publicKey, err := s.cardReader.GetPublicKey(keyID)
	if err != nil {
		// Clean up on failure
		s.cardReader.DeleteKey(keyID)
		return nil, fmt.Errorf("failed to retrieve public key from %s: %w", s.GetProviderName(), err)
	}

	// Convert public key to PEM
	softwareProvider := NewSoftwareKeyProvider(nil)
	publicKeyPEM, err := softwareProvider.publicKeyToPEM(publicKey)
	if err != nil {
		s.cardReader.DeleteKey(keyID)
		return nil, fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	// Create key pair metadata
	keyPair := &KeyPair{
		KeyID:         keyID,
		KeyType:       keyType,
		ProviderType:  s.GetProviderType(),
		PublicKey:     publicKey,
		PrivateKey:    nil, // Private key stays on device
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

	// Add device information
	if deviceInfo, err := s.cardReader.GetDeviceInfo(); err == nil {
		for k, v := range deviceInfo {
			keyPair.Metadata["device_"+k] = v
		}
	}

	// Store metadata
	s.keyMetadata[keyID] = keyPair

	return keyPair, nil
}

// GetKeyPair retrieves a key pair metadata
func (s *SmartCardKeyProvider) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.isAvailableLocked() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	keyPair, exists := s.keyMetadata[keyID]
	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}
	if err := s.validateFIPSKeyTypeLocked(keyPair.KeyType); err != nil {
		return nil, err
	}

	// Check if key has expired
	if keyPair.ExpiresAt != nil && time.Now().After(*keyPair.ExpiresAt) {
		return nil, fmt.Errorf("key with ID %s has expired", keyID)
	}

	// Verify key still exists on device
	_, err := s.cardReader.GetKeyInfo(keyID)
	if err != nil {
		return nil, fmt.Errorf("key not found on %s: %w", s.GetProviderName(), err)
	}

	return keyPair, nil
}

// DeleteKeyPair deletes a key pair from device and metadata
func (s *SmartCardKeyProvider) DeleteKeyPair(ctx context.Context, keyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isAvailableLocked() {
		return fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	// Delete from device first
	err := s.cardReader.DeleteKey(keyID)
	if err != nil {
		return fmt.Errorf("failed to delete key from %s: %w", s.GetProviderName(), err)
	}

	// Remove metadata
	delete(s.keyMetadata, keyID)
	return nil
}

// ListKeyPairs lists all key pair IDs
func (s *SmartCardKeyProvider) ListKeyPairs(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.isAvailableLocked() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	// Get keys from device to ensure consistency
	deviceKeys, err := s.cardReader.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to list keys from %s: %w", s.GetProviderName(), err)
	}

	return deviceKeys, nil
}

// Sign signs data using the device
func (s *SmartCardKeyProvider) Sign(ctx context.Context, keyID string, data []byte) ([]byte, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	// Update usage count
	s.mu.Lock()
	if err := s.validateFIPSKeyByIDLocked(keyID); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if keyPair, exists := s.keyMetadata[keyID]; exists {
		keyPair.UsageCount++
	}
	s.mu.Unlock()

	return s.cardReader.Sign(keyID, data)
}

// Decrypt decrypts data using the device
func (s *SmartCardKeyProvider) Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	// Update usage count
	s.mu.Lock()
	if err := s.validateFIPSKeyByIDLocked(keyID); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if keyPair, exists := s.keyMetadata[keyID]; exists {
		keyPair.UsageCount++
	}
	s.mu.Unlock()

	return s.cardReader.Decrypt(keyID, ciphertext)
}

// Encrypt encrypts data using the device
func (s *SmartCardKeyProvider) Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error) {
	if !s.IsAvailable() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	// Update usage count
	s.mu.Lock()
	if err := s.validateFIPSKeyByIDLocked(keyID); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	if keyPair, exists := s.keyMetadata[keyID]; exists {
		keyPair.UsageCount++
	}
	s.mu.Unlock()

	return s.cardReader.Encrypt(keyID, plaintext)
}

// RotateKey rotates a key on the device
func (s *SmartCardKeyProvider) RotateKey(ctx context.Context, keyID string) (*KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.isAvailableLocked() {
		return nil, fmt.Errorf("%s is not available or not authenticated", s.GetProviderName())
	}

	oldKeyPair, exists := s.keyMetadata[keyID]
	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}
	if err := s.validateFIPSKeyTypeLocked(oldKeyPair.KeyType); err != nil {
		return nil, err
	}

	// Create config from metadata
	config := make(map[string]string)
	for k, v := range oldKeyPair.Metadata {
		if !strings.HasPrefix(k, "device_") { // Skip device-specific metadata
			config[k] = v
		}
	}

	// Delete old key from device
	err := s.cardReader.DeleteKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old key from %s: %w", s.GetProviderName(), err)
	}

	// Remove old metadata
	delete(s.keyMetadata, keyID)

	// Generate new key
	newKeyPair, err := s.generateKeyPairLocked(oldKeyPair.KeyType, keyID, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new key during rotation: %w", err)
	}

	now := time.Now()
	newKeyPair.LastRotated = &now

	return newKeyPair, nil
}

// Configure sets provider configuration
func (s *SmartCardKeyProvider) Configure(config map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Update config
	for k, v := range config {
		s.config[k] = v
	}
	if err := s.applyFIPSModeFromConfigLocked(); err != nil {
		return err
	}

	if useHardwareCardReaderConfig(s.config) {
		if !isYubiKeyCardReader(s.cardReader) {
			s.cardReader = NewYubiKeyPIVCardReader()
		}
	} else if s.cardReader == nil {
		s.cardReader = newMockCardReader()
	}

	// Initialize device connection
	if s.cardReader != nil {
		err := s.cardReader.Connect(config)
		if err != nil {
			return fmt.Errorf("failed to connect to %s: %w", s.GetProviderName(), err)
		}

		// Select device if specified
		if deviceID, exists := config["device_id"]; exists {
			err = s.cardReader.SelectDevice(deviceID)
			if err != nil {
				return fmt.Errorf("failed to select device %s: %w", deviceID, err)
			}
		}

		// Authenticate if PIN provided
		if pin, exists := config["pin"]; exists {
			err = s.cardReader.Authenticate(pin)
			if err != nil {
				return fmt.Errorf("failed to authenticate with %s: %w", s.GetProviderName(), err)
			}
		}

		s.initialized = true
	}

	return nil
}

func (s *SmartCardKeyProvider) getSupportedKeyTypesLocked() []KeyType {
	supported := []KeyType{
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
	}
	if s.isFIPSEnabledLocked() {
		return filterFIPSKeyTypes(supported)
	}
	return supported
}

func (s *SmartCardKeyProvider) isFIPSEnabledLocked() bool {
	return fipsbuild.Enabled || s.fipsEnabled
}

func (s *SmartCardKeyProvider) applyFIPSModeFromConfigLocked() error {
	raw, exists := s.config["fips_enabled"]
	if !exists {
		s.fipsEnabled = fipsbuild.Enabled
		return nil
	}

	enabled, err := strconv.ParseBool(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("invalid fips_enabled value %q: %w", raw, err)
	}
	s.fipsEnabled = enabled || fipsbuild.Enabled
	return nil
}

func (s *SmartCardKeyProvider) validateFIPSKeyTypeLocked(keyType KeyType) error {
	if !s.isFIPSEnabledLocked() {
		return nil
	}
	if isFIPSKeyTypeAllowed(keyType) {
		return nil
	}
	return fmt.Errorf("key type %s is not allowed in FIPS mode for %s", keyType, s.GetProviderName())
}

func (s *SmartCardKeyProvider) validateFIPSKeyByIDLocked(keyID string) error {
	if !s.isFIPSEnabledLocked() {
		return nil
	}

	keyType := KeyType_KEY_TYPE_UNSPECIFIED
	if keyPair, exists := s.keyMetadata[keyID]; exists {
		keyType = keyPair.KeyType
	} else {
		publicKey, err := s.cardReader.GetPublicKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to resolve key type for %s in FIPS mode: %w", keyID, err)
		}
		keyType = keyTypeFromPublicKey(publicKey)
	}

	if isFIPSKeyTypeAllowed(keyType) {
		return nil
	}
	return fmt.Errorf("key %s type %s is not allowed in FIPS mode for %s", keyID, keyType, s.GetProviderName())
}

// GetConfiguration returns current configuration (excluding sensitive data like PIN)
func (s *SmartCardKeyProvider) GetConfiguration() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	config := make(map[string]string)
	for k, v := range s.config {
		if k != "pin" { // Don't return sensitive information
			config[k] = v
		}
	}

	return config
}

// Mock Card Reader Implementation
func (m *MockCardReader) Connect(config map[string]string) error {
	m.connected = true
	return nil
}

func (m *MockCardReader) Disconnect() error {
	m.connected = false
	m.authenticated = false
	return nil
}

func (m *MockCardReader) IsConnected() bool {
	return m.connected
}

func (m *MockCardReader) ListDevices() ([]string, error) {
	if !m.connected {
		return nil, fmt.Errorf("not connected")
	}

	devices := make([]string, 0, len(m.devices))
	for deviceID := range m.devices {
		devices = append(devices, deviceID)
	}
	return devices, nil
}

func (m *MockCardReader) SelectDevice(deviceID string) error {
	if !m.connected {
		return fmt.Errorf("not connected")
	}

	if _, exists := m.devices[deviceID]; !exists {
		return fmt.Errorf("device not found")
	}

	m.selectedDevice = deviceID
	return nil
}

func (m *MockCardReader) GetDeviceInfo() (map[string]string, error) {
	if !m.connected || m.selectedDevice == "" {
		return nil, fmt.Errorf("no device selected")
	}

	return map[string]string{
		"id":           m.selectedDevice,
		"name":         m.devices[m.selectedDevice],
		"manufacturer": "Mock Corp",
		"version":      "1.0",
	}, nil
}

func (m *MockCardReader) Authenticate(pin string) error {
	if !m.connected {
		return fmt.Errorf("not connected")
	}

	// Mock PIN validation
	if pin == "1234" || pin == "test" {
		m.authenticated = true
		return nil
	}

	return fmt.Errorf("invalid PIN")
}

func (m *MockCardReader) IsAuthenticated() bool {
	return m.authenticated
}

func (m *MockCardReader) GenerateKey(keyType KeyType, keyID string, options map[string]interface{}) error {
	if !m.connected || !m.authenticated {
		return fmt.Errorf("not connected or authenticated")
	}

	key := &mockCardKey{
		keyType: keyType,
		created: time.Now(),
	}

	switch keyType {
	case KeyType_KEY_TYPE_RSA_2048:
		privateKey, err := rsa.GenerateKey(crand.Reader, 2048)
		if err != nil {
			return fmt.Errorf("failed to generate RSA key: %w", err)
		}
		key.rsaPrivate = privateKey
	case KeyType_KEY_TYPE_ECC_P256:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECC P-256 key: %w", err)
		}
		key.ecdsaPrivate = privateKey
	case KeyType_KEY_TYPE_ECC_P384:
		privateKey, err := ecdsa.GenerateKey(elliptic.P384(), crand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate ECC P-384 key: %w", err)
		}
		key.ecdsaPrivate = privateKey
	default:
		return fmt.Errorf("unsupported key type %s", keyType)
	}

	m.keys[keyID] = key
	return nil
}

func (m *MockCardReader) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	if !m.connected || !m.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	key, exists := m.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	if key.rsaPrivate != nil {
		return &key.rsaPrivate.PublicKey, nil
	}
	if key.ecdsaPrivate != nil {
		return &key.ecdsaPrivate.PublicKey, nil
	}

	return nil, fmt.Errorf("public key not available")
}

func (m *MockCardReader) DeleteKey(keyID string) error {
	if !m.connected || !m.authenticated {
		return fmt.Errorf("not connected or authenticated")
	}

	delete(m.keys, keyID)
	return nil
}

func (m *MockCardReader) ListKeys() ([]string, error) {
	if !m.connected || !m.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	keys := make([]string, 0, len(m.keys))
	for keyID := range m.keys {
		keys = append(keys, keyID)
	}
	return keys, nil
}

func (m *MockCardReader) Sign(keyID string, data []byte) ([]byte, error) {
	if !m.connected || !m.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	if _, exists := m.keys[keyID]; !exists {
		return nil, fmt.Errorf("key not found")
	}

	key := m.keys[keyID]
	hash := sha256.Sum256(data)

	if key.rsaPrivate != nil {
		return rsa.SignPKCS1v15(crand.Reader, key.rsaPrivate, crypto.SHA256, hash[:])
	}
	if key.ecdsaPrivate != nil {
		return ecdsa.SignASN1(crand.Reader, key.ecdsaPrivate, hash[:])
	}

	return nil, fmt.Errorf("private key not available")
}

func (m *MockCardReader) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	if !m.connected || !m.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	key, exists := m.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	if key.rsaPrivate != nil {
		plaintext, err := rsa.DecryptOAEP(sha256.New(), crand.Reader, key.rsaPrivate, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA decrypt failed: %w", err)
		}
		return plaintext, nil
	}

	return nil, fmt.Errorf("decrypt not supported for key type %s", key.keyType)
}

func (m *MockCardReader) Encrypt(keyID string, plaintext []byte) ([]byte, error) {
	if !m.connected || !m.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	key, exists := m.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	if key.rsaPrivate != nil {
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), crand.Reader, &key.rsaPrivate.PublicKey, plaintext, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA encrypt failed: %w", err)
		}
		return ciphertext, nil
	}

	return nil, fmt.Errorf("encrypt not supported for key type %s", key.keyType)
}

func (m *MockCardReader) GetKeyInfo(keyID string) (map[string]interface{}, error) {
	if !m.connected || !m.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	if key, exists := m.keys[keyID]; exists {
		info := map[string]interface{}{
			"type":    key.keyType,
			"created": key.created,
		}
		return info, nil
	}

	return nil, fmt.Errorf("key not found")
}
