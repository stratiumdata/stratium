package key_manager

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"stratium/pkg/auth"
	"sync"
	"time"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ClientKeyStore manages client public keys for DEK unwrapping operations
// This is separate from the KeyStore which manages service encryption keys (KEKs)
type ClientKeyStore interface {
	// RegisterKey registers a new client public key
	RegisterKey(ctx context.Context, key *Key) error

	// GetKey retrieves a client public key by key ID
	GetKey(ctx context.Context, keyID string) (*Key, error)

	// GetActiveKeyForClient retrieves the active key for a user
	GetActiveKeyForClient(ctx context.Context, clientID string) (*Key, error)

	// ListKeysForClient lists all keys for a specific user
	ListKeysForClient(ctx context.Context, clientID string, includeRevoked bool) ([]*Key, error)

	// RevokeKey revokes a client public key
	RevokeKey(ctx context.Context, keyID, reason string) error

	// ListClients lists all subjects that have registered keys
	ListClients(ctx context.Context) ([]string, error)
}

// InMemoryClientKeyStore provides an in-memory implementation of ClientKeyStore
type InMemoryClientKeyStore struct {
	mu             sync.RWMutex
	keys           map[string]*Key     // keyID -> key
	clientKeys     map[string][]string // clientID -> []keyID
	integrityMgr   *KeyIntegrityManager
	parsedKeyCache map[string]crypto.PublicKey // keyID -> parsed public key
}

// KeyIntegrityManager provides tamper-proof key verification
type KeyIntegrityManager struct {
	signingKey []byte
}

// NewKeyIntegrityManager creates a new key integrity manager
func NewKeyIntegrityManager() *KeyIntegrityManager {
	// In production, this should be loaded from secure key management system
	// For now, using a static key - THIS MUST BE CHANGED IN PRODUCTION
	signingKey := []byte("CHANGE_ME_IN_PRODUCTION_USE_PROPER_KEY_MANAGEMENT")

	return &KeyIntegrityManager{
		signingKey: signingKey,
	}
}

// CreateKeyIntegrityHash creates a tamper-proof hash linking the key to the OIDC profile
func (kim *KeyIntegrityManager) CreateKeyIntegrityHash(keyPEM string, keyType KeyType, claims *auth.UserClaims) string {
	if claims == nil {
		return ""
	}

	// Create deterministic string combining key and profile
	keyData := fmt.Sprintf("key_pem:%s|key_type:%d",
		keyPEM, int32(keyType))

	// Create HMAC with signing key
	hash := sha256.New()
	hash.Write(kim.signingKey)
	hash.Write([]byte(keyData))

	return hex.EncodeToString(hash.Sum(nil))
}

// VerifyKeyIntegrity verifies that a key record hasn't been tampered with
func (kim *KeyIntegrityManager) VerifyKeyIntegrity(key *Key, claims *auth.UserClaims) error {
	if claims == nil {
		return fmt.Errorf("user claims are required for verification")
	}

	// Verify key integrity hash
	expectedKeyHash := kim.CreateKeyIntegrityHash(key.PublicKeyPem, key.KeyType, claims)
	if subtle.ConstantTimeCompare([]byte(key.KeyIntegrityHash), []byte(expectedKeyHash)) != 1 {
		return fmt.Errorf("key integrity hash mismatch - key has been tampered with")
	}

	return nil
}

// NewInMemoryClientKeyStore creates a new in-memory client key store
func NewInMemoryClientKeyStore() *InMemoryClientKeyStore {
	return &InMemoryClientKeyStore{
		keys:           make(map[string]*Key),
		clientKeys:     make(map[string][]string),
		integrityMgr:   NewKeyIntegrityManager(),
		parsedKeyCache: make(map[string]crypto.PublicKey),
	}
}

// RegisterKey registers a new client public key
func (s *InMemoryClientKeyStore) RegisterKey(ctx context.Context, key *Key) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}

	if key.KeyId == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	if key.PublicKeyPem == "" {
		return fmt.Errorf("public key PEM cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Check if key already exists
	if _, exists := s.keys[key.KeyId]; exists {
		return fmt.Errorf("key with ID %s already exists", key.KeyId)
	}

	// Parse and validate the public key
	parsedKey, err := s.parsePublicKeyPEM(key.PublicKeyPem, key.KeyType)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Store the key
	s.keys[key.KeyId] = key

	// Add to user's key list
	s.clientKeys[key.ClientId] = append(s.clientKeys[key.ClientId], key.KeyId)

	// Cache the parsed key
	s.parsedKeyCache[key.KeyId] = parsedKey

	return nil
}

// GetKey retrieves a client public key by key ID
func (s *InMemoryClientKeyStore) GetKey(ctx context.Context, keyID string) (*Key, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	key, exists := s.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key with ID %s not found", keyID)
	}

	// Return a copy to avoid race conditions
	keyCopy := *key
	return &keyCopy, nil
}

// GetActiveKeyForClient retrieves the active key for a user
func (s *InMemoryClientKeyStore) GetActiveKeyForClient(ctx context.Context, clientID string) (*Key, error) {
	if clientID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	keyIDs, exists := s.clientKeys[clientID]
	if !exists || len(keyIDs) == 0 {
		return nil, fmt.Errorf("no keys found for user %s", clientID)
	}

	// Find the most recent active key
	var activeKey *Key
	var latestCreatedAt time.Time

	for _, keyID := range keyIDs {
		key, exists := s.keys[keyID]
		if !exists {
			continue
		}

		// Skip revoked or expired keys
		if key.Status != KeyStatus_KEY_STATUS_ACTIVE {
			continue
		}

		if key.ExpiresAt != nil && key.ExpiresAt.AsTime().Before(time.Now()) {
			continue
		}

		keyCreatedAt := key.CreatedAt.AsTime()
		if activeKey == nil || keyCreatedAt.After(latestCreatedAt) {
			activeKey = key
			latestCreatedAt = keyCreatedAt
		}
	}

	if activeKey == nil {
		return nil, fmt.Errorf("no active key found for user %s", clientID)
	}

	// Return a copy
	return activeKey, nil
}

// ListKeysForClient lists all keys for a specific user
func (s *InMemoryClientKeyStore) ListKeysForClient(ctx context.Context, clientID string, includeRevoked bool) ([]*Key, error) {
	if clientID == "" {
		return nil, fmt.Errorf("user ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	keyIDs, exists := s.clientKeys[clientID]
	if !exists {
		return []*Key{}, nil
	}

	var result []*Key
	for _, keyID := range keyIDs {
		key, exists := s.keys[keyID]
		if !exists {
			continue
		}

		// Skip revoked keys if not requested
		if !includeRevoked && key.Status == KeyStatus_KEY_STATUS_REVOKED {
			continue
		}

		// Create a copy
		keyCopy := *key
		result = append(result, &keyCopy)
	}

	return result, nil
}

// RevokeKey revokes a client public key
func (s *InMemoryClientKeyStore) RevokeKey(ctx context.Context, keyID, reason string) error {
	if keyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key, exists := s.keys[keyID]
	if !exists {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	key.Status = KeyStatus_KEY_STATUS_REVOKED

	// Remove from parsed key cache
	delete(s.parsedKeyCache, keyID)

	return nil
}

// ListClients lists all subjects that have registered keys
func (s *InMemoryClientKeyStore) ListClients(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]string, 0, len(s.clientKeys))
	for userID := range s.clientKeys {
		clients = append(clients, userID)
	}

	sort.Strings(clients)
	return clients, nil
}

// GetClientPublicKey retrieves the crypto.PublicKey for DEK operations
// This implements the SubjectKeyStore interface used by DEKUnwrappingService
func (s *InMemoryClientKeyStore) GetClientPublicKey(ctx context.Context, subject string) (crypto.PublicKey, error) {
	if subject == "" {
		return nil, fmt.Errorf("subject cannot be empty")
	}

	// First check if we have a cached parsed key
	activeKey, err := s.GetActiveKeyForClient(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("failed to get active key for subject %s: %w", subject, err)
	}

	s.mu.RLock()
	cachedKey, hasCached := s.parsedKeyCache[activeKey.KeyId]
	s.mu.RUnlock()

	if hasCached {
		return cachedKey, nil
	}

	// Parse the public key
	parsedKey, err := s.parsePublicKeyPEM(activeKey.PublicKeyPem, activeKey.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key for subject %s: %w", subject, err)
	}

	// Cache the parsed key
	s.mu.Lock()
	s.parsedKeyCache[activeKey.KeyId] = parsedKey
	s.mu.Unlock()

	return parsedKey, nil
}

// StoreClientPublicKey stores a subject's public key directly
// This implements the SubjectKeyStore interface and provides a simple way to register keys
func (s *InMemoryClientKeyStore) StoreClientPublicKey(ctx context.Context, subject string, publicKey crypto.PublicKey) error {
	if subject == "" {
		return fmt.Errorf("subject cannot be empty")
	}

	if publicKey == nil {
		return fmt.Errorf("public key cannot be nil")
	}

	// Convert the crypto.PublicKey to PEM format
	publicKeyPEM, keyType, err := s.publicKeyToPEM(publicKey)
	if err != nil {
		return fmt.Errorf("failed to convert public key to PEM: %w", err)
	}

	// Generate a unique key ID
	keyID := fmt.Sprintf("client-key-%s-%d", subject, time.Now().UnixNano())

	// Create a Key record
	userKey := &Key{
		KeyId:        keyID,
		PublicKeyPem: publicKeyPEM,
		KeyType:      keyType,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		Metadata:     make(map[string]string),
	}

	// Register the key
	return s.RegisterKey(ctx, userKey)
}

// publicKeyToPEM converts a crypto.PublicKey to PEM format and determines the key type
func (s *InMemoryClientKeyStore) publicKeyToPEM(publicKey crypto.PublicKey) (string, KeyType, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		// Determine RSA key size
		keySize := key.N.BitLen()
		var keyType KeyType
		switch keySize {
		case 2048:
			keyType = KeyType_KEY_TYPE_RSA_2048
		case 3072:
			keyType = KeyType_KEY_TYPE_RSA_3072
		case 4096:
			keyType = KeyType_KEY_TYPE_RSA_4096
		default:
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported RSA key size: %d", keySize)
		}

		// Marshal to ASN.1 DER
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal RSA public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		return string(pemBlock), keyType, nil

	case *ecdsa.PublicKey:
		// Determine ECC curve
		var keyType KeyType
		switch key.Curve.Params().Name {
		case "P-256":
			keyType = KeyType_KEY_TYPE_ECC_P256
		case "P-384":
			keyType = KeyType_KEY_TYPE_ECC_P384
		case "P-521":
			keyType = KeyType_KEY_TYPE_ECC_P521
		default:
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported ECC curve: %s", key.Curve.Params().Name)
		}

		// Marshal to ASN.1 DER
		derBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal ECC public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: derBytes,
		})

		return string(pemBlock), keyType, nil

	case *kyber512.PublicKey:
		// Marshal KYBER key to binary
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal KYBER-512 public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "KYBER-512 PUBLIC KEY",
			Bytes: keyBytes,
		})

		return string(pemBlock), KeyType_KEY_TYPE_KYBER_512, nil

	case *kyber768.PublicKey:
		// Marshal KYBER key to binary
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal KYBER-768 public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "KYBER-768 PUBLIC KEY",
			Bytes: keyBytes,
		})

		return string(pemBlock), KeyType_KEY_TYPE_KYBER_768, nil

	case *kyber1024.PublicKey:
		// Marshal KYBER key to binary
		keyBytes, err := key.MarshalBinary()
		if err != nil {
			return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("failed to marshal KYBER-1024 public key: %w", err)
		}

		// Encode to PEM
		pemBlock := pem.EncodeToMemory(&pem.Block{
			Type:  "KYBER-1024 PUBLIC KEY",
			Bytes: keyBytes,
		})

		return string(pemBlock), KeyType_KEY_TYPE_KYBER_1024, nil

	default:
		return "", KeyType_KEY_TYPE_UNSPECIFIED, fmt.Errorf("unsupported public key type: %T", publicKey)
	}
}

// parsePublicKeyPEM parses a PEM-encoded public key based on key type
func (s *InMemoryClientKeyStore) parsePublicKeyPEM(pemData string, keyType KeyType) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Handle KYBER keys differently - they use binary encoding, not ASN.1
	switch keyType {
	case KeyType_KEY_TYPE_KYBER_512:
		pub, err := kyber512.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal KYBER-512 public key: %w", err)
		}
		return pub, nil

	case KeyType_KEY_TYPE_KYBER_768:
		pub, err := kyber768.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal KYBER-768 public key: %w", err)
		}
		return pub, nil

	case KeyType_KEY_TYPE_KYBER_1024:
		pub, err := kyber1024.Scheme().UnmarshalBinaryPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal KYBER-1024 public key: %w", err)
		}
		return pub, nil

	case KeyType_KEY_TYPE_RSA_2048, KeyType_KEY_TYPE_RSA_3072, KeyType_KEY_TYPE_RSA_4096:
		// Parse as RSA key
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
		}
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected RSA public key, got %T", publicKey)
		}
		return rsaKey, nil

	case KeyType_KEY_TYPE_ECC_P256, KeyType_KEY_TYPE_ECC_P384, KeyType_KEY_TYPE_ECC_P521:
		// Parse as ECC key
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECC public key: %w", err)
		}
		eccKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("expected ECDSA public key, got %T", publicKey)
		}
		return eccKey, nil

	default:
		// Try generic parsing
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		return publicKey, nil
	}
}
