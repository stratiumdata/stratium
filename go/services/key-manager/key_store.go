package key_manager

import (
	"context"
	"fmt"
	"sync"
)

// InMemoryKeyStore provides an in-memory implementation of KeyStore
// It stores both public key metadata (Key) and private key material (KeyPair)
type InMemoryKeyStore struct {
	mu       sync.RWMutex
	keys     map[string]*Key     // Public key metadata
	keyPairs map[string]*KeyPair // Private key material for cryptographic operations
}

// NewInMemoryKeyStore creates a new in-memory key store
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{
		keys:     make(map[string]*Key),
		keyPairs: make(map[string]*KeyPair),
	}
}

// StoreKey stores a key in the store
func (s *InMemoryKeyStore) StoreKey(ctx context.Context, key *Key) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}

	if key.KeyId == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.keys[key.KeyId] = key
	return nil
}

// GetKey retrieves a key from the store
func (s *InMemoryKeyStore) GetKey(ctx context.Context, keyID string) (*Key, error) {
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

// ListKeys returns all keys matching the filters
func (s *InMemoryKeyStore) ListKeys(ctx context.Context, filters map[string]interface{}) ([]*Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Key

	for _, key := range s.keys {
		if s.matchesFilters(key, filters) {
			// Create a copy
			keyCopy := *key
			result = append(result, &keyCopy)
		}
	}

	return result, nil
}

// DeleteKey deletes a key from the store (and its associated key pair if any)
func (s *InMemoryKeyStore) DeleteKey(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[keyID]; !exists {
		return fmt.Errorf("key with ID %s not found", keyID)
	}

	delete(s.keys, keyID)

	// Also delete the key pair if it exists
	delete(s.keyPairs, keyID)

	return nil
}

// UpdateKey updates a key in the store
func (s *InMemoryKeyStore) UpdateKey(ctx context.Context, key *Key) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}

	if key.KeyId == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keys[key.KeyId]; !exists {
		return fmt.Errorf("key with ID %s not found", key.KeyId)
	}

	s.keys[key.KeyId] = key
	return nil
}

// StoreKeyPair stores a complete key pair (including private key material)
// This is used by providers to store keys for cryptographic operations
func (s *InMemoryKeyStore) StoreKeyPair(ctx context.Context, keyPair *KeyPair) error {
	if keyPair == nil {
		return fmt.Errorf("key pair cannot be nil")
	}

	if keyPair.KeyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.keyPairs[keyPair.KeyID] = keyPair
	return nil
}

// GetKeyPair retrieves a complete key pair (including private key material)
// This is used by providers for cryptographic operations
func (s *InMemoryKeyStore) GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error) {
	if keyID == "" {
		return nil, fmt.Errorf("key ID cannot be empty")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	keyPair, exists := s.keyPairs[keyID]
	if !exists {
		return nil, fmt.Errorf("key pair with ID %s not found", keyID)
	}

	return keyPair, nil
}

// DeleteKeyPair deletes a key pair from the store
func (s *InMemoryKeyStore) DeleteKeyPair(ctx context.Context, keyID string) error {
	if keyID == "" {
		return fmt.Errorf("key ID cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.keyPairs[keyID]; !exists {
		return fmt.Errorf("key pair with ID %s not found", keyID)
	}

	delete(s.keyPairs, keyID)
	return nil
}

// matchesFilters checks if a key matches the given filters
func (s *InMemoryKeyStore) matchesFilters(key *Key, filters map[string]interface{}) bool {
	for filterKey, filterValue := range filters {
		switch filterKey {

		case "provider_type":
			providerTypeFilter := filterValue.(KeyProviderType)
			if key.ProviderType != providerTypeFilter {
				return false
			}

		case "status":
			statusFilter := filterValue.(KeyStatus)
			if key.Status != statusFilter {
				return false
			}
		}
	}

	return true
}
