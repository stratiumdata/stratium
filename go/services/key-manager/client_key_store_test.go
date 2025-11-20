package key_manager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewInMemoryClientKeyStore(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	require.NotNil(t, store)
	require.NotNil(t, store.keys)
	require.NotNil(t, store.clientKeys)
	require.NotNil(t, store.integrityMgr)
	require.NotNil(t, store.parsedKeyCache)
}

func TestKeyIntegrityManager_CreateKeyIntegrityHash(t *testing.T) {
	kim := NewKeyIntegrityManager()
	require.NotNil(t, kim)

	// Test hash creation
	hash1 := kim.CreateKeyIntegrityHash("test-pem", KeyType_KEY_TYPE_RSA_2048, nil)
	assert.Empty(t, hash1, "Hash should be empty when claims are nil")

	// Hash with valid data should produce consistent results
	keyPEM := "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
	hash2 := kim.CreateKeyIntegrityHash(keyPEM, KeyType_KEY_TYPE_RSA_2048, nil)
	assert.Empty(t, hash2)
}

func generateRSAKeyPEM(t *testing.T) string {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM)
}

func generateECCKeyPEM(t *testing.T) string {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(publicKeyPEM)
}

func TestInMemoryClientKeyStore_RegisterKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKeyPEM := generateRSAKeyPEM(t)
	eccKeyPEM := generateECCKeyPEM(t)

	tests := []struct {
		name      string
		key       *Key
		expectErr bool
		errMsg    string
	}{
		{
			name: "Register valid RSA key",
			key: &Key{
				KeyId:        "test-rsa-key-1",
				ClientId:     "client-1",
				PublicKeyPem: rsaKeyPEM,
				KeyType:      KeyType_KEY_TYPE_RSA_2048,
				Status:       KeyStatus_KEY_STATUS_ACTIVE,
				CreatedAt:    timestamppb.Now(),
			},
			expectErr: false,
		},
		{
			name: "Register valid ECC key",
			key: &Key{
				KeyId:        "test-ecc-key-1",
				ClientId:     "client-2",
				PublicKeyPem: eccKeyPEM,
				KeyType:      KeyType_KEY_TYPE_ECC_P256,
				Status:       KeyStatus_KEY_STATUS_ACTIVE,
				CreatedAt:    timestamppb.Now(),
			},
			expectErr: false,
		},
		{
			name:      "Register nil key should fail",
			key:       nil,
			expectErr: true,
			errMsg:    "key cannot be nil",
		},
		{
			name: "Register key with empty ID should fail",
			key: &Key{
				KeyId:        "",
				ClientId:     "client-3",
				PublicKeyPem: rsaKeyPEM,
				KeyType:      KeyType_KEY_TYPE_RSA_2048,
			},
			expectErr: true,
			errMsg:    "key ID cannot be empty",
		},
		{
			name: "Register key with empty public key PEM should fail",
			key: &Key{
				KeyId:        "test-key-no-pem",
				ClientId:     "client-4",
				PublicKeyPem: "",
				KeyType:      KeyType_KEY_TYPE_RSA_2048,
			},
			expectErr: true,
			errMsg:    "public key PEM cannot be empty",
		},
		{
			name: "Register key with invalid PEM should fail",
			key: &Key{
				KeyId:        "test-key-invalid-pem",
				ClientId:     "client-5",
				PublicKeyPem: "not-a-valid-pem",
				KeyType:      KeyType_KEY_TYPE_RSA_2048,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.RegisterKey(ctx, tt.key)

			if tt.expectErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}

	// Test registering duplicate key
	t.Run("Register duplicate key should fail", func(t *testing.T) {
		dupKey := &Key{
			KeyId:        "test-rsa-key-1",
			ClientId:     "client-1",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			CreatedAt:    timestamppb.Now(),
		}
		err := store.RegisterKey(ctx, dupKey)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestInMemoryClientKeyStore_GetKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Register a test key
	rsaKeyPEM := generateRSAKeyPEM(t)
	testKey := &Key{
		KeyId:        "test-get-key",
		ClientId:     "client-1",
		PublicKeyPem: rsaKeyPEM,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	err := store.RegisterKey(ctx, testKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		keyID     string
		expectErr bool
	}{
		{
			name:      "Get existing key",
			keyID:     "test-get-key",
			expectErr: false,
		},
		{
			name:      "Get non-existent key",
			keyID:     "non-existent",
			expectErr: true,
		},
		{
			name:      "Get with empty key ID",
			keyID:     "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retrievedKey, err := store.GetKey(ctx, tt.keyID)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, retrievedKey)
			} else {
				require.NoError(t, err)
				require.NotNil(t, retrievedKey)
				assert.Equal(t, testKey.KeyId, retrievedKey.KeyId)
				assert.Equal(t, testKey.ClientId, retrievedKey.ClientId)
				assert.Equal(t, testKey.KeyType, retrievedKey.KeyType)
			}
		})
	}
}

func TestInMemoryClientKeyStore_GetActiveKeyForClient(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKeyPEM := generateRSAKeyPEM(t)

	// Register multiple keys for same client
	now := time.Now()
	keys := []*Key{
		{
			KeyId:        "client1-key-old",
			ClientId:     "client-1",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.New(now.Add(-2 * time.Hour)),
		},
		{
			KeyId:        "client1-key-revoked",
			ClientId:     "client-1",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_REVOKED,
			CreatedAt:    timestamppb.New(now.Add(-1 * time.Hour)),
		},
		{
			KeyId:        "client1-key-newest",
			ClientId:     "client-1",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.New(now),
		},
	}

	for _, key := range keys {
		err := store.RegisterKey(ctx, key)
		require.NoError(t, err)
	}

	tests := []struct {
		name        string
		clientID    string
		expectErr   bool
		expectedKey string
	}{
		{
			name:        "Get active key for client with multiple keys",
			clientID:    "client-1",
			expectErr:   false,
			expectedKey: "client1-key-newest",
		},
		{
			name:      "Get active key for non-existent client",
			clientID:  "non-existent-client",
			expectErr: true,
		},
		{
			name:      "Get active key with empty client ID",
			clientID:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			activeKey, err := store.GetActiveKeyForClient(ctx, tt.clientID)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, activeKey)
			} else {
				require.NoError(t, err)
				require.NotNil(t, activeKey)
				assert.Equal(t, tt.expectedKey, activeKey.KeyId)
			}
		})
	}
}

func TestInMemoryClientKeyStore_ListKeysForClient(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKeyPEM := generateRSAKeyPEM(t)

	// Register keys for multiple clients
	keys := []*Key{
		{
			KeyId:        "client1-key1",
			ClientId:     "client-1",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.Now(),
		},
		{
			KeyId:        "client1-key2",
			ClientId:     "client-1",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_REVOKED,
			CreatedAt:    timestamppb.Now(),
		},
		{
			KeyId:        "client2-key1",
			ClientId:     "client-2",
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.Now(),
		},
	}

	for _, key := range keys {
		err := store.RegisterKey(ctx, key)
		require.NoError(t, err)
	}

	tests := []struct {
		name           string
		clientID       string
		includeRevoked bool
		expectErr      bool
		expectedCount  int
	}{
		{
			name:           "List all keys for client-1 including revoked",
			clientID:       "client-1",
			includeRevoked: true,
			expectErr:      false,
			expectedCount:  2,
		},
		{
			name:           "List active keys for client-1",
			clientID:       "client-1",
			includeRevoked: false,
			expectErr:      false,
			expectedCount:  1,
		},
		{
			name:           "List keys for client-2",
			clientID:       "client-2",
			includeRevoked: false,
			expectErr:      false,
			expectedCount:  1,
		},
		{
			name:           "List keys for non-existent client",
			clientID:       "non-existent",
			includeRevoked: false,
			expectErr:      false,
			expectedCount:  0,
		},
		{
			name:           "List keys with empty client ID",
			clientID:       "",
			includeRevoked: false,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listedKeys, err := store.ListKeysForClient(ctx, tt.clientID, tt.includeRevoked)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedCount, len(listedKeys))
			}
		})
	}
}

func TestInMemoryClientKeyStore_RevokeKey(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	// Register a test key
	rsaKeyPEM := generateRSAKeyPEM(t)
	testKey := &Key{
		KeyId:        "test-revoke-key",
		ClientId:     "client-1",
		PublicKeyPem: rsaKeyPEM,
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}
	err := store.RegisterKey(ctx, testKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		keyID     string
		reason    string
		expectErr bool
	}{
		{
			name:      "Revoke existing key",
			keyID:     "test-revoke-key",
			reason:    "Test revocation",
			expectErr: false,
		},
		{
			name:      "Revoke non-existent key",
			keyID:     "non-existent",
			reason:    "Test",
			expectErr: true,
		},
		{
			name:      "Revoke with empty key ID",
			keyID:     "",
			reason:    "Test",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.RevokeKey(ctx, tt.keyID, tt.reason)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify key was revoked
				if tt.keyID == "test-revoke-key" {
					revokedKey, err := store.GetKey(ctx, tt.keyID)
					require.NoError(t, err)
					assert.Equal(t, KeyStatus_KEY_STATUS_REVOKED, revokedKey.Status)
				}
			}
		})
	}
}

func TestInMemoryClientKeyStore_ListClients(t *testing.T) {
	store := NewInMemoryClientKeyStore()
	ctx := context.Background()

	rsaKeyPEM := generateRSAKeyPEM(t)

	// Register keys for multiple clients
	clients := []string{"client-1", "client-2", "client-3"}
	for i, clientID := range clients {
		key := &Key{
			KeyId:        "key-" + clientID,
			ClientId:     clientID,
			PublicKeyPem: rsaKeyPEM,
			KeyType:      KeyType_KEY_TYPE_RSA_2048,
			Status:       KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.Now(),
		}
		err := store.RegisterKey(ctx, key)
		require.NoError(t, err, "Failed to register key %d", i)
	}

	t.Run("List all clients", func(t *testing.T) {
		listedClients, err := store.ListClients(ctx)
		require.NoError(t, err)
		assert.Equal(t, 3, len(listedClients))
		// Results should be sorted
		assert.Contains(t, listedClients, "client-1")
		assert.Contains(t, listedClients, "client-2")
		assert.Contains(t, listedClients, "client-3")
	})

	t.Run("List clients from empty store", func(t *testing.T) {
		emptyStore := NewInMemoryClientKeyStore()
		listedClients, err := emptyStore.ListClients(ctx)
		require.NoError(t, err)
		assert.Equal(t, 0, len(listedClients))
	})
}
