package key_manager

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestNewInMemoryKeyStore(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	require.NotNil(t, keyStore)
}

func TestInMemoryKeyStore_StoreKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	now := time.Now()
	key := &Key{
		KeyId:        "test-key-1",
		Name:         "Test Key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest-public-key\n-----END PUBLIC KEY-----",
		CreatedAt:    timestamppb.New(now),
	}

	tests := []struct {
		name      string
		key       *Key
		expectErr bool
	}{
		{
			name:      "Store valid key",
			key:       key,
			expectErr: false,
		},
		{
			name: "Store key with empty ID should fail",
			key: &Key{
				KeyId:   "",
				Name:    "Test",
				KeyType: KeyType_KEY_TYPE_RSA_2048,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyStore.StoreKey(ctx, tt.key)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInMemoryKeyStore_GetKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store a test key
	now := time.Now()
	key := &Key{
		KeyId:        "test-get-key",
		Name:         "Test Get Key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest-public-key\n-----END PUBLIC KEY-----",
		CreatedAt:    timestamppb.New(now),
	}
	err := keyStore.StoreKey(ctx, key)
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
			retrievedKey, err := keyStore.GetKey(ctx, tt.keyID)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, retrievedKey)
			} else {
				require.NoError(t, err)
				require.NotNil(t, retrievedKey)
				assert.Equal(t, key.KeyId, retrievedKey.KeyId)
				assert.Equal(t, key.Name, retrievedKey.Name)
				assert.Equal(t, key.KeyType, retrievedKey.KeyType)
			}
		})
	}
}

func TestInMemoryKeyStore_ListKeys(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store multiple test keys
	keys := []*Key{
		{
			KeyId:     "key-1",
			Name:      "Key 1",
			KeyType:   KeyType_KEY_TYPE_RSA_2048,
			Status:    KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt: timestamppb.Now(),
		},
		{
			KeyId:     "key-2",
			Name:      "Key 2",
			KeyType:   KeyType_KEY_TYPE_ECC_P256,
			Status:    KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt: timestamppb.Now(),
		},
		{
			KeyId:     "key-3",
			Name:      "Key 3",
			KeyType:   KeyType_KEY_TYPE_RSA_4096,
			Status:    KeyStatus_KEY_STATUS_REVOKED,
			CreatedAt: timestamppb.Now(),
		},
	}

	for _, key := range keys {
		err := keyStore.StoreKey(ctx, key)
		require.NoError(t, err)
	}

	tests := []struct {
		name           string
		filters        map[string]interface{}
		expectMinCount int
	}{
		{
			name:           "List all keys",
			filters:        nil,
			expectMinCount: 3,
		},
		{
			name:           "List with empty filters",
			filters:        map[string]interface{}{},
			expectMinCount: 3,
		},
		{
			name: "List with status filter",
			filters: map[string]interface{}{
				"status": KeyStatus_KEY_STATUS_ACTIVE,
			},
			expectMinCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listedKeys, err := keyStore.ListKeys(ctx, tt.filters)

			require.NoError(t, err)
			assert.GreaterOrEqual(t, len(listedKeys), tt.expectMinCount)
		})
	}
}

func TestInMemoryKeyStore_DeleteKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store a test key
	key := &Key{
		KeyId:     "test-delete-key",
		Name:      "Test Delete Key",
		KeyType:   KeyType_KEY_TYPE_RSA_2048,
		CreatedAt: timestamppb.Now(),
	}
	err := keyStore.StoreKey(ctx, key)
	require.NoError(t, err)

	tests := []struct {
		name      string
		keyID     string
		expectErr bool
	}{
		{
			name:      "Delete existing key",
			keyID:     "test-delete-key",
			expectErr: false,
		},
		{
			name:      "Delete non-existent key",
			keyID:     "non-existent",
			expectErr: true,
		},
		{
			name:      "Delete with empty key ID",
			keyID:     "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyStore.DeleteKey(ctx, tt.keyID)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify key was deleted
				_, err := keyStore.GetKey(ctx, tt.keyID)
				assert.Error(t, err)
			}
		})
	}
}

func TestInMemoryKeyStore_UpdateKey(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store initial key
	originalKey := &Key{
		KeyId:     "test-update-key",
		Name:      "Original Name",
		KeyType:   KeyType_KEY_TYPE_RSA_2048,
		Status:    KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt: timestamppb.Now(),
	}
	err := keyStore.StoreKey(ctx, originalKey)
	require.NoError(t, err)

	tests := []struct {
		name      string
		key       *Key
		expectErr bool
	}{
		{
			name: "Update existing key",
			key: &Key{
				KeyId:     "test-update-key",
				Name:      "Updated Name",
				KeyType:   KeyType_KEY_TYPE_RSA_2048,
				Status:    KeyStatus_KEY_STATUS_INACTIVE,
				CreatedAt: originalKey.CreatedAt,
			},
			expectErr: false,
		},
		{
			name: "Update non-existent key",
			key: &Key{
				KeyId:     "non-existent",
				Name:      "Non Existent",
				KeyType:   KeyType_KEY_TYPE_RSA_2048,
				CreatedAt: timestamppb.Now(),
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyStore.UpdateKey(ctx, tt.key)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)

				// Verify update was applied
				updatedKey, err := keyStore.GetKey(ctx, tt.key.KeyId)
				require.NoError(t, err)
				assert.Equal(t, tt.key.Name, updatedKey.Name)
				assert.Equal(t, tt.key.Status, updatedKey.Status)
			}
		})
	}
}

func TestInMemoryKeyStore_StoreKeyPair(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	keyPair := &KeyPair{
		KeyID:      "test-keypair-1",
		KeyType:    KeyType_KEY_TYPE_RSA_2048,
		PublicKey:  "test-public-key",
		PrivateKey: "test-private-key",
		CreatedAt:  time.Now(),
		Metadata: map[string]string{
			"purpose": "testing",
		},
	}

	tests := []struct {
		name      string
		keyPair   *KeyPair
		expectErr bool
	}{
		{
			name:      "Store valid key pair",
			keyPair:   keyPair,
			expectErr: false,
		},
		{
			name: "Store key pair with empty ID should fail",
			keyPair: &KeyPair{
				KeyID:   "",
				KeyType: KeyType_KEY_TYPE_RSA_2048,
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyStore.StoreKeyPair(ctx, tt.keyPair)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInMemoryKeyStore_GetKeyPair(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store a test key pair
	keyPair := &KeyPair{
		KeyID:      "test-get-keypair",
		KeyType:    KeyType_KEY_TYPE_RSA_2048,
		PublicKey:  "test-public-key",
		PrivateKey: "test-private-key",
		CreatedAt:  time.Now(),
	}
	err := keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	tests := []struct {
		name      string
		keyID     string
		expectErr bool
	}{
		{
			name:      "Get existing key pair",
			keyID:     "test-get-keypair",
			expectErr: false,
		},
		{
			name:      "Get non-existent key pair",
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
			retrievedKeyPair, err := keyStore.GetKeyPair(ctx, tt.keyID)

			if tt.expectErr {
				assert.Error(t, err)
				assert.Nil(t, retrievedKeyPair)
			} else {
				require.NoError(t, err)
				require.NotNil(t, retrievedKeyPair)
				assert.Equal(t, keyPair.KeyID, retrievedKeyPair.KeyID)
				assert.Equal(t, keyPair.KeyType, retrievedKeyPair.KeyType)
			}
		})
	}
}

func TestInMemoryKeyStore_DeleteKeyPair(t *testing.T) {
	keyStore := NewInMemoryKeyStore()
	ctx := context.Background()

	// Store a test key pair
	keyPair := &KeyPair{
		KeyID:     "test-delete-keypair",
		KeyType:   KeyType_KEY_TYPE_RSA_2048,
		PublicKey: "test-public-key",
		CreatedAt: time.Now(),
	}
	err := keyStore.StoreKeyPair(ctx, keyPair)
	require.NoError(t, err)

	tests := []struct {
		name      string
		keyID     string
		expectErr bool
	}{
		{
			name:      "Delete existing key pair",
			keyID:     "test-delete-keypair",
			expectErr: false,
		},
		{
			name:      "Delete non-existent key pair",
			keyID:     "non-existent",
			expectErr: true,
		},
		{
			name:      "Delete with empty key ID",
			keyID:     "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := keyStore.DeleteKeyPair(ctx, tt.keyID)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify key pair was deleted
				_, err := keyStore.GetKeyPair(ctx, tt.keyID)
				assert.Error(t, err)
			}
		})
	}
}