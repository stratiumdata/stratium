package key_access

import (
	"stratium/pkg/auth"
	keyManager "stratium/services/key-manager"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewKeyIntegrityManager(t *testing.T) {
	kim := NewKeyIntegrityManager()
	require.NotNil(t, kim)
	require.NotNil(t, kim.signingKey)
	assert.Greater(t, len(kim.signingKey), 0)
}

func TestKeyIntegrityManager_CreateOIDCProfileHash(t *testing.T) {
	kim := NewKeyIntegrityManager()

	tests := []struct {
		name   string
		claims *auth.UserClaims
	}{
		{
			name: "Basic claims",
			claims: &auth.UserClaims{
				Sub:           "user123",
				Email:         "user@example.com",
				EmailVerified: true,
			},
		},
		{
			name: "Claims with roles",
			claims: &auth.UserClaims{
				Sub:           "user456",
				Email:         "admin@example.com",
				EmailVerified: true,
				Roles:         []string{"admin", "user"},
			},
		},
		{
			name: "Claims with groups",
			claims: &auth.UserClaims{
				Sub:           "user789",
				Email:         "dev@example.com",
				EmailVerified: false,
				Groups:        []string{"engineering", "devops"},
			},
		},
		{
			name: "Claims with roles and groups",
			claims: &auth.UserClaims{
				Sub:           "user999",
				Email:         "superadmin@example.com",
				EmailVerified: true,
				Roles:         []string{"superadmin", "admin", "user"},
				Groups:        []string{"leadership", "engineering", "ops"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := kim.CreateOIDCProfileHash(tt.claims)

			// Hash should not be empty
			assert.NotEmpty(t, hash)

			// Hash should be deterministic
			hash2 := kim.CreateOIDCProfileHash(tt.claims)
			assert.Equal(t, hash, hash2, "Hash should be deterministic")

			// Hash should be hex-encoded (64 chars for SHA-256)
			assert.Equal(t, 64, len(hash), "SHA-256 hash should be 64 hex characters")
		})
	}
}

func TestKeyIntegrityManager_CreateOIDCProfileHash_Deterministic(t *testing.T) {
	kim := NewKeyIntegrityManager()

	// Test that roles/groups in different orders produce same hash
	claims1 := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
		Roles:         []string{"admin", "user", "editor"},
		Groups:        []string{"eng", "ops", "qa"},
	}

	claims2 := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
		Roles:         []string{"user", "editor", "admin"}, // Different order
		Groups:        []string{"qa", "ops", "eng"},        // Different order
	}

	hash1 := kim.CreateOIDCProfileHash(claims1)
	hash2 := kim.CreateOIDCProfileHash(claims2)

	assert.Equal(t, hash1, hash2, "Hashes should be equal regardless of role/group order")
}

func TestKeyIntegrityManager_CreateOIDCProfileHash_Uniqueness(t *testing.T) {
	kim := NewKeyIntegrityManager()

	claims1 := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
	}

	claims2 := &auth.UserClaims{
		Sub:           "user456",
		Email:         "user@example.com",
		EmailVerified: true,
	}

	claims3 := &auth.UserClaims{
		Sub:           "user123",
		Email:         "different@example.com",
		EmailVerified: true,
	}

	hash1 := kim.CreateOIDCProfileHash(claims1)
	hash2 := kim.CreateOIDCProfileHash(claims2)
	hash3 := kim.CreateOIDCProfileHash(claims3)

	// Different users should have different hashes
	assert.NotEqual(t, hash1, hash2, "Different subjects should produce different hashes")
	assert.NotEqual(t, hash1, hash3, "Different emails should produce different hashes")
	assert.NotEqual(t, hash2, hash3, "All hashes should be unique")
}

func TestKeyIntegrityManager_CreateKeyIntegrityHash(t *testing.T) {
	kim := NewKeyIntegrityManager()

	keyPEM := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----"

	claims := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
		Roles:         []string{"admin"},
	}

	tests := []struct {
		name    string
		keyPEM  string
		keyType keyManager.KeyType
		claims  *auth.UserClaims
	}{
		{
			name:    "RSA 2048 key",
			keyPEM:  keyPEM,
			keyType: keyManager.KeyType_KEY_TYPE_RSA_2048,
			claims:  claims,
		},
		{
			name:    "ECC P256 key",
			keyPEM:  keyPEM,
			keyType: keyManager.KeyType_KEY_TYPE_ECC_P256,
			claims:  claims,
		},
		{
			name:    "Kyber 512 key",
			keyPEM:  keyPEM,
			keyType: keyManager.KeyType_KEY_TYPE_KYBER_512,
			claims:  claims,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := kim.CreateKeyIntegrityHash(tt.keyPEM, tt.keyType, tt.claims)

			// Hash should not be empty
			assert.NotEmpty(t, hash)

			// Hash should be deterministic
			hash2 := kim.CreateKeyIntegrityHash(tt.keyPEM, tt.keyType, tt.claims)
			assert.Equal(t, hash, hash2, "Hash should be deterministic")

			// Hash should be hex-encoded (64 chars for SHA-256)
			assert.Equal(t, 64, len(hash), "SHA-256 hash should be 64 hex characters")
		})
	}
}

func TestKeyIntegrityManager_CreateKeyIntegrityHash_DifferentKeyTypes(t *testing.T) {
	kim := NewKeyIntegrityManager()

	keyPEM := "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"
	claims := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
	}

	hashRSA := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, claims)
	hashECC := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_ECC_P256, claims)
	hashKyber := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_KYBER_512, claims)

	// Different key types should produce different hashes
	assert.NotEqual(t, hashRSA, hashECC)
	assert.NotEqual(t, hashRSA, hashKyber)
	assert.NotEqual(t, hashECC, hashKyber)
}

func TestKeyIntegrityManager_CreateKeyIntegrityHash_DifferentKeys(t *testing.T) {
	kim := NewKeyIntegrityManager()

	keyPEM1 := "-----BEGIN PUBLIC KEY-----\nkey1\n-----END PUBLIC KEY-----"
	keyPEM2 := "-----BEGIN PUBLIC KEY-----\nkey2\n-----END PUBLIC KEY-----"

	claims := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
	}

	hash1 := kim.CreateKeyIntegrityHash(keyPEM1, keyManager.KeyType_KEY_TYPE_RSA_2048, claims)
	hash2 := kim.CreateKeyIntegrityHash(keyPEM2, keyManager.KeyType_KEY_TYPE_RSA_2048, claims)

	// Different keys should produce different hashes
	assert.NotEqual(t, hash1, hash2)
}

func TestKeyIntegrityManager_CreateKeyIntegrityHash_DifferentUsers(t *testing.T) {
	kim := NewKeyIntegrityManager()

	keyPEM := "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----"

	claims1 := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user1@example.com",
		EmailVerified: true,
	}

	claims2 := &auth.UserClaims{
		Sub:           "user456",
		Email:         "user2@example.com",
		EmailVerified: true,
	}

	hash1 := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, claims1)
	hash2 := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, claims2)

	// Same key for different users should produce different hashes
	assert.NotEqual(t, hash1, hash2, "Same key for different users should have different integrity hashes")
}

func TestKeyIntegrityManager_CrossUserKeyInjectionPrevention(t *testing.T) {
	kim := NewKeyIntegrityManager()

	keyPEM := "-----BEGIN PUBLIC KEY-----\nshared-key\n-----END PUBLIC KEY-----"

	// Two different users
	user1Claims := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user1@example.com",
		EmailVerified: true,
	}

	user2Claims := &auth.UserClaims{
		Sub:           "user456",
		Email:         "user2@example.com",
		EmailVerified: true,
	}

	// Generate integrity hashes for same key but different users
	hash1 := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, user1Claims)
	hash2 := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, user2Claims)

	// Hashes must be different to prevent cross-user key injection attacks
	assert.NotEqual(t, hash1, hash2, "Key integrity hashes must differ per user to prevent cross-user key injection")
}

func TestKeyIntegrityManager_OIDCHashIncluded(t *testing.T) {
	kim := NewKeyIntegrityManager()

	keyPEM := "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"

	claims := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
		Roles:         []string{"admin"},
	}

	// Get the key integrity hash
	keyHash := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, claims)

	// Modify the claims
	claimsModified := &auth.UserClaims{
		Sub:           "user123",
		Email:         "user@example.com",
		EmailVerified: true,
		Roles:         []string{"admin", "superadmin"}, // Added role
	}

	keyHashModified := kim.CreateKeyIntegrityHash(keyPEM, keyManager.KeyType_KEY_TYPE_RSA_2048, claimsModified)

	// Hashes should differ because OIDC profile changed
	assert.NotEqual(t, keyHash, keyHashModified, "Key hash should change when user roles/profile changes")
}