package key_access

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"stratium/pkg/auth"
	keyManager "stratium/services/key-manager"
	"strings"
)

// KeyIntegrityManager provides tamper-proof key verification tied to OIDC profiles
type KeyIntegrityManager struct {
	// Signing key for HMAC operations - in production this should be from secure storage
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

// CreateOIDCProfileHash creates a tamper-proof hash of the OIDC user profile
func (kim *KeyIntegrityManager) CreateOIDCProfileHash(claims *auth.UserClaims) string {
	// Create deterministic string from critical OIDC claims
	profileData := fmt.Sprintf("sub:%s|email:%s|email_verified:%t",
		claims.Sub, claims.Email, claims.EmailVerified)

	// Add roles and groups in deterministic order
	if len(claims.Roles) > 0 {
		roles := make([]string, len(claims.Roles))
		copy(roles, claims.Roles)
		sort.Strings(roles)
		profileData += "|roles:" + strings.Join(roles, ",")
	}

	if len(claims.Groups) > 0 {
		groups := make([]string, len(claims.Groups))
		copy(groups, claims.Groups)
		sort.Strings(groups)
		profileData += "|groups:" + strings.Join(groups, ",")
	}

	// Create hash with signing key
	hash := sha256.New()
	hash.Write(kim.signingKey)
	hash.Write([]byte(profileData))

	return hex.EncodeToString(hash.Sum(nil))
}

// CreateKeyIntegrityHash creates a tamper-proof hash linking the key to the OIDC profile
func (kim *KeyIntegrityManager) CreateKeyIntegrityHash(keyPEM string, keyType keyManager.KeyType, claims *auth.UserClaims) string {
	// Create deterministic string combining key and profile
	keyData := fmt.Sprintf("key_pem:%s|key_type:%d|user_id:%s|email:%s",
		keyPEM, int32(keyType), claims.Sub, claims.Email)

	// Include OIDC profile hash to prevent cross-user key injection
	oidcHash := kim.CreateOIDCProfileHash(claims)
	keyData += "|oidc_hash:" + oidcHash

	// Create HMAC with signing key
	hash := sha256.New()
	hash.Write(kim.signingKey)
	hash.Write([]byte(keyData))

	return hex.EncodeToString(hash.Sum(nil))
}
