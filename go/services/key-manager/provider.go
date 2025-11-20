package key_manager

import (
	"context"
	"time"
)

// KeyProviderInterface defines the interface for different key management technologies
type KeyProviderInterface interface {
	// Provider Information
	GetProviderType() KeyProviderType
	GetProviderName() string
	IsAvailable() bool
	GetSupportedKeyTypes() []KeyType
	SupportsRotation() bool
	SupportsHardwareSecurity() bool

	// Key Operations
	GenerateKeyPair(ctx context.Context, keyType KeyType, keyID string, config map[string]string) (*KeyPair, error)
	GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error)
	DeleteKeyPair(ctx context.Context, keyID string) error
	ListKeyPairs(ctx context.Context) ([]string, error)

	// Cryptographic Operations
	Sign(ctx context.Context, keyID string, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) ([]byte, error)
	Encrypt(ctx context.Context, keyID string, plaintext []byte) ([]byte, error)

	// Key Rotation
	RotateKey(ctx context.Context, keyID string) (*KeyPair, error)

	// Configuration
	Configure(config map[string]string) error
	GetConfiguration() map[string]string
}

// KeyPair represents a public/private key pair
// PublicKey and PrivateKey use any to support both crypto standard keys (RSA, ECDSA)
// and KEM keys (Kyber) which don't implement crypto.PublicKey/crypto.PrivateKey interfaces
type KeyPair struct {
	KeyID         string
	KeyType       KeyType
	ProviderType  KeyProviderType
	PublicKey     any // crypto.PublicKey for RSA/ECDSA, kem.PublicKey for Kyber
	PrivateKey    any // crypto.PrivateKey for RSA/ECDSA, kem.PrivateKey for Kyber
	PublicKeyPEM  string
	CreatedAt     time.Time
	ExpiresAt     *time.Time
	LastRotated   *time.Time
	UsageCount    int64
	MaxUsageCount int64
	Metadata      map[string]string
	ExternallyManaged bool
	ExternalSource    string
	ExternalManifestPath string
	PrivateKeySource  string
	ExternalLoaderType string
	ExternalLoadedAt  *time.Time
}

// ProviderFactory creates key providers based on type
type ProviderFactory interface {
	CreateProvider(providerType KeyProviderType, config map[string]string) (KeyProviderInterface, error)
	GetProvider(providerType KeyProviderType) (KeyProviderInterface, error)
	GetAvailableProviders() []KeyProviderType
}

// KeyRotationManager handles automated key rotation
type KeyRotationManager interface {
	ScheduleRotation(keyID string, policy RotationPolicy, interval time.Duration) error
	CancelRotation(keyID string) error
	CheckRotationNeeded(key *Key) bool
	PerformRotation(ctx context.Context, keyID string) (*RotateKeyResponse, error)
}

// ABACEvaluator handles attribute-based access control for key operations
type ABACEvaluator interface {
	EvaluateAccess(ctx context.Context, resource, action string, context map[string]string) (*AccessDecision, error)
	AddRule(rule *ABACRule) error
	RemoveRule(ruleID string) error
	ListRules() []*ABACRule
}

// AccessDecision represents the result of ABAC evaluation
type AccessDecision struct {
	Granted      bool
	Reason       string
	AppliedRules []string
	Context      map[string]string
}

// KeyMetrics tracks key usage and performance metrics
type KeyMetrics struct {
	KeyID          string
	UsageCount     int64
	LastUsed       time.Time
	SuccessfulOps  int64
	FailedOps      int64
	AverageLatency time.Duration
	SecurityEvents []SecurityEvent
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	EventType   string
	Timestamp   time.Time
	KeyID       string
	Subject     string
	Description string
	Severity    string
	Metadata    map[string]string
}

// KeyStore defines the interface for key persistence
type KeyStore interface {
	StoreKey(ctx context.Context, key *Key) error
	GetKey(ctx context.Context, keyID string) (*Key, error)
	ListKeys(ctx context.Context, filters map[string]interface{}) ([]*Key, error)
	DeleteKey(ctx context.Context, keyID string) error
	UpdateKey(ctx context.Context, key *Key) error
	// Key pair operations (for storing/retrieving private key material)
	StoreKeyPair(ctx context.Context, keyPair *KeyPair) error
	GetKeyPair(ctx context.Context, keyID string) (*KeyPair, error)
}
