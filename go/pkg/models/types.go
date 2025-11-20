package models

import (
	"context"
	"crypto/rsa"
	keyManager "stratium/services/key-manager"
	"time"
)

// KeyManagerClient is an alias for the gRPC-generated client
// This allows us to use the actual gRPC client directly
type KeyManagerClient = keyManager.KeyManagerServiceClient

// KeyManager manages client key pairs
type KeyManager interface {
	// LoadOrGenerate loads existing key or generates new one
	LoadOrGenerate() error

	// GetPublicKey returns the public key
	GetPublicKey() (*rsa.PublicKey, error)

	// GetPrivateKey returns the private key
	GetPrivateKey() (*rsa.PrivateKey, error)

	// RegisterPublicKey registers public key with KAS
	RegisterPublicKey(ctx context.Context, kmClient KeyManagerClient, authToken string) error

	// DecryptDEK decrypts a DEK with the private key
	DecryptDEK(encryptedDEK []byte) ([]byte, error)

	// GetKeyID returns the key identifier
	GetKeyID() string

	// GetMetadata returns key metadata
	GetMetadata() *KeyMetadata

	// Rotate generates a new key pair and registers it
	Rotate(ctx context.Context, kmClient KeyManagerClient, authToken string) error
}

// KeyMetadata stores key information
type KeyMetadata struct {
	KeyID        string             `json:"key_id"`
	CreatedAt    time.Time          `json:"created_at"`
	RegisteredAt time.Time          `json:"registered_at,omitempty"`
	Client       string             `json:"client"`
	KeyType      keyManager.KeyType `json:"key_type"`
	Status       string             `json:"status"` // active, rotated, revoked
	KeySize      int                `json:"key_size"`
}

// WrapOptions for customizing wrap operations
type WrapOptions struct {
	Resource       string            // Resource name for ABAC
	Policy         *ZtdfPolicy       // Custom policy (optional)
	Attributes     []Attribute       // Data attributes
	IntegrityCheck bool              // Enable integrity verification
	Context        map[string]string // Additional context for ABAC
}

// UnwrapOptions for customizing unwrap operations
type UnwrapOptions struct {
	Resource        string            // Resource name for ABAC
	VerifyIntegrity bool              // Verify payload integrity
	VerifyPolicy    bool              // Verify policy binding
	Context         map[string]string // Additional context for ABAC
}

// Attribute represents a data attribute
type Attribute struct {
	URI         string // Attribute URI (e.g., "http://example.com/attr/classification/value/secret")
	DisplayName string // Human-readable name
	IsDefault   bool   // Whether this is a default attribute
}

// Error types
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Code + ": " + e.Message + ": " + e.Err.Error()
	}
	return e.Code + ": " + e.Message
}

func (e *Error) Unwrap() error {
	return e.Err
}

// Common error codes
const (
	ErrCodeKeyNotFound      = "KEY_NOT_FOUND"
	ErrCodeAuthFailed       = "AUTH_FAILED"
	ErrCodeAccessDenied     = "ACCESS_DENIED"
	ErrCodeInvalidPolicy    = "INVALID_POLICY"
	ErrCodeEncryptionFailed = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed = "DECRYPTION_FAILED"
	ErrCodeIntegrityFailed  = "INTEGRITY_FAILED"
	ErrCodeInvalidManifest  = "INVALID_MANIFEST"
)
