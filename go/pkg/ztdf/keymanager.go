package ztdf

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"stratium/pkg/models"
	keyManager "stratium/services/key-manager"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"
)

// LocalKeyManager implements KeyManager with local file storage
type LocalKeyManager struct {
	keyStorePath string
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	keyID        string
	metadata     *models.KeyMetadata
}

// NewLocalKeyManager creates a key manager with local storage
// keyStorePath: directory to store keys (e.g., ~/.ztdf/client-keys)
func NewLocalKeyManager(keyStorePath string) (models.KeyManager, error) {
	if keyStorePath == "" {
		// Default to ~/.ztdf/client-keys
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		keyStorePath = filepath.Join(home, ".ztdf", "client-keys")
	}

	return &LocalKeyManager{
		keyStorePath: keyStorePath,
	}, nil
}

// LoadOrGenerate loads existing key or generates new one
func (km *LocalKeyManager) LoadOrGenerate() error {
	privateKeyPath := filepath.Join(km.keyStorePath, "private_key.pem")

	// Check if key exists
	if _, err := os.Stat(privateKeyPath); err == nil {
		// Key exists, load it
		log.Printf("Loading existing client key from %s", km.keyStorePath)
		return km.loadExistingKey()
	}

	// Key doesn't exist, generate new one
	log.Printf("Generating new client key pair at %s", km.keyStorePath)
	return km.generateAndSaveKey()
}

// loadExistingKey loads private key and metadata from disk
func (km *LocalKeyManager) loadExistingKey() error {
	// Load private key
	privateKeyPath := filepath.Join(km.keyStorePath, "private_key.pem")
	privateKeyPEM, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "failed to read private key file",
			Err:     err,
		}
	}

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "failed to decode PEM block",
		}
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "failed to parse private key",
			Err:     err,
		}
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey

	// Load metadata
	metadataPath := filepath.Join(km.keyStorePath, "key_metadata.json")
	metadataJSON, err := os.ReadFile(metadataPath)
	if err != nil {
		// Metadata file doesn't exist, create default
		km.metadata = &models.KeyMetadata{
			KeyID:     fmt.Sprintf("key-%d", time.Now().Unix()),
			CreatedAt: time.Now(),
			KeyType:   keyManager.KeyType_KEY_TYPE_RSA_2048,
			Status:    "active",
			KeySize:   2048,
		}
		return nil
	}

	metadata, err := parseMetadataFile(metadataJSON)
	if err != nil {
		return &models.Error{
			Code:    "INVALID_METADATA",
			Message: "failed to parse key metadata",
			Err:     err,
		}
	}

	km.metadata = metadata
	km.keyID = metadata.KeyID

	log.Printf("Loaded client key: %s (created: %s)", km.keyID, km.metadata.CreatedAt.Format(time.RFC3339))
	return nil
}

// generateAndSaveKey generates a new RSA key pair and saves it to disk
func (km *LocalKeyManager) generateAndSaveKey() error {
	// Ensure directory exists
	if err := os.MkdirAll(km.keyStorePath, 0700); err != nil {
		return &models.Error{
			Code:    "KEY_GENERATION_FAILED",
			Message: "failed to create key storage directory",
			Err:     err,
		}
	}

	// Generate RSA 2048-bit key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return &models.Error{
			Code:    "KEY_GENERATION_FAILED",
			Message: "failed to generate RSA key pair",
			Err:     err,
		}
	}

	km.privateKey = privateKey
	km.publicKey = &privateKey.PublicKey

	// Create metadata
	km.keyID = fmt.Sprintf("key-%d", time.Now().UnixNano())
	km.metadata = &models.KeyMetadata{
		KeyID:     km.keyID,
		CreatedAt: time.Now(),
		KeyType:   keyManager.KeyType_KEY_TYPE_RSA_2048,
		Status:    "active",
		KeySize:   2048,
	}

	// Save private key
	privateKeyPath := filepath.Join(km.keyStorePath, "private_key.pem")
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return &models.Error{
			Code:    "KEY_SAVE_FAILED",
			Message: "failed to save private key",
			Err:     err,
		}
	}

	// Save public key
	publicKeyPath := filepath.Join(km.keyStorePath, "public_key.pem")
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(km.publicKey)
	if err != nil {
		return &models.Error{
			Code:    "KEY_SAVE_FAILED",
			Message: "failed to marshal public key",
			Err:     err,
		}
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return &models.Error{
			Code:    "KEY_SAVE_FAILED",
			Message: "failed to save public key",
			Err:     err,
		}
	}

	// Save metadata
	if err := km.saveMetadata(); err != nil {
		return err
	}

	log.Printf("Generated new client key: %s", km.keyID)
	return nil
}

type metadataFile struct {
	KeyID        string          `json:"key_id"`
	CreatedAt    time.Time       `json:"created_at"`
	RegisteredAt *time.Time      `json:"registered_at,omitempty"`
	Client       string          `json:"client"`
	KeyTypeRaw   json.RawMessage `json:"key_type"`
	Status       string          `json:"status"`
	KeySize      int             `json:"key_size"`
}

func parseMetadataFile(data []byte) (*models.KeyMetadata, error) {
	var metadata models.KeyMetadata
	if err := json.Unmarshal(data, &metadata); err == nil {
		return &metadata, nil
	}

	var legacy metadataFile
	if err := json.Unmarshal(data, &legacy); err != nil {
		return nil, err
	}

	keyType, err := parseKeyTypeRaw(legacy.KeyTypeRaw)
	if err != nil {
		return nil, err
	}

	result := &models.KeyMetadata{
		KeyID:     legacy.KeyID,
		CreatedAt: legacy.CreatedAt,
		Client:    legacy.Client,
		KeyType:   keyType,
		Status:    legacy.Status,
		KeySize:   legacy.KeySize,
	}

	if legacy.RegisteredAt != nil {
		result.RegisteredAt = *legacy.RegisteredAt
	}

	return result, nil
}

func parseKeyTypeRaw(raw json.RawMessage) (keyManager.KeyType, error) {
	if len(raw) == 0 {
		return keyManager.KeyType_KEY_TYPE_RSA_2048, nil
	}

	var numeric int32
	if err := json.Unmarshal(raw, &numeric); err == nil {
		return keyManager.KeyType(numeric), nil
	}

	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		str = strings.TrimSpace(str)
		if str == "" {
			return keyManager.KeyType_KEY_TYPE_RSA_2048, nil
		}

		if value, ok := keyManager.KeyType_value[str]; ok {
			return keyManager.KeyType(value), nil
		}

		if parsed, err := strconv.Atoi(str); err == nil {
			return keyManager.KeyType(parsed), nil
		}

		return 0, fmt.Errorf("unknown key type %q", str)
	}

	return 0, fmt.Errorf("unsupported key_type format")
}

// saveMetadata saves key metadata to disk
func (km *LocalKeyManager) saveMetadata() error {
	metadataPath := filepath.Join(km.keyStorePath, "key_metadata.json")
	metadataJSON, err := json.MarshalIndent(km.metadata, "", "  ")
	if err != nil {
		return &models.Error{
			Code:    "METADATA_SAVE_FAILED",
			Message: "failed to marshal metadata",
			Err:     err,
		}
	}

	if err := os.WriteFile(metadataPath, metadataJSON, 0600); err != nil {
		return &models.Error{
			Code:    "METADATA_SAVE_FAILED",
			Message: "failed to save metadata",
			Err:     err,
		}
	}

	return nil
}

// GetPublicKey returns the public key
func (km *LocalKeyManager) GetPublicKey() (*rsa.PublicKey, error) {
	if km.publicKey == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "public key not loaded",
		}
	}
	return km.publicKey, nil
}

// GetPrivateKey returns the private key
func (km *LocalKeyManager) GetPrivateKey() (*rsa.PrivateKey, error) {
	if km.privateKey == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "private key not loaded",
		}
	}
	return km.privateKey, nil
}

// RegisterPublicKey registers public key with Key Access Service
func (km *LocalKeyManager) RegisterPublicKey(ctx context.Context, kmClient models.KeyManagerClient, authToken string) error {
	if km.publicKey == nil {
		return &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "public key not loaded",
		}
	}

	// Marshal public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(km.publicKey)
	if err != nil {
		return &models.Error{
			Code:    "KEY_MARSHAL_FAILED",
			Message: "failed to marshal public key",
			Err:     err,
		}
	}
	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))

	// Add auth token to context
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", fmt.Sprintf("Bearer %s", authToken))

	// Call RegisterClientKey - server will extract user claims from auth token
	resp, err := kmClient.RegisterClientKey(ctx, &keyManager.RegisterClientKeyRequest{
		ClientId:     "stratium-key-manager",
		PublicKeyPem: publicKeyPEM,
		KeyType:      keyManager.KeyType_KEY_TYPE_RSA_2048,
		Metadata: map[string]string{
			"key_id":   km.keyID,
			"key_size": "2048",
		},
	})
	if err != nil {
		return &models.Error{
			Code:    "REGISTRATION_FAILED",
			Message: "failed to register public key with KAS",
			Err:     err,
		}
	}

	if !resp.Success {
		return &models.Error{
			Code:    "REGISTRATION_FAILED",
			Message: fmt.Sprintf("key registration failed: %s", resp.ErrorMessage),
		}
	}

	// Update metadata
	km.metadata.RegisteredAt = time.Now()
	km.metadata.Client = resp.Key.ClientId
	km.metadata.KeyID = resp.Key.KeyId
	if err := km.saveMetadata(); err != nil {
		log.Printf("Warning: failed to save metadata after registration: %v", err)
	}

	log.Printf("Successfully registered public key with KAS (key_id: %s)", resp.Key.KeyId)
	return nil
}

// DecryptDEK decrypts a DEK with the private key
func (km *LocalKeyManager) DecryptDEK(encryptedDEK []byte) ([]byte, error) {
	if km.privateKey == nil {
		return nil, &models.Error{
			Code:    models.ErrCodeKeyNotFound,
			Message: "private key not loaded",
		}
	}

	dek, err := DecryptDEKWithPrivateKey(km.privateKey, encryptedDEK)
	if err != nil {
		return nil, err
	}

	return dek, nil
}

// GetKeyID returns the key identifier
func (km *LocalKeyManager) GetKeyID() string {
	return km.keyID
}

// GetMetadata returns key metadata
func (km *LocalKeyManager) GetMetadata() *models.KeyMetadata {
	return km.metadata
}

// Rotate generates a new key pair and registers it
func (km *LocalKeyManager) Rotate(ctx context.Context, kmClient models.KeyManagerClient, authToken string) error {
	// Mark current key as rotated
	if km.metadata != nil {
		km.metadata.Status = "rotated"
		if err := km.saveMetadata(); err != nil {
			log.Printf("Warning: failed to save metadata: %v", err)
		}
	}

	// Generate new key
	if err := km.generateAndSaveKey(); err != nil {
		return &models.Error{
			Code:    "ROTATION_FAILED",
			Message: "failed to generate new key during rotation",
			Err:     err,
		}
	}

	// Register new public key
	if err := km.RegisterPublicKey(ctx, kmClient, authToken); err != nil {
		return &models.Error{
			Code:    "ROTATION_FAILED",
			Message: "failed to register new key during rotation",
			Err:     err,
		}
	}

	log.Printf("Successfully rotated client key: %s", km.keyID)
	return nil
}
