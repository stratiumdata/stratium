package key_manager

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// AdminKeyManager manages the master admin key used to encrypt/decrypt private key material
// The admin key is a symmetric key (AES-256) that acts as a Key Encryption Key (KEK)
type AdminKeyManager struct {
	provider AdminKeyProvider
}

// AdminKeyProvider defines the interface for retrieving the admin key from various sources
type AdminKeyProvider interface {
	// GetAdminKey retrieves the admin key from the provider
	GetAdminKey(ctx context.Context) ([]byte, error)

	// SaveAdminKey saves the admin key to the provider (for initialization)
	SaveAdminKey(ctx context.Context, key []byte) error

	// GetProviderType returns the type of provider (e.g., "env", "file", "aws-secrets-manager")
	GetProviderType() string
}

// NewAdminKeyManager creates a new admin key manager with the specified provider
func NewAdminKeyManager(provider AdminKeyProvider) *AdminKeyManager {
	return &AdminKeyManager{
		provider: provider,
	}
}

// GetOrCreateAdminKey retrieves the admin key or creates a new one if it doesn't exist
func (m *AdminKeyManager) GetOrCreateAdminKey(ctx context.Context) ([]byte, error) {
	// Try to retrieve existing key
	key, err := m.provider.GetAdminKey(ctx)
	if err == nil && len(key) == 32 { // AES-256 requires 32 bytes
		return key, nil
	}

	// Generate new key
	key = make([]byte, 32) // 256 bits for AES-256
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate admin key: %w", err)
	}

	// Save the key
	if err := m.provider.SaveAdminKey(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to save admin key: %w", err)
	}

	return key, nil
}

// RotateAdminKey generates a new admin key and returns both old and new keys
// The caller is responsible for re-encrypting all key material with the new key
func (m *AdminKeyManager) RotateAdminKey(ctx context.Context) (oldKey, newKey []byte, err error) {
	// Get current key
	oldKey, err = m.provider.GetAdminKey(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current admin key: %w", err)
	}

	// Generate new key
	newKey = make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, nil, fmt.Errorf("failed to generate new admin key: %w", err)
	}

	// Save the new key
	if err := m.provider.SaveAdminKey(ctx, newKey); err != nil {
		return nil, nil, fmt.Errorf("failed to save new admin key: %w", err)
	}

	return oldKey, newKey, nil
}

// ===========================================================================================
// ADMIN KEY PROVIDERS
// ===========================================================================================

// EnvAdminKeyProvider retrieves the admin key from an environment variable
// Best for development/testing, not recommended for production
type EnvAdminKeyProvider struct {
	envVarName string
}

func NewEnvAdminKeyProvider(envVarName string) *EnvAdminKeyProvider {
	if envVarName == "" {
		envVarName = "STRATIUM_ADMIN_KEY"
	}
	return &EnvAdminKeyProvider{envVarName: envVarName}
}

func (p *EnvAdminKeyProvider) GetAdminKey(ctx context.Context) ([]byte, error) {
	encoded := os.Getenv(p.envVarName)
	if encoded == "" {
		return nil, fmt.Errorf("admin key not found in environment variable %s", p.envVarName)
	}

	// Decode from base64
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode admin key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("invalid admin key length: expected 32 bytes, got %d", len(key))
	}

	return key, nil
}

func (p *EnvAdminKeyProvider) SaveAdminKey(ctx context.Context, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)
	fmt.Printf("\n=================================================================\n")
	fmt.Printf("IMPORTANT: Save this admin key to your secrets manager:\n")
	fmt.Printf("export %s=%s\n", p.envVarName, encoded)
	fmt.Printf("=================================================================\n\n")
	return nil
}

func (p *EnvAdminKeyProvider) GetProviderType() string {
	return "env"
}

// FileAdminKeyProvider retrieves the admin key from a file
// Better for Docker volumes and persistent storage
type FileAdminKeyProvider struct {
	filePath string
}

func NewFileAdminKeyProvider(filePath string) *FileAdminKeyProvider {
	if filePath == "" {
		filePath = "/var/run/secrets/stratium/admin-key"
	}
	return &FileAdminKeyProvider{filePath: filePath}
}

func (p *FileAdminKeyProvider) GetAdminKey(ctx context.Context) ([]byte, error) {
	data, err := os.ReadFile(p.filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read admin key file: %w", err)
	}

	// Decode from base64 and trim whitespace
	encoded := strings.TrimSpace(string(data))
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode admin key: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("invalid admin key length: expected 32 bytes, got %d", len(key))
	}

	return key, nil
}

func (p *FileAdminKeyProvider) SaveAdminKey(ctx context.Context, key []byte) error {
	encoded := base64.StdEncoding.EncodeToString(key)

	// Create directory if it doesn't exist
	dir := filepath.Dir(p.filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Handle legacy cases where the target path was accidentally created as a directory
	if info, err := os.Stat(p.filePath); err == nil && info.IsDir() {
		if err := os.RemoveAll(p.filePath); err != nil {
			return fmt.Errorf("failed to remove directory at admin key path: %w", err)
		}
	}

	// Write key to file with restricted permissions
	if err := os.WriteFile(p.filePath, []byte(encoded), 0600); err != nil {
		return fmt.Errorf("failed to write admin key file: %w", err)
	}

	fmt.Printf("\n=================================================================\n")
	fmt.Printf("Admin key saved to: %s\n", p.filePath)
	fmt.Printf("Ensure this file is backed up and secured!\n")
	fmt.Printf("For Docker, mount this as a volume to persist across container restarts.\n")
	fmt.Printf("=================================================================\n\n")

	return nil
}

func (p *FileAdminKeyProvider) GetProviderType() string {
	return "file"
}

// CompositeAdminKeyProvider tries multiple providers in order
// Useful for fallback scenarios (e.g., try secrets manager, then file, then env)
type CompositeAdminKeyProvider struct {
	providers []AdminKeyProvider
}

func NewCompositeAdminKeyProvider(providers ...AdminKeyProvider) *CompositeAdminKeyProvider {
	return &CompositeAdminKeyProvider{providers: providers}
}

func (p *CompositeAdminKeyProvider) GetAdminKey(ctx context.Context) ([]byte, error) {
	var lastErr error
	for _, provider := range p.providers {
		key, err := provider.GetAdminKey(ctx)
		if err == nil && len(key) == 32 {
			return key, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all providers failed, last error: %w", lastErr)
	}
	return nil, fmt.Errorf("no admin key provider succeeded")
}

func (p *CompositeAdminKeyProvider) SaveAdminKey(ctx context.Context, key []byte) error {
	// Save to the first provider that supports saving
	if len(p.providers) > 0 {
		return p.providers[0].SaveAdminKey(ctx, key)
	}
	return fmt.Errorf("no providers available")
}

func (p *CompositeAdminKeyProvider) GetProviderType() string {
	types := make([]string, len(p.providers))
	for i, provider := range p.providers {
		types[i] = provider.GetProviderType()
	}
	return "composite(" + strings.Join(types, ",") + ")"
}

// CreateAdminKeyProvider creates an admin key provider based on configuration
func CreateAdminKeyProvider(providerType, config string) (AdminKeyProvider, error) {
	switch strings.ToLower(providerType) {
	case "env":
		return NewEnvAdminKeyProvider(config), nil
	case "file":
		return NewFileAdminKeyProvider(config), nil
	case "composite":
		// For composite, try file first, then env
		return NewCompositeAdminKeyProvider(
			NewFileAdminKeyProvider(config),
			NewEnvAdminKeyProvider("STRATIUM_ADMIN_KEY"),
		), nil
	default:
		return nil, fmt.Errorf("unsupported admin key provider type: %s", providerType)
	}
}
