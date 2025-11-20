package key_manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ===========================================================================================
// MOCK ADMIN KEY PROVIDER
// ===========================================================================================

type MockAdminKeyProvider struct {
	getAdminKeyFunc  func(ctx context.Context) ([]byte, error)
	saveAdminKeyFunc func(ctx context.Context, key []byte) error
	providerType     string
}

func NewMockAdminKeyProvider() *MockAdminKeyProvider {
	return &MockAdminKeyProvider{
		providerType: "mock",
	}
}

func (m *MockAdminKeyProvider) GetAdminKey(ctx context.Context) ([]byte, error) {
	if m.getAdminKeyFunc != nil {
		return m.getAdminKeyFunc(ctx)
	}
	return make([]byte, 32), nil
}

func (m *MockAdminKeyProvider) SaveAdminKey(ctx context.Context, key []byte) error {
	if m.saveAdminKeyFunc != nil {
		return m.saveAdminKeyFunc(ctx, key)
	}
	return nil
}

func (m *MockAdminKeyProvider) GetProviderType() string {
	return m.providerType
}

// ===========================================================================================
// ADMIN KEY MANAGER TESTS
// ===========================================================================================

func TestNewAdminKeyManager(t *testing.T) {
	provider := NewMockAdminKeyProvider()
	manager := NewAdminKeyManager(provider)

	if manager == nil {
		t.Fatal("NewAdminKeyManager returned nil")
	}

	if manager.provider != provider {
		t.Error("AdminKeyManager provider not set correctly")
	}
}

func TestAdminKeyManager_GetOrCreateAdminKey_ExistingKey(t *testing.T) {
	existingKey := make([]byte, 32)
	for i := range existingKey {
		existingKey[i] = byte(i)
	}

	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return existingKey, nil
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	key, err := manager.GetOrCreateAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateAdminKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	// Should return the existing key
	for i := range key {
		if key[i] != existingKey[i] {
			t.Errorf("Key mismatch at index %d: expected %d, got %d", i, existingKey[i], key[i])
		}
	}
}

func TestAdminKeyManager_GetOrCreateAdminKey_CreateNew(t *testing.T) {
	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("key not found")
	}

	var savedKey []byte
	provider.saveAdminKeyFunc = func(ctx context.Context, key []byte) error {
		savedKey = key
		return nil
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	key, err := manager.GetOrCreateAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateAdminKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	if savedKey == nil {
		t.Error("SaveAdminKey was not called")
	}

	if len(savedKey) != 32 {
		t.Errorf("Expected saved key length 32, got %d", len(savedKey))
	}

	// Verify the saved key matches returned key
	for i := range key {
		if key[i] != savedKey[i] {
			t.Errorf("Key mismatch at index %d: expected %d, got %d", i, savedKey[i], key[i])
		}
	}
}

func TestAdminKeyManager_GetOrCreateAdminKey_InvalidKeyLength(t *testing.T) {
	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return make([]byte, 16), nil // Wrong length
	}

	var savedKey []byte
	provider.saveAdminKeyFunc = func(ctx context.Context, key []byte) error {
		savedKey = key
		return nil
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	key, err := manager.GetOrCreateAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateAdminKey failed: %v", err)
	}

	// Should create new key with correct length
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}

	if savedKey == nil {
		t.Error("SaveAdminKey was not called")
	}
}

func TestAdminKeyManager_GetOrCreateAdminKey_SaveError(t *testing.T) {
	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("key not found")
	}
	provider.saveAdminKeyFunc = func(ctx context.Context, key []byte) error {
		return fmt.Errorf("save failed")
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	_, err := manager.GetOrCreateAdminKey(ctx)
	if err == nil {
		t.Error("Expected error when save fails")
	}

	if !strings.Contains(err.Error(), "failed to save admin key") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestAdminKeyManager_RotateAdminKey(t *testing.T) {
	oldKey := make([]byte, 32)
	for i := range oldKey {
		oldKey[i] = byte(i)
	}

	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return oldKey, nil
	}

	var savedKey []byte
	provider.saveAdminKeyFunc = func(ctx context.Context, key []byte) error {
		savedKey = key
		return nil
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	returnedOld, newKey, err := manager.RotateAdminKey(ctx)
	if err != nil {
		t.Fatalf("RotateAdminKey failed: %v", err)
	}

	// Verify old key is returned correctly
	if len(returnedOld) != 32 {
		t.Errorf("Expected old key length 32, got %d", len(returnedOld))
	}
	for i := range returnedOld {
		if returnedOld[i] != oldKey[i] {
			t.Errorf("Old key mismatch at index %d", i)
		}
	}

	// Verify new key is generated and saved
	if len(newKey) != 32 {
		t.Errorf("Expected new key length 32, got %d", len(newKey))
	}

	if savedKey == nil {
		t.Error("SaveAdminKey was not called")
	}

	// Verify new key is different from old key
	same := true
	for i := range newKey {
		if newKey[i] != oldKey[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("New key should be different from old key")
	}
}

func TestAdminKeyManager_RotateAdminKey_GetError(t *testing.T) {
	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("get failed")
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	_, _, err := manager.RotateAdminKey(ctx)
	if err == nil {
		t.Error("Expected error when get fails")
	}

	if !strings.Contains(err.Error(), "failed to get current admin key") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestAdminKeyManager_RotateAdminKey_SaveError(t *testing.T) {
	oldKey := make([]byte, 32)

	provider := NewMockAdminKeyProvider()
	provider.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return oldKey, nil
	}
	provider.saveAdminKeyFunc = func(ctx context.Context, key []byte) error {
		return fmt.Errorf("save failed")
	}

	manager := NewAdminKeyManager(provider)
	ctx := context.Background()

	_, _, err := manager.RotateAdminKey(ctx)
	if err == nil {
		t.Error("Expected error when save fails")
	}

	if !strings.Contains(err.Error(), "failed to save new admin key") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// ===========================================================================================
// ENV ADMIN KEY PROVIDER TESTS
// ===========================================================================================

func TestNewEnvAdminKeyProvider(t *testing.T) {
	tests := []struct {
		name       string
		envVarName string
		expected   string
	}{
		{
			name:       "custom env var",
			envVarName: "CUSTOM_KEY",
			expected:   "CUSTOM_KEY",
		},
		{
			name:       "default env var",
			envVarName: "",
			expected:   "STRATIUM_ADMIN_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewEnvAdminKeyProvider(tt.envVarName)
			if provider.envVarName != tt.expected {
				t.Errorf("Expected envVarName %s, got %s", tt.expected, provider.envVarName)
			}
		})
	}
}

func TestEnvAdminKeyProvider_GetAdminKey(t *testing.T) {
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}
	encodedKey := base64.StdEncoding.EncodeToString(testKey)

	tests := []struct {
		name        string
		envVarName  string
		envValue    string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid key",
			envVarName:  "TEST_ADMIN_KEY",
			envValue:    encodedKey,
			expectError: false,
		},
		{
			name:        "missing env var",
			envVarName:  "MISSING_KEY",
			envValue:    "",
			expectError: true,
			errorMsg:    "admin key not found",
		},
		{
			name:        "invalid base64",
			envVarName:  "INVALID_KEY",
			envValue:    "not-valid-base64!@#",
			expectError: true,
			errorMsg:    "failed to decode admin key",
		},
		{
			name:        "invalid key length",
			envVarName:  "SHORT_KEY",
			envValue:    base64.StdEncoding.EncodeToString([]byte("short")),
			expectError: true,
			errorMsg:    "invalid admin key length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv(tt.envVarName, tt.envValue)
				defer os.Unsetenv(tt.envVarName)
			}

			provider := NewEnvAdminKeyProvider(tt.envVarName)
			ctx := context.Background()

			key, err := provider.GetAdminKey(ctx)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got none")
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(key) != 32 {
					t.Errorf("Expected key length 32, got %d", len(key))
				}
			}
		})
	}
}

func TestEnvAdminKeyProvider_SaveAdminKey(t *testing.T) {
	testKey := make([]byte, 32)
	provider := NewEnvAdminKeyProvider("TEST_KEY")
	ctx := context.Background()

	// SaveAdminKey should not return an error (it just prints)
	err := provider.SaveAdminKey(ctx, testKey)
	if err != nil {
		t.Errorf("SaveAdminKey returned error: %v", err)
	}
}

func TestEnvAdminKeyProvider_GetProviderType(t *testing.T) {
	provider := NewEnvAdminKeyProvider("")
	if provider.GetProviderType() != "env" {
		t.Errorf("Expected provider type 'env', got %s", provider.GetProviderType())
	}
}

// ===========================================================================================
// FILE ADMIN KEY PROVIDER TESTS
// ===========================================================================================

func TestNewFileAdminKeyProvider(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		expected string
	}{
		{
			name:     "custom path",
			filePath: "/custom/path",
			expected: "/custom/path",
		},
		{
			name:     "default path",
			filePath: "",
			expected: "/var/run/secrets/stratium/admin-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewFileAdminKeyProvider(tt.filePath)
			if provider.filePath != tt.expected {
				t.Errorf("Expected filePath %s, got %s", tt.expected, provider.filePath)
			}
		})
	}
}

func TestFileAdminKeyProvider_SaveAndGetAdminKey(t *testing.T) {
	// Create temporary directory
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "admin-key")

	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}

	provider := NewFileAdminKeyProvider(filePath)
	ctx := context.Background()

	// Save key
	err := provider.SaveAdminKey(ctx, testKey)
	if err != nil {
		t.Fatalf("SaveAdminKey failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		t.Error("Admin key file was not created")
	}

	// Get key
	retrievedKey, err := provider.GetAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetAdminKey failed: %v", err)
	}

	if len(retrievedKey) != 32 {
		t.Errorf("Expected key length 32, got %d", len(retrievedKey))
	}

	// Verify keys match
	for i := range testKey {
		if testKey[i] != retrievedKey[i] {
			t.Errorf("Key mismatch at index %d: expected %d, got %d", i, testKey[i], retrievedKey[i])
		}
	}
}

func TestFileAdminKeyProvider_SaveAdminKey_CreateDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "nested", "dir", "admin-key")

	testKey := make([]byte, 32)
	provider := NewFileAdminKeyProvider(filePath)
	ctx := context.Background()

	err := provider.SaveAdminKey(ctx, testKey)
	if err != nil {
		t.Fatalf("SaveAdminKey failed: %v", err)
	}

	// Verify nested directory was created
	if _, err := os.Stat(filepath.Dir(filePath)); os.IsNotExist(err) {
		t.Error("Nested directory was not created")
	}
}

func TestFileAdminKeyProvider_SaveAdminKey_RemoveExistingDirectory(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "admin-key")

	// Create a directory at the target path (legacy case)
	err := os.MkdirAll(filePath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	testKey := make([]byte, 32)
	provider := NewFileAdminKeyProvider(filePath)
	ctx := context.Background()

	// Should remove the directory and create a file
	err = provider.SaveAdminKey(ctx, testKey)
	if err != nil {
		t.Fatalf("SaveAdminKey failed: %v", err)
	}

	// Verify it's now a file, not a directory
	info, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("Failed to stat admin key path: %v", err)
	}
	if info.IsDir() {
		t.Error("Admin key path is still a directory")
	}
}

func TestFileAdminKeyProvider_GetAdminKey_FileNotFound(t *testing.T) {
	provider := NewFileAdminKeyProvider("/nonexistent/path")
	ctx := context.Background()

	_, err := provider.GetAdminKey(ctx)
	if err == nil {
		t.Error("Expected error for nonexistent file")
	}

	if !strings.Contains(err.Error(), "failed to read admin key file") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFileAdminKeyProvider_GetAdminKey_InvalidBase64(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "admin-key")

	// Write invalid base64
	err := os.WriteFile(filePath, []byte("invalid!@#"), 0600)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	provider := NewFileAdminKeyProvider(filePath)
	ctx := context.Background()

	_, err = provider.GetAdminKey(ctx)
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	if !strings.Contains(err.Error(), "failed to decode admin key") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFileAdminKeyProvider_GetAdminKey_InvalidLength(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "admin-key")

	// Write key with wrong length
	shortKey := []byte("short")
	encoded := base64.StdEncoding.EncodeToString(shortKey)
	err := os.WriteFile(filePath, []byte(encoded), 0600)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	provider := NewFileAdminKeyProvider(filePath)
	ctx := context.Background()

	_, err = provider.GetAdminKey(ctx)
	if err == nil {
		t.Error("Expected error for invalid key length")
	}

	if !strings.Contains(err.Error(), "invalid admin key length") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestFileAdminKeyProvider_GetProviderType(t *testing.T) {
	provider := NewFileAdminKeyProvider("")
	if provider.GetProviderType() != "file" {
		t.Errorf("Expected provider type 'file', got %s", provider.GetProviderType())
	}
}

// ===========================================================================================
// COMPOSITE ADMIN KEY PROVIDER TESTS
// ===========================================================================================

func TestNewCompositeAdminKeyProvider(t *testing.T) {
	provider1 := NewMockAdminKeyProvider()
	provider2 := NewMockAdminKeyProvider()

	composite := NewCompositeAdminKeyProvider(provider1, provider2)

	if len(composite.providers) != 2 {
		t.Errorf("Expected 2 providers, got %d", len(composite.providers))
	}
}

func TestCompositeAdminKeyProvider_GetAdminKey_FirstSucceeds(t *testing.T) {
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}

	provider1 := NewMockAdminKeyProvider()
	provider1.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return testKey, nil
	}

	provider2 := NewMockAdminKeyProvider()
	provider2Called := false
	provider2.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		provider2Called = true
		return nil, fmt.Errorf("should not be called")
	}

	composite := NewCompositeAdminKeyProvider(provider1, provider2)
	ctx := context.Background()

	key, err := composite.GetAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetAdminKey failed: %v", err)
	}

	if provider2Called {
		t.Error("Second provider should not have been called")
	}

	for i := range testKey {
		if key[i] != testKey[i] {
			t.Errorf("Key mismatch at index %d", i)
		}
	}
}

func TestCompositeAdminKeyProvider_GetAdminKey_FallbackToSecond(t *testing.T) {
	testKey := make([]byte, 32)
	for i := range testKey {
		testKey[i] = byte(i)
	}

	provider1 := NewMockAdminKeyProvider()
	provider1.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("provider 1 failed")
	}

	provider2 := NewMockAdminKeyProvider()
	provider2.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return testKey, nil
	}

	composite := NewCompositeAdminKeyProvider(provider1, provider2)
	ctx := context.Background()

	key, err := composite.GetAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetAdminKey failed: %v", err)
	}

	for i := range testKey {
		if key[i] != testKey[i] {
			t.Errorf("Key mismatch at index %d", i)
		}
	}
}

func TestCompositeAdminKeyProvider_GetAdminKey_AllFail(t *testing.T) {
	provider1 := NewMockAdminKeyProvider()
	provider1.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("provider 1 failed")
	}

	provider2 := NewMockAdminKeyProvider()
	provider2.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return nil, fmt.Errorf("provider 2 failed")
	}

	composite := NewCompositeAdminKeyProvider(provider1, provider2)
	ctx := context.Background()

	_, err := composite.GetAdminKey(ctx)
	if err == nil {
		t.Error("Expected error when all providers fail")
	}

	if !strings.Contains(err.Error(), "all providers failed") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestCompositeAdminKeyProvider_GetAdminKey_InvalidKeyLength(t *testing.T) {
	provider1 := NewMockAdminKeyProvider()
	provider1.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return make([]byte, 16), nil // Wrong length
	}

	testKey := make([]byte, 32)
	provider2 := NewMockAdminKeyProvider()
	provider2.getAdminKeyFunc = func(ctx context.Context) ([]byte, error) {
		return testKey, nil
	}

	composite := NewCompositeAdminKeyProvider(provider1, provider2)
	ctx := context.Background()

	key, err := composite.GetAdminKey(ctx)
	if err != nil {
		t.Fatalf("GetAdminKey failed: %v", err)
	}

	// Should use the second provider due to invalid length from first
	if len(key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key))
	}
}

func TestCompositeAdminKeyProvider_SaveAdminKey(t *testing.T) {
	var savedKey []byte

	provider1 := NewMockAdminKeyProvider()
	provider1.saveAdminKeyFunc = func(ctx context.Context, key []byte) error {
		savedKey = key
		return nil
	}

	provider2 := NewMockAdminKeyProvider()

	composite := NewCompositeAdminKeyProvider(provider1, provider2)
	ctx := context.Background()

	testKey := make([]byte, 32)
	err := composite.SaveAdminKey(ctx, testKey)
	if err != nil {
		t.Fatalf("SaveAdminKey failed: %v", err)
	}

	if savedKey == nil {
		t.Error("Key was not saved to first provider")
	}
}

func TestCompositeAdminKeyProvider_SaveAdminKey_NoProviders(t *testing.T) {
	composite := NewCompositeAdminKeyProvider()
	ctx := context.Background()

	err := composite.SaveAdminKey(ctx, make([]byte, 32))
	if err == nil {
		t.Error("Expected error when no providers available")
	}

	if !strings.Contains(err.Error(), "no providers available") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestCompositeAdminKeyProvider_GetProviderType(t *testing.T) {
	provider1 := NewMockAdminKeyProvider()
	provider1.providerType = "type1"

	provider2 := NewMockAdminKeyProvider()
	provider2.providerType = "type2"

	composite := NewCompositeAdminKeyProvider(provider1, provider2)

	expected := "composite(type1,type2)"
	if composite.GetProviderType() != expected {
		t.Errorf("Expected provider type %s, got %s", expected, composite.GetProviderType())
	}
}

// ===========================================================================================
// CREATE ADMIN KEY PROVIDER TESTS
// ===========================================================================================

func TestCreateAdminKeyProvider_Env(t *testing.T) {
	provider, err := CreateAdminKeyProvider("env", "CUSTOM_KEY")
	if err != nil {
		t.Fatalf("CreateAdminKeyProvider failed: %v", err)
	}

	envProvider, ok := provider.(*EnvAdminKeyProvider)
	if !ok {
		t.Error("Expected EnvAdminKeyProvider")
	}

	if envProvider.envVarName != "CUSTOM_KEY" {
		t.Errorf("Expected envVarName CUSTOM_KEY, got %s", envProvider.envVarName)
	}
}

func TestCreateAdminKeyProvider_File(t *testing.T) {
	provider, err := CreateAdminKeyProvider("file", "/custom/path")
	if err != nil {
		t.Fatalf("CreateAdminKeyProvider failed: %v", err)
	}

	fileProvider, ok := provider.(*FileAdminKeyProvider)
	if !ok {
		t.Error("Expected FileAdminKeyProvider")
	}

	if fileProvider.filePath != "/custom/path" {
		t.Errorf("Expected filePath /custom/path, got %s", fileProvider.filePath)
	}
}

func TestCreateAdminKeyProvider_Composite(t *testing.T) {
	provider, err := CreateAdminKeyProvider("composite", "/custom/path")
	if err != nil {
		t.Fatalf("CreateAdminKeyProvider failed: %v", err)
	}

	compositeProvider, ok := provider.(*CompositeAdminKeyProvider)
	if !ok {
		t.Error("Expected CompositeAdminKeyProvider")
	}

	if len(compositeProvider.providers) != 2 {
		t.Errorf("Expected 2 providers in composite, got %d", len(compositeProvider.providers))
	}
}

func TestCreateAdminKeyProvider_CaseInsensitive(t *testing.T) {
	tests := []string{"ENV", "Env", "env", "FILE", "File", "file"}

	for _, providerType := range tests {
		_, err := CreateAdminKeyProvider(providerType, "")
		if err != nil {
			t.Errorf("CreateAdminKeyProvider failed for type %s: %v", providerType, err)
		}
	}
}

func TestCreateAdminKeyProvider_Unsupported(t *testing.T) {
	_, err := CreateAdminKeyProvider("unsupported", "")
	if err == nil {
		t.Error("Expected error for unsupported provider type")
	}

	if !strings.Contains(err.Error(), "unsupported admin key provider type") {
		t.Errorf("Unexpected error message: %v", err)
	}
}
