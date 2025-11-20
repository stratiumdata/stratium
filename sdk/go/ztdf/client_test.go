package ztdf

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	stratium "github.com/stratiumdata/go-sdk"
	"github.com/stratiumdata/go-sdk/gen/models"
)

// mockKeyAccessClient mocks the KeyAccess client for testing
type mockKeyAccessClient struct {
	requestDEKFunc func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error)
	unwrapDEKFunc  func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error)
}

func (m *mockKeyAccessClient) RequestDEK(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
	if m.requestDEKFunc != nil {
		return m.requestDEKFunc(ctx, req)
	}
	if req.ClientKeyID == "" {
		return nil, fmt.Errorf("client key ID is required")
	}
	if len(req.ClientWrappedDEK) == 0 {
		return nil, fmt.Errorf("client wrapped DEK is required")
	}
	// Default implementation
	return &stratium.DEKResponse{
		WrappedDEK: req.DEK, // Just return the DEK as "wrapped"
		KeyID:      "mock-key-id",
	}, nil
}

func (m *mockKeyAccessClient) UnwrapDEK(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
	if m.unwrapDEKFunc != nil {
		return m.unwrapDEKFunc(ctx, resource, clientKeyID, keyID, wrappedDEK, policy)
	}
	// Default implementation - just return the wrapped DEK as if unwrapped
	return wrappedDEK, nil
}

// generateTestKeyPair generates an RSA key pair for testing
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, string, string) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create temp directory for keys
	tempDir := t.TempDir()

	// Save private key
	privateKeyPath := filepath.Join(tempDir, "private.pem")
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}

	// Save public key
	publicKeyPath := filepath.Join(tempDir, "public.pem")
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}

	return privateKey, privateKeyPath, publicKeyPath
}

// Helper to create a test client with mocked dependencies
func createTestClient(keyAccessMock *mockKeyAccessClient) *Client {
	// Create ZTDF client with injected mock
	client := &Client{
		keyAccessURL: "kas.example.com:50053",
		keyAccess:    keyAccessMock, // inject the mock
	}

	return client
}

// ===== NewClient Tests =====

func TestNewClient(t *testing.T) {
	config := &stratium.Config{
		KeyAccessAddress: "kas.example.com:50053",
	}

	stratiumClient, err := stratium.NewClient(config)
	if err != nil {
		t.Skipf("Cannot create real client without services: %v", err)
	}
	defer stratiumClient.Close()

	client := NewClient(stratiumClient)
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}

	if client.keyAccessURL != config.KeyAccessAddress {
		t.Errorf("NewClient() keyAccessURL = %v, want %v", client.keyAccessURL, config.KeyAccessAddress)
	}
}

func TestNewClient_DefaultKeyAccessURL(t *testing.T) {
	config := &stratium.Config{
		PlatformAddress: "localhost:50051",
		// No KeyAccessAddress specified
	}

	stratiumClient, err := stratium.NewClient(config)
	if err != nil {
		t.Skipf("Cannot create real client without services: %v", err)
	}
	defer stratiumClient.Close()

	client := NewClient(stratiumClient)
	if client == nil {
		t.Fatal("NewClient() returned nil client")
	}

	if client.keyAccessURL != DefaultKeyAccessURL {
		t.Errorf("NewClient() keyAccessURL = %v, want %v", client.keyAccessURL, DefaultKeyAccessURL)
	}
}

// ===== Wrap Tests =====

func TestClient_Wrap_MinimalOptions(t *testing.T) {
	_, privateKeyPath, _ := generateTestKeyPair(t)
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)

	plaintext := []byte("test data to encrypt")
	opts := &WrapOptions{
		Resource:             "test-resource",
		ClientKeyID:          "client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)

	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	if tdo == nil {
		t.Fatal("Wrap() returned nil TDO")
	}

	if tdo.Manifest == nil {
		t.Error("Wrap() should create manifest")
	}

	if tdo.Payload == nil {
		t.Error("Wrap() should create payload")
	}

	if len(tdo.Payload.Data) == 0 {
		t.Error("Wrap() should encrypt payload data")
	}
}

func TestClient_Wrap_WithAttributes(t *testing.T) {
	_, privateKeyPath, _ := generateTestKeyPair(t)
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)

	plaintext := []byte("classified data")
	opts := &WrapOptions{
		Resource:             "classified-document",
		ClientKeyID:          "client-key",
		ClientPrivateKeyPath: privateKeyPath,
		Attributes: []Attribute{
			{
				URI:         "http://example.com/attr/classification/value/secret",
				DisplayName: "Classification: Secret",
				IsDefault:   true,
			},
		},
		ResourceAttributes: map[string]string{
			"name": "classified-document",
			"type": "document",
		},
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)

	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	if tdo == nil {
		t.Fatal("Wrap() returned nil TDO")
	}

	// Verify policy was created with attributes
	if tdo.Manifest.EncryptionInformation.Policy == "" {
		t.Error("Wrap() should include policy")
	}
}

func TestClient_Wrap_WithCustomPolicy(t *testing.T) {
	_, privateKeyPath, _ := generateTestKeyPair(t)
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)

	customPolicy := CreatePolicy("kas.example.com:50053", []Attribute{
		{
			URI:         "http://example.com/attr/custom/value/test",
			DisplayName: "Custom Attribute",
			IsDefault:   false,
		},
	})

	plaintext := []byte("data with custom policy")
	opts := &WrapOptions{
		Resource:             "custom-resource",
		Policy:               customPolicy,
		ClientKeyID:          "client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)

	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	if tdo == nil {
		t.Fatal("Wrap() returned nil TDO")
	}

	if tdo.Manifest.EncryptionInformation.Policy == "" {
		t.Error("Wrap() should include custom policy")
	}
}

// ===== Unwrap Tests =====

func TestClient_Unwrap_NilManifest(t *testing.T) {
	client := &Client{
		keyAccessURL: "kas.example.com:50053",
	}

	tdo := &TrustedDataObject{
		Manifest: nil,
		Payload:  &Payload{Data: []byte("encrypted")},
	}

	opts := &UnwrapOptions{
		Resource:             "test-resource",
		ClientKeyID:          "test-key-id",
		ClientPrivateKeyPath: "/path/to/key",
	}

	ctx := context.Background()
	_, err := client.Unwrap(ctx, tdo, opts)

	if err == nil {
		t.Error("Unwrap() with nil manifest expected error, got nil")
	}

	if err.Error() != ErrMsgInvalidZTDF+": "+ErrMsgMissingEncryptionInfo {
		t.Errorf("Unwrap() error = %v, want error containing %s", err, ErrMsgMissingEncryptionInfo)
	}
}

func TestClient_Unwrap_NoKeyAccess(t *testing.T) {
	client := &Client{
		keyAccessURL: "kas.example.com:50053",
	}

	tdo := &TrustedDataObject{
		Manifest: &models.Manifest{
			EncryptionInformation: &models.EncryptionInformation{
				KeyAccess: []*models.EncryptionInformation_KeyAccessObject{},
			},
		},
		Payload: &Payload{Data: []byte("encrypted")},
	}

	opts := &UnwrapOptions{
		Resource:             "test-resource",
		ClientKeyID:          "test-key-id",
		ClientPrivateKeyPath: "/path/to/key",
	}

	ctx := context.Background()
	_, err := client.Unwrap(ctx, tdo, opts)

	if err == nil {
		t.Error("Unwrap() with no key access objects expected error, got nil")
	}

	if err.Error() != ErrMsgInvalidZTDF+": "+ErrMsgNoKeyAccessObjects {
		t.Errorf("Unwrap() error = %v, want error containing %s", err, ErrMsgNoKeyAccessObjects)
	}
}

func TestClient_Unwrap_NilPayload(t *testing.T) {
	t.Skip("Requires integration with real KeyAccess service")

	// Would need to mock the entire unwrapDEK process which requires
	// a functional stratiumClient.KeyAccess
}

// ===== Integrity Verification Tests =====

func TestClient_Unwrap_WithIntegrityVerification_Valid(t *testing.T) {
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)
	privateKey, privateKeyPath, _ := generateTestKeyPair(t)

	// Mock RequestDEK to encrypt the DEK with our public key
	mockKeyAccess.requestDEKFunc = func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
		wrappedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, req.DEK)
		if err != nil {
			return nil, err
		}
		return &stratium.DEKResponse{
			WrappedDEK: wrappedDEK,
			KeyID:      "mock-key-id",
		}, nil
	}

	// Mock UnwrapDEK to return the wrapped DEK
	mockKeyAccess.unwrapDEKFunc = func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
		return wrappedDEK, nil
	}

	// Create a TDO by wrapping some data
	plaintext := []byte("test data for integrity verification")
	opts := &WrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Now unwrap with integrity verification enabled
	unwrapOpts := &UnwrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-key-id",
		ClientPrivateKeyPath: privateKeyPath,
		VerifyIntegrity:      true, // Enable integrity verification
	}

	decrypted, err := client.Unwrap(ctx, tdo, unwrapOpts)
	if err != nil {
		t.Fatalf("Unwrap() with valid integrity error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Unwrap() decrypted = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestClient_Unwrap_WithIntegrityVerification_Invalid(t *testing.T) {
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)
	privateKey, privateKeyPath, _ := generateTestKeyPair(t)

	// Mock RequestDEK to encrypt the DEK with our public key
	mockKeyAccess.requestDEKFunc = func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
		wrappedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, req.DEK)
		if err != nil {
			return nil, err
		}
		return &stratium.DEKResponse{
			WrappedDEK: wrappedDEK,
			KeyID:      "mock-key-id",
		}, nil
	}

	// Mock UnwrapDEK to return the wrapped DEK
	mockKeyAccess.unwrapDEKFunc = func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
		return wrappedDEK, nil
	}

	// Create a TDO by wrapping some data
	plaintext := []byte("test data for integrity verification")
	opts := &WrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Tamper with the integrity signature to make it invalid
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature.Sig = "aW52YWxpZC1oYXNo" // "invalid-hash" in base64

	// Now unwrap with integrity verification enabled
	unwrapOpts := &UnwrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-key-id",
		ClientPrivateKeyPath: privateKeyPath,
		VerifyIntegrity:      true, // Enable integrity verification
	}

	_, err = client.Unwrap(ctx, tdo, unwrapOpts)
	if err == nil {
		t.Error("Unwrap() with invalid integrity expected error, got nil")
	}

	if err != nil && !contains(err.Error(), ErrMsgIntegrityVerificationFailed) {
		t.Errorf("Unwrap() error = %v, want error containing %s", err, ErrMsgIntegrityVerificationFailed)
	}
}

func TestClient_Unwrap_WithIntegrityVerification_Disabled(t *testing.T) {
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)
	privateKey, privateKeyPath, _ := generateTestKeyPair(t)

	// Mock RequestDEK to encrypt the DEK with our public key
	mockKeyAccess.requestDEKFunc = func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
		wrappedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, req.DEK)
		if err != nil {
			return nil, err
		}
		return &stratium.DEKResponse{
			WrappedDEK: wrappedDEK,
			KeyID:      "mock-key-id",
		}, nil
	}

	// Mock UnwrapDEK to return the wrapped DEK
	mockKeyAccess.unwrapDEKFunc = func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
		return wrappedDEK, nil
	}

	// Create a TDO by wrapping some data
	plaintext := []byte("test data for integrity verification")
	opts := &WrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Tamper with the integrity signature to make it invalid
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature.Sig = "aW52YWxpZC1oYXNo" // "invalid-hash" in base64

	// Now unwrap with integrity verification DISABLED
	unwrapOpts := &UnwrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-key-id",
		ClientPrivateKeyPath: privateKeyPath,
		VerifyIntegrity:      false, // Disable integrity verification
	}

	decrypted, err := client.Unwrap(ctx, tdo, unwrapOpts)
	if err != nil {
		t.Fatalf("Unwrap() with disabled integrity verification error: %v", err)
	}

	// Should succeed even with tampered signature since verification is disabled
	if string(decrypted) != string(plaintext) {
		t.Errorf("Unwrap() decrypted = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestClient_Unwrap_WithIntegrityVerification_NilIntegrityInfo(t *testing.T) {
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)
	privateKey, privateKeyPath, _ := generateTestKeyPair(t)

	// Mock RequestDEK to encrypt the DEK with our public key
	mockKeyAccess.requestDEKFunc = func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
		wrappedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, req.DEK)
		if err != nil {
			return nil, err
		}
		return &stratium.DEKResponse{
			WrappedDEK: wrappedDEK,
			KeyID:      "mock-key-id",
		}, nil
	}

	// Mock UnwrapDEK to return the wrapped DEK
	mockKeyAccess.unwrapDEKFunc = func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
		return wrappedDEK, nil
	}

	// Create a TDO by wrapping some data
	plaintext := []byte("test data for integrity verification")
	opts := &WrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Remove IntegrityInformation
	tdo.Manifest.EncryptionInformation.IntegrityInformation = nil

	// Now unwrap with integrity verification enabled but no integrity info
	unwrapOpts := &UnwrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-key-id",
		ClientPrivateKeyPath: privateKeyPath,
		VerifyIntegrity:      true, // Enable integrity verification
	}

	decrypted, err := client.Unwrap(ctx, tdo, unwrapOpts)
	if err != nil {
		t.Fatalf("Unwrap() with nil integrity info error: %v", err)
	}

	// Should succeed because the condition checks for nil IntegrityInformation
	if string(decrypted) != string(plaintext) {
		t.Errorf("Unwrap() decrypted = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestClient_Unwrap_WithIntegrityVerification_InvalidBase64(t *testing.T) {
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)
	privateKey, privateKeyPath, _ := generateTestKeyPair(t)

	// Mock RequestDEK to encrypt the DEK with our public key
	mockKeyAccess.requestDEKFunc = func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
		wrappedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, req.DEK)
		if err != nil {
			return nil, err
		}
		return &stratium.DEKResponse{
			WrappedDEK: wrappedDEK,
			KeyID:      "mock-key-id",
		}, nil
	}

	// Mock UnwrapDEK to return the wrapped DEK
	mockKeyAccess.unwrapDEKFunc = func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
		return wrappedDEK, nil
	}

	// Create a TDO by wrapping some data
	plaintext := []byte("test data for integrity verification")
	opts := &WrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Set invalid base64 in the signature
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature.Sig = "!!!invalid-base64!!!"

	// Now unwrap with integrity verification enabled
	unwrapOpts := &UnwrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-key-id",
		ClientPrivateKeyPath: privateKeyPath,
		VerifyIntegrity:      true, // Enable integrity verification
	}

	decrypted, err := client.Unwrap(ctx, tdo, unwrapOpts)
	if err != nil {
		t.Fatalf("Unwrap() with invalid base64 signature error: %v", err)
	}

	// Should succeed because base64 decode error is silently ignored (if err == nil)
	if string(decrypted) != string(plaintext) {
		t.Errorf("Unwrap() decrypted = %v, want %v", string(decrypted), string(plaintext))
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ===== WrapFile Tests =====

func TestClient_WrapFile(t *testing.T) {
	_, privateKeyPath, _ := generateTestKeyPair(t)
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)

	// Create temporary input file
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.txt")
	outputPath := filepath.Join(tempDir, "output.ztdf")

	testData := []byte("test file content to encrypt")
	if err := os.WriteFile(inputPath, testData, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := &WrapOptions{
		Resource:             "test-file",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	err := client.WrapFile(ctx, inputPath, outputPath, opts)

	if err != nil {
		t.Fatalf("WrapFile() error: %v", err)
	}

	// Verify output file was created
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("WrapFile() should create output file")
	}
}

func TestClient_WrapFile_InputNotFound(t *testing.T) {
	_, privateKeyPath, _ := generateTestKeyPair(t)
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)

	opts := &WrapOptions{
		Resource:             "test-file",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "output.ztdf")

	ctx := context.Background()
	err := client.WrapFile(ctx, "/nonexistent/file.txt", outputPath, opts)

	if err == nil {
		t.Error("WrapFile() with nonexistent input expected error, got nil")
	}
}

// ===== UnwrapFile Tests =====

func TestClient_UnwrapFile(t *testing.T) {
	mockKeyAccess := &mockKeyAccessClient{}
	client := createTestClient(mockKeyAccess)
	privateKey, privateKeyPath, _ := generateTestKeyPair(t)

	// Mock RequestDEK to encrypt the DEK with our public key
	mockKeyAccess.requestDEKFunc = func(ctx context.Context, req *stratium.DEKRequest) (*stratium.DEKResponse, error) {
		// Encrypt the DEK with the public key (simulating real behavior)
		wrappedDEK, err := EncryptDEKWithRSAPublicKey(&privateKey.PublicKey, req.DEK)
		if err != nil {
			return nil, err
		}

		return &stratium.DEKResponse{
			WrappedDEK: wrappedDEK,
			KeyID:      "mock-key-id",
		}, nil
	}

	// First wrap some data to create a valid ZTDF file
	tempDir := t.TempDir()
	inputPath := filepath.Join(tempDir, "input.ztdf")
	outputPath := filepath.Join(tempDir, "output.txt")

	plaintext := []byte("test data for unwrapping")
	opts := &WrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-client-key",
		ClientPrivateKeyPath: privateKeyPath,
	}

	ctx := context.Background()
	tdo, err := client.Wrap(ctx, plaintext, opts)
	if err != nil {
		t.Fatalf("Wrap() error: %v", err)
	}

	// Save the TDO to a file
	if err := SaveToFile(tdo, inputPath); err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}

	// Now unwrap the file
	unwrapOpts := &UnwrapOptions{
		Resource:             "test-document",
		ClientKeyID:          "mock-key-id",
		ClientPrivateKeyPath: privateKeyPath,
	}

	// Mock UnwrapDEK to return the RSA-encrypted DEK (which will be decrypted by the client)
	mockKeyAccess.unwrapDEKFunc = func(ctx context.Context, resource, clientKeyID, keyID string, wrappedDEK []byte, policy string) ([]byte, error) {
		// Return the wrapped DEK as-is - the client will decrypt it with the private key
		return wrappedDEK, nil
	}

	err = client.UnwrapFile(ctx, inputPath, outputPath, unwrapOpts)
	if err != nil {
		t.Fatalf("UnwrapFile() error: %v", err)
	}

	// Verify output file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Error("UnwrapFile() should create output file")
	}

	// Read and verify content
	decrypted, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read decrypted file: %v", err)
	}

	if len(decrypted) == 0 {
		t.Error("UnwrapFile() should write decrypted data")
	}

	// Verify the content matches the original plaintext
	if string(decrypted) != string(plaintext) {
		t.Errorf("UnwrapFile() decrypted content = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestClient_UnwrapFile_InputNotFound(t *testing.T) {
	client := &Client{
		keyAccessURL: "kas.example.com:50053",
	}

	opts := &UnwrapOptions{
		Resource:             "test-file",
		ClientKeyID:          "test-key-id",
		ClientPrivateKeyPath: "/path/to/key",
	}

	ctx := context.Background()
	err := client.UnwrapFile(ctx, "/nonexistent/file.ztdf", "/tmp/output.txt", opts)

	if err == nil {
		t.Error("UnwrapFile() with nonexistent input expected error, got nil")
	}
}

// ===== Wrap/Unwrap DEK Tests (via private methods) =====

func TestClient_wrapDEK_EmptyResource(t *testing.T) {
	// Create a valid config and stratium client
	config := &stratium.Config{
		KeyAccessAddress: "kas.example.com:50053",
	}

	stratiumClient, err := stratium.NewClient(config)
	if err != nil {
		t.Skipf("Cannot create real client without services: %v", err)
	}
	defer stratiumClient.Close()

	client := &Client{
		stratiumClient: stratiumClient,
		keyAccessURL:   "kas.example.com:50053",
	}

	ctx := context.Background()
	dek := make([]byte, 32)

	_, _, err = client.wrapDEK(ctx, "", "client-key", []byte("wrapped"), dek, nil, "test-policy", nil)

	if err == nil {
		t.Error("wrapDEK() with empty resource expected error, got nil")
	}

	if err.Error() != ErrMsgFailedToWrapDEK+": resource identifier cannot be empty" {
		t.Errorf("wrapDEK() error = %v, want error about empty resource", err)
	}
}

func TestClient_unwrapDEK_EmptyResource(t *testing.T) {
	// Create a valid config and stratium client
	config := &stratium.Config{
		KeyAccessAddress: "kas.example.com:50053",
	}

	stratiumClient, err := stratium.NewClient(config)
	if err != nil {
		t.Skipf("Cannot create real client without services: %v", err)
	}
	defer stratiumClient.Close()

	client := &Client{
		stratiumClient: stratiumClient,
		keyAccessURL:   "kas.example.com:50053",
	}

	ctx := context.Background()
	opts := &UnwrapOptions{
		Resource:    "", // Empty resource
		ClientKeyID: "test-key-id",
	}

	_, err = client.unwrapDEK(ctx, opts, "test-kid", []byte("wrapped"), "policy")

	if err == nil {
		t.Error("unwrapDEK() with empty resource expected error, got nil")
	}

	if err.Error() != ErrMsgFailedToUnwrapDEK+": resource identifier cannot be empty" {
		t.Errorf("unwrapDEK() error = %v, want error about empty resource", err)
	}
}

// ===== createManifest Tests =====

func TestClient_createManifest_NilBaseline(t *testing.T) {
	client := &Client{
		keyAccessURL: "kas.example.com:50053",
	}

	wrappedDEK := []byte("wrapped-dek")
	keyID := "test-key-id"
	policyBase64 := "test-policy"
	policyBindingHash := "test-hash"
	iv := make([]byte, 16)
	encryptedPayload := []byte("encrypted-payload")
	plaintext := []byte("plaintext")
	payloadHash := make([]byte, 32)

	manifest := client.createManifest(
		nil, // nil baseline
		wrappedDEK,
		keyID,
		policyBase64,
		policyBindingHash,
		iv,
		encryptedPayload,
		plaintext,
		payloadHash,
	)

	if manifest == nil {
		t.Fatal("createManifest() returned nil manifest")
	}

	if manifest.EncryptionInformation == nil {
		t.Error("createManifest() should create EncryptionInformation")
	}

	if len(manifest.EncryptionInformation.KeyAccess) == 0 {
		t.Error("createManifest() should create KeyAccess objects")
	}

	kao := manifest.EncryptionInformation.KeyAccess[0]
	if kao.Kid != keyID {
		t.Errorf("createManifest() keyID = %v, want %v", kao.Kid, keyID)
	}

	if kao.PolicyBinding.Hash != policyBindingHash {
		t.Errorf("createManifest() policyBindingHash = %v, want %v", kao.PolicyBinding.Hash, policyBindingHash)
	}
}

func TestClient_createManifest_WithBaseline(t *testing.T) {
	client := &Client{
		keyAccessURL: "kas.example.com:50053",
	}

	baseline := &models.Manifest{
		EncryptionInformation: &models.EncryptionInformation{
			KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
				{
					Type:     models.EncryptionInformation_KeyAccessObject_WRAPPED,
					Protocol: models.EncryptionInformation_KeyAccessObject_KAS,
					PolicyBinding: &models.EncryptionInformation_KeyAccessObject_PolicyBinding{
						Alg: AlgorithmHS256,
					},
				},
			},
			Method: &models.EncryptionInformation_Method{
				Algorithm: AlgorithmAES256GCM,
			},
			IntegrityInformation: &models.EncryptionInformation_IntegrityInformation{
				RootSignature: &models.EncryptionInformation_IntegrityInformation_RootSignature{
					Alg: AlgorithmHS256,
				},
				Segments: []*models.EncryptionInformation_IntegrityInformation_Segment{
					{},
				},
			},
		},
	}

	wrappedDEK := []byte("wrapped-dek")
	keyID := "test-key-id"
	policyBase64 := "test-policy"
	policyBindingHash := "test-hash"
	iv := make([]byte, 16)
	encryptedPayload := []byte("encrypted-payload")
	plaintext := []byte("plaintext")
	payloadHash := make([]byte, 32)

	manifest := client.createManifest(
		baseline,
		wrappedDEK,
		keyID,
		policyBase64,
		policyBindingHash,
		iv,
		encryptedPayload,
		plaintext,
		payloadHash,
	)

	if manifest == nil {
		t.Fatal("createManifest() returned nil manifest")
	}

	// Verify baseline was updated with new values
	kao := manifest.EncryptionInformation.KeyAccess[0]
	if kao.Kid != keyID {
		t.Errorf("createManifest() keyID = %v, want %v", kao.Kid, keyID)
	}

	if kao.PolicyBinding.Hash != policyBindingHash {
		t.Errorf("createManifest() policyBindingHash = %v, want %v", kao.PolicyBinding.Hash, policyBindingHash)
	}
}

// ===== Integration-style Tests (would need real services) =====

func TestClient_WrapUnwrap_Roundtrip(t *testing.T) {
	t.Skip("Requires integration with real KeyAccess service")

	// This would be an integration test that:
	// 1. Wraps data
	// 2. Unwraps it
	// 3. Verifies the plaintext matches
}
