package key_manager

import (
	"context"
	"fmt"
	"testing"

	"stratium/pkg/security/encryption"
)

func TestServer_CreateKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	tests := []struct {
		name            string
		request         *CreateKeyRequest
		expectError     bool
		expectedKeyType KeyType
	}{
		{
			name: "Create RSA software key",
			request: &CreateKeyRequest{
				Name:         "test-rsa-key",
				KeyType:      KeyType_KEY_TYPE_RSA_2048,
				ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
				Metadata: map[string]string{
					"environment": "test",
				},
			},
			expectError:     false,
			expectedKeyType: KeyType_KEY_TYPE_RSA_2048,
		},
		{
			name: "Create ECC software key",
			request: &CreateKeyRequest{
				Name:                 "test-ecc-key",
				KeyType:              KeyType_KEY_TYPE_ECC_P256,
				ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
				RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
				RotationIntervalDays: 30,
			},
			expectError:     false,
			expectedKeyType: KeyType_KEY_TYPE_ECC_P256,
		},
		{
			name: "Create key without name should fail",
			request: &CreateKeyRequest{
				KeyType:      KeyType_KEY_TYPE_RSA_2048,
				ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
			},
			expectError: true,
		},
		{
			name: "Create key without key type should fail",
			request: &CreateKeyRequest{
				Name:         "test-key",
				ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.CreateKey(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Key.KeyType != tt.expectedKeyType {
				t.Errorf("Expected key type %v, got %v", tt.expectedKeyType, response.Key.KeyType)
			}

			if response.Key.Name != tt.request.Name {
				t.Errorf("Expected key name %s, got %s", tt.request.Name, response.Key.Name)
			}

			if response.Key.Status != KeyStatus_KEY_STATUS_ACTIVE {
				t.Errorf("Expected key status ACTIVE, got %v", response.Key.Status)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}
		})
	}
}

func TestServer_GetKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// First create a key
	createReq := &CreateKeyRequest{
		Name:         "test-get-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	}

	createResp, err := server.CreateKey(context.Background(), createReq)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	keyID := createResp.Key.KeyId

	tests := []struct {
		name            string
		request         *GetKeyRequest
		expectError     bool
		expectPublicKey bool
	}{
		{
			name: "Get key with public key",
			request: &GetKeyRequest{
				KeyId:            keyID,
				IncludePublicKey: true,
			},
			expectError:     false,
			expectPublicKey: true,
		},
		{
			name: "Get key without public key",
			request: &GetKeyRequest{
				KeyId:            keyID,
				IncludePublicKey: false,
			},
			expectError:     false,
			expectPublicKey: false,
		},
		{
			name: "Get non-existent key should fail",
			request: &GetKeyRequest{
				KeyId: "non-existent-key",
			},
			expectError: true,
		},
		{
			name: "Get key without ID should fail",
			request: &GetKeyRequest{
				IncludePublicKey: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.GetKey(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Key.KeyId != keyID {
				t.Errorf("Expected key ID %s, got %s", keyID, response.Key.KeyId)
			}

			if tt.expectPublicKey && response.Key.PublicKeyPem == "" {
				t.Error("Expected public key to be included")
			}

			if !tt.expectPublicKey && response.Key.PublicKeyPem != "" {
				t.Error("Expected public key to be excluded")
			}
		})
	}
}

func TestServer_ListKeys(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create multiple test keys
	testKeys := []struct {
		name     string
		keyType  KeyType
		subjects []string
	}{
		{
			name:     "user-key-1",
			keyType:  KeyType_KEY_TYPE_RSA_2048,
			subjects: []string{"user123"},
		},
		{
			name:     "user-key-2",
			keyType:  KeyType_KEY_TYPE_ECC_P256,
			subjects: []string{"user456"},
		},
		{
			name:     "service-key",
			keyType:  KeyType_KEY_TYPE_RSA_4096,
			subjects: []string{"service-account"},
		},
	}

	for _, tk := range testKeys {
		req := &CreateKeyRequest{
			Name:               tk.name,
			KeyType:            tk.keyType,
			ProviderType:       KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
			AuthorizedSubjects: tk.subjects,
		}

		_, err := server.CreateKey(context.Background(), req)
		if err != nil {
			t.Fatalf("Failed to create test key %s: %v", tk.name, err)
		}
	}

	tests := []struct {
		name           string
		request        *ListKeysRequest
		expectMinCount int
	}{
		{
			name:           "List all keys",
			request:        &ListKeysRequest{},
			expectMinCount: len(testKeys),
		},
		{
			name: "List keys with subject filter",
			request: &ListKeysRequest{
				SubjectFilter: "user123",
			},
			expectMinCount: 1,
		},
		{
			name: "List keys with pagination",
			request: &ListKeysRequest{
				PageSize: 2,
			},
			expectMinCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.ListKeys(context.Background(), tt.request)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(response.Keys) < tt.expectMinCount {
				t.Errorf("Expected at least %d keys, got %d", tt.expectMinCount, len(response.Keys))
			}

			if response.TotalCount < int64(tt.expectMinCount) {
				t.Errorf("Expected total count at least %d, got %d", tt.expectMinCount, response.TotalCount)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}
		})
	}
}

func TestServer_UnwrapDEK(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a test key for DEK unwrapping
	createReq := &CreateKeyRequest{
		Name:                "dek-test-key",
		KeyType:             KeyType_KEY_TYPE_RSA_2048,
		ProviderType:        KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		AuthorizedSubjects:  []string{"user123", "admin456"},
		AuthorizedResources: []string{"test-resource"},
	}

	createResp, err := server.CreateKey(context.Background(), createReq)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	keyID := createResp.Key.KeyId

	// Create a properly encrypted DEK for testing
	// First, get the provider to encrypt a mock DEK with the service key
	provider, err := server.providerFactory.GetProvider(KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE)
	if err != nil {
		t.Fatalf("Failed to get provider: %v", err)
	}

	// Mock DEK data to encrypt
	mockDEK := []byte("mock-dek-32-bytes-for-testing-12")

	// Encrypt the mock DEK with the service key
	mockEncryptedDEK, err := provider.Encrypt(context.Background(), keyID, mockDEK)
	if err != nil {
		t.Fatalf("Failed to encrypt mock DEK: %v", err)
	}

	tests := []struct {
		name         string
		request      *UnwrapDEKRequest
		expectAccess bool
	}{
		{
			name: "Valid unwrap request should be denied (SubjectKeyStore not configured)",
			request: &UnwrapDEKRequest{
				Subject:      "admin456",
				Resource:     "test-resource",
				EncryptedDek: mockEncryptedDEK,
				KeyId:        keyID,
				Action:       "unwrap_dek",
				Context: map[string]string{
					"role": "admin",
				},
			},
			expectAccess: false, // SubjectKeyStore is nil, so unwrapping will fail
		},
		{
			name: "Another unwrap request should be denied (SubjectKeyStore not configured)",
			request: &UnwrapDEKRequest{
				Subject:      "user123",
				Resource:     "test-resource",
				EncryptedDek: mockEncryptedDEK,
				KeyId:        keyID,
				Action:       "unwrap_dek",
				Context: map[string]string{
					"department": "engineering",
				},
			},
			expectAccess: false, // SubjectKeyStore is nil, so unwrapping will fail
		},
		{
			name: "Request without subject should be denied",
			request: &UnwrapDEKRequest{
				Resource:     "test-resource",
				EncryptedDek: mockEncryptedDEK,
				KeyId:        keyID,
				Action:       "unwrap_dek",
			},
			expectAccess: false,
		},
		{
			name: "Request with non-existent key should be denied",
			request: &UnwrapDEKRequest{
				Subject:      "user123",
				Resource:     "test-resource",
				EncryptedDek: mockEncryptedDEK,
				KeyId:        "non-existent-key",
				Action:       "unwrap_dek",
			},
			expectAccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.UnwrapDEK(context.Background(), tt.request)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.AccessGranted != tt.expectAccess {
				t.Errorf("Expected access granted %t, got %t", tt.expectAccess, response.AccessGranted)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			// Additional checks for successful access
			if tt.expectAccess && response.AccessGranted {
				if len(response.EncryptedDekForSubject) == 0 {
					t.Error("Expected encrypted DEK for subject to be returned")
				}

				if response.SubjectKeyId == "" {
					t.Error("Expected subject key ID to be returned")
				}

				// Note: AppliedRules will be empty since ABAC is performed by Key Access Service
				if response.AccessReason == "" {
					t.Error("Expected access reason to be returned")
				}
			}
		})
	}
}

func TestServer_RotateKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a test key with rotation enabled
	createReq := &CreateKeyRequest{
		Name:                 "rotation-test-key",
		KeyType:              KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationIntervalDays: 90,
	}

	createResp, err := server.CreateKey(context.Background(), createReq)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	keyID := createResp.Key.KeyId

	tests := []struct {
		name        string
		request     *RotateKeyRequest
		expectError bool
	}{
		{
			name: "Rotate existing key",
			request: &RotateKeyRequest{
				KeyId: keyID,
				Force: true,
			},
			expectError: false,
		},
		{
			name: "Rotate non-existent key should fail",
			request: &RotateKeyRequest{
				KeyId: "non-existent-key",
				Force: true,
			},
			expectError: true,
		},
		{
			name: "Rotate without key ID should fail",
			request: &RotateKeyRequest{
				Force: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.RotateKey(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.NewKey == nil {
				t.Error("Expected new key to be returned")
			}

			if response.OldKey == nil {
				t.Error("Expected old key to be returned")
			}

			if response.NewKey.KeyId != response.OldKey.KeyId {
				t.Error("Expected new and old keys to have the same ID")
			}

			if response.NewKey.LastRotated == nil {
				t.Error("Expected new key to have rotation timestamp")
			}

			if response.Timestamp == nil {
				t.Error("Expected response timestamp to be set")
			}
		})
	}
}

func TestServer_ListProviders(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	tests := []struct {
		name           string
		request        *ListProvidersRequest
		expectMinCount int
	}{
		{
			name:           "List all providers",
			request:        &ListProvidersRequest{},
			expectMinCount: 4, // Software, HSM, Smart Card, USB Token
		},
		{
			name: "List available providers only",
			request: &ListProvidersRequest{
				AvailableOnly: true,
			},
			expectMinCount: 4, // All mock providers are available
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.ListProviders(context.Background(), tt.request)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if len(response.Providers) < tt.expectMinCount {
				t.Errorf("Expected at least %d providers, got %d", tt.expectMinCount, len(response.Providers))
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			// Check that all providers have required information
			for _, provider := range response.Providers {
				if provider.Name == "" {
					t.Error("Provider name should not be empty")
				}

				if provider.Description == "" {
					t.Error("Provider description should not be empty")
				}

				if len(provider.SupportedKeyTypes) == 0 {
					t.Error("Provider should support at least one key type")
				}
			}
		})
	}
}

func TestServer_DeleteKey(t *testing.T) {
	server := newTestKeyManagerServer(t, encryption.RSA2048)

	// Create a test key
	createReq := &CreateKeyRequest{
		Name:         "delete-test-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	}

	createResp, err := server.CreateKey(context.Background(), createReq)
	if err != nil {
		t.Fatalf("Failed to create test key: %v", err)
	}

	keyID := createResp.Key.KeyId

	tests := []struct {
		name          string
		request       *DeleteKeyRequest
		expectError   bool
		expectSuccess bool
	}{
		{
			name: "Delete existing key with force",
			request: &DeleteKeyRequest{
				KeyId: keyID,
				Force: true,
			},
			expectError:   false,
			expectSuccess: true,
		},
		{
			name: "Delete non-existent key should fail",
			request: &DeleteKeyRequest{
				KeyId: "non-existent-key",
				Force: true,
			},
			expectError: true,
		},
		{
			name: "Delete without key ID should fail",
			request: &DeleteKeyRequest{
				Force: true,
			},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := server.DeleteKey(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if response.Success != tt.expectSuccess {
				t.Errorf("Expected success %t, got %t", tt.expectSuccess, response.Success)
			}

			if response.Timestamp == nil {
				t.Error("Expected timestamp to be set")
			}

			if tt.expectSuccess && response.Message == "" {
				t.Error("Expected success message to be set")
			}
		})
	}
}

// Benchmark tests
func BenchmarkServer_CreateKey(b *testing.B) {
	server := newTestKeyManagerServer(b, encryption.RSA2048)

	req := &CreateKeyRequest{
		Name:         "benchmark-key",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Name = fmt.Sprintf("benchmark-key-%d", i)
		_, err := server.CreateKey(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkServer_UnwrapDEK(b *testing.B) {
	server := newTestKeyManagerServer(b, encryption.RSA2048)

	// Create a test key
	createReq := &CreateKeyRequest{
		Name:               "benchmark-dek-key",
		KeyType:            KeyType_KEY_TYPE_RSA_2048,
		ProviderType:       KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		AuthorizedSubjects: []string{"benchmark-user"},
	}

	createResp, err := server.CreateKey(context.Background(), createReq)
	if err != nil {
		b.Fatal(err)
	}

	req := &UnwrapDEKRequest{
		Subject:      "benchmark-user",
		Resource:     "benchmark-resource",
		EncryptedDek: []byte("mock-encrypted-dek"),
		KeyId:        createResp.Key.KeyId,
		Action:       "unwrap_dek",
		Context: map[string]string{
			"role": "admin",
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.UnwrapDEK(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
