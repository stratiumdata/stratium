package stratium

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	keymanager "github.com/stratiumdata/go-sdk/gen/services/key-manager"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Integration tests for KeyManagerClient using in-process gRPC server mocking.

const keyManagerBufSize = 1024 * 1024

// mockKeyManagerServer implements the KeyManagerServiceServer interface for testing
type mockKeyManagerServer struct {
	keymanager.UnimplementedKeyManagerServiceServer

	// Configure response behavior
	shouldError   bool
	registeredKey *keymanager.Key
	keys          []*keymanager.Key
}

func (m *mockKeyManagerServer) RegisterClientKey(ctx context.Context, req *keymanager.RegisterClientKeyRequest) (*keymanager.RegisterClientKeyResponse, error) {
	if m.shouldError {
		return nil, fmt.Errorf("internal server error")
	}

	key := &keymanager.Key{
		KeyId:        "test-key-id",
		ClientId:     req.ClientId,
		KeyType:      req.KeyType,
		PublicKeyPem: req.PublicKeyPem,
		Status:       keymanager.KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
		ExpiresAt:    req.ExpiresAt,
		Metadata:     req.Metadata,
	}

	if m.registeredKey != nil {
		key = m.registeredKey
	}

	return &keymanager.RegisterClientKeyResponse{
		Key:       key,
		Success:   true,
		Timestamp: timestamppb.Now(),
	}, nil
}

func (m *mockKeyManagerServer) GetClientKey(ctx context.Context, req *keymanager.GetClientKeyRequest) (*keymanager.GetClientKeyResponse, error) {
	if m.shouldError {
		return nil, fmt.Errorf("internal server error")
	}

	// Return not found if no keys set
	if len(m.keys) == 0 {
		return &keymanager.GetClientKeyResponse{
			Found:     false,
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Return the first key
	return &keymanager.GetClientKeyResponse{
		Key:       m.keys[0],
		Found:     true,
		Timestamp: timestamppb.Now(),
	}, nil
}

func (m *mockKeyManagerServer) ListClientKeys(ctx context.Context, req *keymanager.ListClientKeysRequest) (*keymanager.ListClientKeysResponse, error) {
	if m.shouldError {
		return nil, fmt.Errorf("internal server error")
	}

	return &keymanager.ListClientKeysResponse{
		Keys:      m.keys,
		Timestamp: timestamppb.Now(),
	}, nil
}

// setupKeyManagerTest creates an in-process gRPC server for testing
func setupKeyManagerTest(t *testing.T, mockServer *mockKeyManagerServer) (*KeyManagerClient, func()) {
	lis := bufconn.Listen(keyManagerBufSize)

	s := grpc.NewServer()
	keymanager.RegisterKeyManagerServiceServer(s, mockServer)

	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to create client connection: %v", err)
	}

	config := &Config{
		Timeout: 0,
	}
	mockAuth := &mockAuthManager{
		token: "test-token",
	}
	client := newKeyManagerClient(conn, config, mockAuth)

	cleanup := func() {
		conn.Close()
		s.Stop()
	}

	return client, cleanup
}

// ===== RegisterKey Tests =====

func TestKeyManagerClient_RegisterKey(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &RegisterKeyRequest{
		ClientID:     "test-client",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----",
		KeyType:      KeyTypeRSA4096,
		Metadata:     map[string]string{"purpose": "testing"},
	}

	ctx := context.Background()
	key, err := client.RegisterKey(ctx, req)
	if err != nil {
		t.Fatalf("RegisterKey() error: %v", err)
	}

	if key == nil {
		t.Fatal("RegisterKey() returned nil key")
	}

	if key.KeyID == "" {
		t.Error("RegisterKey() should return a key ID")
	}

	if key.ClientID != req.ClientID {
		t.Errorf("RegisterKey() client ID = %v, want %v", key.ClientID, req.ClientID)
	}

	if key.PublicKeyPEM != req.PublicKeyPEM {
		t.Error("RegisterKey() should return the same public key")
	}
}

func TestKeyManagerClient_RegisterKey_NilRequest(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.RegisterKey(ctx, nil)
	if err != ErrRequestNil {
		t.Errorf("RegisterKey() with nil request expected ErrRequestNil, got: %v", err)
	}
}

func TestKeyManagerClient_RegisterKey_MissingClientID(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &RegisterKeyRequest{
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----",
		KeyType:      KeyTypeRSA4096,
	}

	ctx := context.Background()
	_, err := client.RegisterKey(ctx, req)
	if err != ErrClientIDRequired {
		t.Errorf("RegisterKey() with missing client ID expected ErrClientIDRequired, got: %v", err)
	}
}

func TestKeyManagerClient_RegisterKey_MissingPublicKey(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &RegisterKeyRequest{
		ClientID: "test-client",
		KeyType:  KeyTypeRSA4096,
	}

	ctx := context.Background()
	_, err := client.RegisterKey(ctx, req)
	if err == nil {
		t.Error("RegisterKey() with missing public key expected error, got nil")
	}
}

func TestKeyManagerClient_RegisterKey_WithExpiration(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	expiresAt := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	req := &RegisterKeyRequest{
		ClientID:     "test-client",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----",
		KeyType:      KeyTypeRSA4096,
		ExpiresAt:    expiresAt,
	}

	ctx := context.Background()
	key, err := client.RegisterKey(ctx, req)
	if err != nil {
		t.Fatalf("RegisterKey() error: %v", err)
	}

	if key.ExpiresAt == "" {
		t.Error("RegisterKey() should return expiration time")
	}
}

func TestKeyManagerClient_RegisterKey_InvalidExpirationFormat(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &RegisterKeyRequest{
		ClientID:     "test-client",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----",
		KeyType:      KeyTypeRSA4096,
		ExpiresAt:    "invalid-date",
	}

	ctx := context.Background()
	_, err := client.RegisterKey(ctx, req)
	if err == nil {
		t.Error("RegisterKey() with invalid expiration expected error, got nil")
	}
}

func TestKeyManagerClient_RegisterKey_ServerError(t *testing.T) {
	mockServer := &mockKeyManagerServer{
		shouldError: true,
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &RegisterKeyRequest{
		ClientID:     "test-client",
		PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----",
		KeyType:      KeyTypeRSA4096,
	}

	ctx := context.Background()
	_, err := client.RegisterKey(ctx, req)
	if err == nil {
		t.Error("RegisterKey() expected error for server error, got nil")
	}
}

// ===== GetKey Tests =====

func TestKeyManagerClient_GetKey(t *testing.T) {
	testKey := &keymanager.Key{
		KeyId:        "test-key-id",
		ClientId:     "test-client",
		KeyType:      keymanager.KeyType_KEY_TYPE_RSA_4096,
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----\ntest-key\n-----END PUBLIC KEY-----",
		Status:       keymanager.KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}

	mockServer := &mockKeyManagerServer{
		keys: []*keymanager.Key{testKey},
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &GetKeyRequest{
		ClientID: "test-client",
		KeyID:    "test-key-id",
	}

	ctx := context.Background()
	key, err := client.GetKey(ctx, req)
	if err != nil {
		t.Fatalf("GetKey() error: %v", err)
	}

	if key == nil {
		t.Fatal("GetKey() returned nil key")
	}

	if key.KeyID != testKey.KeyId {
		t.Errorf("GetKey() key ID = %v, want %v", key.KeyID, testKey.KeyId)
	}

	if key.ClientID != testKey.ClientId {
		t.Errorf("GetKey() client ID = %v, want %v", key.ClientID, testKey.ClientId)
	}
}

func TestKeyManagerClient_GetKey_NilRequest(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.GetKey(ctx, nil)
	if err != ErrRequestNil {
		t.Errorf("GetKey() with nil request expected ErrRequestNil, got: %v", err)
	}
}

func TestKeyManagerClient_GetKey_MissingClientID(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &GetKeyRequest{
		KeyID: "test-key-id",
	}

	ctx := context.Background()
	_, err := client.GetKey(ctx, req)
	if err != ErrClientIDRequired {
		t.Errorf("GetKey() with missing client ID expected ErrClientIDRequired, got: %v", err)
	}
}

func TestKeyManagerClient_GetKey_MissingKeyID(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &GetKeyRequest{
		ClientID: "test-client",
	}

	ctx := context.Background()
	_, err := client.GetKey(ctx, req)
	if err == nil {
		t.Error("GetKey() with missing key ID expected error, got nil")
	}
}

func TestKeyManagerClient_GetKey_NotFound(t *testing.T) {
	mockServer := &mockKeyManagerServer{
		keys: []*keymanager.Key{}, // Empty keys list
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &GetKeyRequest{
		ClientID: "test-client",
		KeyID:    "nonexistent-key",
	}

	ctx := context.Background()
	_, err := client.GetKey(ctx, req)
	if err == nil {
		t.Error("GetKey() expected error for not found, got nil")
	}
}

func TestKeyManagerClient_GetKey_ServerError(t *testing.T) {
	mockServer := &mockKeyManagerServer{
		shouldError: true,
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	req := &GetKeyRequest{
		ClientID: "test-client",
		KeyID:    "test-key-id",
	}

	ctx := context.Background()
	_, err := client.GetKey(ctx, req)
	if err == nil {
		t.Error("GetKey() expected error for server error, got nil")
	}
}

// ===== ListKeys Tests =====

func TestKeyManagerClient_ListKeys(t *testing.T) {
	testKeys := []*keymanager.Key{
		{
			KeyId:        "key-1",
			ClientId:     "test-client",
			KeyType:      keymanager.KeyType_KEY_TYPE_RSA_4096,
			PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nkey1\n-----END PUBLIC KEY-----",
			Status:       keymanager.KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.Now(),
		},
		{
			KeyId:        "key-2",
			ClientId:     "test-client",
			KeyType:      keymanager.KeyType_KEY_TYPE_ECC_P256,
			PublicKeyPem: "-----BEGIN PUBLIC KEY-----\nkey2\n-----END PUBLIC KEY-----",
			Status:       keymanager.KeyStatus_KEY_STATUS_ACTIVE,
			CreatedAt:    timestamppb.Now(),
		},
	}

	mockServer := &mockKeyManagerServer{
		keys: testKeys,
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	keys, err := client.ListKeys(ctx, "test-client", false)
	if err != nil {
		t.Fatalf("ListKeys() error: %v", err)
	}

	if len(keys) != len(testKeys) {
		t.Errorf("ListKeys() returned %d keys, want %d", len(keys), len(testKeys))
	}

	for i, key := range keys {
		if key.KeyID != testKeys[i].KeyId {
			t.Errorf("ListKeys() key %d ID = %v, want %v", i, key.KeyID, testKeys[i].KeyId)
		}
	}
}

func TestKeyManagerClient_ListKeys_Empty(t *testing.T) {
	mockServer := &mockKeyManagerServer{
		keys: []*keymanager.Key{},
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	keys, err := client.ListKeys(ctx, "test-client", false)
	if err != nil {
		t.Fatalf("ListKeys() error: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("ListKeys() returned %d keys, want 0", len(keys))
	}
}

func TestKeyManagerClient_ListKeys_MissingClientID(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.ListKeys(ctx, "", false)
	if err != ErrClientIDRequired {
		t.Errorf("ListKeys() with missing client ID expected ErrClientIDRequired, got: %v", err)
	}
}

func TestKeyManagerClient_ListKeys_ServerError(t *testing.T) {
	mockServer := &mockKeyManagerServer{
		shouldError: true,
	}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.ListKeys(ctx, "test-client", false)
	if err == nil {
		t.Error("ListKeys() expected error for server error, got nil")
	}
}

// ===== EncryptData/DecryptData Tests =====

func TestKeyManagerClient_EncryptData_NotImplemented(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.EncryptData(ctx, "test-client", "test-key-id", []byte("test data"))
	if err == nil {
		t.Error("EncryptData() expected not implemented error")
	}
}

func TestKeyManagerClient_DecryptData_NotImplemented(t *testing.T) {
	mockServer := &mockKeyManagerServer{}
	client, cleanup := setupKeyManagerTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	req := &DecryptionRequest{
		ClientID:   "test-client",
		KeyID:      "test-key-id",
		Ciphertext: []byte("encrypted"),
		WrappedDEK: []byte("wrapped-key"),
	}
	_, err := client.DecryptData(ctx, req)
	if err == nil {
		t.Error("DecryptData() expected not implemented error")
	}
}