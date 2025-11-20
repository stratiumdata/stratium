package stratium

import (
	"context"
	"fmt"
	"net"
	"testing"

	keyaccess "github.com/stratiumdata/go-sdk/gen/services/key-access"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Integration tests for KeyAccessClient using in-process gRPC server mocking.
//
// These tests use:
// - bufconn for in-process gRPC communication
// - mockKeyAccessServer to simulate the Key Access service
// - mockAuthManager from helpers_test.go for authentication mocking
//
// Test coverage:
// - Input validation (nil requests, missing fields)
// - Full gRPC integration tests with mock server
// - Error handling and edge cases

const bufSize = 1024 * 1024

// mockKeyAccessServer implements the KeyAccessServiceServer interface for testing
type mockKeyAccessServer struct {
	keyaccess.UnimplementedKeyAccessServiceServer

	// Configure response behavior
	shouldDenyAccess  bool
	shouldReturnError bool
	wrapResponse      *keyaccess.WrapDEKResponse
	unwrapResponse    *keyaccess.UnwrapDEKResponse
}

func (m *mockKeyAccessServer) WrapDEK(ctx context.Context, req *keyaccess.WrapDEKRequest) (*keyaccess.WrapDEKResponse, error) {
	if m.shouldReturnError {
		return nil, fmt.Errorf("internal server error")
	}

	if m.wrapResponse != nil {
		return m.wrapResponse, nil
	}

	// Default response
	return &keyaccess.WrapDEKResponse{
		AccessGranted: !m.shouldDenyAccess,
		AccessReason:  "Policy evaluation passed",
		WrappedDek:    []byte("wrapped-dek-data"),
		KeyId:         "test-key-id",
		Timestamp:     timestamppb.Now(),
	}, nil
}

func (m *mockKeyAccessServer) UnwrapDEK(ctx context.Context, req *keyaccess.UnwrapDEKRequest) (*keyaccess.UnwrapDEKResponse, error) {
	if m.shouldReturnError {
		return nil, fmt.Errorf("internal server error")
	}

	if m.unwrapResponse != nil {
		return m.unwrapResponse, nil
	}

	// Default response
	return &keyaccess.UnwrapDEKResponse{
		AccessGranted: !m.shouldDenyAccess,
		AccessReason:  "Policy evaluation passed",
		DekForSubject: []byte("unwrapped-dek-data"),
	}, nil
}

// setupKeyAccessTest creates an in-process gRPC server for testing
func setupKeyAccessTest(t *testing.T, mockServer *mockKeyAccessServer) (*KeyAccessClient, func()) {
	// Create a listener with a buffer
	lis := bufconn.Listen(bufSize)

	// Create gRPC server
	s := grpc.NewServer()
	keyaccess.RegisterKeyAccessServiceServer(s, mockServer)

	// Start server in background
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Logf("Server exited with error: %v", err)
		}
	}()

	// Create client connection
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("Failed to create client connection: %v", err)
	}

	// Create config and client with mock auth
	config := &Config{
		Timeout: 0, // No timeout for tests
	}
	mockAuth := &mockAuthManager{
		token: "test-token",
	}
	client := newKeyAccessClient(conn, config, mockAuth)

	// Cleanup function
	cleanup := func() {
		conn.Close()
		s.Stop()
	}

	return client, cleanup
}

// ===== RequestDEK Tests =====

func TestKeyAccessClient_RequestDEK(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		Resource:           "test-resource",
		ResourceAttributes: map[string]string{"classification": "secret"},
		Purpose:            "encryption",
		DEK:                []byte("test-dek"),
		Policy:             "test-policy",
		ClientKeyID:        "client-key",
		ClientWrappedDEK:   []byte("wrapped"),
	}

	ctx := context.Background()
	resp, err := client.RequestDEK(ctx, req)
	if err != nil {
		t.Fatalf("RequestDEK() error: %v", err)
	}

	if resp == nil {
		t.Fatal("RequestDEK() returned nil response")
	}

	if len(resp.WrappedDEK) == 0 {
		t.Error("RequestDEK() should return wrapped DEK")
	}

	if resp.KeyID == "" {
		t.Error("RequestDEK() should return key ID")
	}

	if resp.Algorithm == "" {
		t.Error("RequestDEK() should return algorithm")
	}
}

func TestKeyAccessClient_RequestDEK_NilRequest(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, nil)
	if err != ErrRequestNil {
		t.Errorf("RequestDEK() with nil request expected ErrRequestNil, got: %v", err)
	}
}

func TestKeyAccessClient_RequestDEK_MissingResource(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		ResourceAttributes: map[string]string{"classification": "secret"},
		Purpose:            "encryption",
		ClientKeyID:        "client-key",
		ClientWrappedDEK:   []byte("wrapped"),
	}

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, req)
	if err != ErrResourceRequired {
		t.Errorf("RequestDEK() with missing resource expected ErrResourceRequired, got: %v", err)
	}
}

func TestKeyAccessClient_RequestDEK_MissingResourceAttributes(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		Resource:         "test-resource",
		Purpose:          "encryption",
		ClientKeyID:      "client-key",
		ClientWrappedDEK: []byte("wrapped"),
	}

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, req)
	if err != ErrResourceAttributesRequired {
		t.Errorf("RequestDEK() with missing attributes expected ErrResourceAttributesRequired, got: %v", err)
	}
}

func TestKeyAccessClient_RequestDEK_MissingClientKey(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		Resource:           "test-resource",
		ResourceAttributes: map[string]string{"classification": "secret"},
		Purpose:            "encryption",
		DEK:                []byte("test-dek"),
		Policy:             "test-policy",
		ClientWrappedDEK:   []byte("wrapped"),
	}

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, req)
	if err != ErrClientKeyRequired {
		t.Errorf("RequestDEK() with missing client key expected ErrClientKeyRequired, got: %v", err)
	}
}

func TestKeyAccessClient_RequestDEK_MissingClientWrap(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		Resource:           "test-resource",
		ResourceAttributes: map[string]string{"classification": "secret"},
		Purpose:            "encryption",
		DEK:                []byte("test-dek"),
		Policy:             "test-policy",
		ClientKeyID:        "client-key",
	}

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, req)
	if err != ErrClientWrapRequired {
		t.Errorf("RequestDEK() with missing client wrap expected ErrClientWrapRequired, got: %v", err)
	}
}

func TestKeyAccessClient_RequestDEK_AccessDenied(t *testing.T) {
	mockServer := &mockKeyAccessServer{
		shouldDenyAccess: true,
	}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		Resource:           "test-resource",
		ResourceAttributes: map[string]string{"classification": "secret"},
		Purpose:            "encryption",
		DEK:                []byte("test-dek"),
		Policy:             "test-policy",
		ClientKeyID:        "client-key",
		ClientWrappedDEK:   []byte("wrapped"),
	}

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, req)
	if err == nil {
		t.Error("RequestDEK() expected error for access denied, got nil")
	}
}

func TestKeyAccessClient_RequestDEK_ServerError(t *testing.T) {
	mockServer := &mockKeyAccessServer{
		shouldReturnError: true,
	}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	req := &DEKRequest{
		Resource:           "test-resource",
		ResourceAttributes: map[string]string{"classification": "secret"},
		Purpose:            "encryption",
		DEK:                []byte("test-dek"),
		Policy:             "test-policy",
		ClientKeyID:        "client-key",
		ClientWrappedDEK:   []byte("wrapped"),
	}

	ctx := context.Background()
	_, err := client.RequestDEK(ctx, req)
	if err == nil {
		t.Error("RequestDEK() expected error for server error, got nil")
	}
}

// ===== UnwrapDEK Tests =====

func TestKeyAccessClient_UnwrapDEK(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	dek, err := client.UnwrapDEK(ctx, "test-resource", "client-kid", "key-id", []byte("wrapped-dek"), "test-policy")
	if err != nil {
		t.Fatalf("UnwrapDEK() error: %v", err)
	}

	if len(dek) == 0 {
		t.Error("UnwrapDEK() should return unwrapped DEK")
	}
}

func TestKeyAccessClient_UnwrapDEK_MissingResource(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.UnwrapDEK(ctx, "", "client-kid", "key-id", []byte("wrapped-dek"), "test-policy")
	if err != ErrResourceRequired {
		t.Errorf("UnwrapDEK() with missing resource expected ErrResourceRequired, got: %v", err)
	}
}

func TestKeyAccessClient_UnwrapDEK_EmptyWrappedDEK(t *testing.T) {
	mockServer := &mockKeyAccessServer{}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.UnwrapDEK(ctx, "test-resource", "client-kid", "key-id", []byte{}, "test-policy")
	if err == nil {
		t.Error("UnwrapDEK() with empty wrapped DEK expected error, got nil")
	}
}

func TestKeyAccessClient_UnwrapDEK_AccessDenied(t *testing.T) {
	mockServer := &mockKeyAccessServer{
		shouldDenyAccess: true,
	}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.UnwrapDEK(ctx, "test-resource", "client-kid", "key-id", []byte("wrapped-dek"), "test-policy")
	if err == nil {
		t.Error("UnwrapDEK() expected error for access denied, got nil")
	}
}

func TestKeyAccessClient_UnwrapDEK_ServerError(t *testing.T) {
	mockServer := &mockKeyAccessServer{
		shouldReturnError: true,
	}
	client, cleanup := setupKeyAccessTest(t, mockServer)
	defer cleanup()

	ctx := context.Background()
	_, err := client.UnwrapDEK(ctx, "test-resource", "client-kid", "key-id", []byte("wrapped-dek"), "test-policy")
	if err == nil {
		t.Error("UnwrapDEK() expected error for server error, got nil")
	}
}
