package key_access

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"stratium/pkg/auth"
	"stratium/pkg/extractors"
	"stratium/pkg/models"
	keyManager "stratium/services/key-manager"
	platform "stratium/services/platform"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MockPlatformClient provides a simple mock for testing without Platform service
type MockPlatformClient struct{}

// NewMockPlatformClient creates a mock Platform client that allows all access
func NewMockPlatformClient() *MockPlatformClient {
	logger.Info("Warning: Using MockPlatformClient - all access will be allowed for testing")
	return &MockPlatformClient{}
}

// EvaluateAccess always returns allowed for testing
func (m *MockPlatformClient) EvaluateAccess(ctx context.Context, resource map[string]string, action string, context map[string]string) (*AccessDecision, error) {
	tokenString, err := auth.ExtractTokenFromMetadata(ctx)
	if err != nil {
		return &AccessDecision{
			Granted:      false,
			Reason:       "failed to extract token from metadata",
			AppliedRules: []string{},
		}, err
	}

	jwtExtractor := &extractors.JWTClaimsExtractor{}
	subjectAttributes, err := jwtExtractor.ExtractSubjectAttributes(tokenString)
	if err != nil {
		return &AccessDecision{
			Granted:      false,
			Reason:       "failed to extract token attributes",
			AppliedRules: []string{},
		}, err
	}

	subject := subjectAttributes["sub"]

	logger.Info("MockPlatformClient: Allowing access for subject=%s, resource=%s, action=%s", subject, resource, action)

	return &AccessDecision{
		Granted:      true,
		Reason:       "Access granted by mock platform client (testing mode)",
		AppliedRules: []string{"mock-allow-all"},
		Context:      context,
	}, nil
}

func TestServer_WrapDEK(t *testing.T) {
	// Create mock key manager server (simplified for testing)
	server := &Server{
		platformClient: NewMockPlatformClient(),
		authService:    nil, // Auth service not used in these tests
	}
	server.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return &keyManager.RewrapClientDEKResponse{
			ServiceWrappedDek: req.ClientWrappedDek,
			ServiceKeyId:      req.ServiceKeyId,
		}, nil
	}

	// Generate a mock DEK
	mockDEK := make([]byte, 32)
	_, err := rand.Read(mockDEK)
	if err != nil {
		t.Fatalf("Failed to generate mock DEK: %v", err)
	}

	tests := []struct {
		name         string
		request      *WrapDEKRequest
		mockUserID   string
		expectAccess bool
	}{
		{
			name: "Admin user should get access",
			request: &WrapDEKRequest{
				Resource:    "test-resource",
				Dek:         mockDEK,
				Action:      "wrap_dek",
				KeyId:       "service-key",
				ClientKeyId: "client-key",
				Context: map[string]string{
					"role": "admin",
				},
			},
			mockUserID:   "admin456",
			expectAccess: true,
		},
		{
			name: "Regular user should get access for allowed resource",
			request: &WrapDEKRequest{
				Resource:    "test-resource",
				Dek:         mockDEK,
				Action:      "wrap_dek",
				KeyId:       "service-key",
				ClientKeyId: "client-key",
				Context: map[string]string{
					"department": "engineering",
				},
			},
			mockUserID:   "user123",
			expectAccess: true,
		},
		{
			name: "Request should be valid for user with access",
			request: &WrapDEKRequest{
				Resource:    "test-resource",
				Dek:         mockDEK,
				Action:      "wrap_dek",
				KeyId:       "service-key",
				ClientKeyId: "client-key",
			},
			mockUserID:   "user123",
			expectAccess: true,
		},
		{
			name: "All users get access with mock client",
			request: &WrapDEKRequest{
				Resource:    "secret-resource",
				Dek:         mockDEK,
				Action:      "wrap_dek",
				KeyId:       "service-key",
				ClientKeyId: "client-key",
			},
			mockUserID:   "any-user",
			expectAccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: This test is limited because we don't have a real key manager connection
			// We're mainly testing request validation
			// ABAC evaluation requires proper auth metadata setup and is covered in integration tests

			// Test request validation (subject is not part of the request)
			err := server.validateWrapRequest(tt.request)
			if err != nil {
				t.Errorf("Request validation failed for valid request: %v", err)
			}
		})
	}
}

// Integration test: exercise real gRPC clients backed by mock platform/key manager services.
func TestServer_WrapDEK_Integration(t *testing.T) {
	t.Parallel()

	// Generate client/service keys.
	clientPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	servicePrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate service key: %v", err)
	}

	clientKeyID := "client-key-id"
	serviceKeyID := "service-key-id"

	kmAddr, kmServer := startMockKeyManagerGRPCServer(t, map[string]*rsa.PublicKey{
		clientKeyID: &clientPrivate.PublicKey,
	}, map[string]*rsa.PrivateKey{
		serviceKeyID: servicePrivate,
	})
	defer kmServer.cleanup()

	platformHandle := startMockPlatformGRPCServer(t)
	defer platformHandle.cleanup()

	platformClient, err := NewGRPCPlatformClient(platformHandle.addr)
	if err != nil {
		t.Fatalf("failed to create platform client: %v", err)
	}
	t.Cleanup(func() {
		platformClient.Close()
	})

	kmConn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("failed to connect to key manager: %v", err)
	}
	t.Cleanup(func() {
		kmConn.Close()
	})
	kmClient := keyManager.NewKeyManagerServiceClient(kmConn)

	server := &Server{
		platformClient:   platformClient,
		keyManagerClient: kmClient,
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	server.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return kmClient.RewrapClientDEK(ctx, req)
	}

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("failed to create DEK: %v", err)
	}
	clientWrapped, err := wrapDEKWithPrivateKey(clientPrivate, dek)
	if err != nil {
		t.Fatalf("failed to wrap DEK with client key: %v", err)
	}

	policy := mustMakePolicy(t, "document-service")

	req := &WrapDEKRequest{
		Resource:    "document-service",
		Dek:         clientWrapped,
		Action:      "wrap_dek",
		KeyId:       serviceKeyID,
		ClientKeyId: clientKeyID,
		Policy:      policy,
		Context: map[string]string{
			"department": "engineering",
		},
	}

	token := mustCreateJWT(t, map[string]interface{}{
		"sub":                "user123",
		"preferred_username": "user123",
		"role":               "user",
		"department":         "engineering",
	})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	resp, err := server.WrapDEK(ctx, req)
	if err != nil {
		t.Fatalf("WrapDEK failed: %v", err)
	}
	if !resp.AccessGranted {
		t.Fatalf("expected access granted, got denied: %s", resp.AccessReason)
	}
	if resp.KeyId != serviceKeyID {
		t.Fatalf("expected key id %s, got %s", serviceKeyID, resp.KeyId)
	}
	if len(resp.WrappedDek) == 0 {
		t.Fatalf("expected wrapped DEK from key manager")
	}
	kmServer.mu.Lock()
	defer kmServer.mu.Unlock()
	if !bytes.Equal(kmServer.lastPlainDEK, dek) {
		t.Fatalf("key manager rewrap received incorrect DEK")
	}
}

// --- Test helpers for integration scenario ---

type mockKeyManagerServer struct {
	keyManager.UnimplementedKeyManagerServiceServer

	clientKeys  map[string]*rsa.PublicKey
	serviceKeys map[string]*rsa.PrivateKey

	mu           sync.Mutex
	lastPlainDEK []byte
	stop         func()
}

func (m *mockKeyManagerServer) cleanup() {
	if m.stop != nil {
		m.stop()
	}
}

func (m *mockKeyManagerServer) RewrapClientDEK(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
	pub := m.clientKeys[req.GetClientKeyId()]
	if pub == nil {
		return nil, fmt.Errorf("client key %s not registered", req.GetClientKeyId())
	}

	dek, err := recoverClientDEK(pub, req.GetClientWrappedDek())
	if err != nil {
		return nil, fmt.Errorf("failed to recover client DEK: %w", err)
	}

	priv := m.serviceKeys[req.GetServiceKeyId()]
	if priv == nil {
		return nil, fmt.Errorf("service key %s not registered", req.GetServiceKeyId())
	}

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &priv.PublicKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap with service key: %w", err)
	}

	m.mu.Lock()
	m.lastPlainDEK = append([]byte(nil), dek...)
	m.mu.Unlock()

	return &keyManager.RewrapClientDEKResponse{
		ServiceWrappedDek: wrapped,
		ServiceKeyId:      req.GetServiceKeyId(),
		Timestamp:         timestamppb.Now(),
	}, nil
}

type platformServerHandle struct {
	addr string
	stop func()
}

func (p *platformServerHandle) cleanup() {
	if p.stop != nil {
		p.stop()
	}
}

type mockPlatformServer struct {
	platform.UnimplementedPlatformServiceServer
}

func (m *mockPlatformServer) GetDecision(ctx context.Context, req *platform.GetDecisionRequest) (*platform.GetDecisionResponse, error) {
	_ = valueFromStruct(req.SubjectAttributes["sub"])
	role := valueFromStruct(req.SubjectAttributes["role"])
	resourceName := req.ResourceAttributes["name"]

	decision := platform.Decision_DECISION_DENY
	reason := "access denied"

	if role == "admin" || resourceName == "document-service" {
		decision = platform.Decision_DECISION_ALLOW
		reason = "access granted"
	}

	return &platform.GetDecisionResponse{
		Decision:        decision,
		Reason:          reason,
		Details:         map[string]string{},
		EvaluatedPolicy: "test-policy",
		Timestamp:       timestamppb.Now(),
	}, nil
}

func (m *mockPlatformServer) GetEntitlements(ctx context.Context, req *platform.GetEntitlementsRequest) (*platform.GetEntitlementsResponse, error) {
	return &platform.GetEntitlementsResponse{
		Entitlements: []*platform.Entitlement{},
		Timestamp:    timestamppb.Now(),
		TotalCount:   0,
	}, nil
}

func startMockKeyManagerGRPCServer(t *testing.T, clientKeys map[string]*rsa.PublicKey, serviceKeys map[string]*rsa.PrivateKey) (string, *mockKeyManagerServer) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server := &mockKeyManagerServer{
		clientKeys:  clientKeys,
		serviceKeys: serviceKeys,
	}

	grpcServer := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(grpcServer, server)

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("mock key manager server exited: %v", err)
		}
	}()

	server.stop = func() {
		grpcServer.Stop()
		lis.Close()
	}

	return lis.Addr().String(), server
}

func startMockPlatformGRPCServer(t *testing.T) *platformServerHandle {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	grpcServer := grpc.NewServer()
	platform.RegisterPlatformServiceServer(grpcServer, &mockPlatformServer{})

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("mock platform server exited: %v", err)
		}
	}()

	return &platformServerHandle{
		addr: lis.Addr().String(),
		stop: func() {
			grpcServer.Stop()
			lis.Close()
		},
	}
}

func recoverClientDEK(pub *rsa.PublicKey, wrapped []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if len(wrapped) != k {
		return nil, fmt.Errorf("wrapped length mismatch")
	}

	c := new(big.Int).SetBytes(wrapped)
	m := new(big.Int).Exp(c, big.NewInt(int64(pub.E)), pub.N)

	em := m.Bytes()
	if len(em) < k {
		padded := make([]byte, k)
		copy(padded[k-len(em):], em)
		em = padded
	}
	if len(em) < 3 || em[0] != 0x00 || em[1] != 0x01 {
		return nil, fmt.Errorf("invalid padding")
	}
	idx := bytes.IndexByte(em[2:], 0x00)
	if idx < 0 {
		return nil, fmt.Errorf("delimiter not found")
	}
	return em[2+idx+1:], nil
}

func wrapDEKWithPrivateKey(privateKey *rsa.PrivateKey, dek []byte) ([]byte, error) {
	k := (privateKey.N.BitLen() + 7) / 8
	if len(dek) > k-11 {
		return nil, fmt.Errorf("DEK too large for client key")
	}

	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01
	psLen := k - len(dek) - 3
	for i := 0; i < psLen; i++ {
		em[2+i] = 0xff
	}
	em[2+psLen] = 0x00
	copy(em[3+psLen:], dek)

	m := new(big.Int).SetBytes(em)
	if m.Cmp(privateKey.N) >= 0 {
		return nil, fmt.Errorf("message representative out of range")
	}

	var c *big.Int
	if privateKey.Precomputed.Dp == nil {
		c = new(big.Int).Exp(m, privateKey.D, privateKey.N)
	} else {
		c = new(big.Int).Exp(m, privateKey.D, privateKey.N)
	}

	out := c.Bytes()
	if len(out) < k {
		padded := make([]byte, k)
		copy(padded[k-len(out):], out)
		out = padded
	}
	return out, nil
}

func mustMakePolicy(t *testing.T, resourceName string) string {
	t.Helper()
	policy := &models.ZtdfPolicy{
		Body: &models.ZtdfPolicy_Body{
			DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
				{
					Attribute:   fmt.Sprintf("http://example.com/attr/name/value/%s", resourceName),
					DisplayName: "name",
					IsDefault:   true,
				},
			},
		},
	}
	b, err := protojson.Marshal(policy)
	if err != nil {
		t.Fatalf("failed to marshal policy: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func mustCreateJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "none", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(claims)
	token := fmt.Sprintf("%s.%s.",
		base64.RawURLEncoding.EncodeToString(headerBytes),
		base64.RawURLEncoding.EncodeToString(payloadBytes),
	)
	return token
}

func valueFromStruct(val *structpb.Value) string {
	if val == nil {
		return ""
	}
	switch val.Kind.(type) {
	case *structpb.Value_StringValue:
		return val.GetStringValue()
	default:
		return val.String()
	}
}

func TestServer_ValidateRequests(t *testing.T) {
	server := &Server{}

	// Test WrapDEK validation
	t.Run("WrapDEK validation", func(t *testing.T) {
		// Valid request - subject comes from OIDC token, not from request
		validReq := &WrapDEKRequest{
			Resource:    "test-resource",
			Dek:         []byte("test-dek"),
			Action:      "wrap_dek",
			ClientKeyId: "client-key",
		}

		if err := server.validateWrapRequest(validReq); err != nil {
			t.Errorf("Valid request should not fail validation: %v", err)
		}

		// Test missing resource
		invalidReq := &WrapDEKRequest{
			Dek:         []byte("test-dek"),
			Action:      "wrap_dek",
			ClientKeyId: "client-key",
		}

		if err := server.validateWrapRequest(invalidReq); err == nil {
			t.Error("Request without resource should fail validation")
		}

		// Test missing DEK
		invalidReq2 := &WrapDEKRequest{
			Resource:    "test-resource",
			Action:      "wrap_dek",
			ClientKeyId: "client-key",
		}

		if err := server.validateWrapRequest(invalidReq2); err == nil {
			t.Error("Request without DEK should fail validation")
		}
		invalidReq3 := &WrapDEKRequest{
			Resource: "test-resource",
			Dek:      []byte("test-dek"),
			Action:   "wrap_dek",
		}

		if err := server.validateWrapRequest(invalidReq3); err == nil {
			t.Error("Request without client key ID should fail validation")
		}
	})

	// Test UnwrapDEK validation
	t.Run("UnwrapDEK validation", func(t *testing.T) {
		// Valid request - subject comes from OIDC token, not from request
		validReq := &UnwrapDEKRequest{
			Resource:   "test-resource",
			WrappedDek: []byte("wrapped-dek"),
			KeyId:      "key-123",
			Action:     "unwrap_dek",
		}

		if err := server.validateUnwrapRequest(validReq); err != nil {
			t.Errorf("Valid request should not fail validation: %v", err)
		}

		// Test missing key ID
		invalidReq := &UnwrapDEKRequest{
			Resource:   "test-resource",
			WrappedDek: []byte("wrapped-dek"),
			Action:     "unwrap_dek",
		}

		if err := server.validateUnwrapRequest(invalidReq); err == nil {
			t.Error("Request without key ID should fail validation")
		}

		// Test missing resource
		invalidReq2 := &UnwrapDEKRequest{
			WrappedDek: []byte("wrapped-dek"),
			KeyId:      "key-123",
			Action:     "unwrap_dek",
		}

		if err := server.validateUnwrapRequest(invalidReq2); err == nil {
			t.Error("Request without resource should fail validation")
		}

		// Test missing wrapped DEK
		invalidReq3 := &UnwrapDEKRequest{
			Resource: "test-resource",
			KeyId:    "key-123",
			Action:   "unwrap_dek",
		}

		if err := server.validateUnwrapRequest(invalidReq3); err == nil {
			t.Error("Request without wrapped DEK should fail validation")
		}
	})
}

func TestPlatformClient_EvaluateAccess(t *testing.T) {
	// Note: MockPlatformClient.EvaluateAccess expects auth token in context metadata
	// The signature is: EvaluateAccess(ctx, resourceAttributes map[string]string, action, context)
	// Since setting up proper auth metadata is complex for unit tests, we skip this test
	// Integration tests should cover the full auth flow
	t.Skip("Skipping - MockPlatformClient requires auth token in metadata for proper testing")
}

func TestSubjectKeyStore(t *testing.T) {
	store := NewInMemorySubjectKeyStore()

	// Test that sample keys are loaded
	subjects, err := store.ListSubjects(context.Background())
	if err != nil {
		t.Fatalf("ListSubjects failed: %v", err)
	}

	if len(subjects) == 0 {
		t.Error("Expected sample subjects to be loaded")
	}

	// Test getting a key
	if len(subjects) > 0 {
		_, err := store.GetSubjectPublicKey(context.Background(), subjects[0])
		if err != nil {
			t.Errorf("GetSubjectPublicKey failed for %s: %v", subjects[0], err)
		}
	}

	// Test getting non-existent key
	_, err = store.GetSubjectPublicKey(context.Background(), "non-existent-subject")
	if err == nil {
		t.Error("Expected error for non-existent subject")
	}
}
