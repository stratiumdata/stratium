//go:build !fips

package key_access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	keyManager "stratium/services/key-manager"
	platform "stratium/services/platform"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// NewGRPCPlatformClient — constructor paths
// ---------------------------------------------------------------------------

func TestUnit_NewGRPCPlatformClient_EmptyAddress(t *testing.T) {
	_, err := NewGRPCPlatformClient("", nil)
	if err == nil {
		t.Fatal("expected error for empty address, got nil")
	}
}

func TestUnit_NewGRPCPlatformClient_ValidAddress(t *testing.T) {
	// Start a real mock platform server to connect to.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	platform.RegisterPlatformServiceServer(gs, &mockPlatformServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		lis.Close()
	})

	client, err := NewGRPCPlatformClient(lis.Addr().String(), nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	_ = client.Close()
}

// ---------------------------------------------------------------------------
// GRPCPlatformClient.EvaluateAccess — full client paths
// ---------------------------------------------------------------------------

// failingPlatformServer returns an error for every GetDecision call.
type failingPlatformServer struct {
	platform.UnimplementedPlatformServiceServer
}

func (f *failingPlatformServer) GetDecision(_ context.Context, _ *platform.GetDecisionRequest) (*platform.GetDecisionResponse, error) {
	return nil, fmt.Errorf("storage backend unavailable")
}

func startFailingPlatformGRPCServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	platform.RegisterPlatformServiceServer(gs, &failingPlatformServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		lis.Close()
	})
	return lis.Addr().String()
}

// denyPlatformServer returns a DENY decision for every call.
type denyPlatformServer struct {
	platform.UnimplementedPlatformServiceServer
	evaluatedPolicy string
}

func (d *denyPlatformServer) GetDecision(_ context.Context, _ *platform.GetDecisionRequest) (*platform.GetDecisionResponse, error) {
	return &platform.GetDecisionResponse{
		Decision:        platform.Decision_DECISION_DENY,
		Reason:          "policy denied by test server",
		Details:         map[string]string{},
		EvaluatedPolicy: d.evaluatedPolicy,
		Timestamp:       timestamppb.Now(),
	}, nil
}

// allowPlatformServerWithPolicy returns an ALLOW decision with an evaluated policy.
type allowPlatformServerWithPolicy struct {
	platform.UnimplementedPlatformServiceServer
	policy string
}

func (a *allowPlatformServerWithPolicy) GetDecision(_ context.Context, _ *platform.GetDecisionRequest) (*platform.GetDecisionResponse, error) {
	return &platform.GetDecisionResponse{
		Decision:        platform.Decision_DECISION_ALLOW,
		Reason:          "access granted",
		Details:         map[string]string{"env": "test"},
		EvaluatedPolicy: a.policy,
		Timestamp:       timestamppb.Now(),
	}, nil
}

func startCustomPlatformGRPCServer(t *testing.T, srv platform.PlatformServiceServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	platform.RegisterPlatformServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		lis.Close()
	})
	return lis.Addr().String()
}

// makeTestJWT creates a minimal unsigned JWT for tests (same approach as mustCreateJWT
// but without the testing.T helper requirement).
func makeTestJWT(claims map[string]interface{}) string {
	header := map[string]string{"alg": "none", "typ": "JWT"}
	headerBytes, _ := json.Marshal(header)
	payloadBytes, _ := json.Marshal(claims)
	return fmt.Sprintf("%s.%s.",
		base64.RawURLEncoding.EncodeToString(headerBytes),
		base64.RawURLEncoding.EncodeToString(payloadBytes),
	)
}

// ctxWithJWT returns a context with a valid bearer JWT injected into gRPC metadata.
func ctxWithJWT(claims map[string]interface{}) context.Context {
	token := makeTestJWT(claims)
	md := metadata.Pairs("authorization", "Bearer "+token)
	return metadata.NewIncomingContext(context.Background(), md)
}

func TestUnit_GRPCPlatformClient_EvaluateAccess_RPCFailure(t *testing.T) {
	addr := startFailingPlatformGRPCServer(t)
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := ctxWithJWT(map[string]interface{}{"sub": "user1", "iss": "test"})

	_, err = client.EvaluateAccess(ctx, map[string]string{"name": "res"}, "wrap_dek", nil)
	if err == nil {
		t.Fatal("expected error from failing platform RPC, got nil")
	}
}

func TestUnit_GRPCPlatformClient_EvaluateAccess_DenyDecision(t *testing.T) {
	addr := startCustomPlatformGRPCServer(t, &denyPlatformServer{evaluatedPolicy: "deny-policy"})
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := ctxWithJWT(map[string]interface{}{"sub": "user-denied", "iss": "test"})

	decision, err := client.EvaluateAccess(ctx, map[string]string{"name": "res"}, "wrap_dek", nil)
	if err != nil {
		t.Fatalf("EvaluateAccess returned unexpected error: %v", err)
	}
	if decision.Granted {
		t.Error("expected Granted=false for DENY decision")
	}
	if decision.Reason != "policy denied by test server" {
		t.Errorf("unexpected reason: %q", decision.Reason)
	}
}

func TestUnit_GRPCPlatformClient_EvaluateAccess_DenyWithNoPolicy(t *testing.T) {
	// Empty evaluatedPolicy — covers the `if resp.EvaluatedPolicy != ""` false branch.
	addr := startCustomPlatformGRPCServer(t, &denyPlatformServer{evaluatedPolicy: ""})
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := ctxWithJWT(map[string]interface{}{"sub": "user-denied", "iss": "test"})

	decision, err := client.EvaluateAccess(ctx, map[string]string{"name": "res"}, "wrap_dek", nil)
	if err != nil {
		t.Fatalf("EvaluateAccess returned unexpected error: %v", err)
	}
	if decision.Granted {
		t.Error("expected Granted=false for DENY decision with no policy")
	}
}

func TestUnit_GRPCPlatformClient_EvaluateAccess_AllowWithPolicy(t *testing.T) {
	addr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "allow-policy"})
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := ctxWithJWT(map[string]interface{}{"sub": "user-allowed", "iss": "test"})

	decision, err := client.EvaluateAccess(ctx, map[string]string{"hash": "abc123"}, "wrap_dek", nil)
	if err != nil {
		t.Fatalf("EvaluateAccess returned unexpected error: %v", err)
	}
	if !decision.Granted {
		t.Error("expected Granted=true for ALLOW decision")
	}
	if len(decision.AppliedRules) == 0 || decision.AppliedRules[0] != "allow-policy" {
		t.Errorf("expected AppliedRules=[allow-policy], got %v", decision.AppliedRules)
	}
}

func TestUnit_GRPCPlatformClient_EvaluateAccess_NoToken(t *testing.T) {
	// No bearer token in context — should return an error and a non-granted decision.
	addr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	decision, evalErr := client.EvaluateAccess(context.Background(), map[string]string{}, "wrap_dek", nil)
	// The function should return a non-granted decision + non-nil error when token extraction fails.
	if evalErr == nil {
		t.Fatal("expected error when no token is present in context, got nil")
	}
	if decision == nil {
		t.Fatal("expected non-nil decision struct")
	}
	if decision.Granted {
		t.Error("expected Granted=false when token extraction fails")
	}
}

// ---------------------------------------------------------------------------
// ensureUnwrapClientKeyID — lookup success path
// ---------------------------------------------------------------------------

func TestUnit_ensureUnwrapClientKeyID_LookupSuccess(t *testing.T) {
	clientPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientKeyID := "unwrap-client-key-lu"

	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{
		clientKeyID: {
			publicKey: &clientPriv.PublicKey,
			clientID:  "user-unwrap",
			status:    keyManager.KeyStatus_KEY_STATUS_ACTIVE,
			createdAt: time.Now(),
		},
	}, map[string]*rsa.PrivateKey{})
	defer kmSrv.cleanup()

	conn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	srv := &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}

	req := &UnwrapDEKRequest{ClientKeyId: ""}
	err = srv.ensureUnwrapClientKeyID(context.Background(), req, "user-unwrap")
	if err != nil {
		t.Fatalf("ensureUnwrapClientKeyID lookup: %v", err)
	}
	if req.ClientKeyId != clientKeyID {
		t.Errorf("expected ClientKeyId=%q, got %q", clientKeyID, req.ClientKeyId)
	}
}

func TestUnit_ensureUnwrapClientKeyID_LookupNoActiveKeys(t *testing.T) {
	// Subject exists but has no active keys.
	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{}, map[string]*rsa.PrivateKey{})
	defer kmSrv.cleanup()

	conn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	srv := &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}

	req := &UnwrapDEKRequest{ClientKeyId: ""}
	err = srv.ensureUnwrapClientKeyID(context.Background(), req, "user-no-keys")
	if err == nil {
		t.Fatal("expected error when subject has no active keys, got nil")
	}
}

// ---------------------------------------------------------------------------
// getEnvOrDefault — set variable path (complement to the unset case in unit2)
// ---------------------------------------------------------------------------

func TestUnit_getEnvOrDefault_ValuePresent(t *testing.T) {
	t.Setenv("__UNIT_TEST_SET_ENV_VAR__", "my-value")
	result := getEnvOrDefault("__UNIT_TEST_SET_ENV_VAR__", "fallback")
	if result != "my-value" {
		t.Errorf("expected %q, got %q", "my-value", result)
	}
}

func TestUnit_getEnv_ValuePresent(t *testing.T) {
	t.Setenv("__UNIT_TEST_PRESENT_ENV_VAR__", "hello-world")
	result := getEnv("__UNIT_TEST_PRESENT_ENV_VAR__")
	if result != "hello-world" {
		t.Errorf("expected %q, got %q", "hello-world", result)
	}
}

// ---------------------------------------------------------------------------
// Server.Close
// ---------------------------------------------------------------------------

func TestUnit_Server_Close_NilConnections(t *testing.T) {
	srv := &Server{}
	err := srv.Close()
	if err != nil {
		t.Errorf("Close with nil connections should return nil, got: %v", err)
	}
}

func TestUnit_Server_Close_WithConnections(t *testing.T) {
	// Build real (but idle) gRPC connections so that Close exercises both branches.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()
	addr := lis.Addr().String()

	kmConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial km: %v", err)
	}
	platformConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		kmConn.Close()
		t.Fatalf("dial platform: %v", err)
	}

	srv := &Server{
		keyManagerConn: kmConn,
		platformConn:   platformConn,
	}
	err = srv.Close()
	if err != nil {
		t.Errorf("Close with live connections returned error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — access-denied path via mock platform that returns DENY
// ---------------------------------------------------------------------------

// buildServerWithDenyPlatform creates a Server whose platform client always denies.
func buildServerWithDenyPlatform(t *testing.T) *Server {
	t.Helper()

	addr := startCustomPlatformGRPCServer(t, &denyPlatformServer{evaluatedPolicy: "deny-policy"})
	platformClient, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = platformClient.Close() })

	// Key manager that returns an active service key.
	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	serviceKeyID := "svc-deny-test-key"
	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{}, map[string]*rsa.PrivateKey{
		serviceKeyID: servicePriv,
	})
	t.Cleanup(kmSrv.cleanup)

	kmConn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial km: %v", err)
	}
	t.Cleanup(func() { kmConn.Close() })

	kmClient := keyManager.NewKeyManagerServiceClient(kmConn)

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: kmClient,
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.serviceKeyCache.Set(serviceKeyID, &servicePriv.PublicKey)
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return kmClient.RewrapClientDEK(ctx, req)
	}
	return srv
}

func TestUnit_WrapDEK_PlatformDenied(t *testing.T) {
	srv := buildServerWithDenyPlatform(t)

	dek := make([]byte, 32)
	rand.Read(dek)

	token := makeTestJWT(map[string]interface{}{"sub": "user1", "iss": "test"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       "svc-deny-test-key",
		ClientKeyId: "client-key",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied when platform returns DENY")
	}
}

func TestUnit_UnwrapDEK_PlatformDenied(t *testing.T) {
	addr := startCustomPlatformGRPCServer(t, &denyPlatformServer{evaluatedPolicy: "deny-policy"})
	platformClient, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = platformClient.Close() })

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	serviceKeyID := "unwrap-deny-key"

	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{}, map[string]*rsa.PrivateKey{
		serviceKeyID: servicePriv,
	})
	t.Cleanup(kmSrv.cleanup)

	kmConn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial km: %v", err)
	}
	t.Cleanup(func() { kmConn.Close() })

	kmClient := keyManager.NewKeyManagerServiceClient(kmConn)
	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: kmClient,
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return kmClient.RewrapClientDEK(ctx, req)
	}

	dek := make([]byte, 16)
	rand.Read(dek)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, dek, nil)

	token := makeTestJWT(map[string]interface{}{"sub": "user1", "iss": "test"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       serviceKeyID,
		ClientKeyId: "client-key",
		Action:      "unwrap_dek",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied when platform returns DENY")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — no active key path (getCurrentActiveKeyID used when KeyId omitted)
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_NoActiveServiceKey(t *testing.T) {
	// Platform allows, but no active service keys → WrapDEK returns denied.
	addr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = platformClient.Close() })

	// Key manager with no keys at all.
	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{}, map[string]*rsa.PrivateKey{})
	t.Cleanup(kmSrv.cleanup)

	kmConn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial km: %v", err)
	}
	t.Cleanup(func() { kmConn.Close() })

	kmClient := keyManager.NewKeyManagerServiceClient(kmConn)
	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: kmClient,
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return kmClient.RewrapClientDEK(ctx, req)
	}

	dek := make([]byte, 32)
	rand.Read(dek)

	token := makeTestJWT(map[string]interface{}{"sub": "user1", "iss": "test"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       "", // force getCurrentActiveKeyID
		ClientKeyId: "client-key",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK returned error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied when no active service key exists")
	}
}

// ---------------------------------------------------------------------------
// dialServiceCredentials — no-TLS path (insecure credentials)
// ---------------------------------------------------------------------------

func TestUnit_dialServiceCredentials_NoTLS(t *testing.T) {
	creds, err := dialServiceCredentials(nil)
	if err != nil {
		t.Fatalf("dialServiceCredentials(nil): %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
}
