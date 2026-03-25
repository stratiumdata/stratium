//go:build !fips

package key_access

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"testing"
	"time"

	"stratium/config"
	keyManager "stratium/services/key-manager"
	platform "stratium/services/platform"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cloudflare/circl/kem/kyber/kyber512"
)

// ---------------------------------------------------------------------------
// createAuthServiceFromConfig — error paths
// ---------------------------------------------------------------------------

func TestUnit_createAuthServiceFromConfig_NilConfig(t *testing.T) {
	_, err := createAuthServiceFromConfig(nil)
	if err == nil {
		t.Fatal("expected error for nil OIDC config, got nil")
	}
}

func TestUnit_createAuthServiceFromConfig_EmptyIssuerURL(t *testing.T) {
	cfg := &config.OIDCConfig{
		IssuerURL: "",
		ClientID:  "client",
	}
	_, err := createAuthServiceFromConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty IssuerURL, got nil")
	}
}

func TestUnit_createAuthServiceFromConfig_EmptyClientID(t *testing.T) {
	cfg := &config.OIDCConfig{
		IssuerURL: "https://example.com",
		ClientID:  "",
	}
	_, err := createAuthServiceFromConfig(cfg)
	if err == nil {
		t.Fatal("expected error for empty ClientID, got nil")
	}
}

func TestUnit_createAuthServiceFromConfig_UnreachableIssuer(t *testing.T) {
	// Provide valid-looking config but unreachable issuer so NewAuthService fails.
	cfg := &config.OIDCConfig{
		IssuerURL: "https://localhost:1/unreachable-issuer",
		ClientID:  "test-client",
	}
	_, err := createAuthServiceFromConfig(cfg)
	if err == nil {
		t.Fatal("expected error for unreachable OIDC issuer, got nil")
	}
}

// ---------------------------------------------------------------------------
// GetAuthService
// ---------------------------------------------------------------------------

func TestUnit_GetAuthService_Nil(t *testing.T) {
	srv := &Server{authService: nil}
	if srv.GetAuthService() != nil {
		t.Error("expected nil auth service")
	}
}

// ---------------------------------------------------------------------------
// dialServiceCredentials — non-nil endpoint with TLS disabled
// ---------------------------------------------------------------------------

func TestUnit_dialServiceCredentials_EndpointTLSDisabled(t *testing.T) {
	endpoint := &config.ServiceEndpoint{
		Address: "localhost:9999",
		TLS: config.TLSConfig{
			Enabled: false,
		},
	}
	creds, err := dialServiceCredentials(endpoint)
	if err != nil {
		t.Fatalf("dialServiceCredentials with TLS disabled: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
}

// ---------------------------------------------------------------------------
// getServicePublicKey — bad PEM after fetch (forces parsePublicKeyPEM failure)
// ---------------------------------------------------------------------------

// badPEMGetKeyMockServer returns a key response with invalid PEM data.
type badPEMGetKeyMockServer struct {
	keyManager.UnimplementedKeyManagerServiceServer
	keyID   string
	keyType keyManager.KeyType
}

func (m *badPEMGetKeyMockServer) GetKey(_ context.Context, req *keyManager.GetKeyRequest) (*keyManager.GetKeyResponse, error) {
	if req.GetKeyId() != m.keyID {
		return nil, fmt.Errorf("unknown key %s", req.GetKeyId())
	}
	return &keyManager.GetKeyResponse{
		Key: &keyManager.Key{
			KeyId:        m.keyID,
			KeyType:      m.keyType,
			PublicKeyPem: "not-valid-pem-at-all",
			Status:       keyManager.KeyStatus_KEY_STATUS_ACTIVE,
		},
	}, nil
}

func startBadPEMGetKeyGRPCServer(t *testing.T, impl *badPEMGetKeyMockServer) (addr string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, impl)
	go func() { _ = gs.Serve(lis) }()
	return lis.Addr().String(), func() {
		gs.Stop()
		lis.Close()
	}
}

func TestUnit_getServicePublicKey_ParseFailure(t *testing.T) {
	impl := &badPEMGetKeyMockServer{
		keyID:   "bad-pem-key",
		keyType: keyManager.KeyType_KEY_TYPE_RSA_2048,
	}
	addr, stop := startBadPEMGetKeyGRPCServer(t, impl)
	t.Cleanup(stop)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	srv := &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}

	_, err = srv.getServicePublicKey(context.Background(), "bad-pem-key")
	if err == nil {
		t.Fatal("expected error when PEM is invalid, got nil")
	}
}

// ---------------------------------------------------------------------------
// parsePublicKeyPEM — Kyber key type via full parsePublicKeyPEM function
// ---------------------------------------------------------------------------

func TestUnit_parsePublicKeyPEM_Kyber512(t *testing.T) {
	// Kyber512 keys use raw binary marshaling, wrapped in a PEM block.
	pub, _, err := kyber512.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	// Wrap in PEM so parsePublicKeyPEM can decode it.
	pemStr := "-----BEGIN PUBLIC KEY-----\n" +
		base64.StdEncoding.EncodeToString(pubBytes) + "\n" +
		"-----END PUBLIC KEY-----\n"

	srv := newTestServer()
	key, err := srv.parsePublicKeyPEM(pemStr, keyManager.KeyType_KEY_TYPE_KYBER_512)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM Kyber512: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil Kyber512 public key")
	}
}

// ---------------------------------------------------------------------------
// lookupLatestClientKeyID — active key with nil CreatedAt timestamp
// ---------------------------------------------------------------------------

// nilCreatedAtListClientKeys returns keys where CreatedAt is nil.
type nilCreatedAtListClientKeys struct {
	keyManager.UnimplementedKeyManagerServiceServer
}

func (m *nilCreatedAtListClientKeys) ListClientKeys(_ context.Context, _ *keyManager.ListClientKeysRequest) (*keyManager.ListClientKeysResponse, error) {
	return &keyManager.ListClientKeysResponse{
		Keys: []*keyManager.Key{
			{
				KeyId:     "nil-ts-key",
				Status:    keyManager.KeyStatus_KEY_STATUS_ACTIVE,
				CreatedAt: nil, // explicitly nil
			},
		},
		Timestamp: timestamppb.Now(),
	}, nil
}

func TestUnit_lookupLatestClientKeyID_NilCreatedAt(t *testing.T) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &nilCreatedAtListClientKeys{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() {
		gs.Stop()
		lis.Close()
	})

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	srv := &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}

	keyID, err := srv.lookupLatestClientKeyID(context.Background(), "user123")
	if err != nil {
		t.Fatalf("lookupLatestClientKeyID with nil CreatedAt: %v", err)
	}
	if keyID != "nil-ts-key" {
		t.Errorf("expected key ID %q, got %q", "nil-ts-key", keyID)
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — preferred_username branch and service key ID update from rewrap
// ---------------------------------------------------------------------------

// buildServerForWrapTests creates a Server wired to a mock key manager and
// an allow-all platform client.  The service key is pre-seeded into the cache.
func buildServerForWrapTests(t *testing.T, clientKeys map[string]*mockClientKey, servicePriv *rsa.PrivateKey, serviceKeyID string) *Server {
	t.Helper()

	serviceKeys := map[string]*rsa.PrivateKey{}
	if servicePriv != nil {
		serviceKeys[serviceKeyID] = servicePriv
	}

	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, clientKeys, serviceKeys)
	t.Cleanup(kmSrv.cleanup)

	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "test-policy"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

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
	if servicePriv != nil {
		srv.serviceKeyCache.Set(serviceKeyID, &servicePriv.PublicKey)
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return kmClient.RewrapClientDEK(ctx, req)
	}
	return srv
}

// ctxWithPreferredUsername creates a context bearing a JWT with both sub and preferred_username.
func ctxWithPreferredUsername(sub, preferredUsername string) context.Context {
	claims := map[string]interface{}{
		"sub":                sub,
		"preferred_username": preferredUsername,
	}
	token := makeTestJWT(claims)
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	return context.WithValue(ctx, "user_token", token)
}

func TestUnit_WrapDEK_PreferredUsernameUsed(t *testing.T) {
	// Setup: a client key registered under "user123" (the sub), preferred_username is "john.doe".
	clientPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientKeyID := "wrap-pref-client-key"
	serviceKeyID := "wrap-pref-service-key"

	srv := buildServerForWrapTests(t, map[string]*mockClientKey{
		clientKeyID: {
			publicKey: &clientPriv.PublicKey,
			clientID:  "user123",
			status:    keyManager.KeyStatus_KEY_STATUS_ACTIVE,
			createdAt: time.Now(),
		},
	}, servicePriv, serviceKeyID)

	dek := make([]byte, 32)
	rand.Read(dek)
	clientWrapped, err := wrapDEKWithPrivateKey(clientPriv, dek)
	if err != nil {
		t.Fatalf("wrap DEK: %v", err)
	}

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	ctx := ctxWithPreferredUsername("user123", "john.doe")

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         clientWrapped,
		Action:      "wrap_dek",
		KeyId:       serviceKeyID,
		ClientKeyId: clientKeyID,
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	// Platform is allow-all so access should be granted.
	if !resp.AccessGranted {
		t.Errorf("expected WrapDEK to be granted for user with preferred_username, got denied: %s", resp.AccessReason)
	}
}

func TestUnit_WrapDEK_ServiceKeyIDUpdatedFromRewrapResponse(t *testing.T) {
	// The rewrap mock returns a different service key ID in the response.
	// This exercises the `if rewrapResp.GetServiceKeyId() != ""` branch.
	clientPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientKeyID := "upd-client-key"
	serviceKeyID := "upd-service-key-original"
	updatedKeyID := "upd-service-key-new"

	// Use allow-all platform.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	srv := &Server{
		platformClient:  platformClient,
		serviceKeyCache: newServiceKeyCache(time.Minute),
	}
	srv.serviceKeyCache.Set(serviceKeyID, &servicePriv.PublicKey)

	// Override rewrapClientDEK to return a different service key ID.
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		wrapped, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, []byte("dek"), nil)
		return &keyManager.RewrapClientDEKResponse{
			ServiceWrappedDek: wrapped,
			ServiceKeyId:      updatedKeyID, // different from requested
			Timestamp:         timestamppb.Now(),
		}, nil
	}

	// Need a key manager client for the ListClientKeys path (even if it's not hit here
	// because clientKeyID is provided). Use a simple mock.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial km: %v", err)
	}
	t.Cleanup(func() { kmConn.Close() })
	srv.keyManagerClient = keyManager.NewKeyManagerServiceClient(kmConn)

	dek := make([]byte, 32)
	rand.Read(dek)
	clientWrapped, _ := wrapDEKWithPrivateKey(clientPriv, dek)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))
	ctx := ctxWithPreferredUsername("user123", "john.doe")

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         clientWrapped,
		Action:      "wrap_dek",
		KeyId:       serviceKeyID,
		ClientKeyId: clientKeyID,
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if !resp.AccessGranted {
		t.Fatalf("expected access granted, got denied: %s", resp.AccessReason)
	}
	if resp.KeyId != updatedKeyID {
		t.Errorf("expected KeyId=%q (from rewrap response), got %q", updatedKeyID, resp.KeyId)
	}
}

// ---------------------------------------------------------------------------
// UnwrapDEK — key manager returns AccessGranted=false
// ---------------------------------------------------------------------------

// denyUnwrapKeyManagerServer returns AccessGranted=false for UnwrapDEK calls.
type denyUnwrapKeyManagerServer struct {
	keyManager.UnimplementedKeyManagerServiceServer
	reason string
}

func (m *denyUnwrapKeyManagerServer) UnwrapDEK(_ context.Context, _ *keyManager.UnwrapDEKRequest) (*keyManager.UnwrapDEKResponse, error) {
	return &keyManager.UnwrapDEKResponse{
		AccessGranted: false,
		AccessReason:  m.reason,
		Timestamp:     timestamppb.Now(),
	}, nil
}

func startDenyUnwrapKeyManagerGRPCServer(t *testing.T, impl *denyUnwrapKeyManagerServer) (addr string, stop func()) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, impl)
	go func() { _ = gs.Serve(lis) }()
	return lis.Addr().String(), func() {
		gs.Stop()
		lis.Close()
	}
}

func TestUnit_UnwrapDEK_KeyManagerDenies(t *testing.T) {
	// Platform allows, but key manager denies the unwrap.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	denyKmImpl := &denyUnwrapKeyManagerServer{reason: "key manager policy denied"}
	kmAddr, stopKm := startDenyUnwrapKeyManagerGRPCServer(t, denyKmImpl)
	t.Cleanup(stopKm)

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

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, make([]byte, 16), nil)

	token := makeTestJWT(map[string]interface{}{"sub": "user1", "iss": "test"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       "any-key-id",
		ClientKeyId: "any-client-key",
		Action:      "unwrap_dek",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied when key manager denies")
	}
	if resp.AccessReason != "key manager policy denied" {
		t.Errorf("expected reason %q, got %q", "key manager policy denied", resp.AccessReason)
	}
}

// ---------------------------------------------------------------------------
// UnwrapDEK — preferred_username branch
// ---------------------------------------------------------------------------

func TestUnit_UnwrapDEK_WithPreferredUsername(t *testing.T) {
	// Platform allows, key manager denies (but the preferred_username path is covered).
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	denyKmImpl := &denyUnwrapKeyManagerServer{reason: "key manager denied"}
	kmAddr, stopKm := startDenyUnwrapKeyManagerGRPCServer(t, denyKmImpl)
	t.Cleanup(stopKm)

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

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, make([]byte, 16), nil)

	// Use a JWT with both sub and preferred_username.
	token := makeTestJWT(map[string]interface{}{
		"sub":                "user1",
		"preferred_username": "john.doe",
	})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       "any-key-id",
		ClientKeyId: "any-client-key",
		Action:      "unwrap_dek",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK error: %v", err)
	}
	// Key manager denies, so AccessGranted should be false.
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied (key manager denies)")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — ensureWrapClientKeyID failure path (lookupLatestClientKeyID fails)
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_EnsureWrapClientKeyID_Fails(t *testing.T) {
	// Platform allows, client key ID is empty, and the key manager has no active
	// client keys for the subject → should return a denied response.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	// Key manager with no client keys.
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

	token := makeTestJWT(map[string]interface{}{"sub": "user-no-keys"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       "some-key",
		ClientKeyId: "", // intentionally empty to trigger lookup
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied when ensureWrapClientKeyID fails")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — validateWrapRequest failure (empty DEK via actual WrapDEK flow)
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_ValidateFailure_EmptyDEK(t *testing.T) {
	// This exercises the validateWrapRequest error path inside WrapDEK.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial km: %v", err)
	}
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("should not be called")
	}

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         nil, // empty DEK should fail validateWrapRequest
		Action:      "wrap_dek",
		KeyId:       "some-key",
		ClientKeyId: "client-key",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied for empty DEK")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — resource extraction failure (bad policy base64)
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_BadPolicyBase64(t *testing.T) {
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("should not be called")
	}

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	dek := make([]byte, 32)
	rand.Read(dek)

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       "some-key",
		ClientKeyId: "client-key",
		Policy:      "!!!not-valid-base64!!!", // invalid policy
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied for bad policy")
	}
}

// ---------------------------------------------------------------------------
// UnwrapDEK — ensureUnwrapClientKeyID failure path
// ---------------------------------------------------------------------------

func TestUnit_UnwrapDEK_EnsureUnwrapClientKeyID_Fails(t *testing.T) {
	// Client key ID is empty and subject has no active keys.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

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

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, make([]byte, 16), nil)

	token := makeTestJWT(map[string]interface{}{"sub": "user-no-client-keys"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       "any-key-id",
		ClientKeyId: "", // empty to trigger lookup failure
		Action:      "unwrap_dek",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied when ensureUnwrapClientKeyID fails")
	}
}

// ---------------------------------------------------------------------------
// UnwrapDEK — bad policy (resource extraction failure)
// ---------------------------------------------------------------------------

func TestUnit_UnwrapDEK_BadPolicy(t *testing.T) {
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("should not be called")
	}

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, make([]byte, 16), nil)

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       "key-id",
		ClientKeyId: "client-key",
		Action:      "unwrap_dek",
		Policy:      "!!!bad-base64!!!", // bad policy
	})
	if err != nil {
		t.Fatalf("UnwrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied for bad policy")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — ABAC evaluation failure path
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_ABACEvaluationFailure(t *testing.T) {
	// Use a failing platform server so EvaluateAccess returns an error.
	platformAddr := startFailingPlatformGRPCServer(t)
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("should not be called")
	}

	dek := make([]byte, 32)
	rand.Read(dek)

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       "some-key",
		ClientKeyId: "client-key",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied when ABAC evaluation fails")
	}
}

// ---------------------------------------------------------------------------
// UnwrapDEK — ABAC evaluation failure path
// ---------------------------------------------------------------------------

func TestUnit_UnwrapDEK_ABACEvaluationFailure(t *testing.T) {
	platformAddr := startFailingPlatformGRPCServer(t)
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("should not be called")
	}

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, make([]byte, 16), nil)

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       "key-id",
		ClientKeyId: "client-key",
		Action:      "unwrap_dek",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied when ABAC evaluation fails")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — getServicePublicKey failure path
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_GetServicePublicKeyFailure(t *testing.T) {
	// Platform allows, but the key manager returns an error for GetKey.
	// This exercises the `if _, err := s.getServicePublicKey(...)` failure branch.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	// Key manager that errors on GetKey.
	getKeyErrImpl := &getKeyMockServer{
		err: fmt.Errorf("key storage unavailable"),
	}
	addr, stop := startGetKeyMockGRPCServer(t, getKeyErrImpl)
	t.Cleanup(stop)

	kmConn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
		return nil, fmt.Errorf("should not be called")
	}

	dek := make([]byte, 32)
	rand.Read(dek)

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       "missing-key",
		ClientKeyId: "client-key",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied when getServicePublicKey fails")
	}
}

// ---------------------------------------------------------------------------
// WrapDEK — rewrapClientDEK failure path
// ---------------------------------------------------------------------------

func TestUnit_WrapDEK_RewrapClientDEKFailure(t *testing.T) {
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	serviceKeyID := "rewrap-fail-key"

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &keyManager.UnimplementedKeyManagerServiceServer{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.serviceKeyCache.Set(serviceKeyID, &servicePriv.PublicKey)
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("rewrap failed: internal error")
	}

	dek := make([]byte, 32)
	rand.Read(dek)

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.WrapDEK(ctx, &WrapDEKRequest{
		Resource:    "res",
		Dek:         dek,
		Action:      "wrap_dek",
		KeyId:       serviceKeyID,
		ClientKeyId: "client-key",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("WrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected WrapDEK to be denied when rewrapClientDEK fails")
	}
}

// ---------------------------------------------------------------------------
// UnwrapDEK — key manager RPC error path
// ---------------------------------------------------------------------------

func TestUnit_UnwrapDEK_KeyManagerRPCError(t *testing.T) {
	// Platform allows, but the key manager returns an error for UnwrapDEK.
	platformAddr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	platformClient, err := NewGRPCPlatformClient(platformAddr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { platformClient.Close() })

	// Key manager that errors on UnwrapDEK.
	type errorUnwrapKM struct {
		keyManager.UnimplementedKeyManagerServiceServer
	}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	keyManager.RegisterKeyManagerServiceServer(gs, &errorUnwrapKM{})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); lis.Close() })

	kmConn, _ := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	t.Cleanup(func() { kmConn.Close() })

	srv := &Server{
		platformClient:   platformClient,
		keyManagerClient: keyManager.NewKeyManagerServiceClient(kmConn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
	srv.rewrapClientDEK = func(ctx context.Context, req *keyManager.RewrapClientDEKRequest) (*keyManager.RewrapClientDEKResponse, error) {
		return nil, fmt.Errorf("should not be called")
	}

	servicePriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	wrappedDEK, _ := rsa.EncryptOAEP(sha256.New(), rand.Reader, &servicePriv.PublicKey, make([]byte, 16), nil)

	token := makeTestJWT(map[string]interface{}{"sub": "user1"})
	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = context.WithValue(ctx, "user_token", token)

	policyB64 := base64.StdEncoding.EncodeToString([]byte(`{"body":{"dataAttributes":[{"attribute":"http://example.com/attr/name/value/res"}]}}`))

	resp, err := srv.UnwrapDEK(ctx, &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  wrappedDEK,
		KeyId:       "key-id",
		ClientKeyId: "client-key",
		Action:      "unwrap_dek",
		Policy:      policyB64,
	})
	if err != nil {
		t.Fatalf("UnwrapDEK error: %v", err)
	}
	if resp.AccessGranted {
		t.Error("expected UnwrapDEK to be denied when key manager RPC errors")
	}
}

// ---------------------------------------------------------------------------
// serviceKeyCache — expired entry cleanup (the delete-under-write-lock branch)
// ---------------------------------------------------------------------------

func TestUnit_serviceKeyCache_ExpiredEntryCleanup(t *testing.T) {
	// Use a very short TTL so entry expires before second Get call.
	cache := newServiceKeyCache(5 * time.Millisecond)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache.Set("evict-key", &priv.PublicKey)

	// Let it expire.
	time.Sleep(15 * time.Millisecond)

	// First Get after expiry should trigger the delete-under-write-lock branch.
	_, ok := cache.Get("evict-key")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}

	// Second Get should also miss (entry was cleaned up).
	_, ok = cache.Get("evict-key")
	if ok {
		t.Error("expected cache miss after eviction")
	}
}

// ---------------------------------------------------------------------------
// startKeyAccessSpan — nil tracer branch (keyAccessTracer == nil)
// ---------------------------------------------------------------------------

func TestUnit_startKeyAccessSpan_NilTracer(t *testing.T) {
	// Temporarily nil out the tracer to exercise the nil-tracer fallback branch.
	origTracer := keyAccessTracer
	keyAccessTracer = nil
	defer func() { keyAccessTracer = origTracer }()

	ctx, span := startKeyAccessSpan(context.Background(), "nil-tracer-test")
	span.End()
	if ctx == nil {
		t.Error("expected non-nil context even with nil tracer")
	}
}

// ---------------------------------------------------------------------------
// createPlatformClient — empty address returns error
// ---------------------------------------------------------------------------

func TestUnit_createPlatformClient_EmptyAddress(t *testing.T) {
	cfg := &config.ServiceEndpoint{Address: ""}
	_, _, err := createPlatformClient(cfg)
	if err == nil {
		t.Fatal("expected error for empty platform address, got nil")
	}
}

// ---------------------------------------------------------------------------
// GRPCPlatformClient.EvaluateAccess — JWT extraction failure path
// ---------------------------------------------------------------------------

func TestUnit_GRPCPlatformClient_EvaluateAccess_JWTExtractionFailure(t *testing.T) {
	// No token at all in context → ExtractTokenFromMetadata fails.
	addr := startCustomPlatformGRPCServer(t, &allowPlatformServerWithPolicy{policy: "p"})
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	// context.Background() has no metadata, so token extraction will fail.
	decision, evalErr := client.EvaluateAccess(context.Background(), map[string]string{}, "action", nil)
	if evalErr == nil {
		t.Fatal("expected error from EvaluateAccess with no token, got nil")
	}
	if decision == nil {
		t.Fatal("expected non-nil decision on error")
	}
	if decision.Granted {
		t.Error("expected Granted=false when JWT extraction fails")
	}
}

// ---------------------------------------------------------------------------
// platform client — allow decision with nil Details map
// ---------------------------------------------------------------------------

type allowPlatformServerNilDetails struct {
	platform.UnimplementedPlatformServiceServer
}

func (a *allowPlatformServerNilDetails) GetDecision(_ context.Context, _ *platform.GetDecisionRequest) (*platform.GetDecisionResponse, error) {
	return &platform.GetDecisionResponse{
		Decision:        platform.Decision_DECISION_ALLOW,
		Reason:          "allowed",
		Details:         nil, // nil details
		EvaluatedPolicy: "",  // empty policy — covers the `!= ""` false branch
		Timestamp:       timestamppb.Now(),
	}, nil
}

func TestUnit_GRPCPlatformClient_EvaluateAccess_NilDetails(t *testing.T) {
	addr := startCustomPlatformGRPCServer(t, &allowPlatformServerNilDetails{})
	client, err := NewGRPCPlatformClient(addr, nil)
	if err != nil {
		t.Fatalf("NewGRPCPlatformClient: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	ctx := ctxWithJWT(map[string]interface{}{"sub": "user1", "iss": "test"})
	decision, err := client.EvaluateAccess(ctx, map[string]string{"name": "res"}, "wrap_dek", nil)
	if err != nil {
		t.Fatalf("EvaluateAccess error: %v", err)
	}
	if !decision.Granted {
		t.Error("expected Granted=true")
	}
}
