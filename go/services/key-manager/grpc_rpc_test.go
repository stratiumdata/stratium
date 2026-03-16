package key_manager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"

	"stratium/pkg/auth"
	"stratium/pkg/security/encryption"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// newBufconnClient creates a bufconn-backed gRPC client connected to the given server.
func newBufconnClient(t *testing.T, server *Server) (KeyManagerServiceClient, func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	RegisterKeyManagerServiceServer(grpcServer, server)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("grpc server exited: %v", err)
		}
	}()
	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	cleanup := func() {
		conn.Close()
		grpcServer.Stop()
		lis.Close()
	}
	return NewKeyManagerServiceClient(conn), cleanup
}

// ctxWithUser returns a context carrying UserClaims for test auth bypass.
func ctxWithUser(sub string) context.Context {
	return context.WithValue(context.Background(), "user_claims", &auth.UserClaims{Sub: sub})
}

// generateRSAPEM returns a 2048-bit RSA public key PEM for test registration.
func generateRSAPEM(t *testing.T) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes}))
}

// ---------------------------------------------------------------------------
// GetProviderInfo
// ---------------------------------------------------------------------------

func TestKeyManagerGRPC_GetProviderInfo_Software(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	resp, err := client.GetProviderInfo(context.Background(), &GetProviderInfoRequest{
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
	})
	if err != nil {
		t.Fatalf("GetProviderInfo error = %v", err)
	}
	if resp.Provider == nil {
		t.Fatal("GetProviderInfo returned nil Provider")
	}
	if resp.Provider.Type != KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE {
		t.Errorf("Provider.Type = %v, want SOFTWARE", resp.Provider.Type)
	}
}

func TestKeyManagerGRPC_GetProviderInfo_UnknownType(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	_, err := client.GetProviderInfo(context.Background(), &GetProviderInfoRequest{
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED,
	})
	if err == nil {
		t.Fatal("GetProviderInfo should return error for unspecified type")
	}
	if status.Code(err) != codes.NotFound {
		t.Errorf("status code = %v, want NotFound", status.Code(err))
	}
}

// ---------------------------------------------------------------------------
// RegisterClientKey
// Note: gRPC transport strips plain context values, so auth-protected RPCs
// are tested by calling server methods directly rather than through the wire.
// ---------------------------------------------------------------------------

func TestKeyManagerGRPC_RegisterClientKey_NoAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RegisterClientKey(context.Background(), &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
	})
	if err != nil {
		t.Fatalf("RegisterClientKey unexpected error = %v", err)
	}
	if resp.Success {
		t.Error("RegisterClientKey should return Success=false without auth claims")
	}
}

func TestKeyManagerGRPC_RegisterClientKey_WithAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RegisterClientKey(ctxWithUser("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-1",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
	})
	if err != nil {
		t.Fatalf("RegisterClientKey error = %v", err)
	}
	if !resp.Success {
		t.Errorf("RegisterClientKey Success=false, msg=%s", resp.ErrorMessage)
	}
	if resp.Key == nil || resp.Key.KeyId == "" {
		t.Error("RegisterClientKey returned nil or empty key ID")
	}
}

func TestKeyManagerGRPC_RegisterClientKey_EmptyPEM(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RegisterClientKey(ctxWithUser("alice"), &RegisterClientKeyRequest{
		PublicKeyPem: "",
		ClientId:     "app-1",
	})
	if err != nil {
		t.Fatalf("RegisterClientKey unexpected error = %v", err)
	}
	if resp.Success {
		t.Error("RegisterClientKey should fail for empty PEM")
	}
}

// ---------------------------------------------------------------------------
// GetClientKey
// ---------------------------------------------------------------------------

func TestKeyManagerGRPC_GetClientKey_ByKeyID(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	// Register via RPC so the integrity hash is set correctly
	regResp, err := srv.RegisterClientKey(ctxWithUser("bob"), &RegisterClientKeyRequest{
		PublicKeyPem: generateRSAPEM(t),
		ClientId:     "app-bob",
	})
	if err != nil || !regResp.Success {
		t.Fatalf("RegisterClientKey failed: err=%v, msg=%s", err, regResp.GetErrorMessage())
	}
	keyID := regResp.Key.KeyId

	resp, err := srv.GetClientKey(ctxWithUser("bob"), &GetClientKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		t.Fatalf("GetClientKey error = %v", err)
	}
	if !resp.Found {
		t.Errorf("GetClientKey Found=false for registered key: %s", resp.ErrorMessage)
	}
	if resp.Key == nil || resp.Key.KeyId != keyID {
		t.Errorf("GetClientKey returned wrong key: %v", resp.Key)
	}
}

func TestKeyManagerGRPC_GetClientKey_WrongOwner(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID := seedClientKey(t, srv, "carol", priv)

	resp, err := srv.GetClientKey(ctxWithUser("mallory"), &GetClientKeyRequest{
		KeyId: keyID,
	})
	if err != nil {
		t.Fatalf("GetClientKey unexpected error = %v", err)
	}
	if resp.Found {
		t.Error("GetClientKey should return Found=false for wrong owner")
	}
}

func TestKeyManagerGRPC_GetClientKey_NotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.GetClientKey(ctxWithUser("dave"), &GetClientKeyRequest{
		KeyId: "nonexistent-key-id",
	})
	if err != nil {
		t.Fatalf("GetClientKey unexpected error = %v", err)
	}
	if resp.Found {
		t.Error("GetClientKey should return Found=false for missing key")
	}
}

// ---------------------------------------------------------------------------
// ListClientKeys
// ---------------------------------------------------------------------------

func TestKeyManagerGRPC_ListClientKeys_Empty(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.ListClientKeys(ctxWithUser("nobody"), &ListClientKeysRequest{})
	if err != nil {
		t.Fatalf("ListClientKeys error = %v", err)
	}
	if len(resp.Keys) != 0 {
		t.Errorf("ListClientKeys len = %d, want 0 for user with no keys", len(resp.Keys))
	}
}

func TestKeyManagerGRPC_ListClientKeys_WithKeys(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	for i := 0; i < 2; i++ {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		seedClientKey(t, srv, "eve", priv)
	}

	resp, err := srv.ListClientKeys(ctxWithUser("eve"), &ListClientKeysRequest{
		IncludeRevoked: false,
	})
	if err != nil {
		t.Fatalf("ListClientKeys error = %v", err)
	}
	if len(resp.Keys) != 2 {
		t.Errorf("ListClientKeys len = %d, want 2", len(resp.Keys))
	}
	if resp.TotalCount != 2 {
		t.Errorf("TotalCount = %d, want 2", resp.TotalCount)
	}
}

func TestKeyManagerGRPC_ListClientKeys_NoAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.ListClientKeys(context.Background(), &ListClientKeysRequest{})
	if err != nil {
		t.Fatalf("ListClientKeys unexpected error = %v", err)
	}
	if len(resp.Keys) != 0 {
		t.Errorf("ListClientKeys should return empty list without auth")
	}
}

// ---------------------------------------------------------------------------
// RevokeClientKey
// ---------------------------------------------------------------------------

func TestKeyManagerGRPC_RevokeClientKey_Success(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID := seedClientKey(t, srv, "frank", priv)

	resp, err := srv.RevokeClientKey(ctxWithUser("frank"), &RevokeClientKeyRequest{
		KeyId:  keyID,
		Reason: "test revocation",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey error = %v", err)
	}
	if !resp.Success {
		t.Errorf("RevokeClientKey Success=false: %s", resp.ErrorMessage)
	}
}

func TestKeyManagerGRPC_RevokeClientKey_WrongOwner(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyID := seedClientKey(t, srv, "grace", priv)

	resp, err := srv.RevokeClientKey(ctxWithUser("attacker"), &RevokeClientKeyRequest{
		KeyId:  keyID,
		Reason: "malicious revoke",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey unexpected error = %v", err)
	}
	if resp.Success {
		t.Error("RevokeClientKey should fail for wrong owner")
	}
}

func TestKeyManagerGRPC_RevokeClientKey_NoAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RevokeClientKey(context.Background(), &RevokeClientKeyRequest{
		KeyId: "some-key",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey unexpected error = %v", err)
	}
	if resp.Success {
		t.Error("RevokeClientKey should fail without auth")
	}
}

func TestKeyManagerGRPC_RevokeClientKey_NotFound(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)

	resp, err := srv.RevokeClientKey(ctxWithUser("henry"), &RevokeClientKeyRequest{
		KeyId:  "does-not-exist",
		Reason: "test",
	})
	if err != nil {
		t.Fatalf("RevokeClientKey unexpected error = %v", err)
	}
	if resp.Success {
		t.Error("RevokeClientKey should fail for non-existent key")
	}
}

// ---------------------------------------------------------------------------
// ListClients
// ---------------------------------------------------------------------------

func TestKeyManagerGRPC_ListClients_Empty(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	resp, err := client.ListClients(context.Background(), &ListClientsRequest{})
	if err != nil {
		t.Fatalf("ListClients error = %v", err)
	}
	if len(resp.Clients) != 0 {
		t.Errorf("ListClients len = %d, want 0 for empty store", len(resp.Clients))
	}
}

func TestKeyManagerGRPC_ListClients_WithClients(t *testing.T) {
	srv := newTestKeyManagerServer(t, encryption.RSA2048)
	client, cleanup := newBufconnClient(t, srv)
	defer cleanup()

	// Seed keys for two distinct clients
	for _, clientID := range []string{"client-a", "client-b"} {
		priv, _ := rsa.GenerateKey(rand.Reader, 2048)
		seedClientKey(t, srv, clientID, priv)
	}

	resp, err := client.ListClients(context.Background(), &ListClientsRequest{})
	if err != nil {
		t.Fatalf("ListClients error = %v", err)
	}
	if len(resp.Clients) != 2 {
		t.Errorf("ListClients len = %d, want 2", len(resp.Clients))
	}
}
