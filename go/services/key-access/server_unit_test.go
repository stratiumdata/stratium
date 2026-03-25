package key_access

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"

	keyManager "stratium/services/key-manager"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newTestServer() *Server {
	return &Server{
		serviceKeyCache: newServiceKeyCache(time.Minute),
	}
}

func generateRSAPublicKeyPEM(t *testing.T, bits int) (string, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal RSA public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(pemBytes), priv
}

func generateECPublicKeyPEM(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal EC public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return string(pemBytes), priv
}

// listKeysMockServer is a minimal gRPC server that only implements ListKeys.
type listKeysMockServer struct {
	keyManager.UnimplementedKeyManagerServiceServer
	keys []*keyManager.Key
	err  error
}

func (m *listKeysMockServer) ListKeys(_ context.Context, _ *keyManager.ListKeysRequest) (*keyManager.ListKeysResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &keyManager.ListKeysResponse{
		Keys:      m.keys,
		Timestamp: timestamppb.Now(),
	}, nil
}

func startListKeysMockGRPCServer(t *testing.T, impl *listKeysMockServer) (addr string, stop func()) {
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

func newServerWithListKeysMock(t *testing.T, impl *listKeysMockServer) *Server {
	t.Helper()
	addr, stop := startListKeysMockGRPCServer(t, impl)
	t.Cleanup(stop)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial list-keys mock: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
}

// ---------------------------------------------------------------------------
// parsePublicKeyPEM
// ---------------------------------------------------------------------------

func TestUnit_parsePublicKeyPEM_RSA(t *testing.T) {
	srv := newTestServer()
	pemData, _ := generateRSAPublicKeyPEM(t, 2048)
	key, err := srv.parsePublicKeyPEM(pemData, keyManager.KeyType_KEY_TYPE_RSA_2048)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM RSA: %v", err)
	}
	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", key)
	}
}

func TestUnit_parsePublicKeyPEM_ECC(t *testing.T) {
	srv := newTestServer()
	pemData, _ := generateECPublicKeyPEM(t)
	key, err := srv.parsePublicKeyPEM(pemData, keyManager.KeyType_KEY_TYPE_ECC_P256)
	if err != nil {
		t.Fatalf("parsePublicKeyPEM EC: %v", err)
	}
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", key)
	}
}

func TestUnit_parsePublicKeyPEM_InvalidPEM(t *testing.T) {
	srv := newTestServer()
	_, err := srv.parsePublicKeyPEM("not a pem block", keyManager.KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error for invalid PEM, got nil")
	}
}

func TestUnit_parsePublicKeyPEM_CorruptDER(t *testing.T) {
	srv := newTestServer()
	corrupt := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage bytes")})
	_, err := srv.parsePublicKeyPEM(string(corrupt), keyManager.KeyType_KEY_TYPE_RSA_2048)
	if err == nil {
		t.Fatal("expected error for corrupt DER, got nil")
	}
}

// ---------------------------------------------------------------------------
// encryptDEK
// ---------------------------------------------------------------------------

func TestUnit_encryptDEK_RSA(t *testing.T) {
	srv := newTestServer()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("random DEK: %v", err)
	}

	encrypted, err := srv.encryptDEK(&priv.PublicKey, dek)
	if err != nil {
		t.Fatalf("encryptDEK RSA: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encryptDEK returned empty ciphertext")
	}

	// Verify round-trip with the private key
	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, encrypted, nil)
	if err != nil {
		t.Fatalf("decrypt RSA OAEP: %v", err)
	}
	for i, b := range dek {
		if decrypted[i] != b {
			t.Errorf("decrypted DEK mismatch at byte %d", i)
		}
	}
}

func TestUnit_encryptDEK_ECC(t *testing.T) {
	srv := newTestServer()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("random DEK: %v", err)
	}

	encrypted, err := srv.encryptDEK(&priv.PublicKey, dek)
	if err != nil {
		t.Fatalf("encryptDEK ECC: %v", err)
	}
	if len(encrypted) == 0 {
		t.Fatal("encryptDEK ECC returned empty ciphertext")
	}
}

type unsupportedKeyType struct{}

func TestUnit_encryptDEK_UnsupportedKeyType(t *testing.T) {
	srv := newTestServer()
	dek := []byte("dek-data")
	_, err := srv.encryptDEK(unsupportedKeyType{}, dek)
	if err == nil {
		t.Fatal("expected error for unsupported key type, got nil")
	}
}

// ---------------------------------------------------------------------------
// decryptDEK / rsaPublicDecrypt
// ---------------------------------------------------------------------------

func TestUnit_decryptDEK_RSA(t *testing.T) {
	srv := newTestServer()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Build PKCS#1 v1.5 signed blob using wrapDEKWithPrivateKey (shared test helper)
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("random data: %v", err)
	}
	ciphertext, err := wrapDEKWithPrivateKey(priv, data)
	if err != nil {
		t.Fatalf("wrapDEKWithPrivateKey: %v", err)
	}

	result, err := srv.decryptDEK(&priv.PublicKey, ciphertext)
	if err != nil {
		t.Fatalf("decryptDEK RSA: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("decryptDEK returned empty plaintext")
	}
}

func TestUnit_decryptDEK_UnsupportedKeyType(t *testing.T) {
	srv := newTestServer()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	_, err = srv.decryptDEK(&priv.PublicKey, []byte("anything"))
	if err == nil {
		t.Fatal("expected error for unsupported key type in decryptDEK, got nil")
	}
}

func TestUnit_rsaPublicDecrypt(t *testing.T) {
	srv := newTestServer()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	data := []byte("hello world")
	ciphertext, err := wrapDEKWithPrivateKey(priv, data)
	if err != nil {
		t.Fatalf("wrapDEKWithPrivateKey: %v", err)
	}

	result, err := srv.rsaPublicDecrypt(&priv.PublicKey, ciphertext)
	if err != nil {
		t.Fatalf("rsaPublicDecrypt: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("rsaPublicDecrypt returned empty result")
	}
}

// ---------------------------------------------------------------------------
// createWrapDeniedResponse
// ---------------------------------------------------------------------------

func TestUnit_createWrapDeniedResponse(t *testing.T) {
	srv := newTestServer()
	req := &WrapDEKRequest{
		Resource: "test-resource",
		Dek:      []byte("dek"),
	}
	reason := "policy denied"
	resp := srv.createWrapDeniedResponse(req, reason)
	if resp == nil {
		t.Fatal("createWrapDeniedResponse returned nil")
	}
	if resp.AccessGranted {
		t.Error("expected AccessGranted=false")
	}
	if resp.AccessReason != reason {
		t.Errorf("expected reason %q, got %q", reason, resp.AccessReason)
	}
	if resp.WrappedDek != nil {
		t.Error("expected WrappedDek to be nil")
	}
	if resp.KeyId != "" {
		t.Errorf("expected empty KeyId, got %q", resp.KeyId)
	}
	if resp.Timestamp == nil {
		t.Error("expected non-nil Timestamp")
	}
	if len(resp.AppliedRules) != 0 {
		t.Errorf("expected empty AppliedRules, got %v", resp.AppliedRules)
	}
}

func TestUnit_createWrapDeniedResponse_EmptyReason(t *testing.T) {
	srv := newTestServer()
	req := &WrapDEKRequest{}
	resp := srv.createWrapDeniedResponse(req, "")
	if resp.AccessGranted {
		t.Error("expected AccessGranted=false")
	}
	if resp.AccessReason != "" {
		t.Errorf("expected empty reason, got %q", resp.AccessReason)
	}
}

// ---------------------------------------------------------------------------
// StoreSubjectPublicKey
// ---------------------------------------------------------------------------

func TestUnit_StoreSubjectPublicKey(t *testing.T) {
	store := NewInMemorySubjectKeyStore()
	ctx := context.Background()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	subject := "unit-test-subject"
	err = store.StoreSubjectPublicKey(ctx, subject, &priv.PublicKey)
	if err != nil {
		t.Fatalf("StoreSubjectPublicKey: %v", err)
	}

	retrieved, err := store.GetSubjectPublicKey(ctx, subject)
	if err != nil {
		t.Fatalf("GetSubjectPublicKey: %v", err)
	}
	rsaKey, ok := retrieved.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", retrieved)
	}
	if rsaKey.N.Cmp(priv.PublicKey.N) != 0 {
		t.Error("retrieved key modulus does not match stored key")
	}
}

func TestUnit_StoreSubjectPublicKey_Overwrite(t *testing.T) {
	store := NewInMemorySubjectKeyStore()
	ctx := context.Background()
	subject := "overwrite-subject"

	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)

	_ = store.StoreSubjectPublicKey(ctx, subject, &priv1.PublicKey)
	_ = store.StoreSubjectPublicKey(ctx, subject, &priv2.PublicKey)

	retrieved, err := store.GetSubjectPublicKey(ctx, subject)
	if err != nil {
		t.Fatalf("GetSubjectPublicKey after overwrite: %v", err)
	}
	rsaKey, _ := retrieved.(*rsa.PublicKey)
	if rsaKey.N.Cmp(priv2.PublicKey.N) != 0 {
		t.Error("expected second key to be stored after overwrite")
	}
}

// ---------------------------------------------------------------------------
// getCurrentActiveKeyID
// ---------------------------------------------------------------------------

func TestUnit_getCurrentActiveKeyID_ActiveKey(t *testing.T) {
	activeKey := &keyManager.Key{
		KeyId:  "active-key-1",
		Status: keyManager.KeyStatus_KEY_STATUS_ACTIVE,
	}
	srv := newServerWithListKeysMock(t, &listKeysMockServer{keys: []*keyManager.Key{activeKey}})

	keyID, err := srv.getCurrentActiveKeyID(context.Background())
	if err != nil {
		t.Fatalf("getCurrentActiveKeyID: %v", err)
	}
	if keyID != "active-key-1" {
		t.Errorf("expected key ID %q, got %q", "active-key-1", keyID)
	}
}

func TestUnit_getCurrentActiveKeyID_NoKeys(t *testing.T) {
	srv := newServerWithListKeysMock(t, &listKeysMockServer{keys: []*keyManager.Key{}})

	_, err := srv.getCurrentActiveKeyID(context.Background())
	if err == nil {
		t.Fatal("expected error when no keys available, got nil")
	}
}

func TestUnit_getCurrentActiveKeyID_NoActiveKeys(t *testing.T) {
	inactiveKey := &keyManager.Key{
		KeyId:  "inactive-key-1",
		Status: keyManager.KeyStatus_KEY_STATUS_INACTIVE,
	}
	srv := newServerWithListKeysMock(t, &listKeysMockServer{keys: []*keyManager.Key{inactiveKey}})

	_, err := srv.getCurrentActiveKeyID(context.Background())
	if err == nil {
		t.Fatal("expected error when no active keys found, got nil")
	}
}

func TestUnit_getCurrentActiveKeyID_RPCError(t *testing.T) {
	srv := newServerWithListKeysMock(t, &listKeysMockServer{err: fmt.Errorf("database unavailable")})

	_, err := srv.getCurrentActiveKeyID(context.Background())
	if err == nil {
		t.Fatal("expected error when RPC fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// ensureUnwrapClientKeyID
// ---------------------------------------------------------------------------

func TestUnit_ensureUnwrapClientKeyID_AlreadySet(t *testing.T) {
	// When ClientKeyId is already populated, ensureUnwrapClientKeyID must return nil
	// without calling the key manager.
	srv := newTestServer() // no keyManagerClient needed
	req := &UnwrapDEKRequest{ClientKeyId: "existing-key-id"}
	err := srv.ensureUnwrapClientKeyID(context.Background(), req, "user123")
	if err != nil {
		t.Fatalf("ensureUnwrapClientKeyID with existing key ID: %v", err)
	}
	if req.ClientKeyId != "existing-key-id" {
		t.Errorf("ClientKeyId should be unchanged, got %q", req.ClientKeyId)
	}
}

func TestUnit_ensureUnwrapClientKeyID_EmptyClientKeyID_LookupFails(t *testing.T) {
	// When ClientKeyId is empty and the key manager returns no keys, expect an error.
	srv := newServerWithListKeysMock(t, &listKeysMockServer{
		keys: []*keyManager.Key{}, // no client keys for the subject
	})

	// Override the keyManagerClient with one that returns no client keys for ListClientKeys
	// by wiring to a mockKeyManagerServer with an empty map.
	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{}, map[string]*rsa.PrivateKey{})
	defer kmSrv.cleanup()

	conn, err := grpc.NewClient(kmAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	srv.keyManagerClient = keyManager.NewKeyManagerServiceClient(conn)

	req := &UnwrapDEKRequest{ClientKeyId: ""} // intentionally empty
	err = srv.ensureUnwrapClientKeyID(context.Background(), req, "user-with-no-keys")
	if err == nil {
		t.Fatal("expected error when lookup finds no active client keys, got nil")
	}
}
