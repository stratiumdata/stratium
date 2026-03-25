//go:build !fips

package key_access

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	keyManager "stratium/services/key-manager"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// ---------------------------------------------------------------------------
// isFIPSKeyTypeAllowed
// ---------------------------------------------------------------------------

func TestUnit_isFIPSKeyTypeAllowed_RSATypes(t *testing.T) {
	allowedTypes := []keyManager.KeyType{
		keyManager.KeyType_KEY_TYPE_RSA_2048,
		keyManager.KeyType_KEY_TYPE_RSA_3072,
		keyManager.KeyType_KEY_TYPE_RSA_4096,
	}
	for _, kt := range allowedTypes {
		if !isFIPSKeyTypeAllowed(kt) {
			t.Errorf("isFIPSKeyTypeAllowed(%v) = false, want true", kt)
		}
	}
}

func TestUnit_isFIPSKeyTypeAllowed_NonRSATypes(t *testing.T) {
	disallowedTypes := []keyManager.KeyType{
		keyManager.KeyType_KEY_TYPE_ECC_P256,
		keyManager.KeyType_KEY_TYPE_ECC_P384,
		keyManager.KeyType_KEY_TYPE_ECC_P521,
		keyManager.KeyType_KEY_TYPE_KYBER_512,
		keyManager.KeyType_KEY_TYPE_KYBER_768,
		keyManager.KeyType_KEY_TYPE_KYBER_1024,
		keyManager.KeyType_KEY_TYPE_UNSPECIFIED,
	}
	for _, kt := range disallowedTypes {
		if isFIPSKeyTypeAllowed(kt) {
			t.Errorf("isFIPSKeyTypeAllowed(%v) = true, want false", kt)
		}
	}
}

// ---------------------------------------------------------------------------
// encryptDEKWithSharedSecret
// ---------------------------------------------------------------------------

func TestUnit_encryptDEKWithSharedSecret_HappyPath(t *testing.T) {
	srv := newTestServer()

	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand.Read dek: %v", err)
	}
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("rand.Read sharedSecret: %v", err)
	}
	kemCiphertext := []byte("kem-ciphertext-prefix")

	result, err := srv.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	if err != nil {
		t.Fatalf("encryptDEKWithSharedSecret: %v", err)
	}

	// Result must be non-empty
	if len(result) == 0 {
		t.Fatal("encryptDEKWithSharedSecret returned empty result")
	}

	// Result must start with the KEM ciphertext prefix
	if !bytes.HasPrefix(result, kemCiphertext) {
		t.Errorf("result does not start with kemCiphertext prefix; got len=%d, prefix len=%d", len(result), len(kemCiphertext))
	}

	// There must be additional bytes beyond the prefix (the AES-GCM ciphertext)
	if len(result) <= len(kemCiphertext) {
		t.Error("result should contain more bytes than just the KEM ciphertext")
	}
}

func TestUnit_encryptDEKWithSharedSecret_LargerSharedSecret(t *testing.T) {
	// sharedSecret longer than 32 bytes — only first 32 bytes are used
	srv := newTestServer()

	dek := make([]byte, 16)
	rand.Read(dek)
	sharedSecret := make([]byte, 64)
	rand.Read(sharedSecret)
	kemCiphertext := []byte("ct")

	result, err := srv.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	if err != nil {
		t.Fatalf("encryptDEKWithSharedSecret with 64-byte secret: %v", err)
	}
	if !bytes.HasPrefix(result, kemCiphertext) {
		t.Error("result should start with kemCiphertext")
	}
}

func TestUnit_encryptDEKWithSharedSecret_DeterministicPrefixNonceVariance(t *testing.T) {
	// Two calls with the same inputs should produce different ciphertexts (random nonce)
	// but both must start with the same KEM ciphertext.
	srv := newTestServer()

	dek := make([]byte, 32)
	rand.Read(dek)
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)
	kemCiphertext := []byte("fixed-kem-ct")

	result1, err1 := srv.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	result2, err2 := srv.encryptDEKWithSharedSecret(dek, sharedSecret, kemCiphertext)
	if err1 != nil || err2 != nil {
		t.Fatalf("encryptDEKWithSharedSecret errors: %v, %v", err1, err2)
	}

	if !bytes.HasPrefix(result1, kemCiphertext) || !bytes.HasPrefix(result2, kemCiphertext) {
		t.Error("both results should start with kemCiphertext")
	}
	// Because nonce is random, the two results should differ
	if bytes.Equal(result1, result2) {
		t.Error("two calls with same inputs should produce different ciphertexts (random nonce)")
	}
}

// ---------------------------------------------------------------------------
// encryptDEKWithKyber
// ---------------------------------------------------------------------------

func TestUnit_encryptDEKWithKyber_Kyber512(t *testing.T) {
	srv := newTestServer()
	pub, _, err := kyber512.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber512: %v", err)
	}
	dek := make([]byte, 32)
	rand.Read(dek)

	result, handled, err := srv.encryptDEKWithKyber(pub, dek)
	if err != nil {
		t.Fatalf("encryptDEKWithKyber Kyber512: %v", err)
	}
	if !handled {
		t.Error("expected handled=true for kyber512.PublicKey")
	}
	if len(result) == 0 {
		t.Error("encryptDEKWithKyber Kyber512 returned empty result")
	}
}

func TestUnit_encryptDEKWithKyber_Kyber768(t *testing.T) {
	srv := newTestServer()
	pub, _, err := kyber768.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber768: %v", err)
	}
	dek := make([]byte, 32)
	rand.Read(dek)

	result, handled, err := srv.encryptDEKWithKyber(pub, dek)
	if err != nil {
		t.Fatalf("encryptDEKWithKyber Kyber768: %v", err)
	}
	if !handled {
		t.Error("expected handled=true for kyber768.PublicKey")
	}
	if len(result) == 0 {
		t.Error("encryptDEKWithKyber Kyber768 returned empty result")
	}
}

func TestUnit_encryptDEKWithKyber_Kyber1024(t *testing.T) {
	srv := newTestServer()
	pub, _, err := kyber1024.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair kyber1024: %v", err)
	}
	dek := make([]byte, 32)
	rand.Read(dek)

	result, handled, err := srv.encryptDEKWithKyber(pub, dek)
	if err != nil {
		t.Fatalf("encryptDEKWithKyber Kyber1024: %v", err)
	}
	if !handled {
		t.Error("expected handled=true for kyber1024.PublicKey")
	}
	if len(result) == 0 {
		t.Error("encryptDEKWithKyber Kyber1024 returned empty result")
	}
}

func TestUnit_encryptDEKWithKyber_UnknownKeyType(t *testing.T) {
	srv := newTestServer()
	dek := []byte("dek")

	result, handled, err := srv.encryptDEKWithKyber(unsupportedKeyType{}, dek)
	if err != nil {
		t.Fatalf("unexpected error for unknown type: %v", err)
	}
	if handled {
		t.Error("expected handled=false for unknown key type")
	}
	if result != nil {
		t.Error("expected nil result for unknown key type")
	}
}

// Verify that encryptDEK dispatches to the Kyber path for a Kyber512 key
func TestUnit_encryptDEK_Kyber512(t *testing.T) {
	srv := newTestServer()
	pub, _, err := kyber512.Scheme().GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	dek := make([]byte, 32)
	rand.Read(dek)

	result, err := srv.encryptDEK(pub, dek)
	if err != nil {
		t.Fatalf("encryptDEK with Kyber512: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("encryptDEK Kyber512 returned empty ciphertext")
	}
}

// ---------------------------------------------------------------------------
// serviceKeyCache — TTL expiry, hit/miss, concurrent access
// ---------------------------------------------------------------------------

func TestUnit_serviceKeyCache_HitAndMiss(t *testing.T) {
	cache := newServiceKeyCache(time.Minute)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	// Miss on empty cache
	_, ok := cache.Get("key1")
	if ok {
		t.Error("expected miss on empty cache, got hit")
	}

	// Set then hit
	cache.Set("key1", pub)
	got, ok := cache.Get("key1")
	if !ok {
		t.Fatal("expected hit after Set, got miss")
	}
	if got != pub {
		t.Error("retrieved key does not match stored key")
	}
}

func TestUnit_serviceKeyCache_TTLExpiry(t *testing.T) {
	// Use a very short TTL so the entry expires quickly
	cache := newServiceKeyCache(10 * time.Millisecond)

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache.Set("exp-key", &priv.PublicKey)

	// Should hit immediately
	_, ok := cache.Get("exp-key")
	if !ok {
		t.Fatal("expected hit immediately after Set")
	}

	// Wait for TTL to expire
	time.Sleep(20 * time.Millisecond)

	// Should be a miss now
	_, ok = cache.Get("exp-key")
	if ok {
		t.Error("expected miss after TTL expiry, got hit")
	}
}

func TestUnit_serviceKeyCache_MultipleKeys(t *testing.T) {
	cache := newServiceKeyCache(time.Minute)

	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)

	cache.Set("k1", &priv1.PublicKey)
	cache.Set("k2", &priv2.PublicKey)

	got1, ok1 := cache.Get("k1")
	got2, ok2 := cache.Get("k2")

	if !ok1 || !ok2 {
		t.Fatalf("expected both keys to hit; k1=%v k2=%v", ok1, ok2)
	}
	if got1 == got2 {
		t.Error("expected different keys for k1 and k2")
	}
}

func TestUnit_serviceKeyCache_Overwrite(t *testing.T) {
	cache := newServiceKeyCache(time.Minute)

	priv1, _ := rsa.GenerateKey(rand.Reader, 2048)
	priv2, _ := rsa.GenerateKey(rand.Reader, 2048)

	cache.Set("k", &priv1.PublicKey)
	cache.Set("k", &priv2.PublicKey)

	got, ok := cache.Get("k")
	if !ok {
		t.Fatal("expected hit after overwrite")
	}
	rsaGot, _ := got.(*rsa.PublicKey)
	if rsaGot.N.Cmp(priv2.PublicKey.N) != 0 {
		t.Error("expected second key after overwrite")
	}
}

func TestUnit_serviceKeyCache_ConcurrentAccess(t *testing.T) {
	cache := newServiceKeyCache(time.Minute)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	cache.Set("concurrent-key", &priv.PublicKey)

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = cache.Get("concurrent-key")
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// getServicePublicKey — cache hit path and FIPS rejection path
// ---------------------------------------------------------------------------

// getKeyMockServer serves a single key.
type getKeyMockServer struct {
	keyManager.UnimplementedKeyManagerServiceServer
	keyID   string
	keyType keyManager.KeyType
	priv    *rsa.PrivateKey
	err     error
}

func (m *getKeyMockServer) GetKey(_ context.Context, req *keyManager.GetKeyRequest) (*keyManager.GetKeyResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	if req.GetKeyId() != m.keyID {
		return nil, fmt.Errorf("unknown key %s", req.GetKeyId())
	}
	der, _ := x509.MarshalPKIXPublicKey(&m.priv.PublicKey)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &keyManager.GetKeyResponse{
		Key: &keyManager.Key{
			KeyId:        m.keyID,
			KeyType:      m.keyType,
			PublicKeyPem: string(pemBytes),
			Status:       keyManager.KeyStatus_KEY_STATUS_ACTIVE,
		},
	}, nil
}

func startGetKeyMockGRPCServer(t *testing.T, impl *getKeyMockServer) (addr string, stop func()) {
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

func newServerWithGetKeyMock(t *testing.T, impl *getKeyMockServer) *Server {
	t.Helper()
	addr, stop := startGetKeyMockGRPCServer(t, impl)
	t.Cleanup(stop)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
}

func TestUnit_getServicePublicKey_CacheHit(t *testing.T) {
	// Pre-populate the cache; the key manager must not be called.
	srv := newTestServer()
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	srv.serviceKeyCache.Set("cached-key", &priv.PublicKey)

	got, err := srv.getServicePublicKey(context.Background(), "cached-key")
	if err != nil {
		t.Fatalf("getServicePublicKey: %v", err)
	}
	if got != &priv.PublicKey {
		t.Error("expected the exact pointer from cache")
	}
}

func TestUnit_getServicePublicKey_CacheMiss_FetchesKey(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	impl := &getKeyMockServer{
		keyID:   "fetched-key",
		keyType: keyManager.KeyType_KEY_TYPE_RSA_2048,
		priv:    priv,
	}
	srv := newServerWithGetKeyMock(t, impl)

	got, err := srv.getServicePublicKey(context.Background(), "fetched-key")
	if err != nil {
		t.Fatalf("getServicePublicKey fetch: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil public key")
	}

	// Second call should use cache (same key pointer should come back as *rsa.PublicKey)
	got2, err := srv.getServicePublicKey(context.Background(), "fetched-key")
	if err != nil {
		t.Fatalf("getServicePublicKey second call: %v", err)
	}
	if got2 == nil {
		t.Fatal("expected non-nil public key on second call")
	}
}

func TestUnit_getServicePublicKey_FIPSModeRejectsNonRSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	impl := &getKeyMockServer{
		keyID:   "ecc-key",
		keyType: keyManager.KeyType_KEY_TYPE_ECC_P256, // not allowed in FIPS
		priv:    priv,
	}
	srv := newServerWithGetKeyMock(t, impl)
	srv.fipsEnabled = true

	_, err := srv.getServicePublicKey(context.Background(), "ecc-key")
	if err == nil {
		t.Fatal("expected error for ECC key in FIPS mode, got nil")
	}
}

func TestUnit_getServicePublicKey_KeyManagerRPCError(t *testing.T) {
	impl := &getKeyMockServer{
		err: fmt.Errorf("key manager unavailable"),
	}
	srv := newServerWithGetKeyMock(t, impl)

	_, err := srv.getServicePublicKey(context.Background(), "any-key")
	if err == nil {
		t.Fatal("expected error when key manager RPC fails, got nil")
	}
}

// ---------------------------------------------------------------------------
// ensureUnwrapClientKeyID — anonymous subject path
// ---------------------------------------------------------------------------

func TestUnit_ensureUnwrapClientKeyID_AnonymousSubject(t *testing.T) {
	srv := newTestServer()
	req := &UnwrapDEKRequest{ClientKeyId: ""}
	err := srv.ensureUnwrapClientKeyID(context.Background(), req, "")
	if err == nil {
		t.Fatal("expected error for anonymous subject with no client key ID, got nil")
	}
}

// ---------------------------------------------------------------------------
// ensureWrapClientKeyID — anonymous subject path
// ---------------------------------------------------------------------------

func TestUnit_ensureWrapClientKeyID_AnonymousSubject(t *testing.T) {
	srv := newTestServer()
	req := &WrapDEKRequest{ClientKeyId: ""}
	err := srv.ensureWrapClientKeyID(context.Background(), req, "")
	if err == nil {
		t.Fatal("expected error for anonymous subject with no client key ID, got nil")
	}
}

func TestUnit_ensureWrapClientKeyID_AlreadySet(t *testing.T) {
	srv := newTestServer()
	req := &WrapDEKRequest{ClientKeyId: "existing-key"}
	err := srv.ensureWrapClientKeyID(context.Background(), req, "user123")
	if err != nil {
		t.Fatalf("ensureWrapClientKeyID with existing key ID: %v", err)
	}
	if req.ClientKeyId != "existing-key" {
		t.Errorf("ClientKeyId should be unchanged, got %q", req.ClientKeyId)
	}
}

func TestUnit_ensureWrapClientKeyID_LookupSuccess(t *testing.T) {
	// Wire up a mock key manager that returns an active client key
	clientPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	clientKeyID := "wrap-client-key"

	kmAddr, kmSrv := startMockKeyManagerGRPCServer(t, map[string]*mockClientKey{
		clientKeyID: {
			publicKey: &clientPriv.PublicKey,
			clientID:  "user123",
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

	req := &WrapDEKRequest{ClientKeyId: ""}
	err = srv.ensureWrapClientKeyID(context.Background(), req, "user123")
	if err != nil {
		t.Fatalf("ensureWrapClientKeyID lookup: %v", err)
	}
	if req.ClientKeyId != clientKeyID {
		t.Errorf("expected ClientKeyId=%q, got %q", clientKeyID, req.ClientKeyId)
	}
}

// ---------------------------------------------------------------------------
// lookupLatestClientKeyID — selects most recently created active key
// ---------------------------------------------------------------------------

// listClientKeysMockServer is a key manager mock that implements ListClientKeys.
type listClientKeysMockServer struct {
	keyManager.UnimplementedKeyManagerServiceServer
	keys []*keyManager.Key
	err  error
}

func (m *listClientKeysMockServer) ListClientKeys(_ context.Context, _ *keyManager.ListClientKeysRequest) (*keyManager.ListClientKeysResponse, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &keyManager.ListClientKeysResponse{
		Keys:      m.keys,
		Timestamp: timestamppb.Now(),
	}, nil
}

func startListClientKeysMockGRPCServer(t *testing.T, impl *listClientKeysMockServer) (addr string, stop func()) {
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

func newServerWithListClientKeysMock(t *testing.T, impl *listClientKeysMockServer) *Server {
	t.Helper()
	addr, stop := startListClientKeysMockGRPCServer(t, impl)
	t.Cleanup(stop)
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Server{
		keyManagerClient: keyManager.NewKeyManagerServiceClient(conn),
		serviceKeyCache:  newServiceKeyCache(time.Minute),
	}
}

func TestUnit_lookupLatestClientKeyID_SelectsMostRecent(t *testing.T) {
	older := timestamppb.New(time.Now().Add(-1 * time.Hour))
	newer := timestamppb.New(time.Now())

	impl := &listClientKeysMockServer{
		keys: []*keyManager.Key{
			{KeyId: "old-key", Status: keyManager.KeyStatus_KEY_STATUS_ACTIVE, CreatedAt: older},
			{KeyId: "new-key", Status: keyManager.KeyStatus_KEY_STATUS_ACTIVE, CreatedAt: newer},
		},
	}
	srv := newServerWithListClientKeysMock(t, impl)

	keyID, err := srv.lookupLatestClientKeyID(context.Background(), "user123")
	if err != nil {
		t.Fatalf("lookupLatestClientKeyID: %v", err)
	}
	if keyID != "new-key" {
		t.Errorf("expected newest key %q, got %q", "new-key", keyID)
	}
}

func TestUnit_lookupLatestClientKeyID_SkipsInactiveKeys(t *testing.T) {
	impl := &listClientKeysMockServer{
		keys: []*keyManager.Key{
			{KeyId: "inactive-key", Status: keyManager.KeyStatus_KEY_STATUS_INACTIVE, CreatedAt: timestamppb.Now()},
		},
	}
	srv := newServerWithListClientKeysMock(t, impl)

	_, err := srv.lookupLatestClientKeyID(context.Background(), "user123")
	if err == nil {
		t.Fatal("expected error when all keys are inactive, got nil")
	}
}

func TestUnit_lookupLatestClientKeyID_RPCError(t *testing.T) {
	impl := &listClientKeysMockServer{
		err: fmt.Errorf("storage unavailable"),
	}
	srv := newServerWithListClientKeysMock(t, impl)

	_, err := srv.lookupLatestClientKeyID(context.Background(), "user123")
	if err == nil {
		t.Fatal("expected error on RPC failure, got nil")
	}
}

func TestUnit_lookupLatestClientKeyID_AnonymousSubject(t *testing.T) {
	srv := newTestServer()
	_, err := srv.lookupLatestClientKeyID(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty subject, got nil")
	}
}

// ---------------------------------------------------------------------------
// validateWrapRequest — default action assignment
// ---------------------------------------------------------------------------

func TestUnit_validateWrapRequest_SetsDefaultAction(t *testing.T) {
	srv := newTestServer()
	req := &WrapDEKRequest{
		Resource:    "r",
		Dek:         []byte("dek"),
		ClientKeyId: "ck",
		Action:      "", // intentionally empty
	}
	if err := srv.validateWrapRequest(req); err != nil {
		t.Fatalf("validateWrapRequest: %v", err)
	}
	if req.Action != "wrap_dek" {
		t.Errorf("expected default action %q, got %q", "wrap_dek", req.Action)
	}
}

// ---------------------------------------------------------------------------
// validateUnwrapRequest — default action assignment
// ---------------------------------------------------------------------------

func TestUnit_validateUnwrapRequest_SetsDefaultAction(t *testing.T) {
	srv := newTestServer()
	req := &UnwrapDEKRequest{
		Resource:   "r",
		WrappedDek: []byte("wdek"),
		KeyId:      "kk",
		Action:     "", // intentionally empty
	}
	if err := srv.validateUnwrapRequest(req); err != nil {
		t.Fatalf("validateUnwrapRequest: %v", err)
	}
	if req.Action != "unwrap_dek" {
		t.Errorf("expected default action %q, got %q", "unwrap_dek", req.Action)
	}
}

// ---------------------------------------------------------------------------
// createUnwrapDeniedResponse
// ---------------------------------------------------------------------------

func TestUnit_createUnwrapDeniedResponse(t *testing.T) {
	srv := newTestServer()
	req := &UnwrapDEKRequest{Resource: "r", WrappedDek: []byte("wdek")}
	reason := "policy denied"
	resp := srv.createUnwrapDeniedResponse(req, reason)

	if resp == nil {
		t.Fatal("createUnwrapDeniedResponse returned nil")
	}
	if resp.AccessGranted {
		t.Error("expected AccessGranted=false")
	}
	if resp.AccessReason != reason {
		t.Errorf("expected reason %q, got %q", reason, resp.AccessReason)
	}
	if resp.DekForSubject != nil {
		t.Error("expected DekForSubject to be nil")
	}
	if resp.Timestamp == nil {
		t.Error("expected non-nil Timestamp")
	}
}

func TestUnit_createUnwrapDeniedResponse_EmptyReason(t *testing.T) {
	srv := newTestServer()
	req := &UnwrapDEKRequest{}
	resp := srv.createUnwrapDeniedResponse(req, "")
	if resp.AccessGranted {
		t.Error("expected AccessGranted=false")
	}
	if resp.AccessReason != "" {
		t.Errorf("expected empty reason, got %q", resp.AccessReason)
	}
}

// ---------------------------------------------------------------------------
// InMemorySubjectKeyStore — additional paths
// ---------------------------------------------------------------------------

func TestUnit_InMemorySubjectKeyStore_addSampleKeys(t *testing.T) {
	store := NewInMemorySubjectKeyStore()
	subjects, err := store.ListSubjects(context.Background())
	if err != nil {
		t.Fatalf("ListSubjects: %v", err)
	}
	// addSampleKeys generates keys for 4 test subjects
	if len(subjects) < 4 {
		t.Errorf("expected at least 4 sample subjects, got %d", len(subjects))
	}
}

func TestUnit_InMemorySubjectKeyStore_ListSubjectsOnEmptyStore(t *testing.T) {
	// Bypass NewInMemorySubjectKeyStore to avoid calling addSampleKeys
	emptyStore := &InMemorySubjectKeyStore{
		keys: make(map[string]crypto.PublicKey),
	}
	subjects, err := emptyStore.ListSubjects(context.Background())
	if err != nil {
		t.Fatalf("ListSubjects on empty store: %v", err)
	}
	if len(subjects) != 0 {
		t.Errorf("expected empty subjects list, got %d", len(subjects))
	}
}

// ---------------------------------------------------------------------------
// telemetry — recordServiceKeyCacheEvent exercised via cache operations
// ---------------------------------------------------------------------------

func TestUnit_telemetry_serviceKeyCacheEvents(t *testing.T) {
	// Ensure initKeyAccessTelemetry is called (it's idempotent)
	initKeyAccessTelemetry()

	// recordServiceKeyCacheEvent handles nil metric gracefully
	// Exercise both paths
	recordServiceKeyCacheEvent(true)  // hit
	recordServiceKeyCacheEvent(false) // miss
}

func TestUnit_telemetry_startKeyAccessSpan(t *testing.T) {
	initKeyAccessTelemetry()
	ctx, span := startKeyAccessSpan(context.Background(), "test-span")
	span.End()
	if ctx == nil {
		t.Error("expected non-nil context from startKeyAccessSpan")
	}
}

func TestUnit_telemetry_recordWrapTelemetry(t *testing.T) {
	initKeyAccessTelemetry()
	// Exercise with no error
	recordWrapTelemetry(context.Background(), 10*time.Millisecond, true, nil)
	// Exercise with error
	recordWrapTelemetry(context.Background(), 10*time.Millisecond, false, fmt.Errorf("test error"))
}

func TestUnit_telemetry_recordUnwrapTelemetry(t *testing.T) {
	initKeyAccessTelemetry()
	recordUnwrapTelemetry(context.Background(), 10*time.Millisecond, true, nil)
	recordUnwrapTelemetry(context.Background(), 10*time.Millisecond, false, fmt.Errorf("test error"))
}

// ---------------------------------------------------------------------------
// GRPCPlatformClient.Close
// ---------------------------------------------------------------------------

func TestUnit_GRPCPlatformClient_Close_NilConn(t *testing.T) {
	client := &GRPCPlatformClient{conn: nil}
	err := client.Close()
	if err != nil {
		t.Errorf("Close with nil conn should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// getEnvOrDefault / getEnv
// ---------------------------------------------------------------------------

func TestUnit_getEnvOrDefault_DefaultUsedWhenEnvEmpty(t *testing.T) {
	result := getEnvOrDefault("__UNIT_TEST_NONEXISTENT_ENV_VAR__", "fallback")
	if result != "fallback" {
		t.Errorf("expected %q, got %q", "fallback", result)
	}
}

func TestUnit_getEnv_ReturnsEmpty(t *testing.T) {
	result := getEnv("__UNIT_TEST_NONEXISTENT_ENV_VAR__")
	if result != "" {
		t.Errorf("expected empty string for unset env var, got %q", result)
	}
}
