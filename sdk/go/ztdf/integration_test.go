package ztdf

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	stratium "github.com/stratiumdata/go-sdk"
	keyaccess "github.com/stratiumdata/go-sdk/gen/services/key-access"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// integrationKeyAccessServer captures real gRPC traffic for verification.
type integrationKeyAccessServer struct {
	keyaccess.UnimplementedKeyAccessServiceServer

	clientPubKey *rsa.PublicKey

	mu          sync.Mutex
	lastWrapReq *keyaccess.WrapDEKRequest
	lastAuth    string
	lastDEK     []byte
}

func newIntegrationKeyAccessServer(pub *rsa.PublicKey) *integrationKeyAccessServer {
	return &integrationKeyAccessServer{clientPubKey: pub}
}

func (s *integrationKeyAccessServer) WrapDEK(ctx context.Context, req *keyaccess.WrapDEKRequest) (*keyaccess.WrapDEKResponse, error) {
	auth := ""
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if vals := md.Get("authorization"); len(vals) > 0 {
			auth = vals[0]
		}
	}

	dek, err := recoverClientDEK(s.clientPubKey, req.Dek)
	if err != nil {
		return nil, fmt.Errorf("failed to recover client DEK: %w", err)
	}

	s.mu.Lock()
	s.lastWrapReq = req
	s.lastAuth = auth
	s.lastDEK = dek
	s.mu.Unlock()

	return &keyaccess.WrapDEKResponse{
		WrappedDek:    []byte("service-wrapped"),
		KeyId:         "service-key-id",
		AccessGranted: true,
		AccessReason:  "granted",
	}, nil
}

func (s *integrationKeyAccessServer) UnwrapDEK(ctx context.Context, req *keyaccess.UnwrapDEKRequest) (*keyaccess.UnwrapDEKResponse, error) {
	return &keyaccess.UnwrapDEKResponse{
		AccessGranted: true,
		DekForSubject: []byte("encrypted-for-client"),
	}, nil
}

// recoverClientDEK reverses the PKCS#1 v1.5 padding produced by WrapDEKWithPrivateKey.
func recoverClientDEK(pub *rsa.PublicKey, wrapped []byte) ([]byte, error) {
	k := (pub.N.BitLen() + 7) / 8
	if len(wrapped) != k {
		return nil, fmt.Errorf("wrapped length %d does not match modulus %d", len(wrapped), k)
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
		return nil, fmt.Errorf("padding delimiter missing")
	}
	return em[2+idx+1:], nil
}

func TestClient_Wrap_Integration(t *testing.T) {
	privateKey, privateKeyPath, publicPath := generateTestKeyPair(t)
	publicKey := loadPublicKey(t, publicPath)

	kasServer := newIntegrationKeyAccessServer(publicKey)
	bufSize := 1024 * 1024
	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	keyaccess.RegisterKeyAccessServiceServer(grpcServer, kasServer)
	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("grpc server exited: %v", err)
		}
	}()
	t.Cleanup(func() {
		grpcServer.Stop()
		lis.Close()
	})

	fakeOIDC := newFakeOIDCServer(t)
	defer fakeOIDC.Close()

	cfg := &stratium.Config{
		KeyAccessAddress: "passthrough://bufnet",
		Timeout:          5 * time.Second,
		OIDC: &stratium.OIDCConfig{
			IssuerURL:    fakeOIDC.URL,
			ClientID:     "test-client",
			ClientSecret: "test-secret",
			Scopes:       []string{"openid"},
		},
		DialOptions: []grpc.DialOption{
			grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
				return lis.Dial()
			}),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		},
	}

	stratiumClient, err := stratium.NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create stratium client: %v", err)
	}
	t.Cleanup(func() {
		stratiumClient.Close()
	})

	client := NewClient(stratiumClient)
	ctx := context.Background()

	opts := &WrapOptions{
		Resource:             "integration-resource",
		ClientKeyID:          "client-key-id",
		ClientPrivateKeyPath: privateKeyPath,
	}

	tdo, err := client.Wrap(ctx, []byte("integration payload"), opts)
	if err != nil {
		t.Fatalf("Wrap() integration failed: %v", err)
	}

	if tdo.Manifest == nil || len(tdo.Manifest.EncryptionInformation.KeyAccess) == 0 {
		t.Fatalf("expected manifest with key access objects")
	}

	kasServer.mu.Lock()
	defer kasServer.mu.Unlock()

	if kasServer.lastAuth != "Bearer test-access-token" {
		t.Fatalf("expected authorization header to carry token, got %q", kasServer.lastAuth)
	}

	if kasServer.lastWrapReq == nil {
		t.Fatalf("key access server did not receive wrap request")
	}

	if kasServer.lastWrapReq.ClientKeyId != "client-key-id" {
		t.Fatalf("expected client key id %s, got %s", "client-key-id", kasServer.lastWrapReq.ClientKeyId)
	}

	if len(kasServer.lastDEK) != 32 {
		t.Fatalf("expected DEK size 32, got %d", len(kasServer.lastDEK))
	}

	// Ensure the wrapped key returned by the server was propagated into the manifest.
	gotWrapped := tdo.Manifest.EncryptionInformation.KeyAccess[0].WrappedKey
	if gotWrapped == "" || gotWrapped != base64.StdEncoding.EncodeToString([]byte("service-wrapped")) {
		t.Fatalf("expected wrapped key from service to be stored in manifest")
	}

	// Avoid unused warnings for helper output.
	_ = privateKey
}

func loadPublicKey(t *testing.T, path string) *rsa.PublicKey {
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read public key: %v", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatalf("failed to decode PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse public key: %v", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected RSA public key, got %T", pub)
	}
	return rsaPub
}

func newFakeOIDCServer(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	issuer := server.URL

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"issuer":         issuer,
			"token_endpoint": issuer + "/protocol/openid-connect/token",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		resp := map[string]any{
			"access_token": "test-access-token",
			"expires_in":   3600,
			"token_type":   "Bearer",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	return server
}
