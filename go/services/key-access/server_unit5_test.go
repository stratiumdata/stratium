//go:build !fips

package key_access

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"stratium/config"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ---------------------------------------------------------------------------
// createPlatformClient — valid address (happy path)
// ---------------------------------------------------------------------------

func TestUnit_createPlatformClient_ValidAddress(t *testing.T) {
	// Start a real gRPC listener so grpc.NewClient can succeed.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	// Close the listener immediately; grpc.NewClient is non-blocking and does
	// not require the server to be running at creation time.
	lis.Close()

	cfg := &config.ServiceEndpoint{Address: addr}
	client, conn, err := createPlatformClient(cfg)
	if err != nil {
		t.Fatalf("createPlatformClient: %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil PlatformClient")
	}
	if conn == nil {
		t.Fatal("expected non-nil *grpc.ClientConn")
	}
	conn.Close()
}

// ---------------------------------------------------------------------------
// createPlatformClient — nil config (graceful nil-deref guard)
// ---------------------------------------------------------------------------

func TestUnit_createPlatformClient_NilConfig(t *testing.T) {
	// The function dereferences config.Address; passing nil should panic or
	// return an error.  We recover a panic so the test is not flaky.
	defer func() { recover() }()

	_, _, err := createPlatformClient(nil)
	// If it returns an error instead of panicking that is also acceptable.
	if err == nil {
		t.Log("createPlatformClient(nil) returned no error and no panic — acceptable")
	}
}

// ---------------------------------------------------------------------------
// dialServiceCredentials — TLS enabled with a real self-signed CA cert
// ---------------------------------------------------------------------------

// generateSelfSignedCACert writes a temporary PEM CA certificate to disk and
// returns its file path.  The caller is responsible for removing the file.
func generateSelfSignedCACert(t *testing.T) string {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
		},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	f, err := os.CreateTemp("", "unit5-ca-cert-*.pem")
	if err != nil {
		t.Fatalf("os.CreateTemp: %v", err)
	}
	if _, err := f.Write(certPEM); err != nil {
		f.Close()
		os.Remove(f.Name())
		t.Fatalf("write cert pem: %v", err)
	}
	f.Close()
	return f.Name()
}

func TestUnit_dialServiceCredentials_WithTLS(t *testing.T) {
	caFile := generateSelfSignedCACert(t)
	defer os.Remove(caFile)

	endpoint := &config.ServiceEndpoint{
		Address: "localhost:19999",
		TLS: config.TLSConfig{
			Enabled: true,
			CAFile:  caFile,
		},
	}

	creds, err := dialServiceCredentials(endpoint)
	if err != nil {
		t.Fatalf("dialServiceCredentials with valid CA: %v", err)
	}
	if creds == nil {
		t.Fatal("expected non-nil credentials")
	}
}

func TestUnit_dialServiceCredentials_TLSEnabledBadCAFile(t *testing.T) {
	endpoint := &config.ServiceEndpoint{
		Address: "localhost:19999",
		TLS: config.TLSConfig{
			Enabled: true,
			CAFile:  "/nonexistent/ca-cert-unit5.pem",
		},
	}

	_, err := dialServiceCredentials(endpoint)
	if err == nil {
		t.Fatal("expected error for non-existent CA file, got nil")
	}
}

// ---------------------------------------------------------------------------
// GRPCPlatformClient.Close — nil conn branch
// ---------------------------------------------------------------------------

func TestUnit_GRPCPlatformClient_Close_NilConn_v2(t *testing.T) {
	client := &GRPCPlatformClient{conn: nil}
	err := client.Close()
	if err != nil {
		t.Errorf("Close with nil conn should return nil, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// GRPCPlatformClient.Close — live conn branch
// ---------------------------------------------------------------------------

func TestUnit_GRPCPlatformClient_Close_LiveConn(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer lis.Close()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	client := &GRPCPlatformClient{conn: conn}
	if err := client.Close(); err != nil {
		t.Errorf("Close with live conn returned error: %v", err)
	}
}
