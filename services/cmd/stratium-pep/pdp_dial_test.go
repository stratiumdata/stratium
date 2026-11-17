package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

func TestPDPTransportCredentials(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "not.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, insecureEnv, caFile string
		wantProtocol, wantErr     string
	}{
		{name: "tls by default", wantProtocol: "tls"},
		{name: "insecure=false is tls", insecureEnv: "false", wantProtocol: "tls"},
		{name: "explicit plaintext", insecureEnv: "true", wantProtocol: "insecure"},
		{name: "plaintext and ca conflict", insecureEnv: "true", caFile: notPEM, wantErr: "conflicts"},
		{name: "unparseable flag", insecureEnv: "sure", wantErr: "STRATIUM_PEP_PDP_INSECURE"},
		{name: "missing ca file", caFile: "/nonexistent/ca.pem", wantErr: "STRATIUM_PEP_PDP_CA_FILE"},
		{name: "ca file without certificates", caFile: notPEM, wantErr: "no PEM certificates"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("STRATIUM_PEP_PDP_INSECURE", tt.insecureEnv)
			t.Setenv("STRATIUM_PEP_PDP_CA_FILE", tt.caFile)
			creds, err := pdpTransportCredentials()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := creds.Info().SecurityProtocol; got != tt.wantProtocol {
				t.Errorf("SecurityProtocol = %q, want %q", got, tt.wantProtocol)
			}
		})
	}
}

// TestDialPDP_TLSHandshake proves the default path end to end: a PEP trusting
// a private CA completes a call to a TLS server, and a PEP without that CA
// is refused rather than downgraded.
func TestDialPDP_TLSHandshake(t *testing.T) {
	certPEM, keyPEM := selfSignedLocalhost(t)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{pair}})))
	grpc_health_v1.RegisterHealthServer(gs, health.NewServer())
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	_, port, _ := net.SplitHostPort(lis.Addr().String())
	addr := "localhost:" + port

	check := func() error {
		conn, err := dialPDP(addr)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err = grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		return err
	}

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STRATIUM_PEP_PDP_INSECURE", "")
	t.Setenv("STRATIUM_PEP_PDP_CA_FILE", caFile)
	if err := check(); err != nil {
		t.Fatalf("trusted CA: %v", err)
	}

	t.Setenv("STRATIUM_PEP_PDP_CA_FILE", "") // system roots don't know this CA
	if err := check(); err == nil {
		t.Fatal("untrusted certificate: call succeeded, want a handshake failure")
	}
}

func selfSignedLocalhost(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}
