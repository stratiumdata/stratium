//go:build !fips

package tlspolicy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"testing"
	"time"
)

// writeSelfSignedCert writes a self-signed cert+key to temp files and returns their paths.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}

	certF, err := os.CreateTemp(t.TempDir(), "cert*.pem")
	if err != nil {
		t.Fatalf("CreateTemp cert: %v", err)
	}
	if err := pem.Encode(certF, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		t.Fatalf("pem.Encode cert: %v", err)
	}
	certF.Close()

	keyF, err := os.CreateTemp(t.TempDir(), "key*.pem")
	if err != nil {
		t.Fatalf("CreateTemp key: %v", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	if err := pem.Encode(keyF, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privDER}); err != nil {
		t.Fatalf("pem.Encode key: %v", err)
	}
	keyF.Close()

	return certF.Name(), keyF.Name()
}

// TestNormalizeServerName verifies host extraction from addr strings.
func TestNormalizeServerName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"localhost:8443", "localhost"},
		{"10.0.0.1:50051", "10.0.0.1"},
		{"kas.example.com:443", "kas.example.com"},
		{"kas.example.com", "kas.example.com"},
		{"  trimmed  ", "trimmed"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeServerName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeServerName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestLoadClientConfig_NoCAFile verifies a TLS config is returned with no CA override.
func TestLoadClientConfig_NoCAFile(t *testing.T) {
	t.Setenv("STRATIUM_GRPC_CA_FILE", "")
	t.Setenv("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "")
	t.Setenv("SSL_CERT_FILE", "")

	cfg, err := LoadClientConfig("localhost:8443", "")
	if err != nil {
		t.Fatalf("LoadClientConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadClientConfig() returned nil")
	}
	if cfg.ServerName != "localhost" {
		t.Errorf("ServerName = %q, want 'localhost'", cfg.ServerName)
	}
}

// TestLoadClientConfig_WithCAFile verifies CA bundle is loaded when provided.
func TestLoadClientConfig_WithCAFile(t *testing.T) {
	certFile, _ := writeSelfSignedCert(t)

	cfg, err := LoadClientConfig("kas:443", certFile)
	if err != nil {
		t.Fatalf("LoadClientConfig() with CA file error = %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("LoadClientConfig() RootCAs should be set when CA file is provided")
	}
}

// TestLoadClientConfig_EnvCAFile verifies env var CA file is picked up.
func TestLoadClientConfig_EnvCAFile(t *testing.T) {
	certFile, _ := writeSelfSignedCert(t)
	t.Setenv("STRATIUM_GRPC_CA_FILE", certFile)
	t.Setenv("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "")
	t.Setenv("SSL_CERT_FILE", "")

	cfg, err := LoadClientConfig("kas:443", "")
	if err != nil {
		t.Fatalf("LoadClientConfig() with env CA error = %v", err)
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs set via env var")
	}
}

// TestLoadClientConfig_InvalidCAFile verifies error on bad CA path.
func TestLoadClientConfig_InvalidCAFile(t *testing.T) {
	_, err := LoadClientConfig("kas:443", "/nonexistent/ca.pem")
	if err == nil {
		t.Error("LoadClientConfig() with missing CA file should fail")
	}
}

// TestLoadRootCAs_Empty verifies nil returned for empty path.
func TestLoadRootCAs_Empty(t *testing.T) {
	pool, err := LoadRootCAs("")
	if err != nil {
		t.Fatalf("LoadRootCAs('') error = %v", err)
	}
	if pool != nil {
		t.Error("LoadRootCAs('') should return nil pool")
	}
}

// TestLoadRootCAs_ValidCert verifies CA pool is populated from a valid PEM file.
func TestLoadRootCAs_ValidCert(t *testing.T) {
	certFile, _ := writeSelfSignedCert(t)
	pool, err := LoadRootCAs(certFile)
	if err != nil {
		t.Fatalf("LoadRootCAs() error = %v", err)
	}
	if pool == nil {
		t.Error("LoadRootCAs() returned nil pool for valid cert")
	}
}

// TestLoadRootCAs_MissingFile verifies error on missing file.
func TestLoadRootCAs_MissingFile(t *testing.T) {
	_, err := LoadRootCAs("/nonexistent/ca.pem")
	if err == nil {
		t.Error("LoadRootCAs() with missing file should fail")
	}
}

// TestLoadRootCAs_InvalidPEM verifies error on non-PEM content.
func TestLoadRootCAs_InvalidPEM(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "bad*.pem")
	f.WriteString("not a certificate")
	f.Close()

	_, err := LoadRootCAs(f.Name())
	if err == nil {
		t.Error("LoadRootCAs() with invalid PEM should fail")
	}
}

// TestLoadServerConfig_MissingCertKey verifies error when cert/key paths are empty.
func TestLoadServerConfig_MissingCertKey(t *testing.T) {
	_, err := LoadServerConfig("", "", "", "", false)
	if err == nil {
		t.Error("LoadServerConfig() with no cert/key should fail")
	}
}

// TestLoadServerConfig_ValidCertKey verifies server config loads from valid cert+key.
func TestLoadServerConfig_ValidCertKey(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	cfg, err := LoadServerConfig(certFile, keyFile, "", "", false)
	if err != nil {
		t.Fatalf("LoadServerConfig() error = %v", err)
	}
	if cfg == nil {
		t.Fatal("LoadServerConfig() returned nil")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Certificates = %d, want 1", len(cfg.Certificates))
	}
}

// TestLoadServerConfig_WithCAFile verifies ClientCAs is set when caFile provided.
func TestLoadServerConfig_WithCAFile(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	cfg, err := LoadServerConfig(certFile, keyFile, certFile, "", false)
	if err != nil {
		t.Fatalf("LoadServerConfig() with CA error = %v", err)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should be set when caFile provided")
	}
}

// TestLoadServerConfig_RequireClientCert verifies mTLS config with client cert requirement.
func TestLoadServerConfig_RequireClientCert(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	cfg, err := LoadServerConfig(certFile, keyFile, "", certFile, true)
	if err != nil {
		t.Fatalf("LoadServerConfig() requireClientCert error = %v", err)
	}
	if cfg.ClientCAs == nil {
		t.Error("ClientCAs should be set when requireClientCert=true")
	}
}

// TestLoadCertPool_EmptyPath verifies error on empty path.
func TestLoadCertPool_EmptyPath(t *testing.T) {
	_, err := loadCertPool("")
	if err == nil {
		t.Error("loadCertPool('') should fail")
	}
}
