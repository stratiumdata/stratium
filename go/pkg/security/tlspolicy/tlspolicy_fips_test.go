//go:build fips

package tlspolicy

import (
	"crypto/tls"
	"testing"
)

func TestEnforceConfigFIPS(t *testing.T) {
	cfg := &tls.Config{}
	if err := EnforceConfig(cfg, false); err != nil {
		t.Fatalf("EnforceConfig returned error: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected MinVersion TLS1.2, got %v", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) == 0 {
		t.Fatalf("expected cipher suites to be set")
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected ClientAuth to remain default when not required, got %v", cfg.ClientAuth)
	}
}

func TestEnforceConfigFIPSRequiresClientCert(t *testing.T) {
	cfg := &tls.Config{}
	if err := EnforceConfig(cfg, true); err != nil {
		t.Fatalf("EnforceConfig returned error: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected ClientAuth RequireAndVerifyClientCert, got %v", cfg.ClientAuth)
	}
}

func TestRequireTLSInFIPS(t *testing.T) {
	if err := RequireTLSInFIPS(true, false); err == nil {
		t.Fatalf("expected error when TLS is disabled in FIPS mode")
	}
	if err := RequireTLSInFIPS(true, true); err != nil {
		t.Fatalf("expected no error when TLS is enabled in FIPS mode, got %v", err)
	}
}
