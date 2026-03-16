//go:build !fips

package tlspolicy

import (
	"crypto/tls"
	"testing"
)

func TestEnforceConfigNonFIPSNoop(t *testing.T) {
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS10,
		CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA},
	}
	if err := EnforceConfig(cfg, true); err != nil {
		t.Fatalf("EnforceConfig returned error: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS10 {
		t.Fatalf("expected MinVersion to remain unchanged, got %v", cfg.MinVersion)
	}
	if len(cfg.CipherSuites) != 1 || cfg.CipherSuites[0] != tls.TLS_RSA_WITH_AES_128_CBC_SHA {
		t.Fatalf("expected CipherSuites to remain unchanged")
	}
}

func TestRequireTLSInFIPSNonFIPSBuild(t *testing.T) {
	if err := RequireTLSInFIPS(true, false); err != nil {
		t.Fatalf("expected no error in non-FIPS build, got %v", err)
	}
}
