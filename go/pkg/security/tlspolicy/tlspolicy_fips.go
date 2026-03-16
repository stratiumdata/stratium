//go:build fips

package tlspolicy

import (
	"crypto/tls"
	"fmt"
)

// EnforceConfig applies the FIPS TLS policy in fips builds.
func EnforceConfig(cfg *tls.Config, requireClientAuth bool) error {
	if cfg == nil {
		return fmt.Errorf("tls config is required")
	}

	cfg.MinVersion = tls.VersionTLS12

	// TLS 1.3 cipher suites are not configurable; they are always FIPS-approved in Go.
	// Restrict TLS 1.2 to AES-GCM with SHA-2.
	cfg.CipherSuites = []uint16{
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	}

	if requireClientAuth {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return nil
}
