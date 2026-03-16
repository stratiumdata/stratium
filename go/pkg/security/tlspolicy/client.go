package tlspolicy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"

	"stratium/pkg/security/fipsbuild"
)

// LoadClientConfig loads a TLS config for client use.
func LoadClientConfig(addr, caFile string) (*tls.Config, error) {
	cfg := &tls.Config{}

	if host, _, err := net.SplitHostPort(addr); err == nil {
		cfg.ServerName = host
	} else if addr != "" {
		cfg.ServerName = addr
	}

	caFilePath := strings.TrimSpace(caFile)
	if caFilePath == "" {
		caFilePath = strings.TrimSpace(os.Getenv("STRATIUM_GRPC_CA_FILE"))
	}
	if caFilePath == "" {
		caFilePath = strings.TrimSpace(os.Getenv("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"))
	}
	if caFilePath == "" {
		caFilePath = strings.TrimSpace(os.Getenv("SSL_CERT_FILE"))
	}

	if caFilePath != "" {
		pool, err := loadCertPool(caFilePath)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}

	if err := EnforceConfig(cfg, false); err != nil {
		return nil, err
	}

	return cfg, nil
}

// RequireTLSInFIPS enforces TLS when running in a FIPS build with FIPS mode enabled.
func RequireTLSInFIPS(enabled bool, useTLS bool) error {
	if !fipsbuild.Enabled {
		return nil
	}
	if enabled && !useTLS {
		return fmt.Errorf("FIPS mode requires TLS for service connections")
	}
	return nil
}

// NormalizeServerName is used by tests to check host extraction behavior.
func NormalizeServerName(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return strings.TrimSpace(addr)
}

// LoadRootCAs loads a custom CA bundle when provided.
func LoadRootCAs(caFile string) (*x509.CertPool, error) {
	if caFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA file: %s", caFile)
	}
	return pool, nil
}
