package tlspolicy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// LoadServerConfig loads a TLS config for server use from certificate paths.
func LoadServerConfig(certFile, keyFile, caFile, clientCAFile string, requireClientCert bool) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("tls cert and key files are required")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	if caFile != "" {
		caPool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = caPool
	}

	if requireClientCert {
		caPool, err := loadCertPool(clientCAFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = caPool
	}

	if err := EnforceConfig(cfg, requireClientCert); err != nil {
		return nil, err
	}

	return cfg, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, fmt.Errorf("CA file path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("failed to parse CA file: %s", path)
	}
	return pool, nil
}
