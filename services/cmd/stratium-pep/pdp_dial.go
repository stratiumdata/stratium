package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strconv"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// dialPDP opens the client connection every PEP mode uses to reach the PDP.
// Keeping the five modes on one function means none of them can drift onto
// a weaker transport than the others.
func dialPDP(addr string) (*grpc.ClientConn, error) {
	creds, err := pdpTransportCredentials()
	if err != nil {
		return nil, err
	}
	return grpc.NewClient(addr, grpc.WithTransportCredentials(creds), grpc.WithUserAgent(pdpUserAgent))
}

// pdpTransportCredentials is TLS unless STRATIUM_PEP_PDP_INSECURE=true.
//
// TLS verifies the PDP's certificate against STRATIUM_PEP_PDP_CA_FILE when it
// is set (a private CA), otherwise against the system roots. Plaintext has to
// be asked for by name: delegation tokens are bearer credentials and ride on
// every call, so a quiet plaintext fallback would leak them. Every error here
// reaches the caller's existing "could not create PDP client" path, which
// denies.
func pdpTransportCredentials() (credentials.TransportCredentials, error) {
	caFile := os.Getenv("STRATIUM_PEP_PDP_CA_FILE")
	plaintext := false
	if v := os.Getenv("STRATIUM_PEP_PDP_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return nil, fmt.Errorf("STRATIUM_PEP_PDP_INSECURE: %w", err)
		}
		plaintext = b
	}
	if plaintext {
		if caFile != "" {
			return nil, fmt.Errorf("STRATIUM_PEP_PDP_INSECURE=true conflicts with STRATIUM_PEP_PDP_CA_FILE: choose one")
		}
		return insecure.NewCredentials(), nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) //nolint:gosec // G304: operator configuration (STRATIUM_PEP_PDP_CA_FILE), the same trust boundary as STRATIUM_PEP_SESSION_FILE in session_file.go
		if err != nil {
			return nil, fmt.Errorf("STRATIUM_PEP_PDP_CA_FILE: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("STRATIUM_PEP_PDP_CA_FILE: no PEM certificates in %s", caFile)
		}
		cfg.RootCAs = pool
	}
	return credentials.NewTLS(cfg), nil
}
