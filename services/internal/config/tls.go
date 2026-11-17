package config

import (
	"fmt"
	"os"
	"strconv"
)

// loadTransport fills the gRPC transport settings: TLS by default, plaintext
// only when the operator asks for it by name.
//
// A PDP with no transport settings refuses to start rather than falling back
// to plaintext. Delegation tokens travel on this connection and are bearer
// credentials, so a silent plaintext default would expose them to anyone on
// the path, and nothing would tell the operator it had happened.
func loadTransport(c *Config) error {
	c.TLSCertFile = os.Getenv("STRATIUM_TLS_CERT_FILE")
	c.TLSKeyFile = os.Getenv("STRATIUM_TLS_KEY_FILE")
	if v := os.Getenv("STRATIUM_GRPC_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("STRATIUM_GRPC_INSECURE: %w", err)
		}
		c.GRPCInsecure = b
	}

	hasCert, hasKey := c.TLSCertFile != "", c.TLSKeyFile != ""
	switch {
	case c.GRPCInsecure && (hasCert || hasKey):
		return fmt.Errorf("STRATIUM_GRPC_INSECURE=true conflicts with STRATIUM_TLS_CERT_FILE/STRATIUM_TLS_KEY_FILE: choose one")
	case c.GRPCInsecure:
		return nil
	case hasCert != hasKey:
		return fmt.Errorf("STRATIUM_TLS_CERT_FILE and STRATIUM_TLS_KEY_FILE must be set together")
	case !hasCert:
		return fmt.Errorf("STRATIUM_TLS_CERT_FILE and STRATIUM_TLS_KEY_FILE are required " +
			"(or set STRATIUM_GRPC_INSECURE=true to serve plaintext, for local development only)")
	}
	return nil
}
