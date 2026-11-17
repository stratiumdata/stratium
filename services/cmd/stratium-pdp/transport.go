package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/stratiumdata/stratium/internal/config"
)

// serverTransport returns the gRPC server option for cfg's transport. TLS
// unless the operator set STRATIUM_GRPC_INSECURE=true (config.Load refuses
// to return a Config with neither), and that choice is logged as a warning
// on every start so it can't go unnoticed in production.
//
// The key pair is read once, here, before the listener opens: a bad
// certificate stops startup instead of failing each client handshake.
// ponytail: no hot reload; rotating the certificate means restarting the PDP.
func serverTransport(logger *slog.Logger, cfg config.Config) (grpc.ServerOption, error) {
	if cfg.GRPCInsecure {
		logger.Warn("serving plaintext gRPC (STRATIUM_GRPC_INSECURE=true): delegation tokens cross the network " +
			"unencrypted; use only for local development")
		return grpc.EmptyServerOption{}, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair (STRATIUM_TLS_CERT_FILE/STRATIUM_TLS_KEY_FILE): %w", err)
	}
	return grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})), nil
}
