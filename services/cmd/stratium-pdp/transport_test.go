package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/stratiumdata/stratium/internal/config"
)

func TestServerTransport(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	opt, err := serverTransport(logger, config.Config{GRPCInsecure: true})
	if err != nil {
		t.Fatalf("insecure: %v", err)
	}
	if _, ok := opt.(grpc.EmptyServerOption); !ok {
		t.Errorf("insecure: got %T, want grpc.EmptyServerOption", opt)
	}

	_, err = serverTransport(logger, config.Config{TLSCertFile: "/nonexistent.crt", TLSKeyFile: "/nonexistent.key"})
	if err == nil || !strings.Contains(err.Error(), "STRATIUM_TLS_CERT_FILE") {
		t.Errorf("missing key pair: err = %v, want one naming STRATIUM_TLS_CERT_FILE", err)
	}
}
