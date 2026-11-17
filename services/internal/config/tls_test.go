package config

import (
	"strings"
	"testing"
)

func TestLoad_Transport(t *testing.T) {
	tests := []struct {
		name, cert, key, insecure string
		wantErr                   string // substring; "" means Load succeeds
		wantInsecure              bool
	}{
		{name: "tls", cert: "/c", key: "/k"},
		{name: "explicit plaintext", insecure: "true", wantInsecure: true},
		{name: "nothing set refuses to start", wantErr: "are required"},
		{name: "insecure=false still needs tls", insecure: "false", wantErr: "are required"},
		{name: "cert without key", cert: "/c", wantErr: "must be set together"},
		{name: "key without cert", key: "/k", wantErr: "must be set together"},
		{name: "plaintext and tls conflict", cert: "/c", key: "/k", insecure: "true", wantErr: "conflicts"},
		{name: "unparseable flag", insecure: "yes please", wantErr: "STRATIUM_GRPC_INSECURE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("STRATIUM_TLS_CERT_FILE", tt.cert)
			t.Setenv("STRATIUM_TLS_KEY_FILE", tt.key)
			t.Setenv("STRATIUM_GRPC_INSECURE", tt.insecure)
			got, err := Load()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.GRPCInsecure != tt.wantInsecure {
				t.Errorf("GRPCInsecure = %v, want %v", got.GRPCInsecure, tt.wantInsecure)
			}
		})
	}
}
