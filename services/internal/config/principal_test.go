package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_PrincipalAuth(t *testing.T) {
	tests := []struct {
		name                                       string
		issuer, audience, claim, timeout, insecure string
		wantErr                                    string // substring; "" means Load succeeds
		wantInsecure                               bool
	}{
		{name: "oidc", issuer: "https://idp", audience: "a", claim: "email"},
		{name: "explicit opt-out", insecure: "true", wantInsecure: true},
		{name: "nothing set refuses to start", wantErr: "missing principal authentication settings"},
		{name: "insecure=false still needs oidc", insecure: "false", wantErr: "missing principal authentication settings"},
		{name: "issuer only", issuer: "https://idp", wantErr: "STRATIUM_PRINCIPAL_OIDC_AUDIENCE, STRATIUM_PRINCIPAL_CLAIM"},
		{name: "no claim", issuer: "https://idp", audience: "a", wantErr: "STRATIUM_PRINCIPAL_CLAIM"},
		{name: "opt-out and oidc conflict", issuer: "https://idp", audience: "a", claim: "email", insecure: "true", wantErr: "conflicts"},
		{name: "opt-out with a stray setting conflicts", claim: "email", insecure: "true", wantErr: "conflicts"},
		{name: "unparseable flag", insecure: "sure", wantErr: "STRATIUM_PRINCIPAL_AUTH_INSECURE"},
		{name: "unparseable timeout", issuer: "https://idp", audience: "a", claim: "email", timeout: "soon", wantErr: "STRATIUM_PRINCIPAL_OIDC_TIMEOUT"},
		{name: "non-positive timeout", issuer: "https://idp", audience: "a", claim: "email", timeout: "0s", wantErr: "must be positive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnv(t)
			t.Setenv("STRATIUM_PRINCIPAL_OIDC_ISSUER", tt.issuer)
			t.Setenv("STRATIUM_PRINCIPAL_OIDC_AUDIENCE", tt.audience)
			t.Setenv("STRATIUM_PRINCIPAL_CLAIM", tt.claim)
			t.Setenv("STRATIUM_PRINCIPAL_OIDC_TIMEOUT", tt.timeout)
			t.Setenv("STRATIUM_PRINCIPAL_AUTH_INSECURE", tt.insecure)
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
			if got.PrincipalAuthInsecure != tt.wantInsecure {
				t.Errorf("PrincipalAuthInsecure = %v, want %v", got.PrincipalAuthInsecure, tt.wantInsecure)
			}
			if got.PrincipalOIDCTimeout != 5*time.Second {
				t.Errorf("PrincipalOIDCTimeout = %s, want the 5s default", got.PrincipalOIDCTimeout)
			}
		})
	}
}
