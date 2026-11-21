package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoad_Ceilings(t *testing.T) {
	const ttl, eval = "STRATIUM_MAX_DELEGATION_TTL", "STRATIUM_POLICY_EVAL_TIMEOUT"

	t.Run("defaults", func(t *testing.T) {
		setValidEnv(t)
		t.Setenv(ttl, "")
		t.Setenv(eval, "")
		got, err := Load()
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if got.MaxDelegationTTL != 24*time.Hour || got.PolicyEvalTimeout != 2*time.Second {
			t.Errorf("got %v and %v, want 24h and 2s", got.MaxDelegationTTL, got.PolicyEvalTimeout)
		}
	})

	t.Run("from the environment", func(t *testing.T) {
		setValidEnv(t)
		t.Setenv(ttl, "168h")
		t.Setenv(eval, "500ms")
		got, err := Load()
		if err != nil {
			t.Fatalf("Load() = %v", err)
		}
		if got.MaxDelegationTTL != 168*time.Hour || got.PolicyEvalTimeout != 500*time.Millisecond {
			t.Errorf("got %v and %v, want 168h and 500ms", got.MaxDelegationTTL, got.PolicyEvalTimeout)
		}
	})

	for _, name := range []string{ttl, eval} {
		for _, bad := range []string{"soon", "0s", "-1h"} {
			t.Run(name+"="+bad, func(t *testing.T) {
				setValidEnv(t)
				t.Setenv(name, bad)
				if _, err := Load(); err == nil || !strings.Contains(err.Error(), name) {
					t.Errorf("Load() = %v, want an error naming %s", err, name)
				}
			})
		}
	}
}
