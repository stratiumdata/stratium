package agent

import (
	"errors"
	"strings"
	"testing"
)

// A missing prerequisite must never read like a Stratium denial. The error
// names the thing and the fix.
func TestPrecheck_FailureNamesTheFix(t *testing.T) {
	err := Precheck(
		Check{Name: "ollama", Probe: func() error { return nil }, Fix: "start ollama"},
		Check{Name: "litellm", Probe: func() error { return errors.New("connection refused") },
			Fix: "docker compose up -d litellm"},
	)
	if err == nil {
		t.Fatal("Precheck() = nil with a failing check")
	}
	for _, want := range []string{"litellm", "connection refused", "docker compose up -d litellm"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

func TestPrecheck_AllPassing(t *testing.T) {
	if err := Precheck(Check{Name: "x", Probe: func() error { return nil }}); err != nil {
		t.Fatalf("Precheck() = %v, want nil", err)
	}
}
