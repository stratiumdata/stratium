package main

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

// discardLogger is a *slog.Logger that writes nowhere -- run's own logging
// is not under test here (and must never be handed a real operator claim
// to log in the first place; see oidc.go), only that it surfaces the
// errors loadConfig and NewVerifier return.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestRun_MissingConfig_ReturnsError proves run() actually calls
// loadConfig and propagates its error, rather than main.go silently
// diverging from what config_test.go proves loadConfig itself does.
func TestRun_MissingConfig_ReturnsError(t *testing.T) {
	clearPAPEnv(t)

	err := run(discardLogger())
	if err == nil {
		t.Fatal("run() error = nil, want the missing configuration error")
	}
	if !strings.Contains(err.Error(), "STRATIUM_PAP_TENANT_ID") {
		t.Errorf("run() error = %q, want it to name a missing required variable", err.Error())
	}
}

// TestRun_UnreachableOIDCIssuer_ReturnsError proves run() calls
// NewVerifier (discovery) as a step distinct from, and after, loadConfig --
// config.go's own doc comment describes why that split exists; this is
// what would catch it being silently collapsed or skipped.
func TestRun_UnreachableOIDCIssuer_ReturnsError(t *testing.T) {
	idp := newTestIdP(t)
	idp.server.Close() // now refuses connections immediately

	clearPAPEnv(t)
	setAllPAPEnv(t, map[string]string{"STRATIUM_PAP_OIDC_ISSUER": idp.server.URL})
	// STRATIUM_PAP_OIDC_TIMEOUT is optional (config.go) so setAllPAPEnv's
	// overrides map -- which only ranges over requiredPAPEnvVars -- cannot
	// set it; set it directly, short so this test fails fast rather than
	// waiting out the 5s default against an endpoint that is refusing
	// connections immediately anyway.
	t.Setenv("STRATIUM_PAP_OIDC_TIMEOUT", "2s")

	err := run(discardLogger())
	if err == nil {
		t.Fatal("run() error = nil, want an error from failed OIDC discovery")
	}
	if !strings.Contains(err.Error(), "OIDC verifier") {
		t.Errorf("run() error = %q, want it to name OIDC verifier initialization", err.Error())
	}
}
