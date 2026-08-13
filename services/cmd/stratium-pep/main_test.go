package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDispatch_NoArgs_UsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch(nil, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Errorf("dispatch() = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a usage message")
	}
}

func TestDispatch_UnknownSubcommand_UsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"bogus"}, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Errorf("dispatch() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "bogus") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", stderr.String())
	}
}

// The mutation-testing anchor for "make the extauthz mode unreachable from
// dispatch": with every extauthz-required variable cleared,
// loadExtauthzConfigFromEnv fails immediately, so this returns without ever
// binding a listener -- fast and hang-free, unlike calling runExtauthzCmd
// with real configuration, which blocks forever inside grpcServer.Serve
// (extauthz.go's own doc comment covers why that function never returns
// under normal operation).
//
// Asserting stderr does NOT contain "unknown subcommand" is what actually
// proves the routing: deleting the "extauthz" case from dispatch's switch
// would still return exit code 1 here too (the default branch also returns
// 1), so the exit code alone cannot tell "routed to extauthz, then failed
// on config" apart from "never routed at all" -- only the stderr text can.
func TestDispatch_Extauthz_RoutesToExtauthzMode(t *testing.T) {
	clearExtauthzEnv(t)

	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"extauthz"}, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Errorf("dispatch() = %d, want 1 (missing extauthz configuration)", code)
	}
	if strings.Contains(stderr.String(), "unknown subcommand") {
		t.Errorf(`stderr = %q, dispatch treated "extauthz" as an unknown subcommand -- it is not wired into the switch`, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing required configuration") {
		t.Errorf("stderr = %q, want it to report extauthz's own missing configuration, proving dispatch actually reached loadExtauthzConfigFromEnv", stderr.String())
	}
}
