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

// TestDispatch_Proxy_RoutesToProxyMode is proxy's own version of
// TestDispatch_Extauthz_RoutesToExtauthzMode above -- the "the mode is reachable from dispatch"
// property the task brief asks for by name, and the mutation-testing anchor for "make the proxy
// mode unreachable from dispatch." With every proxy-required variable cleared,
// loadProxyConfigFromEnv fails immediately, so this returns without ever binding a listener --
// fast and hang-free, unlike calling runProxyCmd with real configuration, which blocks forever
// inside grpcServer.Serve (proxy.go's own doc comment covers why that function never returns
// under normal operation).
//
// Asserting stderr does NOT contain "unknown subcommand" is what actually proves the routing:
// deleting the "proxy" case from dispatch's switch would still return exit code 1 here too (the
// default branch also returns 1), so the exit code alone cannot tell "routed to proxy, then
// failed on config" apart from "never routed at all" -- only the stderr text can. Naming
// STRATIUM_PEP_PROXY_LISTEN_ADDR specifically, not just the generic "missing required
// configuration" prefix every loader in this package shares, further rules out dispatch having
// routed "proxy" to some OTHER mode's config loader that happens to produce the same prefix.
func TestDispatch_Proxy_RoutesToProxyMode(t *testing.T) {
	clearProxyEnv(t)

	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"proxy"}, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Errorf("dispatch() = %d, want 1 (missing proxy configuration)", code)
	}
	if strings.Contains(stderr.String(), "unknown subcommand") {
		t.Errorf(`stderr = %q, dispatch treated "proxy" as an unknown subcommand -- it is not wired into the switch`, stderr.String())
	}
	if !strings.Contains(stderr.String(), "missing required configuration") {
		t.Errorf("stderr = %q, want it to report proxy's own missing configuration, proving dispatch actually reached loadProxyConfigFromEnv", stderr.String())
	}
	if !strings.Contains(stderr.String(), "STRATIUM_PEP_PROXY_LISTEN_ADDR") {
		t.Errorf("stderr = %q, want it to name STRATIUM_PEP_PROXY_LISTEN_ADDR specifically, proving dispatch reached proxy's OWN config loader", stderr.String())
	}
}
