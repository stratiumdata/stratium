package main

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// requiredExtauthzEnvVars names every variable loadExtauthzConfigFromEnv
// requires -- shared by clearExtauthzEnv and setAllExtauthzEnv below, the
// same role requiredHookEnvVars (hook_test.go) plays for hookConfig, so a
// field added to extauthzConfig without a matching entry here goes untested
// for its own absence rather than failing loudly.
var requiredExtauthzEnvVars = []string{
	"STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR", "STRATIUM_PEP_PDP_ADDR",
	"STRATIUM_PEP_AGENT_ID", "STRATIUM_PEP_SUBJECT", "STRATIUM_PEP_CONNECT_TIMEOUT",
}

// clearExtauthzEnv clears every variable loadExtauthzConfigFromEnv reads, so
// each test below starts from a known-empty baseline regardless of what the
// ambient environment happens to have set -- t.Setenv restores each after
// the test, so tests never leak into one another.
func clearExtauthzEnv(t *testing.T) {
	t.Helper()
	for _, k := range requiredExtauthzEnvVars {
		t.Setenv(k, "")
	}
}

// setAllExtauthzEnv sets every required variable to a valid value, then
// applies overrides -- the shared "everything valid except what this test is
// deliberately breaking" baseline every case below builds on, mirroring
// setAllHookEnv (hook_test.go).
func setAllExtauthzEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	values := map[string]string{
		"STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR": "127.0.0.1:9191",
		"STRATIUM_PEP_PDP_ADDR":             "localhost:50051",
		"STRATIUM_PEP_AGENT_ID":             "agent-1",
		"STRATIUM_PEP_SUBJECT":              "alice@example.com",
		"STRATIUM_PEP_CONNECT_TIMEOUT":      "5s",
	}
	for k, v := range overrides {
		values[k] = v
	}
	for _, k := range requiredExtauthzEnvVars {
		t.Setenv(k, values[k])
	}
}

func TestLoadExtauthzConfigFromEnv_AllRequiredValuesPresent_ReturnsPopulatedConfig(t *testing.T) {
	clearExtauthzEnv(t)
	setAllExtauthzEnv(t, nil)

	cfg, err := loadExtauthzConfigFromEnv()
	if err != nil {
		t.Fatalf("loadExtauthzConfigFromEnv() error = %v, want nil", err)
	}
	want := extauthzConfig{
		ListenAddr:     "127.0.0.1:9191",
		PDPAddr:        "localhost:50051",
		AgentID:        "agent-1",
		Subject:        "alice@example.com",
		ConnectTimeout: 5 * time.Second,
	}
	if cfg != want {
		t.Errorf("loadExtauthzConfigFromEnv() = %+v, want %+v", cfg, want)
	}
}

// Each required variable, missing alone, is named in the resulting error --
// the per-field companion to
// TestLoadExtauthzConfigFromEnv_MissingMultipleRequired_NamesAllAtOnce below,
// which proves the same thing holds when more than one is missing at once.
func TestLoadExtauthzConfigFromEnv_MissingVariable_NamesIt(t *testing.T) {
	for _, missing := range requiredExtauthzEnvVars {
		t.Run(missing, func(t *testing.T) {
			clearExtauthzEnv(t)
			setAllExtauthzEnv(t, map[string]string{missing: ""})

			_, err := loadExtauthzConfigFromEnv()
			if err == nil {
				t.Fatalf("loadExtauthzConfigFromEnv() error = nil, want an error naming %s", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("loadExtauthzConfigFromEnv() error = %q, want it to name %s", err.Error(), missing)
			}
		})
	}
}

// The property the brief is built around, and the mutation-testing anchor
// for "make a missing config value report only the first": every required
// variable left unset at once (a freshly configured extauthz deployment
// with none of its environment set yet is exactly this case) must produce
// ONE error naming all of them, not just whichever requiredEnv happened to
// check first -- so fixing configuration takes one read of one error
// message, not one restart per gap. Mirrors
// TestLoad_MissingMultipleRequired_NamesAllAtOnce (internal/config), the
// same property proven for the PDP's own config loader.
func TestLoadExtauthzConfigFromEnv_MissingMultipleRequired_NamesAllAtOnce(t *testing.T) {
	clearExtauthzEnv(t)

	_, err := loadExtauthzConfigFromEnv()
	if err == nil {
		t.Fatal("loadExtauthzConfigFromEnv() with every required variable unset: want error, got nil")
	}
	for _, want := range requiredExtauthzEnvVars {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s alongside the other missing variables", err.Error(), want)
		}
	}
}

// STRATIUM_PEP_CONNECT_TIMEOUT rejects the same three bad shapes
// requiredDuration (config.go) is meant to catch: unparseable, zero, and
// negative -- mirroring the identical duration cases in
// TestLoadHookConfigFromEnv (hook_test.go).
func TestLoadExtauthzConfigFromEnv_InvalidConnectTimeout_ReturnsError(t *testing.T) {
	for _, bad := range []struct {
		name  string
		value string
	}{
		{"not a duration", "not-a-duration"},
		{"zero", "0s"},
		{"negative", "-5s"},
	} {
		t.Run(bad.name, func(t *testing.T) {
			clearExtauthzEnv(t)
			setAllExtauthzEnv(t, map[string]string{"STRATIUM_PEP_CONNECT_TIMEOUT": bad.value})

			_, err := loadExtauthzConfigFromEnv()
			if err == nil {
				t.Fatalf("loadExtauthzConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_CONNECT_TIMEOUT")
			}
			if !strings.Contains(err.Error(), "STRATIUM_PEP_CONNECT_TIMEOUT") {
				t.Errorf("loadExtauthzConfigFromEnv() error = %q, want it to name STRATIUM_PEP_CONNECT_TIMEOUT", err.Error())
			}
		})
	}
}

// startExtauthzServer serves srv (the real extauthzServer under test, not a
// fake) on an OS-assigned loopback port and returns a real
// authv3.AuthorizationClient dialed to it, over an actual TCP connection
// through the generated gRPC client -- the same "exercise the real wire,
// not a mocked interface" choice pdp_fake_test.go's startFakePDP makes for
// the PDP-facing side of this binary (see its own doc comment), applied
// here to the side of this binary that is itself the server: it proves
// CheckResponse's oneof and Status fields cross the wire the way this file
// intends, not merely that a Go struct literal was built correctly in
// memory.
func startExtauthzServer(t *testing.T, srv authv3.AuthorizationServer) authv3.AuthorizationClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer()
	authv3.RegisterAuthorizationServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return authv3.NewAuthorizationClient(conn)
}

// The mutation-testing anchor for "make the skeleton allow instead of
// deny": Task 1 has no decision logic, so the only honest answer to any
// Check call is an unconditional deny, returned as a normal
// (*CheckResponse, nil) -- never a transport-level error (see Check's own
// doc comment for why that distinction matters to Envoy's
// failure_mode_allow). Three independent signals a caller could read this
// response by are asserted separately -- the top-level google.rpc.Status
// Envoy's ext_authz filter actually keys allow/deny off of, the
// HttpResponse oneof's concrete type, and the nested, literal HTTP status
// DeniedHttpResponse carries for the downstream caller -- so a mutation
// flipping any one of the three alone still fails this test. The third
// assertion exists because the first mutation-testing pass for this task
// found it missing: a build that denies correctly at the top level (the
// signal that actually keeps this server fail-closed) but reports the
// downstream HTTP status as 200 would have passed the first two checks
// alone -- not an open-proxy defect, since Envoy still denies, but a wrong,
// user-facing "200 OK" on what is actually a denial, and this test now
// catches it.
func TestCheck_NoDecisionLogicYet_DeniesEveryRequestUnconditionally(t *testing.T) {
	client := startExtauthzServer(t, &extauthzServer{})

	resp, err := client.Check(context.Background(), &authv3.CheckRequest{})
	if err != nil {
		t.Fatalf("Check() returned a transport error (%v); a Task 1 denial must be an ordinary "+
			"CheckResponse with err == nil, not an RPC failure -- see Check's own doc comment", err)
	}

	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED) -- an unconditional-deny skeleton must never report OK", got, want)
	}
	denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse -- Task 1 has no "+
			"decision logic and must never construct an OkResponse", resp.GetHttpResponse())
	}
	if got, want := denied.DeniedResponse.GetStatus().GetCode(), typev3.StatusCode_Forbidden; got != want {
		t.Errorf("DeniedResponse.Status.Code = %s, want %s -- the downstream caller must be told this was a denial, not left with a misleading HTTP status", got, want)
	}
}

// Defends spec defect D1 directly: a request shaped exactly like the kind
// of thing a future implementation might be tempted to wave through with a
// "health checks are fine" shortcut -- GET /healthz -- gets no special
// treatment from a server with no authority to classify anything. This is
// the test the brief's binding constraint asks for by name; it is
// deliberately a second, distinct test from
// TestCheck_NoDecisionLogicYet_DeniesEveryRequestUnconditionally rather
// than a second case folded into it, because the property it defends is
// different: that test proves the skeleton denies AT ALL; this one proves
// nothing about a request's content can turn that denial into an allow.
func TestCheck_RequestShapeIsIrrelevant_StillDenies(t *testing.T) {
	client := startExtauthzServer(t, &extauthzServer{})

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/healthz",
				},
			},
		},
	}
	resp, err := client.Check(context.Background(), req)
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("GET /healthz was allowed (Status.Code = %d, want %d PERMISSION_DENIED) -- "+
			"Task 1 must not special-case any request shape, including one that looks like a health check (spec defect D1)",
			got, want)
	}
}
