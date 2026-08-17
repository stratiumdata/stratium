package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"github.com/google/uuid"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stratium/internal/pdpgrpc"
)

// requiredExtauthzEnvVars names every variable loadExtauthzConfigFromEnv
// requires -- shared by clearExtauthzEnv and setAllExtauthzEnv below, the
// same role requiredHookEnvVars (hook_test.go) plays for hookConfig, so a
// field added to extauthzConfig without a matching entry here goes untested
// for its own absence rather than failing loudly.
var requiredExtauthzEnvVars = []string{
	"STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR", "STRATIUM_PEP_PDP_ADDR",
	"STRATIUM_PEP_AGENT_ID", "STRATIUM_PEP_SUBJECT", "STRATIUM_PEP_CONNECT_TIMEOUT",
	"STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS",
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
		// Two entries, not one: a loader that returned only the first, or
		// only the last, is a live mutation and a single-entry baseline
		// cannot see it.
		"STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS": "gw-a.example:10000,gw-b.example",
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
		AllowedHosts:   []string{"gw-a.example:10000", "gw-b.example"},
	}
	// reflect.DeepEqual rather than ==: extauthzConfig stopped being
	// comparable when AllowedHosts made it carry a slice. Compared whole, not
	// field by field, so a field added to extauthzConfig and never loaded
	// still fails here -- which is the whole point of asserting the struct.
	if !reflect.DeepEqual(cfg, want) {
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

// ---------------------------------------------------------------------------
// Task 2: CheckRequest -> DecideRequest mapping.
// ---------------------------------------------------------------------------

// Fixture values below are deliberately distinctive strings sharing no
// substring with one another or with anything Check itself ever generates
// (a header name, a JSON key, a proto field name) -- a fixture that reused,
// say, "authorization" or "token" as its own value could pass a test by
// accident even after a mixup (reading the wrong field, comparing against
// the wrong constant). None of these could appear in a wire message by
// coincidence.
const (
	testBearerToken          = "extauthz-bearer-f3c9a06e1d8b4257-fixture"
	testOtherCredentialValue = "extauthz-other-credential-77b2e4c1-fixture"
	testAuthLikeHeaderName   = "x-auth-context"
	testAuthLikeHeaderValue  = "extauthz-authlike-header-4e91cd08-fixture"
	testAgentIDFixture       = "extauthz-agent-6a2f0b13-fixture"
	testSubjectFixture       = "extauthz-subject-6a2f0b13-fixture@example.com"
	testDPoPProof            = "extauthz-dpop-proof-b41e7a92-fixture"
	// approvalIDHeaderInTest spells approvalIDHeader out as a literal rather
	// than referencing the constant, so a rename of the constant cannot
	// silently rename the wire key these tests assert against -- the
	// cross-system self-agreement Phase 15 Task 2 was bitten by (a claim name
	// that agreed with itself perfectly and matched no external verifier). The
	// two are checked against each other once, below.
	approvalIDHeaderInTest = "stratium-approval-id"
)

// The wire key both network surfaces read and write must be the one spelled
// out above; a constant compared only against itself proves nothing.
func TestApprovalIDHeaderName(t *testing.T) {
	if approvalIDHeader != approvalIDHeaderInTest {
		t.Errorf("approvalIDHeader = %q, want %q -- this is the key an operator is told to send back, "+
			"and it is published in a denial before any code reads it", approvalIDHeader, approvalIDHeaderInTest)
	}
}

// allowResponse is the DecideResponse a real PDP returns for the only case
// EITHER network surface may forward as of Phase 15: a bound token whose DPoP
// proof verified. Effect alone is no longer enough -- extauthz's
// checkResponseFromDecide and proxy's allowIfSenderConstrained both refuse an
// ALLOW carrying sender_constrained=false (K5) -- so a fixture that set only
// Effect would be scripting a response the PDP produces for a BEARER token,
// and every test asserting a forwarded request would be asserting the
// opposite of what it means to.
//
// Shared with proxy_test.go rather than copied into it: K5 is one rule with
// two enforcement points, and a second, independently maintained fixture is
// how the two would end up scripting different notions of "the PDP allowed
// this".
//
// One helper rather than the literal repeated per test, because that is the
// fact worth stating once: on these surfaces, "the PDP allowed it" and "the
// request may be forwarded" are two different claims. reason is a parameter
// only because a few callers assert on it; the rest pass "".
func allowResponse(reason string) *pdpgrpc.DecideResponse {
	return &pdpgrpc.DecideResponse{
		Effect:            pdpgrpc.Effect_EFFECT_ALLOW,
		Reason:            reason,
		SenderConstrained: true,
	}
}

// testExtauthzServerCfg is the AgentID/Subject/ConnectTimeout every test
// below needs to construct an extauthzServer directly (bypassing
// runExtauthzCmd and its environment-variable loading entirely, the same
// choice hook_test.go's testCfg makes for hookConfig). ListenAddr/PDPAddr
// are left zero-valued: nothing in these tests calls runExtauthzCmd, so
// nothing ever reads them.
// AllowedHosts carries every authority any fixture below sends, so the
// allowlist is never what a test about something else trips over. The tests
// that are ABOUT the allowlist build their own cfg.
func testExtauthzServerCfg() extauthzConfig {
	return extauthzConfig{
		AgentID:        testAgentIDFixture,
		Subject:        testSubjectFixture,
		ConnectTimeout: 5 * time.Second,
		AllowedHosts: []string{
			testHost,
			"gateway.example:10000", "gateway.example", "gateway.example:8443",
		},
	}
}

// testScheme and testHost are what checkRequest stamps onto every request
// below, so the default fixture is shaped like something a real Envoy sends
// rather than like the minimum this file happens to read. Both were measured
// against the real Envoy in deploy/docker rather than assumed -- see
// observedURI's own doc comment for the transcript and for what it settled.
const (
	testScheme = "http"
	testHost   = "extauthz-host-9d1c4b70-fixture.example:10000"
)

// checkRequest builds a CheckRequest carrying method, path, and headers --
// the same three pieces of an HTTP request every test below needs, without
// each one repeating the AttributeContext/AttributeContext_Request/
// AttributeContext_HttpRequest nesting TestCheck_RequestShapeIsIrrelevant_StillDenies
// above already spells out once. Scheme and Host come from the two constants
// above; the tests that vary them (observed_uri's own) call checkRequestFull.
func checkRequest(method, path string, headers map[string]string) *authv3.CheckRequest {
	return checkRequestFull(testScheme, testHost, method, path, headers)
}

func checkRequestFull(scheme, host, method, path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Scheme:  scheme,
					Host:    host,
					Method:  method,
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

// TestCheck_PathBecomesTool defends M1: the request path is the tool
// identity sent to the PDP, unmodified -- no parsing, no stripping a query
// string, no method-based variation. The path used here
// (/inventory.Inventory/DeleteItem) is the plan's own worked example of why
// this matters: it must reach the PDP exactly as a tenant would have
// cataloged it. agent_id/subject are checked in the same test, as a bonus,
// for the same reason hook_test.go folds its own identity check into a
// differently-named test rather than giving it a whole test of its own: it
// is the same "carried through from cfg, unmodified" claim on two more
// fields, on a request this test already built and sent.
func TestCheck_PathBecomesTool(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	cfg := testExtauthzServerCfg()
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: cfg})

	const path = "/inventory.Inventory/DeleteItem"
	_, err := client.Check(context.Background(), checkRequest("POST", path, map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.GetTool() != path {
		t.Errorf("tool = %q, want the request path %q", req.GetTool(), path)
	}
	if req.GetAgentId() != cfg.AgentID || req.GetSubject() != cfg.Subject {
		t.Errorf("request identity = (agent=%q subject=%q), want (%q, %q)",
			req.GetAgentId(), req.GetSubject(), cfg.AgentID, cfg.Subject)
	}
}

// TestCheck_BearerTokenExtracted defends M2's other half: the token named
// in "authorization: Bearer <token>" reaches DecideRequest.Token, with the
// "Bearer " scheme stripped and nothing else altered.
func TestCheck_BearerTokenExtracted(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	_, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.GetToken() != testBearerToken {
		t.Errorf("token = %q, want %q", req.GetToken(), testBearerToken)
	}
}

// TestCheck_Allow_ReturnsOkResponse is the property
// TestCheck_ValidCredential_StillDeniesUntilTask3MapsTheResponse (Task 2)
// existed specifically to prove did NOT hold yet: a well-formed credential
// and a PDP that answers EFFECT_ALLOW now produces an OK CheckResponse, not
// a denial. That Task 2 test is gone, not merely widened, because its
// premise (a well-formed request the PDP allows still denies) is no longer
// this function's behavior. Checked two ways, mirroring
// TestCheck_NoDecisionLogicYet_DeniesEveryRequestUnconditionally's own
// multi-signal approach for the deny case: the top-level Status.Code
// Envoy's filter actually keys allow/deny off of, and the HttpResponse
// oneof's concrete type -- a mutation that flips one but not the other
// still fails this test. requestCount confirms the PDP really was asked,
// the same "still X anyway" discipline the old test used, applied to the
// new outcome.
func TestCheck_Allow_ReturnsOkResponse(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("policy allows")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_OK); got != want {
		t.Errorf("Status.Code = %d, want %d (OK) -- a well-formed credential and an ALLOW from the PDP must let Envoy forward the request", got, want)
	}
	if _, ok := resp.GetHttpResponse().(*authv3.CheckResponse_OkResponse); !ok {
		t.Errorf("HttpResponse = %T, want *authv3.CheckResponse_OkResponse", resp.GetHttpResponse())
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- a well-formed credential must reach the PDP", got)
	}
}

// TestCheck_RepeatedIdenticalRequests_AlwaysCallsPDP is spec §4.8.3 W6 as a
// test, not a comment: this file never gains a decision cache (see
// local_cache.go's own package doc for exactly where that boundary sits and
// why -- extauthz's caller IS the party being policed, so a cache hit here
// would mean serving a decision on the strength of a token this server never
// verified). An identical request repeated must reach the PDP every single
// time; a future edit that wired a cache into this file -- even innocently,
// by copying hook.go's or mcp_authorize.go's own pattern -- would make the
// second and later calls below short-circuit before ever reaching
// fake.Decide, which is exactly what requestCount() catches: it would read
// less than attempts, not equal to it.
func TestCheck_RepeatedIdenticalRequests_AlwaysCallsPDP(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	const attempts = 5
	for i := 0; i < attempts; i++ {
		resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
			"authorization": "Bearer " + testBearerToken,
		}))
		if err != nil {
			t.Fatalf("Check() attempt %d error = %v", i, err)
		}
		if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_OK); got != want {
			t.Fatalf("attempt %d: Status.Code = %d, want %d (OK)", i, got, want)
		}
	}
	if got := fake.requestCount(); got != attempts {
		t.Errorf("PDP received %d Decide call(s) for %d identical requests, want exactly %d -- extauthz "+
			"must never serve a repeat from a cache (spec W6): every request re-authenticates the "+
			"caller's own token, which only the PDP can verify (K2)", got, attempts, attempts)
	}
}

// TestCheck_UnreachablePDP_DeniesAsOrdinaryResponse_NotTransportError is the
// test Check's own doc comment promises but nothing above actually
// exercises: every other test scripts a fakePDP that answers (with ALLOW,
// or implicitly with EFFECT_DENY's zero value); this one points at a real,
// dialed-and-closed loopback port (unreachablePDPClient, pdp_fake_test.go)
// so client.Decide genuinely fails at the transport layer, not merely by a
// scripted fake error value. The property this defends is specifically the
// SHAPE of Check's own return, not just that it denies: (resp, nil), never
// (nil, err) -- Envoy's failure_mode_allow treats a returned Go error as a
// transport fault it may be configured to fail OPEN on, so folding an
// unreachable PDP into an ordinary PERMISSION_DENIED CheckResponse, rather
// than propagating client.Decide's own error outward, is what keeps that
// knob from ever being able to allow a request this server never decided.
func TestCheck_UnreachablePDP_DeniesAsOrdinaryResponse_NotTransportError(t *testing.T) {
	pdpClient := unreachablePDPClient(t)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() returned a transport error (%v); an unreachable PDP must still produce an ordinary "+
			"(*CheckResponse, nil) -- see Check's own doc comment for why a Go error here would hand "+
			"failure_mode_allow a fail-open option this rule exists to deny it", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED) -- an unreachable PDP must deny", got, want)
	}
}

// TestCheck_MissingAuthorizationHeader_DeniesWithoutContactingPDP is the
// test the brief asks for by name: K4 leaves no fallback credential, so a
// request with no authorization header at all must not merely be denied --
// it must never reach the PDP in the first place. Asserted against the
// fake's own received-call count, not against Check's response: a build
// that called Decide and then denied anyway (ignoring what came back) would
// still produce the same CheckResponse this test would otherwise accept,
// which is exactly why "assert the PDP was not called" is the property,
// not "assert the result was deny" -- see the package doc's TASK 2
// ADDITIONS section, and
// TestCheck_ValidCredential_StillDeniesUntilTask3MapsTheResponse above,
// which proves a well-formed credential DOES produce exactly one call, so
// the zero asserted here is a real contrast, not a count that would read
// zero no matter what this server did.
func TestCheck_MissingAuthorizationHeader_DeniesWithoutContactingPDP(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"x-request-id": "req-fixture-does-not-matter",
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED)", got, want)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a missing authorization header must deny "+
			"without ever contacting the PDP (K4: there is no fallback credential to ask about)", got)
	}
}

// TestCheck_MalformedAuthorizationHeader_DeniesWithoutContactingPDP covers
// every shape of "present but useless" M2 leaves this server no fallback
// for: a scheme that is not Bearer, and a Bearer challenge with nothing
// after it. Every case denies for the same reason a missing header does --
// see TestCheck_MissingAuthorizationHeader_DeniesWithoutContactingPDP --
// and is checked the same way, against the PDP's own call count.
func TestCheck_MalformedAuthorizationHeader_DeniesWithoutContactingPDP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"not a Bearer challenge", "Basic " + testBearerToken},
		{"Bearer scheme, no token at all", "Bearer"},
		{"Bearer scheme, trailing space but empty token", "Bearer "},
		{"lowercase bearer scheme", "bearer " + testBearerToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

			resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
				"authorization": tc.value,
			}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
				t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED)", got, want)
			}
			if got := fake.requestCount(); got != 0 {
				t.Errorf("PDP received %d Decide call(s), want 0 -- a malformed authorization header (%q) "+
					"must deny without ever contacting the PDP", got, tc.value)
			}
		})
	}
}

// TestCheck_RawInputCarriesMethodAndPath defends M3's positive half:
// raw_input decodes as JSON carrying the request's own method and path.
// TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing below defends
// M3's negative half on the same field.
func TestCheck_RawInputCarriesMethodAndPath(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	const method, path = "DELETE", "/inventory.Inventory/DeleteItem"
	_, err := client.Check(context.Background(), checkRequest(method, path, map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	var got requestMetadata
	if err := json.Unmarshal([]byte(req.GetRawInput()), &got); err != nil {
		t.Fatalf("raw_input is not well-formed JSON: %v\nraw_input: %s", err, req.GetRawInput())
	}
	if got.Method != method {
		t.Errorf("raw_input method = %q, want %q", got.Method, method)
	}
	if got.Path != path {
		t.Errorf("raw_input path = %q, want %q", got.Path, path)
	}
}

// TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing is the
// load-bearing test in this file: raw_input is hashed into the append-only
// audit chain (see the package doc), so a bearer token that leaks there is
// live authority written permanently into a record designed to be kept and
// read, in a chain that cannot be edited to remove it. Table-driven over
// four header-name spellings -- the exact casing Envoy's own docs say it
// normally sends, and three it does not promise against -- because a
// case-sensitive strip (mutation-tested in the task report) passes for the
// first spelling and fails silently for the other three; testing only
// "authorization" would never catch that.
//
// Every case asserts absence two ways: structurally, by unmarshaling
// raw_input and checking no header key case-insensitively equals
// "authorization" (a check that survives a future change to how the JSON
// happens to be formatted), and by substring, confirming the literal token
// value -- distinctive enough that it cannot appear anywhere else in this
// fixture by coincidence -- is absent from the raw bytes altogether. Either
// alone would catch the mutation this test exists for; both together also
// catch a stripped-but-still-leaked-elsewhere variant neither check alone
// would.
func TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing(t *testing.T) {
	for _, headerName := range []string{"authorization", "Authorization", "AUTHORIZATION", "AuthoriZation"} {
		t.Run(headerName, func(t *testing.T) {
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

			_, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
				headerName: "Bearer " + testBearerToken,
			}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			req := fake.lastRequest()
			if req == nil {
				t.Fatal("PDP never received a request -- extraction must have found this header " +
					"(see TestCheck_BearerTokenExtracted), so Check should have gone on to call the PDP")
			}
			raw := req.GetRawInput()

			if strings.Contains(raw, testBearerToken) {
				t.Errorf("raw_input contains the bearer token verbatim: %s", raw)
			}

			var got requestMetadata
			if err := json.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatalf("raw_input is not well-formed JSON: %v\nraw_input: %s", err, raw)
			}
			for key := range got.Headers {
				if strings.EqualFold(key, "authorization") {
					t.Errorf("raw_input.headers carries key %q -- authorization must never appear, in any casing", key)
				}
			}
		})
	}
}

// TestCheck_RawInputPreservesNonCredentialHeaders guards the other side of
// the stripping rule. TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing
// above would pass just as well if extractBearerToken stripped every
// header instead of only the credential-bearing ones -- an empty headers
// map can never carry "authorization" either. The header used here,
// x-auth-context, is deliberately chosen to also guard against a SPECIFIC
// over-broad implementation: a substring match on "auth" instead of an
// exact match against credentialHeaderNames would wrongly strip this one
// too, even though it carries no credential at all.
func TestCheck_RawInputPreservesNonCredentialHeaders(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	_, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization":        "Bearer " + testBearerToken,
		testAuthLikeHeaderName: testAuthLikeHeaderValue,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	var got requestMetadata
	if err := json.Unmarshal([]byte(req.GetRawInput()), &got); err != nil {
		t.Fatalf("raw_input is not well-formed JSON: %v\nraw_input: %s", err, req.GetRawInput())
	}
	if got.Headers[testAuthLikeHeaderName] != testAuthLikeHeaderValue {
		t.Errorf("raw_input.headers[%q] = %q, want %q -- a non-credential header must still reach raw_input, "+
			"even one whose name merely LOOKS auth-related", testAuthLikeHeaderName, got.Headers[testAuthLikeHeaderName], testAuthLikeHeaderValue)
	}
}

// TestCheck_RawInputStripsOtherCredentialHeaders proves cookie and
// proxy-authorization -- the two other headers credentialHeaderNames' own
// doc comment names as credential-bearing (RFC 6265, RFC 7235) -- are
// actually in that set, not merely described as such in a comment.
// Table-driven over both headers, each in two casings, for the same
// case-insensitivity reason
// TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing is.
func TestCheck_RawInputStripsOtherCredentialHeaders(t *testing.T) {
	for _, headerName := range []string{"cookie", "Cookie", "proxy-authorization", "Proxy-Authorization"} {
		t.Run(headerName, func(t *testing.T) {
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

			_, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
				"authorization": "Bearer " + testBearerToken,
				headerName:      testOtherCredentialValue,
			}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			req := fake.lastRequest()
			if req == nil {
				t.Fatal("PDP never received a request")
			}
			if raw := req.GetRawInput(); strings.Contains(raw, testOtherCredentialValue) {
				t.Errorf("raw_input contains %q's value verbatim: %s", headerName, raw)
			}
		})
	}
}

// TestCheck_NeverSendsDeclaredTier defends the same property hook.go's
// TestRunHook_RequestCarriesRawInputAndNoDeclaredTier and mcp_authorize.go's
// mirror both defend for their own surfaces: declared_tier stays nil across
// a real wire round trip, not merely in the Go struct this file builds in
// memory -- proto3 omits a zero-value/unset optional field from the wire
// entirely, so checking req.DeclaredTier after fakePDP decodes a real
// message proves the WIRE never carried it, which a check against the
// pre-marshal struct alone would not. resource is checked alongside it for
// the same reason hook_test.go's own version does: neither PEP in this repo
// populates it anymore, and this is a cheap place to prove extauthz is no
// exception.
func TestCheck_NeverSendsDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	_, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.DeclaredTier != nil {
		t.Errorf("declared_tier = %v, want unset (nil) -- extauthz has no real tier to declare; "+
			"a guessed one only creates a chance to be wrong", req.GetDeclaredTier())
	}
	if resc := req.GetResource(); len(resc) != 0 {
		t.Errorf("resource = %v, want empty -- this file extracts nothing locally, for any request", resc)
	}
}

// TestDecideRequestFromCheck_NilAttributes_ErrorsWithoutPanicking proves the
// nil-safety decideRequestFromCheck's own doc comment claims: a CheckRequest
// with no HTTP attributes at all -- the shape Task 1's own
// TestCheck_NoDecisionLogicYet_DeniesEveryRequestUnconditionally sends --
// fails the same "no authorization header" way an ordinary request missing
// that header does, never panics chasing a nil Attributes/Request/Http
// pointer.
func TestDecideRequestFromCheck_NilAttributes_ErrorsWithoutPanicking(t *testing.T) {
	_, err := decideRequestFromCheck(&authv3.CheckRequest{}, testExtauthzServerCfg())
	if err == nil {
		t.Fatal("decideRequestFromCheck() error = nil, want an error (no HTTP attributes means no authorization header)")
	}
	// Specifically the CREDENTIAL error, not the authority one: an empty
	// CheckRequest also has no host, and both checks would refuse it. The
	// credential check runs first on purpose (see decideRequestFromCheck's
	// own doc comment), so K4's own integration proof keeps asserting the
	// text it was written for.
	if !strings.Contains(err.Error(), "no authorization header") {
		t.Errorf("error = %q, want the credential error -- the authority check must not preempt it", err)
	}
}

// TestExtractCredentials is the direct, wire-free table of every shape
// extractCredentials must accept or reject -- faster and more exhaustive
// than routing every case through a real gRPC round trip, which the Check-
// level tests above already do for the cases that specifically need to
// prove something about the WIRE (declared_tier, raw_input's JSON shape).
//
// wantProof is asserted on every row, not only the DPoP ones. A missing dpop
// header must yield "" and NOT a failure -- the token may be unbound, and
// deciding what a missing proof means belongs to the PDP (C25) and to
// checkResponseFromDecide (K5), never here -- so every pre-Phase-15 row below
// doubles as the assertion that adding a second credential did not make the
// first one's absence-of-the-second fatal.
func TestExtractCredentials(t *testing.T) {
	for _, tc := range []struct {
		name      string
		headers   map[string]string
		wantToken string
		wantProof string
		wantErr   bool
	}{
		{
			name:      "well-formed bearer token",
			headers:   map[string]string{"authorization": "Bearer " + testBearerToken},
			wantToken: testBearerToken,
		},
		{
			name: "bearer token and dpop proof together",
			headers: map[string]string{
				"authorization": "Bearer " + testBearerToken,
				"dpop":          testDPoPProof,
			},
			wantToken: testBearerToken,
			wantProof: testDPoPProof,
		},
		{
			name: "dpop proof with no authorization is still an error",
			// A proof names no delegation and authenticates nothing on its
			// own: K4's "no fallback credential" applies to it exactly as it
			// does to any other header that is not a bearer token.
			headers: map[string]string{"dpop": testDPoPProof},
			wantErr: true,
		},
		{
			name:    "no headers at all",
			headers: nil,
			wantErr: true,
		},
		{
			name:    "no authorization header",
			headers: map[string]string{"x-request-id": "abc"},
			wantErr: true,
		},
		{
			name:    "not a Bearer scheme",
			headers: map[string]string{"authorization": "Basic " + testBearerToken},
			wantErr: true,
		},
		{
			name:    "Bearer scheme, empty token after trailing space",
			headers: map[string]string{"authorization": "Bearer "},
			wantErr: true,
		},
		{
			name:    "Bearer scheme, no token and no trailing space",
			headers: map[string]string{"authorization": "Bearer"},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, proof, _, stripped, err := extractCredentials(tc.headers)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("extractCredentials() error = nil, want an error")
				}
				// No partial result on the error path, for the proof exactly
				// as for the token: a caller that ignored err must not find a
				// usable proof sitting in the second return value.
				if token != "" || proof != "" || stripped != nil {
					t.Errorf("extractCredentials() on the error path = (%q, %q, %v), want all zero values",
						token, proof, stripped)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractCredentials() error = %v, want nil", err)
			}
			if token != tc.wantToken {
				t.Errorf("extractCredentials() token = %q, want %q", token, tc.wantToken)
			}
			if proof != tc.wantProof {
				t.Errorf("extractCredentials() proof = %q, want %q", proof, tc.wantProof)
			}
		})
	}
}

// TestExtractCredentials_HeaderNameCaseDiffers_CredentialsStillFound is the
// direct-function twin of TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing
// and TestCheck_RawInputNeverCarriesDPoPProof_AnyHeaderCasing: this one proves
// EXTRACTION survives a header name that differs only in case, the others
// prove STRIPPING does. Both properties live in the same loop inside
// extractCredentials (see its own doc comment for why), but a mutation could
// plausibly break one without the other -- e.g. matching case-insensitively
// when deciding what to strip but comparing case-sensitively when deciding
// what to treat as the token -- so both get their own dedicated assertion.
//
// The dpop half matters more than the authorization half ever did, and the
// casings below are chosen to show why: RFC 9449 spells the header "DPoP",
// with an interior capital, while a real Envoy delivers "dpop". A match
// written case-sensitively against EITHER spelling silently drops the proof
// for the other -- and a dropped proof is not a loud failure, it is a
// DecideRequest carrying dpop_proof="" that denies a legitimate caller for a
// reason naming the wrong defect entirely.
func TestExtractCredentials_HeaderNameCaseDiffers_CredentialsStillFound(t *testing.T) {
	for _, tc := range []struct{ authName, dpopName string }{
		{"AUTHORIZATION", "DPoP"},
		{"Authorization", "dpop"},
		{"authorization", "DPOP"},
		{"AuthoriZation", "DpOp"},
	} {
		t.Run(tc.authName+"/"+tc.dpopName, func(t *testing.T) {
			token, proof, _, _, err := extractCredentials(map[string]string{
				tc.authName: "Bearer " + testBearerToken,
				tc.dpopName: testDPoPProof,
			})
			if err != nil {
				t.Fatalf("extractCredentials() error = %v, want nil -- a header named %q must still be found",
					err, tc.authName)
			}
			if token != testBearerToken {
				t.Errorf("extractCredentials() token = %q, want %q", token, testBearerToken)
			}
			if proof != testDPoPProof {
				t.Errorf("extractCredentials() proof = %q, want %q -- a header named %q must still be read as "+
					"the DPoP proof (RFC 9449 spells it \"DPoP\"; Envoy delivers \"dpop\")",
					proof, testDPoPProof, tc.dpopName)
			}
		})
	}
}

// TestExtractCredentials_StripsCredentialHeadersCaseInsensitively is the
// direct-function proof that every entry in credentialHeaderNames -- not
// just authorization -- is actually removed from the returned headers map,
// case-insensitively, while a header that merely looks credential-adjacent
// (testAuthLikeHeaderName) survives untouched.
func TestExtractCredentials_StripsCredentialHeadersCaseInsensitively(t *testing.T) {
	_, _, _, stripped, err := extractCredentials(map[string]string{
		"authorization":        "Bearer " + testBearerToken,
		"Cookie":               testOtherCredentialValue,
		"PROXY-AUTHORIZATION":  testOtherCredentialValue,
		"DPoP":                 testDPoPProof,
		testAuthLikeHeaderName: testAuthLikeHeaderValue,
	})
	if err != nil {
		t.Fatalf("extractCredentials() error = %v, want nil", err)
	}
	for _, credHeader := range []string{"authorization", "Cookie", "PROXY-AUTHORIZATION", "DPoP"} {
		if v, ok := stripped[credHeader]; ok {
			t.Errorf("stripped headers still contain %q = %q", credHeader, v)
		}
	}
	if v, ok := stripped[testAuthLikeHeaderName]; !ok || v != testAuthLikeHeaderValue {
		t.Errorf("stripped[%q] = (%q, %v), want (%q, true) -- not every auth-ish name is a credential",
			testAuthLikeHeaderName, v, ok, testAuthLikeHeaderValue)
	}
}

// TestEveryCredentialHeaderIsStrippedFromRawInput walks credentialHeaderNames
// ITSELF and proves each entry is stripped, in two casings. Iterating the map
// rather than a written-out list matters: a hardcoded list is a second copy of
// the set, which is the exact drift this whole arrangement exists to prevent,
// one level up. A fifth credential added to the map with no test of its own
// is covered here the moment it is added.
//
// What this does NOT do is check the READ side, and the previous version of
// this test claimed to. It iterated a hardcoded {"authorization", dpop} and
// asserted both were in the map -- which a fifth credential READ WITHOUT a
// map entry passes, since the hardcoded list would not have named it either.
// That hole is now closed in the code rather than by a test:
// extractCredentials draws every credential value out of a local map it fills
// only from this one, so a header absent here has no value for any read to
// find. See its own doc comment.
func TestEveryCredentialHeaderIsStrippedFromRawInput(t *testing.T) {
	for name := range credentialHeaderNames {
		if name != strings.ToLower(name) {
			t.Errorf("credentialHeaderNames[%q] is not lower-cased -- extractCredentials folds an incoming "+
				"header name to lower case before every lookup, so this entry can never match", name)
		}
		for _, sent := range []string{name, strings.ToUpper(name)} {
			t.Run(sent, func(t *testing.T) {
				fake := &fakePDP{resp: allowResponse("")}
				pdpClient := startFakePDP(t, fake)
				client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

				// The authorization header is always sent well-formed, so a
				// request never dies before raw_input is built; when the entry
				// under test IS authorization, this is that same header
				// carrying the marker instead of a token, which still parses.
				headers := map[string]string{"authorization": "Bearer " + testBearerToken}
				headers[sent] = testOtherCredentialValue
				if strings.EqualFold(sent, "authorization") {
					headers[sent] = "Bearer " + testOtherCredentialValue
				}

				if _, err := client.Check(context.Background(),
					checkRequest("GET", "/svc.Svc/Method", headers)); err != nil {
					t.Fatalf("Check() error = %v", err)
				}
				req := fake.lastRequest()
				if req == nil {
					t.Fatal("PDP never received a request")
				}
				if raw := req.GetRawInput(); strings.Contains(raw, testOtherCredentialValue) {
					t.Errorf("raw_input contains the value of credential header %q verbatim: %s", sent, raw)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Task 3: DecideResponse -> CheckResponse mapping, and escalation degrade.
// ---------------------------------------------------------------------------

// TestCheck_Deny_CarriesPDPReasonVerbatimAndUnprefixed defends the
// "distinguishable reasons" property for the simplest case: a genuine
// EFFECT_DENY's reason reaches the caller exactly as the PDP wrote it, with
// no stratium-pep framing added -- the same unprefixed-passthrough
// convention hook.go's own default DENY case uses (see its own doc
// comment), so a human reading a denial can tell at a glance whether the
// PDP refused the action or this process failed before ever asking it one.
// Checked in both places the reason appears (Status.Message and
// DeniedResponse.Body) and confirmed no approval header rides along, since
// a genuine deny names no pending approval.
func TestCheck_Deny_CarriesPDPReasonVerbatimAndUnprefixed(t *testing.T) {
	const pdpReason = "extauthz-deny-reason-3f8c1a2d-fixture: delegation revoked"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason, DeniedLeg: "delegation"}}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED)", got, want)
	}
	if got := resp.GetStatus().GetMessage(); got != pdpReason {
		t.Errorf("Status.Message = %q, want the PDP's own reason %q, verbatim", got, pdpReason)
	}
	denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
	}
	if got := denied.DeniedResponse.GetBody(); got != pdpReason {
		t.Errorf("DeniedResponse.Body = %q, want the PDP's own reason %q, verbatim", got, pdpReason)
	}
	if hdrs := denied.DeniedResponse.GetHeaders(); len(hdrs) != 0 {
		t.Errorf("DeniedResponse.Headers = %v, want none -- a genuine deny carries no approval id", hdrs)
	}
}

// TestCheck_Escalate_DeniesAndApprovalIDReachesBothChannels is the E5/M4
// property this task exists for: an ESCALATE degrades to an ordinary
// PERMISSION_DENIED, and the approval id it created reaches the caller in
// BOTH channels checkResponseFromDecide's own doc comment justifies --
// approvalIDHeader, for a retry tool to read deterministically, and the
// body text, for a human who only has the response body -- because a
// pending record neither reader can find is a record that helps nobody.
func TestCheck_Escalate_DeniesAndApprovalIDReachesBothChannels(t *testing.T) {
	const approvalID = "6b9e0c1a-4f2d-4a7e-9c3b-7f1e2d3a4b5c"
	const pdpReason = "extauthz-escalate-reason-9d2b1f-fixture: tier exceeds delegated ceiling"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{
		Effect: pdpgrpc.Effect_EFFECT_ESCALATE, Reason: pdpReason, ApprovalId: approvalID,
	}}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED) -- extauthz cannot block for approval (E5)", got, want)
	}
	denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
	}

	var headerValue string
	var headerFound bool
	for _, h := range denied.DeniedResponse.GetHeaders() {
		if h.GetHeader().GetKey() == approvalIDHeader {
			headerValue, headerFound = h.GetHeader().GetValue(), true
		}
	}
	if !headerFound || headerValue != approvalID {
		t.Errorf("%s header = (%q, found=%v), want (%q, true) -- an operator or retry tool must be able to "+
			"read the approval id without parsing prose", approvalIDHeader, headerValue, headerFound, approvalID)
	}
	if body := denied.DeniedResponse.GetBody(); !strings.Contains(body, approvalID) {
		t.Errorf("DeniedResponse.Body = %q, want it to also contain approval id %q -- a human reading only the body must still find it", body, approvalID)
	}
}

// TestCheck_EscalateWithNoApprovalID_DeniesWithoutClaimingOneExists guards
// the defensive branch checkResponseFromDecide's own doc comment describes:
// a PDP that answers EFFECT_ESCALATE without an approval id has violated
// its own contract (DecideResponse.approval_id) and left nothing to find.
// This must still deny, and must not attach approvalIDHeader with an empty
// value -- an empty header would name no real pending approval, which is
// worse than no header at all for an operator trying to act on it.
//
// The body-text assertion below is not decorative: a mutation that deletes
// this whole defensive branch and lets the ordinary "is pending (approval
// id %s)" framing run with an empty %s still produces zero headers (the
// SAME denyCheckResponse guard this test's header assertion checks), so
// that assertion alone does not catch it -- only the wording differing from
// the misleading empty-slot version does. Found by running exactly that
// mutation, unprompted, during this task's own mutation-testing pass.
func TestCheck_EscalateWithNoApprovalID_DeniesWithoutClaimingOneExists(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ESCALATE, Reason: "escalated, no id"}}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED)", got, want)
	}
	denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
	}
	const wantSubstring = "no approval id to attach"
	if body := denied.DeniedResponse.GetBody(); !strings.Contains(body, wantSubstring) {
		t.Errorf("DeniedResponse.Body = %q, want it to contain %q -- this case must read differently from an "+
			"ordinary pending-approval denial, not silently reuse that framing with an empty id slot", body, wantSubstring)
	}
	if hdrs := denied.DeniedResponse.GetHeaders(); len(hdrs) != 0 {
		t.Errorf("DeniedResponse.Headers = %v, want none -- there is no approval id to attach", hdrs)
	}
}

// TestCheck_PDPError_DeniesAsOrdinaryResponse is
// TestCheck_UnreachablePDP_DeniesAsOrdinaryResponse_NotTransportError's
// twin for the other shape describeRPCError distinguishes: a PDP that was
// reached and answered with an application-level error, rather than one
// that could not be reached at all. Both must deny as an ordinary
// (*CheckResponse, nil), never a transport error -- but they take different
// branches inside describeRPCError, so a mutation could plausibly catch one
// without catching the other, which is why each gets its own test.
func TestCheck_PDPError_DeniesAsOrdinaryResponse(t *testing.T) {
	fake := &fakePDP{err: errors.New("pdp-error-fixture: something went wrong evaluating this request")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() returned a transport error (%v); a PDP application-level error must still produce an ordinary "+
			"(*CheckResponse, nil) -- see Check's own doc comment", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED)", got, want)
	}
}

// TestCheck_UnsetEffect_DeniesAsOrdinaryResponse is the test the brief asks
// for by name: DecideResponse.Effect's zero value is EFFECT_DENY,
// deliberately (proto/pdp/v1/pdp.proto's own doc comment) -- this proves
// that holds over a REAL wire round trip, not merely in an in-memory struct
// literal. fake.resp below never sets Effect at all; proto3 omits a scalar
// field equal to its zero value from the wire entirely, so grpc-go
// marshals this DecideResponse with no Effect bytes on the wire, sends it
// over the real TCP loopback connection startFakePDP dials this server's
// own client through, and unmarshals it back inside Check's handler -- if
// decoding ever invented ambiguity instead of the documented zero value, or
// if this file's own mapping ever treated that ambiguity as anything but a
// denial, this is the test that would catch it, not a comment repeating the
// proto's own promise.
func TestCheck_UnsetEffect_DeniesAsOrdinaryResponse(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Reason: "no effect was ever set"}}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Errorf("Status.Code = %d, want %d (PERMISSION_DENIED) -- an unset Effect must decode to, and be treated as, EFFECT_DENY", got, want)
	}
	if _, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse); !ok {
		t.Errorf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
	}
}

// TestCheck_ReasonsAreDistinguishableAcrossThreeClasses defends the
// property named directly in the brief: "your token expired", "your
// delegation was revoked", and "this needs approval, which is pending" must
// send an operator to three different places, which means their text must
// actually DIFFER -- not merely each be non-empty, which a single generic
// "denied" string would also satisfy. Three real Check() calls, scripted
// with three fakePDP responses standing in for those three classes (two
// distinct ordinary DENYs, and a degraded ESCALATE), asserting all three
// resulting texts are pairwise distinct, plus that the escalate class reads
// as pending rather than final.
func TestCheck_ReasonsAreDistinguishableAcrossThreeClasses(t *testing.T) {
	reasonFor := func(t *testing.T, resp *pdpgrpc.DecideResponse) string {
		t.Helper()
		fake := &fakePDP{resp: resp}
		pdpClient := startFakePDP(t, fake)
		client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})
		got, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
			"authorization": "Bearer " + testBearerToken,
		}))
		if err != nil {
			t.Fatalf("Check() error = %v", err)
		}
		return got.GetStatus().GetMessage()
	}

	tokenExpired := reasonFor(t, &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "token expired", DeniedLeg: "agent"})
	delegationRevoked := reasonFor(t, &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "delegation revoked", DeniedLeg: "delegation"})
	pendingApproval := reasonFor(t, &pdpgrpc.DecideResponse{
		Effect: pdpgrpc.Effect_EFFECT_ESCALATE, Reason: "requires approval", ApprovalId: "d290f1ee-6c54-4b01-90e6-d701748f0851",
	})

	classes := map[string]string{
		"token expired":      tokenExpired,
		"delegation revoked": delegationRevoked,
		"pending approval":   pendingApproval,
	}
	seen := map[string]string{}
	for name, text := range classes {
		if other, dup := seen[text]; dup {
			t.Errorf("%q and %q produced identical reason text (%q) -- they must be distinguishable, not merely both non-empty", name, other, text)
		}
		seen[text] = name
	}
	if !strings.Contains(pendingApproval, "pending") {
		t.Errorf("escalate-degraded reason %q does not say this is pending -- an operator reading it must be able to tell this is not a final refusal", pendingApproval)
	}
}

// TestCheckResponseFromDecide_DenyWithStrayApprovalID_NotTreatedAsEscalation
// is the mutation nobody asked for. DecideResponse.approval_id's own doc
// comment promises it is populated only on EFFECT_ESCALATE, and the real
// Decide implementation upholds that structurally (server.go) -- but
// checkResponseFromDecide does not get to assume a promise about the OTHER
// end of this RPC holds, for the same reason it does not get to assume
// Effect's own zero-value promise holds without checking
// (TestCheck_UnsetEffect_DeniesAsOrdinaryResponse above). A fixture that
// violates the approval_id contract -- impossible from this repo's own PDP,
// not impossible from DecideResponse's own type signature -- must still
// read as an ordinary denial: no approval-pending framing, no header,
// because there is no genuine pending approval behind this EFFECT_DENY for
// either of those to point an operator at.
func TestCheckResponseFromDecide_DenyWithStrayApprovalID_NotTreatedAsEscalation(t *testing.T) {
	const reason = "policy denies -- unrelated to any approval"
	resp := checkResponseFromDecide(&pdpgrpc.DecideResponse{
		Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: reason, ApprovalId: "stray-id-should-be-ignored",
	})

	if got := resp.GetStatus().GetMessage(); got != reason {
		t.Errorf("Status.Message = %q, want the plain deny reason %q, unframed by any escalation text", got, reason)
	}
	denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
	}
	if hdrs := denied.DeniedResponse.GetHeaders(); len(hdrs) != 0 {
		t.Errorf("DeniedResponse.Headers = %v, want none -- a stray approval id on a genuine DENY must not surface as a pending-approval header", hdrs)
	}
}

// TestCheckResponseFromDecide is the direct, wire-free table of every
// Effect value this mapping must handle -- faster and more exhaustive than
// routing every case through a real gRPC round trip, which
// TestCheck_UnsetEffect_DeniesAsOrdinaryResponse and the tests around it
// above already do for the cases that specifically need to prove something
// about the WIRE. This table's job is the branching logic itself: every
// reachable Effect, plus the defensive nil case, in one place.
func TestCheckResponseFromDecide(t *testing.T) {
	for _, tc := range []struct {
		name       string
		resp       *pdpgrpc.DecideResponse
		wantCode   int32
		wantHeader bool
	}{
		{name: "allow", resp: allowResponse(""), wantCode: int32(rpccode.Code_OK)},
		{name: "deny", resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "denied"}, wantCode: int32(rpccode.Code_PERMISSION_DENIED)},
		{name: "escalate with approval id", resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ESCALATE, ApprovalId: "id-1"}, wantCode: int32(rpccode.Code_PERMISSION_DENIED), wantHeader: true},
		{name: "escalate with no approval id", resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ESCALATE}, wantCode: int32(rpccode.Code_PERMISSION_DENIED)},
		{name: "unset effect (zero value)", resp: &pdpgrpc.DecideResponse{}, wantCode: int32(rpccode.Code_PERMISSION_DENIED)},
		{name: "nil response", resp: nil, wantCode: int32(rpccode.Code_PERMISSION_DENIED)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := checkResponseFromDecide(tc.resp)
			if code := got.GetStatus().GetCode(); code != tc.wantCode {
				t.Errorf("Status.Code = %d, want %d", code, tc.wantCode)
			}
			_, isOk := got.GetHttpResponse().(*authv3.CheckResponse_OkResponse)
			if wantOk := tc.wantCode == int32(rpccode.Code_OK); wantOk != isOk {
				t.Errorf("HttpResponse is OkResponse = %v, want %v", isOk, wantOk)
			}
			var hasHeader bool
			if denied, ok := got.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse); ok {
				hasHeader = len(denied.DeniedResponse.GetHeaders()) > 0
			}
			if hasHeader != tc.wantHeader {
				t.Errorf("has approval header = %v, want %v", hasHeader, tc.wantHeader)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Phase 15 Task 5: sender-constrained tokens (spec §4.7.2 K5, K7, K10).
// ---------------------------------------------------------------------------

// TestCheck_DPoPProofForwardedVerbatim defends K7's first half: the value of
// the DPoP header reaches DecideRequest.dpop_proof unaltered, over a real
// wire round trip. Unaltered matters and is asserted as equality against the
// exact fixture rather than as "non-empty": a proof is a compact JWS whose
// signature covers its own encoded header and payload, so any normalization
// at all -- trimming, re-casing, decoding and re-encoding -- destroys it, and
// the resulting denial at the PDP names a signature failure rather than the
// PEP that mangled it.
func TestCheck_DPoPProofForwardedVerbatim(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	_, err := client.Check(context.Background(), checkRequest("POST", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
		"dpop":          testDPoPProof,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if got := req.GetDpopProof(); got != testDPoPProof {
		t.Errorf("dpop_proof = %q, want the DPoP header's value verbatim (%q)", got, testDPoPProof)
	}
}

// TestCheck_NoDPoPHeader_SendsEmptyProofAndStillCallsPDP is the negative
// control for the test above, and it differs from it in exactly one thing:
// the dpop header is absent. It must NOT deny locally.
//
// That is the whole point. dpop_proof="" is the proto's own encoding of "the
// caller presented none," and what that means is a question only the PDP can
// answer -- a bound token with no proof is C25's denial, an unbound token
// reaches the ALLOW branch and K5 refuses it there. A local "no proof, no
// entry" shortcut here would deny bearer-token traffic with a reason naming
// the wrong defect, and would deny it before the PDP ever recorded the
// attempt in the audit chain.
func TestCheck_NoDPoPHeader_SendsEmptyProofAndStillCallsPDP(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	_, err := client.Check(context.Background(), checkRequest("POST", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	if got := fake.requestCount(); got != 1 {
		t.Fatalf("PDP received %d Decide call(s), want exactly 1 -- a request with no proof must still be "+
			"decided by the PDP, not refused locally: whether a proof was required is not this server's "+
			"question to answer", got)
	}
	if got := fake.lastRequest().GetDpopProof(); got != "" {
		t.Errorf("dpop_proof = %q, want \"\" -- an absent DPoP header is the proto's \"the caller presented none\"", got)
	}
}

// TestCheck_ObservedMethodAndURI defends K7's second half: the (method, URI)
// pair the PDP compares a proof's htm/htu claims against is what THIS server
// observed, built from the pieces a real Envoy actually populates.
//
// The table's rows are the two facts measured against the real Envoy that a
// hand-built fixture would never have surfaced (see observedURI's own doc
// comment for the transcript): GetPath() carries the query string inline and
// GetQuery() is empty, so the query has to be cut here; and GetScheme() is
// populated, so htu's scheme has a typed source and does not have to be
// recovered from a header. RFC 9449 §4.3 item 9 defines htu comparison
// "ignoring any query and fragment parts," which is why the query rows expect
// it gone rather than preserved.
//
// The https rows are not redundant with the http ones: they are the only
// rows that would catch a hard-coded scheme, which is the shape a mutation
// building htu from the wrong source most plausibly takes.
func TestCheck_ObservedMethodAndURI(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scheme  string
		host    string
		method  string
		path    string
		wantURI string
	}{
		{
			name:   "plain path",
			scheme: "http", host: "gateway.example:10000", method: "GET", path: "/svc.Svc/Method",
			wantURI: "http://gateway.example:10000/svc.Svc/Method",
		},
		{
			name: "query string inline in the path is excluded",
			// Exactly what the real Envoy sends: GetPath() carries the query,
			// GetQuery() is empty.
			scheme: "http", host: "gateway.example:10000", method: "GET", path: "/svc.Svc/Method?a=1&b=two",
			wantURI: "http://gateway.example:10000/svc.Svc/Method",
		},
		{
			name:   "empty query after a bare question mark is excluded too",
			scheme: "http", host: "gateway.example:10000", method: "GET", path: "/svc.Svc/Method?",
			wantURI: "http://gateway.example:10000/svc.Svc/Method",
		},
		{
			name:   "https scheme is taken from the request, not assumed",
			scheme: "https", host: "gateway.example", method: "POST", path: "/svc.Svc/Method",
			wantURI: "https://gateway.example/svc.Svc/Method",
		},
		{
			name:   "https on an explicit port",
			scheme: "https", host: "gateway.example:8443", method: "DELETE", path: "/a/b",
			wantURI: "https://gateway.example:8443/a/b",
		},
		{
			// The row that catches a method silently case-normalized on its
			// way out. Every other row here sends an already-uppercase method,
			// so an added strings.ToUpper is invisible to all of them -- it
			// was, and it survived a mutation run until this row existed.
			//
			// It is not cosmetic. RFC 9110 §9.1 makes methods case-sensitive
			// and dpop.Proof.MatchesRequest compares htm the same way, so
			// upcasing here would make a proof minted for "GET /a/b" satisfy a
			// request Envoy actually reported as "get /a/b" -- two different
			// requests, one proof, which is precisely the binding this
			// mechanism exists to make exact.
			name:   "method is forwarded verbatim, never case-normalized",
			scheme: "http", host: "gateway.example", method: "get", path: "/a/b",
			wantURI: "http://gateway.example/a/b",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

			_, err := client.Check(context.Background(), checkRequestFull(tc.scheme, tc.host, tc.method, tc.path,
				map[string]string{"authorization": "Bearer " + testBearerToken, "dpop": testDPoPProof}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			req := fake.lastRequest()
			if req == nil {
				t.Fatal("PDP never received a request")
			}
			if got := req.GetObservedUri(); got != tc.wantURI {
				t.Errorf("observed_uri = %q, want %q", got, tc.wantURI)
			}
			if got := req.GetObservedMethod(); got != tc.method {
				t.Errorf("observed_method = %q, want %q -- forwarded verbatim, since dpop compares htm "+
					"case-sensitively (RFC 9110 §9.1)", got, tc.method)
			}
			// The tool identity is deliberately NOT the same value: M1 makes
			// it the request path exactly as Envoy reported it, query string
			// and all, because that is the string a tenant catalogs against.
			// Trimming the query for htu must not have trimmed it here too.
			if got := req.GetTool(); got != tc.path {
				t.Errorf("tool = %q, want the unmodified request path %q -- excluding the query from htu "+
					"(RFC 9449 §4.3) must not change what M1 sends as the tool identity", got, tc.path)
			}
		})
	}
}

// TestCheck_ObservedURIUsesTheTypedFields_NotThePseudoHeaders pins the one
// choice observedURI had to make that a passing test would otherwise leave
// undetermined. In the live stack every source agrees -- GetScheme() equals
// ":scheme" equals "x-forwarded-proto", and GetHost() equals ":authority" --
// so a test built from a realistic fixture cannot tell which one the code
// read, and a mutation swapping them would be invisible.
//
// This fixture disagrees on purpose, on BOTH pieces at once: the typed fields
// say https and gateway.example, while every header says http and
// attacker.example. Only one answer is correct, and it is the typed fields --
// a header is an entry in a map a caller also writes into, and preferring one
// on the strength of which a deployment is less likely to have spoofed would
// be this server classifying its own inputs (D1). The headers here are also
// the positive control for the opposite mutation: they must still reach
// raw_input, since none of them is a credential.
//
// The authority half is the one with teeth. htu's authority is what
// distinguishes a proof minted for this gateway from one minted for another,
// so an authority read from a header a caller controls would let a proof made
// for anywhere satisfy a request made here -- collapsing the binding into a
// value the presenter supplies, which the observed_uri field's own proto doc
// comment says it must never be.
func TestCheck_ObservedURIUsesTheTypedFields_NotThePseudoHeaders(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	_, err := client.Check(context.Background(), checkRequestFull("https", "gateway.example", "GET", "/p",
		map[string]string{
			"authorization":     "Bearer " + testBearerToken,
			"dpop":              testDPoPProof,
			":scheme":           "http",
			"x-forwarded-proto": "http",
			":authority":        "attacker.example",
			":path":             "/somewhere-else",
			// ":method" disagrees too. Without this entry, a build reading
			// observed_method out of the headers map got the zero value and
			// failed for the wrong reason -- the same fixture-omission kill
			// the authority half already had. Real Envoy sends ":method"
			// equal to the typed field, so only a disagreeing fixture can
			// pin which one is read.
			":method": "POST",
		}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	const want = "https://gateway.example/p"
	if got := req.GetObservedUri(); got != want {
		t.Errorf("observed_uri = %q, want %q -- every piece of htu comes from the typed "+
			"AttributeContext_HttpRequest fields, which a real Envoy populates (measured, see observedURI's "+
			"doc comment), never from \":scheme\", \"x-forwarded-proto\", \":authority\", or \":path\", which "+
			"are entries in a map a caller also writes into", got, want)
	}
	if got := req.GetObservedMethod(); got != "GET" {
		t.Errorf("observed_method = %q, want \"GET\" -- it comes from "+
			"AttributeContext_HttpRequest.Method, never from the \":method\" pseudo-header", got)
	}
	// The headers are not credentials, so the same request that must not
	// TRUST them must still record them.
	var meta requestMetadata
	if err := json.Unmarshal([]byte(req.GetRawInput()), &meta); err != nil {
		t.Fatalf("raw_input is not well-formed JSON: %v", err)
	}
	if meta.Headers[":authority"] != "attacker.example" {
		t.Errorf("raw_input.headers[\":authority\"] = %q, want it preserved -- a pseudo-header that must not "+
			"be trusted as htu's authority is still ordinary request metadata an auditor should see",
			meta.Headers[":authority"])
	}
}

// TestCheck_RawInputNeverCarriesDPoPProof_AnyHeaderCasing is K10, and it is
// the sibling of TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing
// for the credential this phase introduces. raw_input is hashed into the
// append-only audit chain, so a proof that leaks there is a signed
// possession-of-key assertion written permanently into a record designed to
// be kept and read, in a chain that cannot be edited to remove it.
//
// Table-driven over five spellings, and the set is not decorative. "dpop" is
// what a real Envoy delivers; "DPoP" is what RFC 9449 itself writes and what
// a conformant client behind any other intermediary sends. A strip written
// case-sensitively against either one leaks for the other, and a suite testing
// only the casing its own fixture happens to use would never see it.
//
// Every case asserts absence three ways: structurally, by unmarshaling
// raw_input and checking no header key case-insensitively equals "dpop"; by
// substring against the raw bytes, since the fixture value cannot appear here
// by coincidence; and positively, by confirming a non-credential header sent
// on the SAME request did survive -- without which "raw_input contains no
// proof" would also be satisfied by raw_input containing nothing at all.
func TestCheck_RawInputNeverCarriesDPoPProof_AnyHeaderCasing(t *testing.T) {
	for _, headerName := range []string{"dpop", "DPoP", "DPOP", "Dpop", "dPoP"} {
		t.Run(headerName, func(t *testing.T) {
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

			_, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
				"authorization":        "Bearer " + testBearerToken,
				headerName:             testDPoPProof,
				testAuthLikeHeaderName: testAuthLikeHeaderValue,
			}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}

			req := fake.lastRequest()
			if req == nil {
				t.Fatal("PDP never received a request")
			}
			// The proof still has to have been READ, or this test would pass
			// on a build that dropped the header entirely -- which strips it
			// from raw_input for the wrong reason and breaks every bound
			// token on this surface.
			if got := req.GetDpopProof(); got != testDPoPProof {
				t.Fatalf("dpop_proof = %q, want %q -- a header spelled %q must still be recognized as the "+
					"proof; a build that merely DROPPED it would satisfy the absence checks below vacuously",
					got, testDPoPProof, headerName)
			}

			raw := req.GetRawInput()
			if strings.Contains(raw, testDPoPProof) {
				t.Errorf("raw_input contains the DPoP proof verbatim: %s", raw)
			}

			var got requestMetadata
			if err := json.Unmarshal([]byte(raw), &got); err != nil {
				t.Fatalf("raw_input is not well-formed JSON: %v\nraw_input: %s", err, raw)
			}
			for key := range got.Headers {
				if strings.EqualFold(key, "dpop") {
					t.Errorf("raw_input.headers carries key %q -- the DPoP proof must never appear, in any casing (K10)", key)
				}
			}
			if v := got.Headers[testAuthLikeHeaderName]; v != testAuthLikeHeaderValue {
				t.Errorf("raw_input.headers[%q] = %q, want %q -- without this the absence checks above would "+
					"also pass for a raw_input carrying no headers at all",
					testAuthLikeHeaderName, v, testAuthLikeHeaderValue)
			}
		})
	}
}

// TestCheck_UnboundToken_DeniedEvenWhenPDPAllows is K5, the converse half of
// C25, and the migration hole a suite written from C25's own sentence leaves
// wide open: C25 says a bound token presented without a proof is denied, and
// says nothing at all about a token that was never bound. An attacker who
// simply asks for an ordinary bearer token walks straight through that gap.
//
// The two rows differ in EXACTLY ONE FIELD -- sender_constrained -- and in
// nothing else: same request, same headers, same Effect, same reason. That is
// what makes the false row a real negative test rather than a request that
// denies for some other reason it happens to also have. Both directions are
// asserted, because a mutation that ignores the field entirely (always
// forward) and one that inverts it (never forward) are different bugs and a
// one-sided test catches only one of them.
//
// The reason text is asserted, not just the code: it has to name the defect
// well enough that an operator can act, and it has to be DISTINGUISHABLE from
// C25's own denial -- see TestCheck_BoundTokenWithNoProof_DeniesWithThePDPsOwnReason
// below, which holds the other half.
func TestCheck_UnboundToken_DeniedEvenWhenPDPAllows(t *testing.T) {
	for _, tc := range []struct {
		name             string
		senderConstained bool
		wantCode         int32
	}{
		{name: "bound token, proof verified", senderConstained: true, wantCode: int32(rpccode.Code_OK)},
		{name: "unbound token", senderConstained: false, wantCode: int32(rpccode.Code_PERMISSION_DENIED)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{
				Effect:            pdpgrpc.Effect_EFFECT_ALLOW,
				Reason:            "policy allows",
				SenderConstrained: tc.senderConstained,
			}}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

			resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
				"authorization": "Bearer " + testBearerToken,
			}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got := resp.GetStatus().GetCode(); got != tc.wantCode {
				t.Fatalf("Status.Code = %d, want %d -- an ALLOW whose token was never bound to a key must "+
					"be refused on this surface (K5), and one that was must not be", got, tc.wantCode)
			}
			_, isOk := resp.GetHttpResponse().(*authv3.CheckResponse_OkResponse)
			if wantOk := tc.wantCode == int32(rpccode.Code_OK); isOk != wantOk {
				t.Errorf("HttpResponse is OkResponse = %v, want %v -- Status.Code and the oneof must agree, "+
					"or a caller reading only one of them sees the wrong answer", isOk, wantOk)
			}
			if tc.senderConstained {
				return
			}

			// The refusal must be findable in both channels a denial has, the
			// same pairing denyCheckResponse already guarantees for every
			// other reason on this surface.
			if got := resp.GetStatus().GetMessage(); got != unboundTokenReason {
				t.Errorf("Status.Message = %q, want %q", got, unboundTokenReason)
			}
			denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
			if !ok {
				t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
			}
			if got := denied.DeniedResponse.GetBody(); got != unboundTokenReason {
				t.Errorf("DeniedResponse.Body = %q, want %q", got, unboundTokenReason)
			}
			// Actionable, not merely refusing: the operator's fix is to ask
			// for a bound token, and the reason has to say so by naming the
			// field that binds one.
			if !strings.Contains(unboundTokenReason, "dpop_jwk") {
				t.Errorf("unboundTokenReason = %q, want it to name dpop_jwk -- the only way a caller can act "+
					"on this refusal is to request a bound token, and the reason is where that is said", unboundTokenReason)
			}
		})
	}
}

// TestCheck_BoundTokenWithNoProof_DeniesWithThePDPsOwnReason is C25 as
// written -- a bound token presented with no proof -- and it exists as much
// to hold the two halves APART as to prove the denial.
//
// The PDP denies this one itself (pdpgrpc's errNoProof), before any
// three-leg evaluation, so what arrives here is an ordinary EFFECT_DENY and
// this surface must pass its reason through verbatim. Substituting K5's text
// would tell an operator holding a perfectly good bound token to go get a
// bound token. The distinctness assertion at the end is the one that would
// fail if a future edit collapsed the two reasons into one shared string.
//
// sender_constrained is deliberately FALSE on this fixture, matching what a
// real PDP sends: the denial happens before Decide's tail, so the field
// reports "not established" -- NOT "the caller presented a bearer token",
// which is exactly the misreading the proto's own doc comment warns against.
// If K5's refusal were keyed off the field outside the ALLOW branch, this
// request would deny with the wrong reason, and this test is what catches it.
func TestCheck_BoundTokenWithNoProof_DeniesWithThePDPsOwnReason(t *testing.T) {
	const pdpReason = "token is sender-constrained but the request carried no dpop proof"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{
		Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason, SenderConstrained: false,
	}}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_PERMISSION_DENIED); got != want {
		t.Fatalf("Status.Code = %d, want %d", got, want)
	}
	if got := resp.GetStatus().GetMessage(); got != pdpReason {
		t.Errorf("Status.Message = %q, want the PDP's own reason verbatim (%q) -- a denial that already "+
			"happened at the PDP must not be re-explained by this surface", got, pdpReason)
	}
	if strings.Contains(resp.GetStatus().GetMessage(), unboundTokenReason) {
		t.Errorf("Status.Message = %q carries K5's unbound-token reason, which names the opposite defect: "+
			"this caller's token IS bound, and telling them to request a bound one is unactionable",
			resp.GetStatus().GetMessage())
	}
	// What this last check does and does not cover, stated plainly because it
	// looks stronger than it is. pdpReason is a LOCAL COPY of pdpgrpc's
	// errNoProof text -- that error is unexported, so this package cannot
	// reference the real one -- which means this fires if someone edits
	// unboundTokenReason toward this literal, and NOT if the PDP's own text
	// drifts toward unboundTokenReason. The verbatim-passthrough assertion
	// above is the real one: it proves whatever the PDP says arrives
	// unaltered, whatever that turns out to be. This is a guard on the half
	// of the pair this package actually owns.
	if pdpReason == unboundTokenReason {
		t.Error("K5's reason has been edited to equal C25's -- the two halves name opposite defects " +
			"(no proof for a bound token, versus a token that was never bound) and an operator has to be " +
			"able to tell which one they hit")
	}
}

// TestCheck_EscalateOnUnboundToken_DeniesAsPendingNotAsUnbound holds the
// boundary the proto's "consult it only when effect is EFFECT_ALLOW" rule
// draws, on the one effect where reading the field early would be tempting
// and wrong.
//
// An EFFECT_ESCALATE degrades to a denial here (E5/M4) and carries a real
// pending approval id a human is about to act on. Reading sender_constrained
// before that degrade -- and denying "your token is not bound" instead --
// would throw the approval id away and send an operator to fix a token whose
// binding was never the problem. K5 still bites: the approved retry comes
// back through this same function as an ALLOW, and the ALLOW branch refuses
// it there.
func TestCheck_EscalateOnUnboundToken_DeniesAsPendingNotAsUnbound(t *testing.T) {
	const approvalID = "extauthz-approval-2c7f5e14-fixture"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{
		Effect: pdpgrpc.Effect_EFFECT_ESCALATE, ApprovalId: approvalID,
		Reason: "requires approval", SenderConstrained: false,
	}}
	pdpClient := startFakePDP(t, fake)
	client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: testExtauthzServerCfg()})

	resp, err := client.Check(context.Background(), checkRequest("GET", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
	}))
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := resp.GetStatus().GetMessage(); got == unboundTokenReason {
		t.Fatalf("Status.Message = K5's unbound-token reason, but this response was an ESCALATE. The "+
			"proto's rule is CONSULT IT ONLY WHEN effect IS EFFECT_ALLOW, and it is honored literally "+
			"rather than approximately: an escalate that reached the three-leg evaluation does carry the "+
			"real answer, but the six pre-decision denials do not, and this surface cannot tell the two "+
			"apart from the response. Reading it here discards a real pending approval (%s)", approvalID)
	}
	if !strings.Contains(resp.GetStatus().GetMessage(), approvalID) {
		t.Errorf("Status.Message = %q, want it to carry the pending approval id %q", resp.GetStatus().GetMessage(), approvalID)
	}
	denied, ok := resp.GetHttpResponse().(*authv3.CheckResponse_DeniedResponse)
	if !ok {
		t.Fatalf("HttpResponse = %T, want *authv3.CheckResponse_DeniedResponse", resp.GetHttpResponse())
	}
	if len(denied.DeniedResponse.GetHeaders()) != 1 {
		t.Errorf("DeniedResponse.Headers = %v, want the approval-id header -- degrading an escalation must "+
			"still hand back the id a retry needs", denied.DeniedResponse.GetHeaders())
	}
}

// TestCheck_UnservedAuthority_DeniesWithoutContactingPDP is the fix for the
// hazard review round 1 found: Envoy's AttributeContext_HttpRequest.Host is
// documented as "The HTTP request Host or :authority header value" -- the
// caller's own header, read from a typed field rather than the headers map.
// Without validation, htu's authority is whatever the presenter claimed, and
// the authority component of the binding contributes nothing.
//
// The replay it closes: capture a bound token and its proof in flight to
// gw-a.example and DROP the request so the jti stays unspent, then replay both
// at a SECOND gateway fronting different upstreams, sending "Host:
// gw-a.example". Every check downstream passes, because the second gateway
// dutifully reports the authority it was told.
//
// The two rows differ in exactly one thing -- the observed Host -- against one
// fixed allowlist. The served row is what proves the denial is attributable to
// the allowlist and not to some unrelated failure the fixture also has.
func TestCheck_UnservedAuthority_DeniesWithoutContactingPDP(t *testing.T) {
	cfg := testExtauthzServerCfg()
	cfg.AllowedHosts = []string{"gw-b.example"}

	for _, tc := range []struct {
		name     string
		host     string
		wantCode int32
	}{
		{name: "an authority this surface serves", host: "gw-b.example", wantCode: int32(rpccode.Code_OK)},
		{name: "an authority it does not", host: "gw-a.example", wantCode: int32(rpccode.Code_PERMISSION_DENIED)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: cfg})

			resp, err := client.Check(context.Background(), checkRequestFull("http", tc.host, "GET", "/p",
				map[string]string{"authorization": "Bearer " + testBearerToken, "dpop": testDPoPProof}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got := resp.GetStatus().GetCode(); got != tc.wantCode {
				t.Fatalf("Status.Code = %d, want %d", got, tc.wantCode)
			}
			if tc.wantCode == int32(rpccode.Code_OK) {
				if got := fake.lastRequest().GetObservedUri(); got != "http://gw-b.example/p" {
					t.Errorf("observed_uri = %q, want %q", got, "http://gw-b.example/p")
				}
				return
			}

			// Denied before the PDP is dialed, the same shape a missing
			// credential already has: there is nothing a round trip could
			// add, since this surface does not serve the authority at all.
			if got := fake.requestCount(); got != 0 {
				t.Errorf("PDP received %d Decide call(s), want 0 -- an authority this surface does not "+
					"serve is refused before the PDP is dialed", got)
			}
			body := resp.GetStatus().GetMessage()
			if !strings.Contains(body, errUnservedAuthority.Error()) {
				t.Errorf("Status.Message = %q, want it to carry %q", body, errUnservedAuthority.Error())
			}
			// Neither side of the comparison may be echoed: the observed value
			// would be request metadata in a denial body (the package doc's
			// NEVER LOG REQUEST METADATA rule), and the configured list would
			// hand an arbitrary caller the set of hostnames this deployment
			// answers for.
			if strings.Contains(body, tc.host) {
				t.Errorf("denial body %q echoes the observed authority", body)
			}
			for _, allowed := range cfg.AllowedHosts {
				if strings.Contains(body, allowed) {
					t.Errorf("denial body %q names a configured host (%q) -- free reconnaissance for a "+
						"caller probing what this deployment serves", body, allowed)
				}
			}
		})
	}
}

// TestCheck_ObservedURIUsesTheMatchedHost_NotTheObservedSpelling is the
// property that makes the allowlist more than a gate: htu is built from the
// CONFIGURED value, so no residue of the caller's spelling reaches the string
// the PDP compares.
//
// It also pins the normalization, which is not free choice. dpop.canonicalURI
// applies RFC 3986 §6.2.2.1 case normalization and §6.2.3 default-port
// removal to the same authority one hop later, so an allowlist that compared
// raw strings would deny traffic the binding itself would have accepted --
// two different notions of host equality inside one binding path. Each row
// below is a spelling RFC 3986 makes equivalent to the configured entry.
func TestCheck_ObservedURIUsesTheMatchedHost_NotTheObservedSpelling(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured string
		scheme     string
		observed   string
		wantURI    string
	}{
		{
			name: "case differs", configured: "gw.example", scheme: "http", observed: "GW.Example",
			wantURI: "http://gw.example/p",
		},
		{
			name: "observed carries http's default port", configured: "gw.example", scheme: "http",
			observed: "gw.example:80", wantURI: "http://gw.example/p",
		},
		{
			name: "observed carries https's default port", configured: "gw.example", scheme: "https",
			observed: "gw.example:443", wantURI: "https://gw.example/p",
		},
		{
			// The converse: the operator wrote the explicit port and the
			// caller omitted it. htu still comes back as the operator's own
			// spelling, which is what "built from the matched value" means.
			name: "configured carries the default port, observed omits it", configured: "gw.example:443",
			scheme: "https", observed: "gw.example", wantURI: "https://gw.example:443/p",
		},
		{
			// A NON-default port is not equivalent and must not be trimmed --
			// the row that catches a normalizer stripping any port at all.
			name: "non-default port is preserved and must match", configured: "gw.example:8443",
			scheme: "https", observed: "gw.example:8443", wantURI: "https://gw.example:8443/p",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testExtauthzServerCfg()
			cfg.AllowedHosts = []string{tc.configured}
			fake := &fakePDP{resp: allowResponse("")}
			pdpClient := startFakePDP(t, fake)
			client := startExtauthzServer(t, &extauthzServer{client: pdpClient, cfg: cfg})

			resp, err := client.Check(context.Background(), checkRequestFull(tc.scheme, tc.observed, "GET", "/p",
				map[string]string{"authorization": "Bearer " + testBearerToken, "dpop": testDPoPProof}))
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got, want := resp.GetStatus().GetCode(), int32(rpccode.Code_OK); got != want {
				t.Fatalf("Status.Code = %d, want %d -- RFC 3986 makes %q and %q the same authority, and the "+
					"PDP's own htu comparison already treats them that way",
					got, want, tc.observed, tc.configured)
			}
			if got := fake.lastRequest().GetObservedUri(); got != tc.wantURI {
				t.Errorf("observed_uri = %q, want %q -- htu's authority is the CONFIGURED value, so no "+
					"residue of the caller's own spelling survives into what the PDP compares", got, tc.wantURI)
			}
		})
	}
}

// TestMatchAllowedHost_NonDefaultPortAndSchemeMismatchesAreRefused is the
// negative half of the normalization above: a fold wider than RFC 3986
// sanctions is a wider allowlist than the operator wrote, and every row here
// is a pair a too-eager normalizer would wrongly accept.
func TestMatchAllowedHost_NonDefaultPortAndSchemeMismatchesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name      string
		scheme    string
		observed  string
		allowed   []string
		wantMatch string
	}{
		{name: "exact", scheme: "http", observed: "gw.example", allowed: []string{"gw.example"}, wantMatch: "gw.example"},
		{name: "different host entirely", scheme: "http", observed: "evil.example", allowed: []string{"gw.example"}},
		{name: "subdomain is not the parent", scheme: "http", observed: "a.gw.example", allowed: []string{"gw.example"}},
		{name: "suffix is not a match", scheme: "http", observed: "notgw.example", allowed: []string{"gw.example"}},
		{name: "non-default port is significant", scheme: "http", observed: "gw.example:8080", allowed: []string{"gw.example"}},
		{
			// :443 is only the default under https. Under http it is an
			// ordinary port and must not be trimmed -- the row that catches a
			// normalizer stripping default ports without checking the scheme.
			name: "https default port under http is not trimmed", scheme: "http",
			observed: "gw.example:443", allowed: []string{"gw.example"},
		},
		{
			name: "http default port under https is not trimmed", scheme: "https",
			observed: "gw.example:80", allowed: []string{"gw.example"},
		},
		{
			// U+212A KELVIN SIGN folds to "k" under Unicode case folding
			// (strings.ToLower, strings.EqualFold) but not under RFC 3986
			// §6.2.2.1, which is ASCII-only. A wider fold here is a wider
			// allowlist than the operator wrote.
			name: "unicode fold does not widen the allowlist", scheme: "http",
			observed: "gKw.example", allowed: []string{"gkw.example"},
		},
		{
			name: "empty observed authority matches nothing", scheme: "http",
			observed: "", allowed: []string{"gw.example"},
		},
		{
			name: "the second entry matches", scheme: "http", observed: "gw-b.example",
			allowed: []string{"gw-a.example", "gw-b.example"}, wantMatch: "gw-b.example",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := matchAllowedHost(tc.scheme, tc.observed, tc.allowed)
			if tc.wantMatch == "" {
				if !errors.Is(err, errUnservedAuthority) {
					t.Fatalf("matchAllowedHost(%q, %q, %v) = (%q, %v), want errUnservedAuthority",
						tc.scheme, tc.observed, tc.allowed, got, err)
				}
				if got != "" {
					t.Errorf("matched host = %q on the error path, want \"\"", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("matchAllowedHost(%q, %q, %v) error = %v, want nil",
					tc.scheme, tc.observed, tc.allowed, err)
			}
			if got != tc.wantMatch {
				t.Errorf("matched host = %q, want %q", got, tc.wantMatch)
			}
		})
	}
}

// TestParseAllowedHosts covers the shapes an operator can actually write into
// a compose file or a Helm value.
func TestParseAllowedHosts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		raw     string
		want    []string
		wantErr bool
	}{
		{name: "one host", raw: "gw.example", want: []string{"gw.example"}},
		{name: "several", raw: "a.example,b.example:8443", want: []string{"a.example", "b.example:8443"}},
		{name: "surrounding whitespace is trimmed", raw: " a.example , b.example ", want: []string{"a.example", "b.example"}},
		// A typo, not a shorter list: silently dropping it is how an
		// allowlist ends up different from what its author read back.
		{name: "an empty entry is a typo", raw: "a.example,,b.example", wantErr: true},
		{name: "a lone comma", raw: ",", wantErr: true},
		{name: "whitespace-only entry", raw: "a.example,   ", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseAllowedHosts(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseAllowedHosts(%q) error = nil, want an error", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseAllowedHosts(%q) error = %v, want nil", tc.raw, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("parseAllowedHosts(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}

// TestCheck_ApprovalIDHeader_ForwardedAndKeptOutOfRawInput is the symmetric twin of proxy's
// TestAuthorize_ApprovalIDMetadata_ForwardedAndKeptOutOfRawInput, and it exists because this
// surface previously had the DEAD-END half of the escalation story: it degrades every escalation
// (E5) and hands back an approval id, but never read one back, and -- because the header is not a
// credential -- never stripped one either.
//
// Both halves were broken and each broke the other's fix. Ignored, the id makes a retry escalate a
// SECOND time, asking a human for the same action twice while the first approval sits unused.
// Reported, it changes raw_input, so the digest no longer matches the first approval -- meaning
// even a later fix that read the id would fail Approval.Verify.
//
// That mattered more than a gap on one surface, because the two surfaces deliberately share the
// header name so an operator learns one key for both: a recipe that works on proxy has to work
// here, or the sharing is a trap rather than a convenience.
//
// The raw_input comparison is the load-bearing assertion, from two requests differing ONLY by the
// presence of the header.
func TestCheck_ApprovalIDHeader_ForwardedAndKeptOutOfRawInput(t *testing.T) {
	approvalID := uuid.NewString()

	escalatingPDP := &fakePDP{resp: allowResponse("")}
	escalatingClient := startFakePDP(t, escalatingPDP)
	escalatingSrv := &extauthzServer{client: escalatingClient, cfg: testExtauthzServerCfg()}
	if _, err := escalatingSrv.Check(context.Background(), checkRequest("POST", "/svc.Svc/Method", map[string]string{
		"authorization": "Bearer " + testBearerToken,
		"dpop":          testDPoPProof,
	})); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	retryPDP := &fakePDP{resp: allowResponse("")}
	retryClient := startFakePDP(t, retryPDP)
	retrySrv := &extauthzServer{client: retryClient, cfg: testExtauthzServerCfg()}
	if _, err := retrySrv.Check(context.Background(), checkRequest("POST", "/svc.Svc/Method", map[string]string{
		"authorization":        "Bearer " + testBearerToken,
		"dpop":                 testDPoPProof,
		approvalIDHeaderInTest: approvalID,
	})); err != nil {
		t.Fatalf("Check() error = %v", err)
	}

	escalating, retry := escalatingPDP.lastRequest(), retryPDP.lastRequest()
	if escalating == nil || retry == nil {
		t.Fatal("PDP never received one of the two requests")
	}
	if got := retry.GetApprovalId(); got != approvalID {
		t.Errorf("approval_id = %q, want %q -- without it a retry escalates again and a human is asked "+
			"for the same action twice", got, approvalID)
	}
	if escalating.ApprovalId != nil {
		t.Errorf("approval_id = %q on a request that sent none, want unset", escalating.GetApprovalId())
	}
	if escalating.GetRawInput() != retry.GetRawInput() {
		t.Errorf("raw_input differs between the escalating request and its retry:\n  escalating: %s\n  retry:      %s\n"+
			"want byte-identical -- resolveEscalation binds the approval to sha256(raw_input), so an extra "+
			"header here makes the approval unusable by the very request it was created for",
			escalating.GetRawInput(), retry.GetRawInput())
	}
	if strings.Contains(retry.GetRawInput(), approvalID) {
		t.Errorf("raw_input carries the approval id verbatim: %s", retry.GetRawInput())
	}
}

// TestCheck_ApprovalIDHeaderCaseDiffers_StillConsumed: HTTP header names are case-insensitive
// (RFC 7230), and unlike the credentials this surface reads, this one is a name STRATIUM ITSELF
// hands out -- in a response header, which Go's own http.Header.Set canonicalizes to
// "Stratium-Approval-Id" before it ever reaches a client. So the spelling that comes back is
// routinely NOT the one this file writes, and a case-sensitive match would drop it on exactly the
// path the system's own denial recommends.
func TestCheck_ApprovalIDHeaderCaseDiffers_StillConsumed(t *testing.T) {
	for _, headerName := range []string{
		"stratium-approval-id", "Stratium-Approval-Id", "STRATIUM-APPROVAL-ID", "sTrAtIuM-aPpRoVaL-iD",
	} {
		t.Run(headerName, func(t *testing.T) {
			approvalID := uuid.NewString()
			fake := &fakePDP{resp: allowResponse("")}
			srv := &extauthzServer{client: startFakePDP(t, fake), cfg: testExtauthzServerCfg()}
			if _, err := srv.Check(context.Background(), checkRequest("POST", "/svc.Svc/Method", map[string]string{
				"authorization": "Bearer " + testBearerToken,
				headerName:      approvalID,
			})); err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			req := fake.lastRequest()
			if got := req.GetApprovalId(); got != approvalID {
				t.Errorf("approval_id = %q, want %q -- a header spelled %q must still be recognized",
					got, approvalID, headerName)
			}
			var meta requestMetadata
			if err := json.Unmarshal([]byte(req.GetRawInput()), &meta); err != nil {
				t.Fatalf("raw_input is not well-formed JSON: %v", err)
			}
			for key := range meta.Headers {
				if strings.EqualFold(key, "stratium-approval-id") {
					t.Errorf("raw_input.headers carries key %q -- reported, it changes the digest the "+
						"approval is bound to", key)
				}
			}
		})
	}
}

// TestCheck_MalformedApprovalIDHeader_DroppedAndTheRequestIsStillDecided is the extauthz half of
// the audit guard: an unparseable approval_id makes Decide fail with InvalidArgument BEFORE
// authenticateToken runs, so no audit row is written. Dropping it lets the request reach a real,
// audited decision, which is what keeps the header from being a switch a caller can use to
// suppress its own audit trail. See forwardableApprovalID (proxy.go) for the full case, including
// why denying locally would close nothing.
func TestCheck_MalformedApprovalIDHeader_DroppedAndTheRequestIsStillDecided(t *testing.T) {
	fake := &fakePDP{resp: allowResponse("")}
	srv := &extauthzServer{client: startFakePDP(t, fake), cfg: testExtauthzServerCfg()}
	if _, err := srv.Check(context.Background(), checkRequest("POST", "/svc.Svc/Method", map[string]string{
		"authorization":        "Bearer " + testBearerToken,
		approvalIDHeaderInTest: "not-a-uuid",
	})); err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got := fake.requestCount(); got != 1 {
		t.Fatalf("PDP received %d Decide call(s), want exactly 1 -- the request must still be DECIDED, "+
			"because that is what writes the audit row", got)
	}
	if req := fake.lastRequest(); req.ApprovalId != nil {
		t.Errorf("approval_id = %q, want unset", req.GetApprovalId())
	}
}
