package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
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
)

// testExtauthzServerCfg is the AgentID/Subject/ConnectTimeout every test
// below needs to construct an extauthzServer directly (bypassing
// runExtauthzCmd and its environment-variable loading entirely, the same
// choice hook_test.go's testCfg makes for hookConfig). ListenAddr/PDPAddr
// are left zero-valued: nothing in these tests calls runExtauthzCmd, so
// nothing ever reads them.
func testExtauthzServerCfg() extauthzConfig {
	return extauthzConfig{
		AgentID:        testAgentIDFixture,
		Subject:        testSubjectFixture,
		ConnectTimeout: 5 * time.Second,
	}
}

// checkRequest builds a CheckRequest carrying method, path, and headers --
// the same three pieces of an HTTP request every test below needs, without
// each one repeating the AttributeContext/AttributeContext_Request/
// AttributeContext_HttpRequest nesting TestCheck_RequestShapeIsIrrelevant_StillDenies
// above already spells out once.
func checkRequest(method, path string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Reason: "policy allows"}}
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
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
	_, err := decideRequestFromCheck(&authv3.CheckRequest{}, testAgentIDFixture, testSubjectFixture)
	if err == nil {
		t.Fatal("decideRequestFromCheck() error = nil, want an error (no HTTP attributes means no authorization header)")
	}
}

// TestExtractBearerToken is the direct, wire-free table of every shape
// extractBearerToken must accept or reject -- faster and more exhaustive
// than routing every case through a real gRPC round trip, which the Check-
// level tests above already do for the cases that specifically need to
// prove something about the WIRE (declared_tier, raw_input's JSON shape).
func TestExtractBearerToken(t *testing.T) {
	for _, tc := range []struct {
		name      string
		headers   map[string]string
		wantToken string
		wantErr   bool
	}{
		{
			name:      "well-formed bearer token",
			headers:   map[string]string{"authorization": "Bearer " + testBearerToken},
			wantToken: testBearerToken,
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
			token, _, err := extractBearerToken(tc.headers)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("extractBearerToken() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractBearerToken() error = %v, want nil", err)
			}
			if token != tc.wantToken {
				t.Errorf("extractBearerToken() token = %q, want %q", token, tc.wantToken)
			}
		})
	}
}

// TestExtractBearerToken_HeaderNameCaseDiffers_TokenStillFound is the
// direct-function twin of TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing:
// this one proves EXTRACTION survives a header name that differs only in
// case, the other proves STRIPPING does. Both properties live in the same
// loop inside extractBearerToken (see its own doc comment for why), but a
// mutation could plausibly break one without the other -- e.g. matching
// case-insensitively when deciding what to strip but comparing case-
// sensitively when deciding what to treat as the token -- so both get their
// own dedicated assertion.
func TestExtractBearerToken_HeaderNameCaseDiffers_TokenStillFound(t *testing.T) {
	token, _, err := extractBearerToken(map[string]string{"AUTHORIZATION": "Bearer " + testBearerToken})
	if err != nil {
		t.Fatalf("extractBearerToken() error = %v, want nil -- a header named AUTHORIZATION must still be found", err)
	}
	if token != testBearerToken {
		t.Errorf("extractBearerToken() token = %q, want %q", token, testBearerToken)
	}
}

// TestExtractBearerToken_StripsCredentialHeadersCaseInsensitively is the
// direct-function proof that every entry in credentialHeaderNames -- not
// just authorization -- is actually removed from the returned headers map,
// case-insensitively, while a header that merely looks credential-adjacent
// (testAuthLikeHeaderName) survives untouched.
func TestExtractBearerToken_StripsCredentialHeadersCaseInsensitively(t *testing.T) {
	_, stripped, err := extractBearerToken(map[string]string{
		"authorization":        "Bearer " + testBearerToken,
		"Cookie":               testOtherCredentialValue,
		"PROXY-AUTHORIZATION":  testOtherCredentialValue,
		testAuthLikeHeaderName: testAuthLikeHeaderValue,
	})
	if err != nil {
		t.Fatalf("extractBearerToken() error = %v, want nil", err)
	}
	for _, credHeader := range []string{"authorization", "Cookie", "PROXY-AUTHORIZATION"} {
		if v, ok := stripped[credHeader]; ok {
			t.Errorf("stripped headers still contain %q = %q", credHeader, v)
		}
	}
	if v, ok := stripped[testAuthLikeHeaderName]; !ok || v != testAuthLikeHeaderValue {
		t.Errorf("stripped[%q] = (%q, %v), want (%q, true) -- not every auth-ish name is a credential",
			testAuthLikeHeaderName, v, ok, testAuthLikeHeaderValue)
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
		{name: "allow", resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}, wantCode: int32(rpccode.Code_OK)},
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
