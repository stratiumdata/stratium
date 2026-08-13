package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"stratium/internal/pdpgrpc"
)

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

// requiredProxyEnvVars names every variable loadProxyConfigFromEnv requires -- shared by
// clearProxyEnv and setAllProxyEnv below, the same role requiredExtauthzEnvVars
// (extauthz_test.go) plays for extauthzConfig, so a field added to proxyConfig without a
// matching entry here goes untested for its own absence rather than failing loudly.
var requiredProxyEnvVars = []string{
	"STRATIUM_PEP_PROXY_LISTEN_ADDR", "STRATIUM_PEP_PROXY_TARGET_ADDR",
	"STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_AGENT_ID", "STRATIUM_PEP_SUBJECT",
	"STRATIUM_PEP_CONNECT_TIMEOUT", "STRATIUM_PEP_APPROVAL_POLL_INTERVAL", "STRATIUM_PEP_APPROVAL_TIMEOUT",
}

// clearProxyEnv clears every variable loadProxyConfigFromEnv reads, so each test below starts
// from a known-empty baseline regardless of what the ambient environment happens to have set --
// t.Setenv restores each after the test, so tests never leak into one another.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, k := range requiredProxyEnvVars {
		t.Setenv(k, "")
	}
}

// setAllProxyEnv sets every required variable to a valid value, then applies overrides -- the
// shared "everything valid except what this test is deliberately breaking" baseline every case
// below builds on, mirroring setAllExtauthzEnv (extauthz_test.go).
func setAllProxyEnv(t *testing.T, overrides map[string]string) {
	t.Helper()
	values := map[string]string{
		"STRATIUM_PEP_PROXY_LISTEN_ADDR":      "127.0.0.1:9292",
		"STRATIUM_PEP_PROXY_TARGET_ADDR":      "localhost:9393",
		"STRATIUM_PEP_PDP_ADDR":               "localhost:50051",
		"STRATIUM_PEP_AGENT_ID":               "agent-1",
		"STRATIUM_PEP_SUBJECT":                "alice@example.com",
		"STRATIUM_PEP_CONNECT_TIMEOUT":        "5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "1s",
		"STRATIUM_PEP_APPROVAL_TIMEOUT":       "1h",
	}
	for k, v := range overrides {
		values[k] = v
	}
	for _, k := range requiredProxyEnvVars {
		t.Setenv(k, values[k])
	}
}

func TestLoadProxyConfigFromEnv_AllRequiredValuesPresent_ReturnsPopulatedConfig(t *testing.T) {
	clearProxyEnv(t)
	setAllProxyEnv(t, nil)

	cfg, err := loadProxyConfigFromEnv()
	if err != nil {
		t.Fatalf("loadProxyConfigFromEnv() error = %v, want nil", err)
	}
	want := proxyConfig{
		ListenAddr:           "127.0.0.1:9292",
		TargetAddr:           "localhost:9393",
		PDPAddr:              "localhost:50051",
		AgentID:              "agent-1",
		Subject:              "alice@example.com",
		ConnectTimeout:       5 * time.Second,
		ApprovalPollInterval: time.Second,
		ApprovalTimeout:      time.Hour,
	}
	if cfg != want {
		t.Errorf("loadProxyConfigFromEnv() = %+v, want %+v", cfg, want)
	}
}

// Each required variable, missing alone, is named in the resulting error -- the per-field
// companion to TestLoadProxyConfigFromEnv_MissingMultipleRequired_NamesAllAtOnce below, which
// proves the same thing holds when more than one is missing at once.
func TestLoadProxyConfigFromEnv_MissingVariable_NamesIt(t *testing.T) {
	for _, missing := range requiredProxyEnvVars {
		t.Run(missing, func(t *testing.T) {
			clearProxyEnv(t)
			setAllProxyEnv(t, map[string]string{missing: ""})

			_, err := loadProxyConfigFromEnv()
			if err == nil {
				t.Fatalf("loadProxyConfigFromEnv() error = nil, want an error naming %s", missing)
			}
			if !strings.Contains(err.Error(), missing) {
				t.Errorf("loadProxyConfigFromEnv() error = %q, want it to name %s", err.Error(), missing)
			}
		})
	}
}

// TestLoadProxyConfigFromEnv_MissingMultipleRequired_NamesAllAtOnce is the mutation-testing
// anchor for "report only the first missing config key": every required variable left unset at
// once -- a freshly configured proxy deployment with none of its environment set yet is exactly
// this case -- must produce ONE error naming all eight, not just whichever requiredEnv call
// happened to run first. See proxyConfig's own doc comment for why this loader is one group,
// not two composed loaders, which is what keeps it out of the failure mode a recent task
// (mcp.go's combineConfigErrors) found and fixed for a genuinely two-loader case. Mirrors
// TestLoadExtauthzConfigFromEnv_MissingMultipleRequired_NamesAllAtOnce (extauthz_test.go).
func TestLoadProxyConfigFromEnv_MissingMultipleRequired_NamesAllAtOnce(t *testing.T) {
	clearProxyEnv(t)

	_, err := loadProxyConfigFromEnv()
	if err == nil {
		t.Fatal("loadProxyConfigFromEnv() with every required variable unset: want error, got nil")
	}
	for _, want := range requiredProxyEnvVars {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %s alongside the other missing variables", err.Error(), want)
		}
	}
}

// TestLoadProxyConfigFromEnv_InvalidDuration_ReturnsError covers all three duration fields --
// not just ConnectTimeout -- against the same three bad shapes requiredDuration (config.go) is
// meant to catch: unparseable, zero, and negative. A zero STRATIUM_PEP_APPROVAL_POLL_INTERVAL in
// particular would panic time.NewTicker inside Task 2's escalation poll loop rather than fail
// cleanly at startup if this check were ever missing -- mirrors the identical breadth
// TestLoadHookConfigFromEnv's own "invalid duration" subtest gives hookConfig (hook_test.go).
func TestLoadProxyConfigFromEnv_InvalidDuration_ReturnsError(t *testing.T) {
	badValues := []struct {
		name  string
		value string
	}{
		{"not a duration", "not-a-duration"},
		{"zero", "0s"},
		{"negative", "-5s"},
	}
	for _, field := range []string{
		"STRATIUM_PEP_CONNECT_TIMEOUT", "STRATIUM_PEP_APPROVAL_POLL_INTERVAL", "STRATIUM_PEP_APPROVAL_TIMEOUT",
	} {
		for _, bad := range badValues {
			t.Run(field+"/"+bad.name, func(t *testing.T) {
				clearProxyEnv(t)
				setAllProxyEnv(t, map[string]string{field: bad.value})

				_, err := loadProxyConfigFromEnv()
				if err == nil {
					t.Fatalf("loadProxyConfigFromEnv() error = nil, want an error naming %s", field)
				}
				if !strings.Contains(err.Error(), field) {
					t.Errorf("loadProxyConfigFromEnv() error = %q, want it to name %s", err.Error(), field)
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// Server test infrastructure.
// ---------------------------------------------------------------------------

// dialInsecure dials addr the same way every mode in this binary dials the PDP, or a
// proxyServer dials its target: grpc.NewClient over insecure credentials. Shared by every test
// below that needs a raw *grpc.ClientConn -- unlike dialTestClient (pdp_fake_test.go), which
// wraps its connection in a typed pdpgrpc.PDPServiceClient, tests here need the bare connection
// itself to call arbitrary, unregistered methods through proxyCodec via grpc.ForceCodec.
func dialInsecure(t *testing.T, addr string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// startProxyServer serves srv (the real proxyServer under test) on an OS-assigned loopback port
// via newProxyGRPCServer -- the same construction runProxyCmd uses for the real binary -- and
// returns a *grpc.ClientConn dialed to it. The test-facing equivalent of startExtauthzServer
// (extauthz_test.go), applied to a server with no generated client stub of its own, since
// nothing this proxy fronts is a fixed, known service.
func startProxyServer(t *testing.T, srv *proxyServer) *grpc.ClientConn {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := newProxyGRPCServer(srv.handleStream)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return dialInsecure(t, lis.Addr().String())
}

// contactCounter is a grpc.UnknownServiceHandler a fake target server uses to record whether,
// and how many times, it was ever invoked -- so a deny test can assert on real contact, not
// merely on what the caller observed. See proxy.go's package doc's DENY BY DEFAULT section: a
// proxy that forwards and then errors has already leaked the request, which checking only the
// caller's own response would miss entirely.
type contactCounter struct {
	mu    sync.Mutex
	calls int
}

func (c *contactCounter) handler(_ any, _ grpc.ServerStream) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return status.Error(codes.Internal, "stratium-pep test: a denied call must never reach the target")
}

func (c *contactCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// startFakeTarget serves a contactCounter on an OS-assigned loopback port and returns its
// address, ready to be dialed into a proxyServer's targetConn. No grpc.ForceServerCodec here,
// unlike startEchoTarget below: contactCounter.handler returns before ever calling RecvMsg, so
// no codec is invoked on the path a deny test exercises (see proxyCodec's own doc comment).
func startFakeTarget(t *testing.T) (addr string, counter *contactCounter) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	counter = &contactCounter{}
	gs := grpc.NewServer(grpc.UnknownServiceHandler(counter.handler))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return lis.Addr().String(), counter
}

// ---------------------------------------------------------------------------
// handleStream: deny by default.
// ---------------------------------------------------------------------------

// TestStartProxyServer_AcceptsAConnection is the "the proxy starts" property the task brief
// asks for by name, proven as its own test rather than left as an incidental side effect of the
// deny tests below: a real RPC through a real dialed connection gets answered at all (with a
// denial, since Task 1 has nothing else to answer with -- TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted
// covers that response's content), which is what actually forces the lazy grpc.NewClient dial
// to complete and proves the listener is live and serving, not merely that a port was bound.
func TestStartProxyServer_AcceptsAConnection(t *testing.T) {
	srv := &proxyServer{}
	conn := startProxyServer(t, srv)

	err := conn.Invoke(context.Background(), "/probe.Probe/Method", &proxyFrame{}, &proxyFrame{}, grpc.ForceCodec(proxyCodec{}))
	if err == nil {
		t.Fatal("Invoke() error = nil, want the connection to have been accepted and answered (with a denial)")
	}
	if status.Code(err) == codes.Unavailable {
		t.Fatalf("Invoke() = %v, want the server to have accepted the connection rather than being unreachable", err)
	}
}

// TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted is the mutation-testing anchor for
// "make the skeleton forward instead of deny," unary half: a plain, single-message,
// unary-shaped call is denied with PermissionDenied, and -- the property that actually matters,
// per proxy.go's package doc's DENY BY DEFAULT section -- the fake target's own call counter
// stays at zero. Asserting only that the caller received an error would still pass a build that
// forwards the request and THEN fails; asserting the target's own contact count is what catches
// that.
func TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted(t *testing.T) {
	targetAddr, target := startFakeTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
	conn := startProxyServer(t, srv)

	var resp proxyFrame
	err := conn.Invoke(context.Background(), "/inventory.Inventory/GetItem", &proxyFrame{payload: []byte("request")}, &resp, grpc.ForceCodec(proxyCodec{}))
	if err == nil {
		t.Fatal("Invoke() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	if got := target.count(); got != 0 {
		t.Errorf("target received %d call(s), want 0 -- a denied call must never reach the target", got)
	}
}

// TestHandleStream_StreamingCall_DeniedAndTargetNeverContacted is the same mutation-testing
// anchor's streaming half, and independently defends the property the task brief separately
// calls out as its own mutation ("make streaming fall through unauthorized while unary still
// denies"): this is a SEPARATE test from the unary one above specifically so that property has
// its own, distinct assertion rather than being inferred from the unary case -- see this task's
// own report for what happened when an actual mutation attempting to treat the two differently
// was tried against this code.
//
// Three messages are sent -- not one -- before the caller even looks at the response, because a
// real streaming client does not wait for a reply between sends; this is what proves even a
// stream a caller has already committed several messages to never reaches the target, not
// merely that a single request never does.
func TestHandleStream_StreamingCall_DeniedAndTargetNeverContacted(t *testing.T) {
	targetAddr, target := startFakeTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
	conn := startProxyServer(t, srv)

	stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/inventory.Inventory/WatchItems", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	for i := 0; i < 3; i++ {
		// A send can itself start failing once the server side has already denied and the
		// transport has noticed -- entirely consistent with a correctly denied stream, not a
		// test failure, so this only stops sending early rather than asserting anything on it.
		// The authoritative status is read from RecvMsg below regardless of how many of these
		// three actually went out.
		if err := stream.SendMsg(&proxyFrame{payload: []byte("watch-request")}); err != nil {
			break
		}
	}
	_ = stream.CloseSend()

	var resp proxyFrame
	err = stream.RecvMsg(&resp)
	if err == nil {
		t.Fatal("RecvMsg() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	if got := target.count(); got != 0 {
		t.Errorf("target received %d call(s), want 0 -- a denied streaming call must never reach the target, even after multiple messages were sent", got)
	}
}

// TestHandleStream_ReflectionAndHealthCheckMethods_StillDenied is the test the task's binding
// constraint asks for by name: authorize special-cases nothing, which specifically means a
// method shaped like introspection -- gRPC's own standard health-check and reflection service
// names, the two examples the task itself names as tempting exemptions -- gets no different
// treatment than any other method. A build that special-cased either as "obviously harmless"
// would still pass every test above (neither uses those method names) but would fail here.
func TestHandleStream_ReflectionAndHealthCheckMethods_StillDenied(t *testing.T) {
	for _, method := range []string{
		"/grpc.health.v1.Health/Check",
		"/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
	} {
		t.Run(method, func(t *testing.T) {
			targetAddr, target := startFakeTarget(t)
			srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
			conn := startProxyServer(t, srv)

			var resp proxyFrame
			err := conn.Invoke(context.Background(), method, &proxyFrame{}, &resp, grpc.ForceCodec(proxyCodec{}))
			if err == nil {
				t.Fatalf("Invoke(%s) error = nil, want PermissionDenied -- no method gets a free pass (D1)", method)
			}
			if got, want := status.Code(err), codes.PermissionDenied; got != want {
				t.Errorf("status code = %s, want %s", got, want)
			}
			if got := target.count(); got != 0 {
				t.Errorf("target received %d call(s), want 0", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// forward: the relay mechanics, exercised directly.
// ---------------------------------------------------------------------------

// echoHandler is a grpc.UnknownServiceHandler that relays every message it receives straight
// back to its own caller, until the caller half-closes -- a target double simple enough to
// prove forward's relay mechanics without needing any real target service or generated proto.
func echoHandler(_ any, stream grpc.ServerStream) error {
	for {
		var f proxyFrame
		if err := stream.RecvMsg(&f); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.SendMsg(&f); err != nil {
			return err
		}
	}
}

// startEchoTarget serves echoHandler on an OS-assigned loopback port, with ForceServerCodec set
// -- unlike startFakeTarget's contactCounter, echoHandler DOES call RecvMsg/SendMsg, so it needs
// the same passthrough codec forward's own client-side dial forces on the way out, or a message
// would fail to decode against the default proto codec trying to unmarshal into *proxyFrame.
func startEchoTarget(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer(
		grpc.UnknownServiceHandler(echoHandler),
		grpc.ForceServerCodec(proxyCodec{}),
	)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return lis.Addr().String()
}

// startForwardOnlyServer wires srv.forward directly onto a handler passed through
// newProxyGRPCServer -- the same codec-registering construction startProxyServer uses for
// srv.handleStream -- deliberately bypassing only handleStream's authorize gate, not the server
// wiring around it. An earlier version of this helper built its own separate grpc.NewServer
// call here instead of reusing newProxyGRPCServer, which meant ForceServerCodec was never
// verified for the construction runProxyCmd and startProxyServer actually share -- a real gap
// this task's own mutation testing found (see this task's report) before this helper was
// changed to close it. See forward's own doc comment (proxy.go) for why proving the relay
// mechanics needs bypassing the gate at all, ahead of Task 2 putting a real one in front of it.
func startForwardOnlyServer(t *testing.T, srv *proxyServer) *grpc.ClientConn {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := newProxyGRPCServer(func(_ any, stream grpc.ServerStream) error {
		fullMethod, ok := grpc.MethodFromServerStream(stream)
		if !ok {
			return status.Error(codes.Internal, "stratium-pep test: could not determine the called method")
		}
		return srv.forward(fullMethod, stream)
	})
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return dialInsecure(t, lis.Addr().String())
}

// TestForward_RelaysMessagesBothDirections is the direct proof that the machinery Task 1
// builds -- and Task 1's own dispatch never calls, since handleStream denies first (see the
// tests above) -- actually relays a caller and a target correctly when something does call it,
// ahead of Task 2 wiring a real gate in front of it and Task 4 proving the whole thing against a
// real service. One test covers both cardinalities this mechanism claims to handle: the first
// send/receive pair alone is the unary wire shape (one message each way); continuing on to a
// second and third is what only a streaming call does. There is no separate unary-only version
// of this test, deliberately -- see proxy.go's package doc's PASSTHROUGH CODEC section for why
// unary is not a distinct code path this relay could pass here and fail elsewhere.
func TestForward_RelaysMessagesBothDirections(t *testing.T) {
	targetAddr := startEchoTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
	conn := startForwardOnlyServer(t, srv)

	stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/echo.Echo/Stream", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}

	for _, msg := range []string{"one", "two", "three"} {
		if err := stream.SendMsg(&proxyFrame{payload: []byte(msg)}); err != nil {
			t.Fatalf("SendMsg(%q) error = %v", msg, err)
		}
		var got proxyFrame
		if err := stream.RecvMsg(&got); err != nil {
			t.Fatalf("RecvMsg() error = %v, want the echoed %q", err, msg)
		}
		if string(got.payload) != msg {
			t.Errorf("RecvMsg() payload = %q, want %q", got.payload, msg)
		}
	}

	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}
	var got proxyFrame
	if err := stream.RecvMsg(&got); !errors.Is(err, io.EOF) {
		t.Errorf("final RecvMsg() error = %v, want io.EOF (clean end)", err)
	}
}

// ---------------------------------------------------------------------------
// Task 2: the real decision -- extractBearerTokenFromMetadata, direct and wire-free.
// ---------------------------------------------------------------------------

// Fixture values below are deliberately distinctive strings sharing no substring with one another
// or with anything this file itself generates (a header name, a JSON key, a proto field name) --
// mirrors extauthz_test.go's identical fixture-naming discipline (its own doc comment explains
// why): a fixture that reused a generic word as its own value could pass a test by accident even
// after a mixup.
const (
	testProxyBearerToken          = "proxy-bearer-a1c9f06e2d8b4357-fixture"
	testProxyOtherCredentialValue = "proxy-other-credential-88b3e5c2-fixture"
	testProxyAuthLikeHeaderName   = "x-auth-context"
	testProxyAuthLikeHeaderValue  = "proxy-authlike-header-5f92de19-fixture"
	testProxyAgentIDFixture       = "proxy-agent-7b3f1c24-fixture"
	testProxySubjectFixture       = "proxy-subject-7b3f1c24-fixture@example.com"
)

// testProxyServerCfg returns a valid baseline proxyConfig: AgentID/Subject identity, a generous
// ConnectTimeout, and small (millisecond) escalation timing -- mirrors testExtauthzServerCfg
// (extauthz_test.go) and testCfg (hook_test.go) for the identical reason: most tests below are not
// themselves about timing and want their escalation fixtures to resolve or time out in well under
// a second. ListenAddr/TargetAddr are left zero-valued: nothing below calls runProxyCmd, so
// nothing ever reads them.
func testProxyServerCfg() proxyConfig {
	return proxyConfig{
		AgentID:              testProxyAgentIDFixture,
		Subject:              testProxySubjectFixture,
		ConnectTimeout:       5 * time.Second,
		ApprovalPollInterval: 5 * time.Millisecond,
		ApprovalTimeout:      500 * time.Millisecond,
	}
}

// incomingBearerCtx builds a context carrying "authorization: Bearer token" (plus any extra
// key/value pairs) as INCOMING gRPC metadata -- the shape handleStream's own stream.Context()
// carries after a real network round trip translates a caller's OUTGOING metadata into this
// process's own incoming metadata. Tests below that call authorize/decideRequestFromStream
// directly (bypassing a real dial) build that translated shape themselves, via
// metadata.NewIncomingContext, rather than attaching OUTGOING metadata the way a real caller's own
// stub would (bearerCtx, further down, is that OUTGOING-side helper, used only by tests that
// actually dial through startProxyServer) -- authorize reads ONLY incoming metadata
// (metadata.FromIncomingContext, decideRequestFromStream), and outgoing metadata attached to a
// context that is never dialed through a real transport never becomes incoming metadata on its
// own.
//
// Built via metadata.Pairs, which lower-cases every key -- fine for every test that uses this
// helper, because none of them are about case sensitivity; the casing-defensiveness tests below
// (TestAuthorize_RawInputNeverCarriesCredential_AnyHeaderCasing,
// TestExtractBearerTokenFromMetadata_HeaderNameCaseDiffers_TokenStillFound, and others) build
// their own metadata.MD as a raw map literal instead, specifically to avoid Pairs' own
// normalization laundering away the exact case variation those tests exist to exercise.
func incomingBearerCtx(token string, extra ...string) context.Context {
	pairs := append([]string{"authorization", "Bearer " + token}, extra...)
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(pairs...))
}

// TestExtractBearerTokenFromMetadata is the direct, wire-free table of every shape
// extractBearerTokenFromMetadata must accept or reject -- mirrors extauthz_test.go's
// TestExtractBearerToken for the analogous gRPC-metadata shape, faster and more exhaustive than
// routing every case through a real dial.
func TestExtractBearerTokenFromMetadata(t *testing.T) {
	for _, tc := range []struct {
		name      string
		md        metadata.MD
		wantToken string
		wantErr   bool
	}{
		{
			name:      "well-formed bearer token",
			md:        metadata.Pairs("authorization", "Bearer "+testProxyBearerToken),
			wantToken: testProxyBearerToken,
		},
		{
			name:    "no metadata at all",
			md:      nil,
			wantErr: true,
		},
		{
			name:    "no authorization key",
			md:      metadata.Pairs("x-request-id", "abc"),
			wantErr: true,
		},
		{
			name:    "not a Bearer scheme",
			md:      metadata.Pairs("authorization", "Basic "+testProxyBearerToken),
			wantErr: true,
		},
		{
			name:    "Bearer scheme, empty token after trailing space",
			md:      metadata.Pairs("authorization", "Bearer "),
			wantErr: true,
		},
		{
			name:    "Bearer scheme, no token and no trailing space",
			md:      metadata.Pairs("authorization", "Bearer"),
			wantErr: true,
		},
		{
			// A repeated authorization key is non-conformant (RFC 7235 defines exactly one
			// credential per header) but not unconstructible on this wire -- metadata.Pairs
			// accumulates repeated keys into one []string, exactly as a client or an
			// interceptor that appended a second value would produce. This is the anchor for
			// a mutation this task's own report found survived on its first attempt (values[0]
			// swapped for the last element): only a fixture carrying genuinely more than one
			// value can distinguish "always reads the first" from "always reads the last" --
			// every other case in this table has exactly one value, where both choices agree.
			name:      "multiple authorization values -- the first one wins",
			md:        metadata.Pairs("authorization", "Bearer "+testProxyBearerToken, "authorization", "Bearer "+testProxyOtherCredentialValue),
			wantToken: testProxyBearerToken,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, _, err := extractBearerTokenFromMetadata(tc.md)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("extractBearerTokenFromMetadata() error = nil, want an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("extractBearerTokenFromMetadata() error = %v, want nil", err)
			}
			if token != tc.wantToken {
				t.Errorf("extractBearerTokenFromMetadata() token = %q, want %q", token, tc.wantToken)
			}
		})
	}
}

// TestExtractBearerTokenFromMetadata_HeaderNameCaseDiffers_TokenStillFound proves EXTRACTION
// survives a metadata key that differs only in case, using a metadata.MD built as a raw map
// literal rather than via metadata.Pairs/New -- both of those already force keys to lower case at
// construction (verified directly against this module's own vendored grpc-go source; see
// extractBearerTokenFromMetadata's own doc comment), which would silently launder away the exact
// case variation this test exists to exercise. A raw literal is the only way to hand this function
// a metadata.MD shaped the way a non-normalizing client or an interceptor could actually produce
// one.
func TestExtractBearerTokenFromMetadata_HeaderNameCaseDiffers_TokenStillFound(t *testing.T) {
	for _, headerName := range []string{"authorization", "Authorization", "AUTHORIZATION", "AuthoriZation"} {
		t.Run(headerName, func(t *testing.T) {
			md := metadata.MD{headerName: {"Bearer " + testProxyBearerToken}}
			token, _, err := extractBearerTokenFromMetadata(md)
			if err != nil {
				t.Fatalf("extractBearerTokenFromMetadata() error = %v, want nil -- a key named %q must still be found", err, headerName)
			}
			if token != testProxyBearerToken {
				t.Errorf("extractBearerTokenFromMetadata() token = %q, want %q", token, testProxyBearerToken)
			}
		})
	}
}

// TestExtractBearerTokenFromMetadata_StripsCredentialHeadersCaseInsensitively is the direct-
// function proof that every entry in credentialHeaderNames (extauthz.go) -- not just
// authorization -- is actually removed from the returned map, case-insensitively, while a key
// that merely looks credential-adjacent (testProxyAuthLikeHeaderName) survives untouched. Built as
// a raw metadata.MD literal for the identical bypass-normalization reason as the test above.
func TestExtractBearerTokenFromMetadata_StripsCredentialHeadersCaseInsensitively(t *testing.T) {
	md := metadata.MD{
		"authorization":             {"Bearer " + testProxyBearerToken},
		"Cookie":                    {testProxyOtherCredentialValue},
		"PROXY-AUTHORIZATION":       {testProxyOtherCredentialValue},
		testProxyAuthLikeHeaderName: {testProxyAuthLikeHeaderValue},
	}
	_, stripped, err := extractBearerTokenFromMetadata(md)
	if err != nil {
		t.Fatalf("extractBearerTokenFromMetadata() error = %v, want nil", err)
	}
	for _, credHeader := range []string{"authorization", "Cookie", "PROXY-AUTHORIZATION"} {
		if v, ok := stripped[credHeader]; ok {
			t.Errorf("stripped headers still contain %q = %q", credHeader, v)
		}
	}
	if v, ok := stripped[testProxyAuthLikeHeaderName]; !ok || len(v) != 1 || v[0] != testProxyAuthLikeHeaderValue {
		t.Errorf("stripped[%q] = (%v, %v), want ([%q], true) -- not every auth-ish name is a credential",
			testProxyAuthLikeHeaderName, v, ok, testProxyAuthLikeHeaderValue)
	}
}

// ---------------------------------------------------------------------------
// Task 2: the real decision -- authorize, direct (bypassing a real dial, exercising a real
// network-dialed fakePDP behind p.client). Faster and more exhaustive than routing every case
// through startProxyServer + a real conn.Invoke, which the wire-level section further down still
// does for the properties that specifically need to prove something about the GATE (that
// handleStream actually reaches authorize, and forward, correctly).
// ---------------------------------------------------------------------------

// TestAuthorize_MethodBecomesTool defends P1: the full method is the tool identity sent to the
// PDP, unmodified. agent_id/subject are checked in the same test, as a bonus, for the same reason
// extauthz_test.go's TestCheck_PathBecomesTool folds its own identity check into a differently-
// named test rather than giving it a whole test of its own.
func TestAuthorize_MethodBecomesTool(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	const method = "/inventory.Inventory/DeleteItem"
	allowed, reason := srv.authorize(incomingBearerCtx(testProxyBearerToken), method)
	if !allowed {
		t.Fatalf("authorize() denied (%s), want allowed", reason)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.GetTool() != method {
		t.Errorf("tool = %q, want the full method %q", req.GetTool(), method)
	}
	if req.GetAgentId() != testProxyAgentIDFixture || req.GetSubject() != testProxySubjectFixture {
		t.Errorf("request identity = (agent=%q subject=%q), want (%q, %q)",
			req.GetAgentId(), req.GetSubject(), testProxyAgentIDFixture, testProxySubjectFixture)
	}
}

// TestAuthorize_TokenExtractedFromBearerMetadata defends P2's other half: the token named in
// "authorization: Bearer <token>" reaches DecideRequest.Token, scheme stripped, unaltered.
func TestAuthorize_TokenExtractedFromBearerMetadata(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	srv.authorize(incomingBearerCtx(testProxyBearerToken), "/svc.Svc/Method")

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.GetToken() != testProxyBearerToken {
		t.Errorf("token = %q, want %q", req.GetToken(), testProxyBearerToken)
	}
}

// TestAuthorize_RawInputCarriesMethod defends P3's positive half: raw_input decodes as JSON
// carrying the called method.
func TestAuthorize_RawInputCarriesMethod(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	const method = "/inventory.Inventory/DeleteItem"
	srv.authorize(incomingBearerCtx(testProxyBearerToken), method)

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	var got proxyRequestMetadata
	if err := json.Unmarshal([]byte(req.GetRawInput()), &got); err != nil {
		t.Fatalf("raw_input is not well-formed JSON: %v\nraw_input: %s", err, req.GetRawInput())
	}
	if got.Method != method {
		t.Errorf("raw_input method = %q, want %q", got.Method, method)
	}
}

// TestAuthorize_RawInputNeverCarriesCredential_AnyHeaderCasing is the load-bearing test in this
// file: raw_input, as actually sent to the PDP over a real (in-process, dialed) gRPC connection,
// never carries a credential header regardless of how the caller capitalized it -- raw_input is
// hashed into the append-only audit chain (see proxy.go's package doc), so a token leaking there
// is live authority written permanently into a record designed to be retained and read, in a
// chain that cannot be edited to remove it. Table-driven over four casings, mirrors
// extauthz_test.go's TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing.
//
// Built with a raw metadata.MD literal via metadata.NewIncomingContext directly, NOT
// incomingBearerCtx (which calls metadata.Pairs, forcing lower case before this test's chosen
// casing ever reaches decideRequestFromStream) -- see incomingBearerCtx's own doc comment for why
// that helper cannot be used here without silently proving nothing.
//
// Every case asserts absence two ways, mirroring extauthz_test.go's identical two-proof
// discipline: structurally, by unmarshaling raw_input and checking no header key
// case-insensitively equals "authorization", and by substring, confirming the literal token value
// is absent from the raw bytes altogether.
func TestAuthorize_RawInputNeverCarriesCredential_AnyHeaderCasing(t *testing.T) {
	for _, headerName := range []string{"authorization", "Authorization", "AUTHORIZATION", "AuthoriZation"} {
		t.Run(headerName, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			pdpClient := startFakePDP(t, fake)
			srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

			md := metadata.MD{headerName: {"Bearer " + testProxyBearerToken}}
			ctx := metadata.NewIncomingContext(context.Background(), md)
			allowed, reason := srv.authorize(ctx, "/svc.Svc/Method")
			if !allowed {
				t.Fatalf("authorize() denied (%s), want allowed -- extraction must have found this header "+
					"(see TestExtractBearerTokenFromMetadata_HeaderNameCaseDiffers_TokenStillFound)", reason)
			}

			req := fake.lastRequest()
			if req == nil {
				t.Fatal("PDP never received a request")
			}
			raw := req.GetRawInput()
			if strings.Contains(raw, testProxyBearerToken) {
				t.Errorf("raw_input contains the bearer token verbatim: %s", raw)
			}

			var got proxyRequestMetadata
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

// TestAuthorize_RawInputStripsOtherCredentialHeaders proves cookie and proxy-authorization -- the
// two other entries credentialHeaderNames' own doc comment names (extauthz.go) -- are actually
// stripped from raw_input as sent to the PDP, each in two casings. Built with a raw metadata.MD
// literal for the identical bypass-normalization reason as the test above.
func TestAuthorize_RawInputStripsOtherCredentialHeaders(t *testing.T) {
	for _, headerName := range []string{"cookie", "Cookie", "proxy-authorization", "Proxy-Authorization"} {
		t.Run(headerName, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			pdpClient := startFakePDP(t, fake)
			srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

			md := metadata.MD{
				"authorization": {"Bearer " + testProxyBearerToken},
				headerName:      {testProxyOtherCredentialValue},
			}
			ctx := metadata.NewIncomingContext(context.Background(), md)
			allowed, reason := srv.authorize(ctx, "/svc.Svc/Method")
			if !allowed {
				t.Fatalf("authorize() denied (%s), want allowed", reason)
			}

			req := fake.lastRequest()
			if req == nil {
				t.Fatal("PDP never received a request")
			}
			if raw := req.GetRawInput(); strings.Contains(raw, testProxyOtherCredentialValue) {
				t.Errorf("raw_input contains %q's value verbatim: %s", headerName, raw)
			}
		})
	}
}

// TestAuthorize_RawInputPreservesNonCredentialHeaders guards the other side of the stripping
// rule. The test above would pass just as well if extraction stripped every header instead of
// only the credential-bearing ones -- an empty headers map can never carry "authorization"
// either. testProxyAuthLikeHeaderName is chosen specifically to also guard against a substring
// match on "auth" instead of an exact match against credentialHeaderNames.
func TestAuthorize_RawInputPreservesNonCredentialHeaders(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	ctx := incomingBearerCtx(testProxyBearerToken, testProxyAuthLikeHeaderName, testProxyAuthLikeHeaderValue)
	allowed, reason := srv.authorize(ctx, "/svc.Svc/Method")
	if !allowed {
		t.Fatalf("authorize() denied (%s), want allowed", reason)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	var got proxyRequestMetadata
	if err := json.Unmarshal([]byte(req.GetRawInput()), &got); err != nil {
		t.Fatalf("raw_input is not well-formed JSON: %v\nraw_input: %s", err, req.GetRawInput())
	}
	vals, ok := got.Headers[testProxyAuthLikeHeaderName]
	if !ok || len(vals) != 1 || vals[0] != testProxyAuthLikeHeaderValue {
		t.Errorf("raw_input.headers[%q] = %v, want [%q] -- a non-credential header must still reach raw_input, "+
			"even one whose name merely LOOKS auth-related", testProxyAuthLikeHeaderName, vals, testProxyAuthLikeHeaderValue)
	}
}

// TestAuthorize_NeverSendsDeclaredTier defends the same property hook.go's, mcp_authorize.go's,
// and extauthz.go's identical tests defend for their own surfaces: declared_tier stays nil across
// a real wire round trip to fakePDP, not merely in the Go struct this file builds in memory --
// proto3 omits a zero-value/unset optional field from the wire entirely, so checking
// req.DeclaredTier after fakePDP decodes a real message proves the WIRE never carried it.
func TestAuthorize_NeverSendsDeclaredTier(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	allowed, reason := srv.authorize(incomingBearerCtx(testProxyBearerToken), "/svc.Svc/Method")
	if !allowed {
		t.Fatalf("authorize() denied (%s), want allowed", reason)
	}

	req := fake.lastRequest()
	if req == nil {
		t.Fatal("PDP never received a request")
	}
	if req.DeclaredTier != nil {
		t.Errorf("declared_tier = %v, want unset (nil) -- proxy has no real tier to declare; "+
			"a guessed one only creates a chance to be wrong", req.GetDeclaredTier())
	}
	if resc := req.GetResource(); len(resc) != 0 {
		t.Errorf("resource = %v, want empty -- this file extracts nothing locally, for any request", resc)
	}
}

// TestAuthorize_MissingToken_DeniesWithoutContactingPDP is the test the brief asks for by name:
// K4 leaves no fallback credential, so a request with no authorization metadata at all must not
// merely be denied -- it must never reach the PDP in the first place. Asserted against the fake's
// own received-call count, mirroring extauthz_test.go's identical
// TestCheck_MissingAuthorizationHeader_DeniesWithoutContactingPDP.
func TestAuthorize_MissingToken_DeniesWithoutContactingPDP(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("x-request-id", "req-fixture-does-not-matter"))
	allowed, reason := srv.authorize(ctx, "/svc.Svc/Method")
	if allowed {
		t.Fatal("authorize() = allowed, want denied -- no credential to send the PDP")
	}
	if !strings.Contains(reason, "no authorization metadata") {
		t.Errorf("reason = %q, want it to say no authorization metadata was present", reason)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a missing token must deny without ever "+
			"contacting the PDP (K4: there is no fallback credential to ask about)", got)
	}
}

// TestAuthorize_NoMetadataAtAll_DeniesWithoutContactingPDP is
// TestAuthorize_MissingToken_DeniesWithoutContactingPDP's twin for a ctx carrying no gRPC metadata
// value AT ALL (metadata.FromIncomingContext's own ok == false case), not merely metadata missing
// the authorization key -- a real call through a real gRPC server always has SOME incoming
// metadata (grpc-go sets it even for an empty case), but this function must not assume that and
// must not panic chasing a nil map either way; ranging over a nil map is defined and safe in Go,
// which is what this test actually proves rather than merely asserts in a comment.
func TestAuthorize_NoMetadataAtAll_DeniesWithoutContactingPDP(t *testing.T) {
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	allowed, _ := srv.authorize(context.Background(), "/svc.Svc/Method")
	if allowed {
		t.Fatal("authorize() = allowed, want denied")
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0", got)
	}
}

// TestAuthorize_MalformedToken_DeniesWithoutContactingPDP covers every shape of "present but
// useless" M2 leaves this surface no fallback for, mirroring
// extauthz_test.go's TestCheck_MalformedAuthorizationHeader_DeniesWithoutContactingPDP.
func TestAuthorize_MalformedToken_DeniesWithoutContactingPDP(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"not a Bearer challenge", "Basic " + testProxyBearerToken},
		{"Bearer scheme, no token at all", "Bearer"},
		{"Bearer scheme, trailing space but empty token", "Bearer "},
		{"lowercase bearer scheme", "bearer " + testProxyBearerToken},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			pdpClient := startFakePDP(t, fake)
			srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", tc.value))
			allowed, _ := srv.authorize(ctx, "/svc.Svc/Method")
			if allowed {
				t.Fatalf("authorize() = allowed for %q, want denied", tc.value)
			}
			if got := fake.requestCount(); got != 0 {
				t.Errorf("PDP received %d Decide call(s), want 0 -- a malformed authorization value (%q) "+
					"must deny without ever contacting the PDP", got, tc.value)
			}
		})
	}
}

// TestAuthorize_Deny_ReturnsPDPReasonVerbatim defends the "distinguishable reasons" property for
// the simplest case: a genuine EFFECT_DENY's reason reaches the caller exactly as the PDP wrote
// it, unprefixed -- the same convention hook.go's and extauthz.go's own default DENY cases use.
func TestAuthorize_Deny_ReturnsPDPReasonVerbatim(t *testing.T) {
	const pdpReason = "proxy-deny-reason-4c8b2f19-fixture: delegation revoked"
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	allowed, reason := srv.authorize(incomingBearerCtx(testProxyBearerToken), "/svc.Svc/Method")
	if allowed {
		t.Fatal("authorize() = allowed, want denied")
	}
	if reason != pdpReason {
		t.Errorf("reason = %q, want the PDP's own reason %q, verbatim and unprefixed", reason, pdpReason)
	}
}

// TestAuthorize_UnreachablePDP_Denies points at a real, dialed-and-closed loopback port
// (unreachablePDPClient, pdp_fake_test.go) so client.Decide genuinely fails at the transport
// layer, mirroring extauthz_test.go's identical
// TestCheck_UnreachablePDP_DeniesAsOrdinaryResponse_NotTransportError -- an unreachable PDP is a
// denial, not a panic or a hang.
func TestAuthorize_UnreachablePDP_Denies(t *testing.T) {
	pdpClient := unreachablePDPClient(t)
	srv := &proxyServer{client: pdpClient, cfg: testProxyServerCfg()}

	allowed, reason := srv.authorize(incomingBearerCtx(testProxyBearerToken), "/svc.Svc/Method")
	if allowed {
		t.Fatal("authorize() = allowed, want denied -- an unreachable PDP must deny")
	}
	if reason == "" {
		t.Error("reason is empty, want it to explain the PDP was unreachable")
	}
}

// TestAuthorize_Escalate_ApprovedRetryAllows is the direct-authorize-level companion to
// TestHandleStream_Escalate_BlocksThenForwardsOnApproval (wire-level, further down): the happy
// path, GetApproval resolves "approved" on its third call, the retry Decide (decideThenAllowClient,
// hook_test.go, reused unmodified) answers ALLOW, and the exact approval id polled and retried
// with is the one the escalation named.
func TestAuthorize_Escalate_ApprovedRetryAllows(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp: escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{
			{Status: "pending"}, {Status: "pending"}, {Status: "approved"},
		},
	}
	client := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: client, first: fake.resp}
	srv := &proxyServer{client: wrapped, cfg: testProxyServerCfg()}

	allowed, reason := srv.authorize(incomingBearerCtx(testProxyBearerToken), "/svc.Svc/Method")
	if !allowed {
		t.Fatalf("authorize() denied (%s), want allowed after approval", reason)
	}
	if fake.getApprovalCallCount() != 3 {
		t.Errorf("GetApproval called %d times, want 3", fake.getApprovalCallCount())
	}
	if got := wrapped.lastDecideReq.GetApprovalId(); got != approvalID {
		t.Errorf("retry Decide request approval_id = %q, want %q", got, approvalID)
	}
}

// TestAuthorize_EscalationTimeout_Denies is the direct-authorize-level companion to
// TestHandleStream_EscalationTimeout_DeniesWithoutForwarding (wire-level, further down):
// GetApproval never resolves (pendingApproval repeats "pending" forever, hook_test.go), so the
// only way this call ends is ApprovalTimeout firing, and it must deny.
// mustReturnWithin (hook_test.go) proves this directly rather than trusting go test's own default
// timeout to eventually notice a "retry forever" mutation.
func TestAuthorize_EscalationTimeout_Denies(t *testing.T) {
	approvalID := uuid.NewString()
	fake := &fakePDP{resp: escalateResp(approvalID), getApprovalResponses: pendingApproval()}
	client := startFakePDP(t, fake)
	cfg := testProxyServerCfg()
	cfg.ApprovalPollInterval = 5 * time.Millisecond
	// Deliberately not a multiple of the interval -- see TestRunHook_Escalate_TimeoutStillPendingDenies
	// (hook_test.go) for why: avoids the deadline racing a tick at the same instant.
	cfg.ApprovalTimeout = 33 * time.Millisecond
	srv := &proxyServer{client: client, cfg: cfg}

	var allowed bool
	var reason string
	mustReturnWithin(t, 2*time.Second, func() {
		allowed, reason = srv.authorize(incomingBearerCtx(testProxyBearerToken), "/svc.Svc/Method")
	})
	if allowed {
		t.Fatal("authorize() = allowed, want denied (C22: a timeout must deny)")
	}
	if !strings.Contains(reason, "did not resolve within the escalation timeout") {
		t.Errorf("reason = %q, want it to name the escalation timeout", reason)
	}
}

// ---------------------------------------------------------------------------
// Task 2: the real decision -- over the wire, through the real handleStream gate. These are the
// tests the task's own brief asks for by name: proof that the GATE (not just authorize in
// isolation, above) actually reaches forward on ALLOW and never does on anything else.
// ---------------------------------------------------------------------------

// bearerCtx attaches "authorization: Bearer token" to ctx as OUTGOING gRPC metadata -- what a
// real caller's own stub sends, which a real dial turns into INCOMING metadata on this process's
// side (see incomingBearerCtx's own doc comment for the direct-call tests' equivalent, and why
// the two are not interchangeable). metadata.AppendToOutgoingContext always lower-cases the key
// it sends -- exactly what a normal, conformant client does, and exactly why none of the tests
// below use this helper to probe case sensitivity; that property is proven at the
// extractBearerTokenFromMetadata/authorize direct-call layer instead, where a raw metadata.MD
// literal can actually bypass the normalization every real outgoing-metadata API in this module
// forces.
func bearerCtx(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// TestHandleStream_Allow_ReachesTargetAndResponseReturns is the required property from this
// task's brief: an allowed unary call reaches the target and its response returns. Uses the echo
// target (startEchoTarget, above) so "reaches the target" is provable two ways at once: the
// echoed payload proves both that the target received the request AND that its own reply made it
// all the way back to the caller.
func TestHandleStream_Allow_ReachesTargetAndResponseReturns(t *testing.T) {
	targetAddr := startEchoTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	var resp proxyFrame
	err := conn.Invoke(ctx, "/inventory.Inventory/GetItem", &proxyFrame{payload: []byte("request")}, &resp, grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("Invoke() error = %v, want the allowed call to succeed", err)
	}
	if string(resp.payload) != "request" {
		t.Errorf("response payload = %q, want the target's own echoed %q", resp.payload, "request")
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1", got)
	}
}

// TestHandleStream_Deny_NeverReachesTarget is the required property "a denied one never reaches
// it" -- a genuine PDP DENY (unlike Task 1's TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted,
// which exercised the OLD fixed always-deny stub), checked against the fake target's own
// received-call counter (contactCounter), not merely against the caller's own error, per that same
// test's own established discipline (proxy.go's package doc DENY BY DEFAULT section): a proxy
// that forwards and then errors has already leaked the request. Anchors the required mutation
// "forward on DENY".
func TestHandleStream_Deny_NeverReachesTarget(t *testing.T) {
	targetAddr, target := startFakeTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: "policy denies"}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	var resp proxyFrame
	err := conn.Invoke(ctx, "/inventory.Inventory/DeleteItem", &proxyFrame{payload: []byte("request")}, &resp, grpc.ForceCodec(proxyCodec{}))
	if err == nil {
		t.Fatal("Invoke() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	if got := target.count(); got != 0 {
		t.Errorf("target received %d call(s), want 0 -- a PDP denial must never reach the target", got)
	}
}

// TestHandleStream_MissingToken_DeniesWithoutContactingPDP is the required property "a missing
// token denies without contacting the PDP" -- asserted, per the task's own instruction, against
// the PDP's own received-call count, over a real wire round trip through the real gate (the
// direct-call TestAuthorize_MissingToken_DeniesWithoutContactingPDP above proves the identical
// property one layer lower).
func TestHandleStream_MissingToken_DeniesWithoutContactingPDP(t *testing.T) {
	targetAddr, target := startFakeTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	var resp proxyFrame
	err := conn.Invoke(context.Background(), "/inventory.Inventory/GetItem", &proxyFrame{payload: []byte("request")}, &resp, grpc.ForceCodec(proxyCodec{}))
	if err == nil {
		t.Fatal("Invoke() error = nil, want PermissionDenied")
	}
	if got, want := status.Code(err), codes.PermissionDenied; got != want {
		t.Errorf("status code = %s, want %s", got, want)
	}
	if got := fake.requestCount(); got != 0 {
		t.Errorf("PDP received %d Decide call(s), want 0 -- a missing token must deny without contacting the PDP", got)
	}
	if got := target.count(); got != 0 {
		t.Errorf("target received %d call(s), want 0", got)
	}
}

// TestHandleStream_AllowedStream_ForwardsBothDirections is the required property "an allowed
// stream forwards in both directions" -- the streaming counterpart to
// TestHandleStream_Allow_ReachesTargetAndResponseReturns, through the REAL handleStream gate
// (unlike TestForward_RelaysMessagesBothDirections, which deliberately bypasses it -- see that
// test's own doc comment). fake.requestCount() == 1 despite three messages crossing is a bonus
// proof of P4 (a stream is authorized once, at open, not per message).
func TestHandleStream_AllowedStream_ForwardsBothDirections(t *testing.T) {
	targetAddr := startEchoTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	stream, err := conn.NewStream(ctx, proxyStreamDesc, "/echo.Echo/Stream", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}

	for _, msg := range []string{"one", "two", "three"} {
		if err := stream.SendMsg(&proxyFrame{payload: []byte(msg)}); err != nil {
			t.Fatalf("SendMsg(%q) error = %v", msg, err)
		}
		var got proxyFrame
		if err := stream.RecvMsg(&got); err != nil {
			t.Fatalf("RecvMsg() error = %v, want the echoed %q", err, msg)
		}
		if string(got.payload) != msg {
			t.Errorf("RecvMsg() payload = %q, want %q", got.payload, msg)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}
	var got proxyFrame
	if err := stream.RecvMsg(&got); !errors.Is(err, io.EOF) {
		t.Errorf("final RecvMsg() error = %v, want io.EOF", err)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- a stream is authorized once, at open (P4)", got)
	}
}

// countingEchoHandler is echoHandler (above) plus a call counter, so a test can prove BOTH
// "nothing reached the target yet" (the counter) and "the target's own reply eventually arrives"
// (the echoed payload) around one escalation wait. TestHandleStream_Escalate_BlocksThenForwardsOnApproval
// needs the counter specifically because a proxy that started relaying immediately and only
// delayed the CALLER-visible reply would still look correct from the client's own RecvMsg timing
// alone -- the same "check the target's own count, not just what the caller observed" discipline
// TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted already applies to an outright denial,
// applied here to a call that is merely still pending.
type countingEchoHandler struct {
	mu    sync.Mutex
	calls int
}

func (c *countingEchoHandler) handler(_ any, stream grpc.ServerStream) error {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return echoHandler(nil, stream)
}

func (c *countingEchoHandler) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

// startCountingEchoTarget serves a countingEchoHandler on an OS-assigned loopback port, with
// ForceServerCodec set -- mirrors startEchoTarget's own construction (countingEchoHandler,
// underneath, calls RecvMsg/SendMsg and needs the same passthrough codec forward's own
// client-side dial forces).
func startCountingEchoTarget(t *testing.T) (addr string, counter *countingEchoHandler) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	counter = &countingEchoHandler{}
	gs := grpc.NewServer(
		grpc.UnknownServiceHandler(counter.handler),
		grpc.ForceServerCodec(proxyCodec{}),
	)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return lis.Addr().String(), counter
}

// streamRecvResult is one RecvMsg outcome, carried over a channel so a test can select between it
// and a timeout without RecvMsg itself blocking the test goroutine indefinitely -- the gRPC-stream
// equivalent of mcp_authorize_test.go's readFrame/assertNoFrame pair, adapted to a live
// grpc.ClientStream instead of a byte-oriented pipe.
type streamRecvResult struct {
	frame proxyFrame
	err   error
}

// tryRecv starts stream.RecvMsg on its own goroutine and returns a channel it reports its one
// result on. Callers select against this with their OWN timeout(s) rather than this function
// taking one, because TestHandleStream_Escalate_BlocksThenForwardsOnApproval needs two different
// things from the SAME in-flight call -- proof nothing arrives within a short window while still
// escalating, then the eventual real result once approval resolves -- and RecvMsg can only be
// issued once per message; a second, independent call to it would race the first rather than
// observing the same outcome.
func tryRecv(stream grpc.ClientStream) <-chan streamRecvResult {
	ch := make(chan streamRecvResult, 1)
	go func() {
		var f proxyFrame
		err := stream.RecvMsg(&f)
		ch <- streamRecvResult{frame: f, err: err}
	}()
	return ch
}

// TestHandleStream_Escalate_BlocksThenForwardsOnApproval is the required property "an escalating
// call blocks then forwards on approval" -- proxy is a BLOCKING surface (spec §4.6), unlike
// extauthz, so this holds the caller's own stream open rather than degrading to a denial. Reuses
// decideThenAllowClient/escalateResp/pendingApproval (hook_test.go) unmodified, the same fixtures
// mcp_authorize_test.go's own escalation tests already share rather than each redefining their
// own.
func TestHandleStream_Escalate_BlocksThenForwardsOnApproval(t *testing.T) {
	targetAddr, target := startCountingEchoTarget(t)
	approvalID := uuid.NewString()
	fake := &fakePDP{
		resp: escalateResp(approvalID),
		getApprovalResponses: []*pdpgrpc.GetApprovalResponse{
			{Status: "pending"}, {Status: "pending"}, {Status: "pending"},
			{Status: "pending"}, {Status: "pending"}, {Status: "pending"},
			{Status: "approved"},
		},
	}
	pdpClient := startFakePDP(t, fake)
	wrapped := &decideThenAllowClient{PDPServiceClient: pdpClient, first: fake.resp}
	cfg := testProxyServerCfg()
	cfg.ApprovalPollInterval = 20 * time.Millisecond // ~6 polls before "approved" lands, ~120ms total
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: wrapped, cfg: cfg}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	stream, err := conn.NewStream(ctx, proxyStreamDesc, "/inventory.Inventory/WatchItems", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	// Buffered client-side (HTTP/2 flow control), so this succeeds immediately even though the
	// server has not yet started reading -- handleStream's authorize call has not returned yet,
	// so forward's relayCallerToTarget goroutine, the only thing that ever calls RecvMsg on the
	// server side of this stream, has not started.
	if err := stream.SendMsg(&proxyFrame{payload: []byte("watch-request")}); err != nil {
		t.Fatalf("SendMsg() error = %v", err)
	}

	result := tryRecv(stream)

	// BLOCKS: nothing reaches the target, and no response arrives, while still polling -- checked
	// well before the ~120ms the scripted "approved" response lands at.
	select {
	case res := <-result:
		t.Fatalf("RecvMsg() returned early (payload=%q err=%v) -- the call must still be blocked on escalation", res.frame.payload, res.err)
	case <-time.After(60 * time.Millisecond):
	}
	if got := target.count(); got != 0 {
		t.Errorf("target received %d call(s) while still escalating, want 0", got)
	}

	// THEN FORWARDS: once GetApproval resolves "approved" and the retry Decide (wrapped) answers
	// ALLOW, the target is reached and its own echoed reply comes back.
	select {
	case res := <-result:
		if res.err != nil {
			t.Fatalf("RecvMsg() error = %v, want the echoed payload after approval", res.err)
		}
		if string(res.frame.payload) != "watch-request" {
			t.Errorf("RecvMsg() payload = %q, want the echoed %q", res.frame.payload, "watch-request")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RecvMsg() did not return within 2s after approval should have resolved")
	}
	if got := target.count(); got != 1 {
		t.Errorf("target received %d call(s), want exactly 1", got)
	}
	if got := fake.lastGetApprovalRequest().GetApprovalId(); got != approvalID {
		t.Errorf("GetApproval was asked about %q, want the escalation's own approval id %q", got, approvalID)
	}
}

// TestHandleStream_EscalationTimeout_DeniesWithoutForwarding is the required property "an
// escalation timeout denies without forwarding" -- checked against the target's own received-call
// count (contactCounter), the anchor for the required mutation "treat an escalation timeout as
// allow".
func TestHandleStream_EscalationTimeout_DeniesWithoutForwarding(t *testing.T) {
	targetAddr, target := startFakeTarget(t)
	approvalID := uuid.NewString()
	fake := &fakePDP{resp: escalateResp(approvalID), getApprovalResponses: pendingApproval()}
	pdpClient := startFakePDP(t, fake)
	cfg := testProxyServerCfg()
	cfg.ApprovalPollInterval = 5 * time.Millisecond
	cfg.ApprovalTimeout = 33 * time.Millisecond
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: cfg}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	var resp proxyFrame
	var err error
	mustReturnWithin(t, 2*time.Second, func() {
		err = conn.Invoke(ctx, "/inventory.Inventory/DeleteItem", &proxyFrame{payload: []byte("request")}, &resp, grpc.ForceCodec(proxyCodec{}))
	})
	if err == nil {
		t.Fatal("Invoke() error = nil, want PermissionDenied (C22: a timeout must deny)")
	}
	st := status.Convert(err)
	if st.Code() != codes.PermissionDenied {
		t.Errorf("status code = %s, want %s", st.Code(), codes.PermissionDenied)
	}
	if !strings.Contains(st.Message(), "did not resolve within the escalation timeout") {
		t.Errorf("status message = %q, want it to name the escalation timeout", st.Message())
	}
	if got := target.count(); got != 0 {
		t.Errorf("target received %d call(s), want 0 -- an escalation timeout must forward nothing", got)
	}
}

// metadataCapture is an echo target with a side channel: it records the incoming gRPC metadata a
// call carried, in addition to echoing every message back the same way echoHandler does. What
// TestHandleStream_Allow_TargetReceivesOriginalCredentials checks the target actually received,
// as distinct from what the PDP received in raw_input (fakePDP.lastRequest) -- forward's own
// independent metadata.FromIncomingContext/NewOutgoingContext pass (proxy.go) and
// decideRequestFromStream's own credential-stripped copy are two SEPARATE reads of the same
// incoming metadata, and this type is what lets a test observe the forwarded side of that split,
// not only the audited side.
type metadataCapture struct {
	mu sync.Mutex
	md metadata.MD
}

func (c *metadataCapture) handler(_ any, stream grpc.ServerStream) error {
	md, _ := metadata.FromIncomingContext(stream.Context())
	c.mu.Lock()
	c.md = md
	c.mu.Unlock()
	return echoHandler(nil, stream)
}

func (c *metadataCapture) get(key string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.md.Get(key)
}

// startMetadataCapturingTarget serves a metadataCapture on an OS-assigned loopback port, with
// ForceServerCodec set -- mirrors startEchoTarget's own construction (metadataCapture.handler,
// like echoHandler, calls RecvMsg/SendMsg and needs the same passthrough codec).
func startMetadataCapturingTarget(t *testing.T) (addr string, capture *metadataCapture) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	capture = &metadataCapture{}
	gs := grpc.NewServer(
		grpc.UnknownServiceHandler(capture.handler),
		grpc.ForceServerCodec(proxyCodec{}),
	)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return lis.Addr().String(), capture
}

// TestHandleStream_Allow_TargetReceivesOriginalCredentials is this task's own bonus mutation,
// converted into a permanent regression test (see this task's report for the mutation itself and
// what running it found): the target must still receive the caller's REAL "authorization"
// metadata on an allowed call, completely unstripped. decideRequestFromStream strips credentials
// only for the COPY that becomes raw_input; forward (proxy.go) reads the caller's incoming
// metadata a second, entirely independent time and forwards it to the target verbatim, because
// the target needs the real credential for its OWN authentication -- this process has no business
// deciding otherwise. Nothing else in this suite inspects what the TARGET itself received, which
// is exactly why a mutation that accidentally shared or mutated the stripped copy in place could
// have shipped undetected without this test.
func TestHandleStream_Allow_TargetReceivesOriginalCredentials(t *testing.T) {
	targetAddr, capture := startMetadataCapturingTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	var resp proxyFrame
	if err := conn.Invoke(ctx, "/inventory.Inventory/GetItem", &proxyFrame{payload: []byte("request")}, &resp, grpc.ForceCodec(proxyCodec{})); err != nil {
		t.Fatalf("Invoke() error = %v", err)
	}

	got := capture.get("authorization")
	want := "Bearer " + testProxyBearerToken
	if len(got) != 1 || got[0] != want {
		t.Errorf("target's own incoming authorization metadata = %v, want [%q] -- an allowed call must "+
			"still reach the target with its real credential, not this process's audit-only stripped copy", got, want)
	}
}

// ---------------------------------------------------------------------------
// forward: response fidelity -- headers, trailers, status ("forward and relay the response back
// faithfully", this task's own brief). Exercised directly via startForwardOnlyServer, the same
// PDP-free bypass TestForward_RelaysMessagesBothDirections already uses (proxy.go's forward doc
// comment explains why that bypass stays useful even now that the real gate can open): none of
// these properties depend on the PDP gate at all, and isolating them keeps a failure here from
// ever being confused with a PDP-wiring problem.
// ---------------------------------------------------------------------------

const (
	testProxyHeaderKey        = "x-target-header"
	testProxyHeaderValue      = "proxy-header-value-9f2ac317-fixture"
	testProxyTrailerKey       = "x-target-trailer"
	testProxyTrailerValue     = "proxy-trailer-value-3d81be04-fixture"
	testProxyTargetErrMessage = "proxy-target-error-message-6e40c952-fixture"
)

// headerTrailerHandler sets a distinctive response header (SetHeader, before anything else --
// gRPC sends headers with the first outbound message unless SendHeader/SetHeader ran first),
// echoes exactly one message, then sets a distinctive trailer before returning.
func headerTrailerHandler(_ any, stream grpc.ServerStream) error {
	if err := stream.SetHeader(metadata.Pairs(testProxyHeaderKey, testProxyHeaderValue)); err != nil {
		return err
	}
	var f proxyFrame
	if err := stream.RecvMsg(&f); err != nil {
		return err
	}
	if err := stream.SendMsg(&f); err != nil {
		return err
	}
	stream.SetTrailer(metadata.Pairs(testProxyTrailerKey, testProxyTrailerValue))
	return nil
}

func startHeaderTrailerTarget(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(
		grpc.UnknownServiceHandler(headerTrailerHandler),
		grpc.ForceServerCodec(proxyCodec{}),
	)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

// TestForward_RelaysResponseHeaders proves the target's own response header reaches the caller --
// a property no Task 1 test checked (TestForward_RelaysMessagesBothDirections's echoHandler never
// sets one).
func TestForward_RelaysResponseHeaders(t *testing.T) {
	targetAddr := startHeaderTrailerTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
	conn := startForwardOnlyServer(t, srv)

	stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/echo.Echo/Method", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if err := stream.SendMsg(&proxyFrame{payload: []byte("hello")}); err != nil {
		t.Fatalf("SendMsg() error = %v", err)
	}
	var got proxyFrame
	if err := stream.RecvMsg(&got); err != nil {
		t.Fatalf("RecvMsg() error = %v", err)
	}

	md, err := stream.Header()
	if err != nil {
		t.Fatalf("Header() error = %v", err)
	}
	if got := md.Get(testProxyHeaderKey); len(got) != 1 || got[0] != testProxyHeaderValue {
		t.Errorf("response header %s = %v, want [%q] -- the target's own header must reach the caller", testProxyHeaderKey, got, testProxyHeaderValue)
	}
}

// TestForward_RelaysTrailers is the anchor for the required mutation "drop trailers": the
// target's own custom trailer must reach the caller after the call completes. A dedicated test,
// deliberately separate from the header tests around it -- forward sets the trailer in its own
// select loop (serverStream.SetTrailer(targetStream.Trailer())), an entirely different line from
// relayTargetToCaller's header handling, so a mutation could plausibly break one without the
// other.
func TestForward_RelaysTrailers(t *testing.T) {
	targetAddr := startHeaderTrailerTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
	conn := startForwardOnlyServer(t, srv)

	stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/echo.Echo/Method", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if err := stream.SendMsg(&proxyFrame{payload: []byte("hello")}); err != nil {
		t.Fatalf("SendMsg() error = %v", err)
	}
	var got proxyFrame
	if err := stream.RecvMsg(&got); err != nil {
		t.Fatalf("RecvMsg() error = %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}
	// Trailer() is only valid once RecvMsg has returned a non-nil error (grpc.ClientStream.Trailer's
	// own doc comment, also cited in forward's own doc comment) -- drain to that point first.
	var drain proxyFrame
	if err := stream.RecvMsg(&drain); !errors.Is(err, io.EOF) {
		t.Fatalf("final RecvMsg() error = %v, want io.EOF", err)
	}

	trailer := stream.Trailer()
	if got := trailer.Get(testProxyTrailerKey); len(got) != 1 || got[0] != testProxyTrailerValue {
		t.Errorf("trailer %s = %v, want [%q] -- the target's own trailer must reach the caller", testProxyTrailerKey, got, testProxyTrailerValue)
	}
}

// errorBeforeAnyMessageHandler sets a distinctive response header, then returns a distinctive
// error status WITHOUT ever calling SendMsg -- exactly the gap Task 1's own doc comment flagged
// and this task's relayTargetToCaller rewrite fixes (see that function's own doc comment): a
// target that errors before sending anything used to never have its headers explicitly forwarded
// at all, because the prior code only ever read them lazily on a first successful RecvMsg, which
// this handler deliberately never reaches.
func errorBeforeAnyMessageHandler(_ any, stream grpc.ServerStream) error {
	if err := stream.SetHeader(metadata.Pairs(testProxyHeaderKey, testProxyHeaderValue)); err != nil {
		return err
	}
	return status.Error(codes.FailedPrecondition, testProxyTargetErrMessage)
}

func startErrorBeforeAnyMessageTarget(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(
		grpc.UnknownServiceHandler(errorBeforeAnyMessageHandler),
		grpc.ForceServerCodec(proxyCodec{}),
	)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

// TestForward_RelaysHeadersEvenWhenTargetErrorsBeforeAnyMessage is the direct proof of this
// task's fix to Task 1's documented gap: a target that sets a response header and then errors,
// without ever sending a single message, must still have that header reach the caller, and the
// target's own error status/message must still propagate faithfully alongside it -- "forward and
// relay the response back faithfully ... including headers, trailers, and status" (this task's
// own brief), proven for the specific case Task 1 could not yet claim it for.
func TestForward_RelaysHeadersEvenWhenTargetErrorsBeforeAnyMessage(t *testing.T) {
	targetAddr := startErrorBeforeAnyMessageTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr)}
	conn := startForwardOnlyServer(t, srv)

	stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/echo.Echo/Method", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	if err := stream.SendMsg(&proxyFrame{payload: []byte("hello")}); err != nil {
		t.Fatalf("SendMsg() error = %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}

	var resp proxyFrame
	recvErr := stream.RecvMsg(&resp)
	if recvErr == nil {
		t.Fatal("RecvMsg() error = nil, want the target's own FailedPrecondition")
	}
	st := status.Convert(recvErr)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("status code = %s, want %s", st.Code(), codes.FailedPrecondition)
	}
	if st.Message() != testProxyTargetErrMessage {
		t.Errorf("status message = %q, want the target's own %q", st.Message(), testProxyTargetErrMessage)
	}

	md, herr := stream.Header()
	if herr != nil {
		t.Fatalf("Header() error = %v", herr)
	}
	if got := md.Get(testProxyHeaderKey); len(got) != 1 || got[0] != testProxyHeaderValue {
		t.Errorf("response header %s = %v, want [%q] -- the target's header must reach the caller even "+
			"though it never sent a message before erroring", testProxyHeaderKey, got, testProxyHeaderValue)
	}
}

// ---------------------------------------------------------------------------
// Task 3: the limits, pinned. Each test below proves the documented BEHAVIOUR
// (docs/pep.md, "The proxy surface's limits"; proxy.go's own package doc, TASK
// 3: THE LIMITS) actually happens -- not merely that the documentation exists.
// ---------------------------------------------------------------------------

// TestHandleStream_AllowedStream_OutlivesRevocationAfterOpen is P4's own
// operational consequence, proven directly: a stream authorized once, at
// open, keeps forwarding even once the decision that authorized it would no
// longer be granted. wrapped (decideThenDenyClient, hook_test.go) answers the
// stream's own opening Decide call with ALLOW and every call after that with
// DENY -- standing in for a delegation revoked, or a policy changed, the
// instant after this stream's one and only authorization decision was made.
// Three messages crossing successfully afterward, and wrapped.calls staying
// at exactly 1, is the fact worth pinning: the PDP is not merely skipped for
// convenience on messages two and three, asking it again right now would
// refuse, and the established stream is asked anyway not at all.
func TestHandleStream_AllowedStream_OutlivesRevocationAfterOpen(t *testing.T) {
	targetAddr := startEchoTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	client := startFakePDP(t, fake)
	wrapped := &decideThenDenyClient{PDPServiceClient: client, first: fake.resp, denyReason: "delegation revoked mid-stream (test)"}
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: wrapped, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	ctx := bearerCtx(context.Background(), testProxyBearerToken)
	stream, err := conn.NewStream(ctx, proxyStreamDesc, "/echo.Echo/Stream", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}

	// Every one of these three messages crosses AFTER the stream's own single
	// authorization decision -- and, per wrapped's own script, after the point
	// at which asking again would deny. None of that matters: handleStream
	// authorizes once, before forward ever runs, and forward has no path back
	// to authorize.
	for _, msg := range []string{"one", "two", "three"} {
		if err := stream.SendMsg(&proxyFrame{payload: []byte(msg)}); err != nil {
			t.Fatalf("SendMsg(%q) error = %v -- want this to keep succeeding after the simulated revocation", msg, err)
		}
		var got proxyFrame
		if err := stream.RecvMsg(&got); err != nil {
			t.Fatalf("RecvMsg() error = %v, want the echoed %q", err, msg)
		}
		if string(got.payload) != msg {
			t.Errorf("RecvMsg() payload = %q, want %q", got.payload, msg)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend() error = %v", err)
	}
	var got proxyFrame
	if err := stream.RecvMsg(&got); !errors.Is(err, io.EOF) {
		t.Errorf("final RecvMsg() error = %v, want io.EOF", err)
	}

	if wrapped.calls != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- an established stream must never be "+
			"re-authorized, not even once, regardless of what a second call would now answer", wrapped.calls)
	}
}

// TestHandleStream_SameMethodDifferentMessageContent_RawInputIdenticalBothCalls
// is P3's own operational consequence: raw_input carries the method -- which
// IS what a resource_field: "method" catalog entry could constrain a
// delegation against -- and nothing else, so two calls to the identical
// method carrying entirely different message content are indistinguishable
// to the PDP. "item 7" and "item 9" are this test's own stand-ins for the
// task brief's own illustration (docs/pep.md, "The proxy surface's limits"):
// both are payload bytes on an ordinary GetItem-shaped call, never parsed,
// never reaching raw_input by any path -- decideRequestFromStream is called
// from authorize, before forward ever reads a message, and takes no
// parameter a message frame could reach it through.
func TestHandleStream_SameMethodDifferentMessageContent_RawInputIdenticalBothCalls(t *testing.T) {
	targetAddr := startEchoTarget(t)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
	pdpClient := startFakePDP(t, fake)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), client: pdpClient, cfg: testProxyServerCfg()}
	conn := startProxyServer(t, srv)

	const method = "/inventory.Inventory/GetItem"
	invoke := func(payload string) *pdpgrpc.DecideRequest {
		ctx := bearerCtx(context.Background(), testProxyBearerToken)
		var resp proxyFrame
		if err := conn.Invoke(ctx, method, &proxyFrame{payload: []byte(payload)}, &resp, grpc.ForceCodec(proxyCodec{})); err != nil {
			t.Fatalf("Invoke(%q) error = %v", payload, err)
		}
		req := fake.lastRequest()
		if req == nil {
			t.Fatal("PDP never received a request")
		}
		return req
	}

	// Two calls to the SAME method, differing only in message content: one
	// requesting item 7, the other item 9 -- the exact distinction the task's
	// own brief names as unavailable to this surface.
	reqItem7 := invoke(`{"item_id":"7"}`)
	reqItem9 := invoke(`{"item_id":"9"}`)

	if reqItem7.GetTool() != method || reqItem9.GetTool() != method {
		t.Fatalf("tool = (%q, %q), want both %q", reqItem7.GetTool(), reqItem9.GetTool(), method)
	}
	if reqItem7.GetRawInput() != reqItem9.GetRawInput() {
		t.Errorf("raw_input differs between item 7's call and item 9's call:\n  item 7: %s\n  item 9: %s\n"+
			"want identical -- message content must never reach raw_input, so two calls to the same method "+
			"carrying different arguments are indistinguishable to the PDP", reqItem7.GetRawInput(), reqItem9.GetRawInput())
	}

	// The other half of the claim: what DOES reach raw_input is real enough to
	// bind a method-level constraint against -- a tenant cataloging
	// resource_field: "method" would extract exactly this value.
	var got proxyRequestMetadata
	if err := json.Unmarshal([]byte(reqItem7.GetRawInput()), &got); err != nil {
		t.Fatalf("raw_input is not well-formed JSON: %v", err)
	}
	if got.Method != method {
		t.Errorf("raw_input method = %q, want %q -- a method-level constraint needs this to be the real, called method", got.Method, method)
	}
}
