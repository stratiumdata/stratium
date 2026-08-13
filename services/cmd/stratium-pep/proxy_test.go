package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
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
