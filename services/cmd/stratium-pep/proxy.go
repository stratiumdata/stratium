// proxy.go implements the "proxy" subcommand: a transparent gRPC proxy. An agent points its
// existing gRPC client at this process instead of the real target, speaks the target's own
// protocol completely unchanged, and this process forwards. Every other mode in this binary
// either sits beside the thing it enforces (hook, mcp) or answers a contract another system
// defines (extauthz's Check); this one terminates the agent's own connection and re-originates
// it against cfg.TargetAddr, which is what "transparent" buys over the predecessor system's
// ExecuteActionRequest envelope: that envelope carried target/method/payload as fields of a
// Stratium-specific RPC, which meant rewriting every agent against this project's own API
// before it could be policed at all. Needing no agent change is the entire reason a proxy is
// worth deploying over that shape (plan §SHAPE RULING).
//
// TASK 1 SCOPE. This task builds the forwarding machinery and its configuration only: the
// codec, the handler, the dial to cfg.TargetAddr, and every config field the modes that
// already exist require. It calls the PDP not at all -- authorize (below) is a fixed function
// of nothing, and forward, the machinery that WOULD relay an allowed call, is unreachable from
// any real caller because authorize never allows one. Task 2 adds the real decision; Task 3
// documents this mechanism's limits (per-message authorization, opaque message bodies -- see
// plan §P3/P4); Task 4 proves the whole thing against a real service.
//
// PASSTHROUGH CODEC + UNKNOWN-SERVICE HANDLER. This proxy has no target .proto for anything it
// forwards -- that is the entire point of "transparent" -- so it cannot register a real service
// or unmarshal a real message for ANY method. Two grpc-go primitives together make that
// unnecessary: grpc.UnknownServiceHandler (server.go) routes every method this server has not
// explicitly registered -- which, since this server registers none, means every method -- to
// one StreamHandler; grpc.ForceServerCodec/ForceCodec force a codec that treats a message as
// its own raw wire bytes (proxyCodec/proxyFrame, below) instead of decoding it as a specific
// proto type. Between them, handleStream never needs to know what /package.Service/Method
// means to accept, decide about, or relay it.
//
// The same pair also collapses unary and streaming into ONE code path, which is the answer to
// "handle unary and streaming from the start" the task brief asks for: UnknownServiceHandler's
// own doc comment registers its StreamDesc with ClientStreams AND ServerStreams both true
// ("We need to assume that the users of the streamHandler will want to use both") precisely
// because the server cannot know, from an unregistered method alone, whether the real RPC is
// unary, server-streaming, client-streaming, or bidi -- every shape arrives at handleStream as
// the same grpc.ServerStream, on which "unary" just means "the caller's own stub happened to
// send exactly one message and expect exactly one back," never a distinct code path this file
// branches on. forward (below) opens the corresponding call to the target the identical way,
// via a StreamDesc with both flags set (proxyStreamDesc) -- so ONE relay loop is provably
// correct for every RPC shape, rather than a unary fast path plus a streaming path that could
// individually regress (exactly the risk the brief's "retrofitting streams onto a unary-only
// proxy means reworking both the codec and the handler" warns about paying for later).
//
// LIBRARY VS STDLIB. github.com/mwitkow/grpc-proxy (and its actively maintained fork,
// github.com/siderolabs/grpc-proxy) popularized exactly this UnknownServiceHandler+Codec
// pattern as a reusable package -- investigated and NOT added as a dependency. Both are thin
// wrappers around the same two grpc-go primitives this file calls directly; taking on either as
// a dependency would buy nothing this file cannot already do with grpc-go's own public API,
// while adding a third party's judgment calls (header/trailer timing, cancellation propagation,
// error wrapping) to a component with more room to leak than any surface in this binary yet --
// see NEVER LOG, below. This mirrors mcp.go's own LIBRARY VS STDLIB precedent, which rejected
// an MCP library for the same shape of reason (id fidelity a typed re-encoder cannot promise
// for input it has never seen): a proxy's core relay is exactly the place this codebase chooses
// to hand-roll against the platform's lowest-level supported primitives rather than depend on
// someone else's convenience wrapper around them.
//
// DENY BY DEFAULT. A forwarding skeleton that allows is an open relay from the moment it is
// deployed -- Phase 10's extauthz established the precedent this task follows: its Task 1 Check
// denied every request unconditionally because no code path could produce an honest ALLOW yet
// (extauthz.go's own package doc). authorize (below) is this file's equivalent: it never
// contacts the PDP and never returns true, for any method, including one shaped to look
// obviously harmless -- see authorize's own doc comment for why that includes reflection and
// health-check methods by name, not just by construction. TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted,
// TestHandleStream_StreamingCall_DeniedAndTargetNeverContacted, and
// TestHandleStream_ReflectionAndHealthCheckMethods_StillDenied (proxy_test.go) all assert this
// against the FAKE TARGET's own received-call count, not merely against what the caller
// observed -- a proxy that forwards and then errors has already leaked the request, which
// checking only the caller's own response would miss entirely.
//
// NO SESSION FILE. Unlike hook and mcp, there is no SessionFilePath field on proxyConfig below,
// and unlike extauthz there is no separate credential-carrying field at all in Task 1's own
// config -- the same absence extauthzConfig's own doc comment calls out, for the same reason:
// the token that will authenticate a forwarded call (plan §P2: gRPC metadata's own
// "authorization: Bearer" key) arrives fresh on every call this process accepts, in the request
// itself, never from a file this process's own operator wrote ahead of a session starting. A
// reader who knows hook's session file should read this absence as that same deliberate design
// carried over to a third transport, not an oversight repeated twice.
//
// FAIL CLOSED. Every required value in proxyConfig has no default (loadProxyConfigFromEnv,
// below, names every missing one at once -- see config.go's requiredEnv), and a missing or
// malformed one stops the process before it ever binds a listener, the same standard hook,
// session-start, and extauthz already hold themselves to. handleStream extends the identical
// rule to the one failure mode unique to THIS surface: a method name grpc-go itself could not
// determine at all (MethodFromServerStream returning false) denies rather than guessing, even
// though no real client through a real gRPC transport can produce that shape (MethodFromServerStream's
// own doc comment) -- there is nothing here safe enough to forward on a guess.
//
// NEVER LOG METADATA, MESSAGE BODIES, OR ANYTHING FROM A TOKEN. This surface forwards entire
// request payloads and the gRPC metadata carrying whatever credential authenticates them --
// strictly more than any surface in this binary has handled before it (extauthz.go's own
// package doc makes the identical claim about itself relative to hook and mcp; this file goes
// one step further than extauthz, which terminates HTTP metadata, because forward's job is
// relaying protobuf message BODIES too, which extauthz never touches). authorize's one denial
// reason (below) is a fixed string naming no method, no metadata, and nothing about any
// specific call -- Task 1 has nothing case-specific to say, and building a per-call string here
// would be the first step toward exactly the local classification (D1) this binary exists to
// refuse. forward and its two relay helpers never construct a log line or an error string from
// a proxyFrame's payload or from any metadata.MD value under any circumstance; the one thing
// stderr in this file ever carries is runProxyCmd's own startup configuration, the same
// operator-supplied-not-request-derived line every other mode's runXCmd already writes once.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// proxyFrame carries one gRPC message's raw wire bytes, and nothing else -- never unmarshaled
// into any typed proto message anywhere in this file, which is what lets this proxy forward a
// method it has never heard of (see the package doc's PASSTHROUGH CODEC section). A struct
// rather than a bare []byte because encoding.Codec's Marshal/Unmarshal both operate on `any`,
// and every caller in this file needs a settled, addressable type to hand a pointer to.
type proxyFrame struct {
	payload []byte
}

// proxyCodec is the encoding.Codec handleStream and forward both force -- ForceServerCodec on
// the server side (newProxyGRPCServer), ForceCodec on the client side dialing the target
// (forward) -- so this process never parses a message it relays, only carries its wire bytes
// through. See the package doc's PASSTHROUGH CODEC and LIBRARY VS STDLIB sections for the
// mechanism this implements and why it is hand-rolled rather than imported.
type proxyCodec struct{}

func (proxyCodec) Marshal(v any) ([]byte, error) {
	f, ok := v.(*proxyFrame)
	if !ok {
		return nil, fmt.Errorf("stratium-pep: proxy codec: Marshal got %T, want *proxyFrame", v)
	}
	return f.payload, nil
}

func (proxyCodec) Unmarshal(data []byte, v any) error {
	f, ok := v.(*proxyFrame)
	if !ok {
		return fmt.Errorf("stratium-pep: proxy codec: Unmarshal got %T, want *proxyFrame", v)
	}
	// Copied, not referenced: grpc-go materializes data from a pooled buffer it reclaims once
	// Unmarshal returns, with no promise the backing array stays valid afterward -- the same
	// defensive copy mcp.go's frameSource takes before handing a scanned line to another
	// goroutine, for the identical buffer-reuse reason (see its own doc comment).
	f.payload = append([]byte(nil), data...)
	return nil
}

func (proxyCodec) Name() string { return "proxy" }

// proxyStreamDesc is what forward opens on the target for every call, and what
// grpc.UnknownServiceHandler registers on the server side (server.go's own implementation),
// regardless of what the original caller's stub believes about the method's real cardinality --
// see the package doc's PASSTHROUGH CODEC section for why both true is the one shape that can
// carry any of unary/server-streaming/client-streaming/bidi without truncating either side.
var proxyStreamDesc = &grpc.StreamDesc{
	StreamName:    "proxy",
	ClientStreams: true,
	ServerStreams: true,
}

// proxyConfig is what runProxyCmd needs to serve a transparent proxy: where to listen, where to
// forward (TargetAddr), and the PDP address, agent identity, subject, connect timeout, and
// escalation poll interval/timeout hook and mcp already require. Task 1's handleStream reads
// none of the latter six -- authorize is a fixed function of nothing (see the package doc) --
// loaded and validated now anyway, for the identical reason extauthzConfig loads PDPAddr,
// AgentID, Subject, and ConnectTimeout before its own Task 1 Check ever read them (see that
// file's package doc): the ENV VAR CONTRACT an operator must satisfy should not change shape
// between this task and the one that first reads a given field. ApprovalPollInterval/
// ApprovalTimeout are here, unlike extauthzConfig, because this surface -- like hook and mcp,
// unlike extauthz -- can hold a call open while a human approves (plan §BLOCKING SURFACE);
// extauthz never grew them because it cannot block at all (E5).
//
// There is deliberately no SessionFilePath field -- see the package doc's NO SESSION FILE
// section.
//
// Every field is required, with no default: loadProxyConfigFromEnv reads all eight via
// requiredEnv before checking for any error, the same single-loader shape loadHookConfigFromEnv
// and loadExtauthzConfigFromEnv each already use for their own one group of fields. That
// singularity matters: a recent task (mcp.go's combineConfigErrors) found that composing TWO
// config loaders and letting the first one fail-fast hides the second loader's own gaps from an
// operator who has not yet fixed the first. Composing hookConfig wholesale the way mcp.go
// composes it for its own PDP-facing half was considered and rejected here, specifically
// because hookConfig carries SessionFilePath -- a field this surface must not have and must not
// require an operator to set (see NO SESSION FILE again) -- so this file loads its own single,
// complete group instead of composing someone else's.
type proxyConfig struct {
	ListenAddr string
	TargetAddr string

	PDPAddr        string
	AgentID        string
	Subject        string
	ConnectTimeout time.Duration

	ApprovalPollInterval time.Duration
	ApprovalTimeout      time.Duration
}

// loadProxyConfigFromEnv reads proxyConfig from the environment, or returns an error naming
// every missing variable at once -- see proxyConfig's own doc comment for why this is one
// loader, not two, and config.go's requiredEnv/requiredDuration/missingConfigError for the
// shared presence-checking convention every loader in this package follows.
func loadProxyConfigFromEnv() (proxyConfig, error) {
	var missing []string
	cfg := proxyConfig{
		ListenAddr: requiredEnv("STRATIUM_PEP_PROXY_LISTEN_ADDR", &missing),
		TargetAddr: requiredEnv("STRATIUM_PEP_PROXY_TARGET_ADDR", &missing),
		PDPAddr:    requiredEnv("STRATIUM_PEP_PDP_ADDR", &missing),
		AgentID:    requiredEnv("STRATIUM_PEP_AGENT_ID", &missing),
		Subject:    requiredEnv("STRATIUM_PEP_SUBJECT", &missing),
	}
	timeoutRaw := requiredEnv("STRATIUM_PEP_CONNECT_TIMEOUT", &missing)
	pollRaw := requiredEnv("STRATIUM_PEP_APPROVAL_POLL_INTERVAL", &missing)
	approvalTimeoutRaw := requiredEnv("STRATIUM_PEP_APPROVAL_TIMEOUT", &missing)
	if len(missing) > 0 {
		return proxyConfig{}, missingConfigError(missing)
	}

	timeout, err := requiredDuration("STRATIUM_PEP_CONNECT_TIMEOUT", timeoutRaw)
	if err != nil {
		return proxyConfig{}, err
	}
	cfg.ConnectTimeout = timeout

	pollInterval, err := requiredDuration("STRATIUM_PEP_APPROVAL_POLL_INTERVAL", pollRaw)
	if err != nil {
		return proxyConfig{}, err
	}
	cfg.ApprovalPollInterval = pollInterval

	approvalTimeout, err := requiredDuration("STRATIUM_PEP_APPROVAL_TIMEOUT", approvalTimeoutRaw)
	if err != nil {
		return proxyConfig{}, err
	}
	cfg.ApprovalTimeout = approvalTimeout

	return cfg, nil
}

// proxyServer implements the passthrough handler every accepted connection runs through.
// targetConn is forward's only means of reaching cfg.TargetAddr, dialed once at startup
// (runProxyCmd) the same lazy way every other mode in this binary dials the PDP. There is
// deliberately no cfg or pdpClient field here in Task 1, unlike extauthzServer: authorize
// (below) is a fixed function of nothing, so there is nothing yet for either field to supply --
// Task 2 adds them together with the code that first reads them, rather than carrying them
// unread on this struct in the meantime (contrast proxyConfig's own doc comment, which is a
// claim about the env var CONTRACT, not about this struct's internal layout).
type proxyServer struct {
	targetConn *grpc.ClientConn
}

// newProxyGRPCServer builds the *grpc.Server every entry point into this mode constructs
// identically -- runProxyCmd for the real binary with srv.handleStream, proxy_test.go's
// startProxyServer with the identical handler for tests that exercise the deny gate, and
// proxy_test.go's startForwardOnlyServer with a handler that calls srv.forward directly for the
// one test that exercises relaying -- so "every test server is wired the same way the real one
// is" is a fact this single function enforces for ALL three, not a claim only two of them
// happen to share. handler is a parameter, not always srv.handleStream, specifically because of
// that third caller: an earlier version hardcoded srv.handleStream here, which meant
// ForceServerCodec was verified only by tests that never call RecvMsg (handleStream denies
// first) and never by the one test that does -- a real gap this task's own mutation testing
// found (see this task's report) before this function had a handler parameter to close it.
// ForceServerCodec is what lets any of the three handlers receive a method this server has no
// generated stub for at all.
func newProxyGRPCServer(handler grpc.StreamHandler) *grpc.Server {
	return grpc.NewServer(
		grpc.UnknownServiceHandler(handler),
		grpc.ForceServerCodec(proxyCodec{}),
	)
}

// handleStream is the grpc.UnknownServiceHandler for every method this process ever receives --
// there is no other handler, because a transparent proxy registers no services of its own (see
// the package doc). It is the single call site where authorize's verdict is read and acted on:
// denied without ever touching forward, or -- once Task 2 gives authorize something real to
// decide with -- forwarded. Task 1's authorize never returns true, so forward is unreachable
// from any real caller through this function; proxy_test.go's TestForward_RelaysMessagesBothDirections
// exercises it directly instead, bypassing this gate on purpose (see forward's own doc comment).
func (p *proxyServer) handleStream(_ any, stream grpc.ServerStream) error {
	fullMethod, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		// Not a shape any real client through a real gRPC transport produces
		// (MethodFromServerStream's own doc comment) -- reachable only if something other than
		// grpc-go's own server ever invoked this handler directly. There is nothing here to
		// identify, let alone forward, so this denies exactly like every other path.
		return status.Error(codes.Internal, "stratium-pep: proxy: could not determine the called method")
	}

	if allowed, reason := p.authorize(fullMethod); !allowed {
		return status.Error(codes.PermissionDenied, reason)
	}
	return p.forward(fullMethod, stream)
}

// authorize is Task 1's entire decision surface, and it decides nothing: it calls the PDP not
// at all -- Task 2 wires that in -- and denies every method, unconditionally, the same
// precedent extauthz's own Task 1 Check established for the identical reason (see the package
// doc's DENY BY DEFAULT section). method is accepted, not merely ignored by convention, so
// Task 2 can grow this function's body into a real Decide call without changing handleStream's
// own call site or the tests anchored to it.
//
// There is no allowlist, no exemption for a method that looks like introspection (grpc.health.v1.Health,
// grpc.reflection.v1alpha.ServerReflection) or anything else "obviously harmless" -- method is
// read only to pass through unread, never compared against any name. Special-casing a method by
// name would BE spec defect D1: this process classifying a call's meaning locally instead of
// leaving that entirely to the PDP, the same defect hook.go's and mcp.go's own package docs
// describe for their surfaces. TestHandleStream_ReflectionAndHealthCheckMethods_StillDenied
// (proxy_test.go) is the test the task's own binding constraint asks for by name.
//
// The reason string is fixed, not built from method or anything else about the call: Task 1 has
// nothing case-specific to say -- every call is denied for the identical reason, there is no
// decision logic yet -- and interpolating method into it here would be the first per-call
// string this file constructs from request-derived data, which the package doc's NEVER LOG
// section exists specifically to keep at zero.
func (p *proxyServer) authorize(method string) (allowed bool, reason string) {
	return false, "stratium-pep: proxy authorizes nothing yet; every call is denied by default"
}

// forward relays fullMethod between serverStream (the caller handleStream accepted) and
// p.targetConn (cfg.TargetAddr) until both directions have ended, copying each message's raw
// wire bytes without ever decoding them -- see the package doc's PASSTHROUGH CODEC section. One
// function is correct for a unary call and a streaming call alike because nothing upstream of
// it preserves that distinction for it to branch on: "unary" here just means "exactly one
// message crossed before the caller's own stub stopped sending," never a separate code path.
//
// Task 1 builds this and never calls it through the real dispatch: handleStream's authorize
// gate denies every method first, so no test dialed against srv.handleStream ever reaches this
// function. proxy_test.go's TestForward_RelaysMessagesBothDirections calls it directly instead,
// via newProxyGRPCServer with a handler that invokes forward straight away (startForwardOnlyServer),
// bypassing handleStream's gate on purpose while still sharing the SAME codec-registering
// construction srv.handleStream's own callers use -- see newProxyGRPCServer's own doc comment
// for why that sharing matters. This proves the relay mechanics are sound ahead of Task 2
// putting a real gate in front of them and Task 4 proving the whole thing against a real
// service.
//
// Adapted from the pattern github.com/mwitkow/grpc-proxy popularized (see the package doc's
// LIBRARY VS STDLIB section) rather than copied from it: two goroutines, one per direction,
// racing a select that decides how the call ends. A caller reaching a clean end (io.EOF) only
// half-closes the send side to the target and lets a reply already in flight keep going -- the
// same asymmetry mcp.go's runMCP applies for the identical reason (see its own doc comment): a
// response the target already started sending must still be delivered, not dropped because the
// caller stopped sending first. The target ending -- cleanly (io.EOF) or with any other error --
// ends the call outright: its trailer becomes the caller's own trailer, and its status becomes
// this function's return, which is what makes a target's real DENY, error, or success reach the
// caller as itself rather than as a generic proxy failure.
func (p *proxyServer) forward(fullMethod string, serverStream grpc.ServerStream) error {
	ctx, cancel := context.WithCancel(serverStream.Context())
	defer cancel()

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		ctx = metadata.NewOutgoingContext(ctx, md.Copy())
	}

	targetStream, err := grpc.NewClientStream(ctx, proxyStreamDesc, p.targetConn, fullMethod, grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		return status.Errorf(codes.Unavailable, "stratium-pep: proxy: could not open target stream: %s", err)
	}

	// Two directions, two goroutines, neither waiting on the other for an individual message --
	// the same reason mcp.go's runMCP runs agent->upstream and upstream->agent independently
	// (see its own CONCURRENCY note): a target slow to reply must not stall the caller's own
	// sends, and a caller slow to send must not stall a reply already in flight.
	callerToTarget := make(chan error, 1)
	go func() { callerToTarget <- relayCallerToTarget(serverStream, targetStream) }()

	targetToCaller := make(chan error, 1)
	go func() { targetToCaller <- relayTargetToCaller(serverStream, targetStream) }()

	for i := 0; i < 2; i++ {
		select {
		case err := <-callerToTarget:
			if err == nil || errors.Is(err, io.EOF) {
				_ = targetStream.CloseSend()
				continue // not a break: see below -- this must reach the next loop iteration, not merely exit the select (which, being the loop body's last statement, would do the same thing here, but continue says so without relying on that coincidence)
			}
			cancel() // unblocks a relayTargetToCaller goroutine still waiting on a target that will now never reply
			return status.Errorf(codes.Internal, "stratium-pep: proxy: forwarding caller to target: %s", err)
		case err := <-targetToCaller:
			cancel() // unblocks a relayCallerToTarget goroutine still waiting on a caller the target no longer cares about
			serverStream.SetTrailer(targetStream.Trailer())
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
	// Unreachable: the loop above always returns or continues, and a second continue on i==1
	// falls out of the loop into this line rather than looping a third time -- present only so
	// this function has an explicit, honest return for a path the compiler cannot prove dead on
	// its own, the same defensive-but-inert shape hook.go's writeDeny takes for a Marshal that
	// cannot fail in practice.
	return status.Error(codes.Internal, "stratium-pep: proxy: forward reached an unreachable state")
}

// relayCallerToTarget copies every message the caller sends to the target, until the caller's
// own stream ends. Returns io.EOF for a clean end (the caller half-closed, exactly as
// grpc.ServerStream.RecvMsg's own doc comment promises) or whatever other error ended it early;
// forward's own select treats the two differently (see its doc comment).
func relayCallerToTarget(serverStream grpc.ServerStream, targetStream grpc.ClientStream) error {
	for {
		var f proxyFrame
		if err := serverStream.RecvMsg(&f); err != nil {
			return err
		}
		if err := targetStream.SendMsg(&f); err != nil {
			return err
		}
	}
}

// relayTargetToCaller copies every message the target sends back to the caller, forwarding the
// target's own response headers ahead of the first one -- gRPC requires headers before the
// first message on a stream, and a target's headers are only readable (Header() blocks until
// they arrive) once it has sent something, so the first successful RecvMsg here is the one
// point this can happen in the right order. A target that errors or completes before sending
// anything never has headers explicitly forwarded this way; grpc-go's own ServerStream.SetHeader
// doc comment covers what happens instead (metadata set but never explicitly sent still goes
// out when the RPC's own status does) -- a known limitation of this relay shape, not a bug, and
// Task 3's job to document alongside the mechanism's others (plan §P3/P4).
//
// Returns io.EOF for a clean end (the target's own RPC completed) or the error that ended it
// early; forward's own select reads targetStream.Trailer() only after this returns, per
// grpc.ClientStream.Trailer's own doc comment (valid only once RecvMsg has returned non-nil).
func relayTargetToCaller(serverStream grpc.ServerStream, targetStream grpc.ClientStream) error {
	headerSent := false
	for {
		var f proxyFrame
		if err := targetStream.RecvMsg(&f); err != nil {
			return err
		}
		if !headerSent {
			md, err := targetStream.Header()
			if err != nil {
				return err
			}
			if err := serverStream.SendHeader(md); err != nil {
				return err
			}
			headerSent = true
		}
		if err := serverStream.SendMsg(&f); err != nil {
			return err
		}
	}
}

// runProxyCmd loads configuration, dials the target (lazily -- see below), binds
// cfg.ListenAddr, and serves every method via handleStream until Serve itself returns. Mirrors
// runExtauthzCmd's own shape (extauthz.go): both are long-running servers that do not return
// under normal operation, and neither wires signal handling or graceful shutdown, for the
// identical reason extauthz's own doc comment gives -- an unhandled SIGTERM killing this
// process outright is a transport fault any caller already has to tolerate, and this binary's
// job is making that fault deny, not making the process unkillable.
//
// cfg.PDPAddr/AgentID/Subject/ConnectTimeout/ApprovalPollInterval/ApprovalTimeout are loaded and
// logged here like every other required value, even though Task 1's handleStream reads none of
// them (see proxyConfig's own doc comment) -- a missing or malformed value among them must still
// fail startup, not surface as a confusing per-call denial only once Task 2 starts reading them.
// This function does not dial the PDP itself, unlike hook/mcp/extauthz's runXCmd: nothing in
// Task 1 would ever use that connection, and opening one solely to validate that cfg.PDPAddr
// parses would be a startup step with no caller -- Task 2 adds the dial together with the first
// code that actually needs it.
func runProxyCmd(stderr io.Writer) int {
	cfg, err := loadProxyConfigFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	// grpc.NewClient dials lazily -- the same non-blocking choice every other mode's PDP dial
	// makes (runHookCmd, runMCPCmd, runExtauthzCmd) -- so this succeeding proves only that
	// cfg.TargetAddr parses as a target, not that anything is listening there yet. An
	// unreachable target is a forward-time failure (Task 2 onward, when forward first becomes
	// reachable), not a startup one.
	targetConn, err := grpc.NewClient(cfg.TargetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create target client: %s\n", err)
		return 1
	}
	defer func() { _ = targetConn.Close() }()

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not listen on %s: %s\n", cfg.ListenAddr, err)
		return 1
	}

	srv := &proxyServer{targetConn: targetConn}
	grpcServer := newProxyGRPCServer(srv.handleStream)

	// This process's own startup configuration, not request data -- see the package doc's NEVER
	// LOG section, which this line does not touch. Logged once, the same way runExtauthzCmd logs
	// its own cfg.
	_, _ = fmt.Fprintf(stderr, "stratium-pep: proxy listening on %s (target %s, PDP %s, agent %s, subject %s, connect timeout %s, approval poll %s, approval timeout %s)\n",
		cfg.ListenAddr, cfg.TargetAddr, cfg.PDPAddr, cfg.AgentID, cfg.Subject, cfg.ConnectTimeout, cfg.ApprovalPollInterval, cfg.ApprovalTimeout)

	if err := grpcServer.Serve(lis); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: proxy server: %s\n", err)
		return 1
	}
	return 0
}
