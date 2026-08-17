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
// TASK 2: THE REAL DECISION. Task 1 built the forwarding machinery with nothing to decide with;
// authorize (below) now builds a DecideRequest from the call it was actually asked to make a
// decision about -- tool is the full method (P1, catalogable per-tenant exactly like write_file
// and extauthz's path), token comes from gRPC metadata's own "authorization: Bearer" key (P2),
// and raw_input is that same metadata, JSON-encoded, with every credential header already
// stripped (P3) -- calls the PDP, and either allows (forward runs, no longer unreachable),
// blocks on EFFECT_ESCALATE (proxy IS a blocking surface, spec §4.6, unlike extauthz -- see the
// ESCALATE BLOCKS section below), or denies. Task 3 documents this mechanism's remaining limits
// (per-message authorization, opaque message bodies -- plan §P3/P4, consequences A and B); Task
// 4 proves the whole thing against a real service.
//
// ESCALATE BLOCKS. Unlike extauthz.go's Check, which cannot hold a call open (Envoy's ext_authz
// budget is milliseconds, not minutes -- pdpgrpc.DegradeEscalateToDeny) and so degrades
// EFFECT_ESCALATE straight to a denial, this surface holds the caller's own stream open exactly
// like hook and mcp already do, by calling escalation.go's resolveApproval -- the same
// transport-free wait mcp_authorize.go's decideAndRelay already reuses unmodified for its own
// blocking surface, not a second poll loop written for a third time. See escalation.go's own
// package doc for what reusing it here required changing in that file, and why.
//
// NO REISSUE ON DENY. hook.go's runHook and mcp_authorize.go's decideAndRelay each attempt
// exactly one reissueAndRetryDecide on a first EFFECT_DENY, because a session file
// (session_file.go) gives them a real delegation id to mint a fresh token against if the denial
// was actually an expired token rather than a policy refusal. This surface has no session file
// (see NO SESSION FILE, below) and therefore no delegation id anywhere it could reissue against
// -- spec K4 removed the bare delegation id specifically so there is no fallback identity left on
// this wire at all. A caller-supplied bearer token the PDP denies is the caller's own problem to
// refresh, not something this process can paper over by minting a replacement on its behalf.
// extauthz.go's Check makes the identical call for the identical reason (it has no session file
// either); this is not a proxy-specific policy, it is what "no session file" already implies
// everywhere it applies.
//
// TASK 3: THE LIMITS. Three properties of this mechanism are permanent, not gaps a later task
// closes -- each is written down for the operator who never reads this file (docs/pep.md, "The
// proxy surface's limits") and pinned here by a test for the one who does, per this task's own
// binding constraint: a limit that is documented but untested is one that can quietly stop being
// true (this project has paid for that once already, at spec §4.4.1 -- see that section's own
// "third instance in this project" note).
//
// P4, once, at open. authorize (above) runs exactly once per stream, before forward ever reads a
// message, and forward has no path back to authorize -- there is no hook in its relay loop where a
// second decision could even be inserted without first parsing a protocol this file deliberately
// never parses. A delegation revoked, or a policy changed, after that one call does not end a
// stream already forwarding. TestHandleStream_AllowedStream_OutlivesRevocationAfterOpen
// (proxy_test.go) proves it against a client scripted to ALLOW the stream's own opening call and
// DENY every call after -- messages keep crossing and the PDP is asked exactly once, never asked
// again to find out its answer has changed.
//
// P3, no message body, ever. decideRequestFromStream (below) takes ctx and method and nothing
// else -- no parameter a message frame could reach it through -- which is what makes "authorization
// cannot see message contents" true by construction, not merely by convention: raw_input is
// already built, and already sent, before forward reads the first byte of the first message.
// TestHandleStream_SameMethodDifferentMessageContent_RawInputIdenticalBothCalls (proxy_test.go)
// sends two calls to one method carrying different payloads and shows the PDP receives
// byte-identical requests for both. That cuts both ways: TestAuthorize_RawInputCarriesMethod
// (Task 2, above) already shows the method itself DOES reach raw_input, real enough to catalog a
// resource_field against -- it is only what is inside a message that this surface cannot see.
//
// Feeding the message body into raw_input anyway, to give the evidence rule (spec §4.4.1)
// something to scan, was proposed and rejected during planning (plan §P3, "DO NOT feed opaque
// protobuf into raw_input"): opaque bytes matching a shell pattern by coincidence would produce a
// false denial with a reason no operator could explain, against an audit digest that commits to
// raw_input and would then be hashing bytes nobody could usefully re-derive the meaning of. Not
// re-litigated here or in docs/pep.md's own copy of this ruling -- read either before reopening it.
//
// No command text, no evidence. destructiveEvidence (internal/authz/tier.go) matches raw input
// against shell/SQL syntax; a method name and ordinary gRPC metadata are neither, so an uncataloged
// method here is never raised by anything about the call -- it takes BuiltinTier's own
// unrecognized-input default, the identical fallback an uncataloged third-party tool already gets
// on mcp (docs/pep.md, "Seeding the tool catalog"). This is PDP-side behavior this file has no
// access to and must not reimplement -- internal/authz stays pure, and this binary classifies
// nothing (package doc, above). It is pinned end to end, through the real Decide path with
// proxy-shaped input, by TestDecide_ProxyShapedRawInput_UncatalogedMethodTakesClassifierDefault
// (internal/pdpgrpc/server_test.go) -- necessarily there, not here: there is nothing in this
// package that computes a tier for this test to call.
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
// DENY BY DEFAULT, STILL. A forwarding skeleton that allows is an open relay from the moment it
// is deployed -- Phase 10's extauthz established the precedent this task follows: its Task 1
// Check denied every request unconditionally because no code path could produce an honest ALLOW
// yet (extauthz.go's own package doc). Task 1's authorize (below) was that file's own equivalent:
// a fixed function of nothing. Task 2 gives it a real PDP call, but the deny-by-default DISCIPLINE
// does not loosen -- it grows more failure modes to hold the line on, not fewer: authorize still
// classifies no method by name (no allowlist, no exemption for reflection or health-check methods
// -- TestHandleStream_ReflectionAndHealthCheckMethods_StillDenied, proxy_test.go, is the test the
// task's own binding constraint asks for by name, and it still passes unmodified, because
// authorize never compared method against anything before and does not start now), and it fails
// closed on every one of: no token, a malformed token, an unreachable PDP, a PDP application
// error, a genuine EFFECT_DENY, and an escalation that times out -- every one of those denies AND
// forwards nothing, asserted, per TestHandleStream_UnaryCall_DeniedAndTargetNeverContacted's own
// precedent, against the FAKE TARGET's own received-call count wherever a test below can reach
// one, not merely against what the caller observed: a proxy that forwards and then errors has
// already leaked the request, which checking only the caller's own response would miss entirely.
//
// NO TOKEN, NO PDP CALL (P2, spec K4). A missing or malformed "authorization: Bearer" metadata
// value denies WITHOUT ever calling Decide -- there is no fallback credential on this wire to ask
// the PDP about instead (K4 removed the bare delegation id precisely so none exists), so a round
// trip could not answer anything the missing credential does not already answer.
// TestHandleStream_MissingToken_DeniesWithoutContactingPDP (over the real wire) and
// TestAuthorize_MissingToken_DeniesWithoutContactingPDP/TestAuthorize_MalformedToken_DeniesWithoutContactingPDP
// (direct, table-driven) all assert this against the PDP's own received-call count, mirroring
// extauthz.go's identical M2/K4 tests for the analogous HTTP header.
//
// NO SESSION FILE. Unlike hook and mcp, there is no SessionFilePath field on proxyConfig below,
// and unlike extauthz there is no separate credential-carrying field at all in this surface's own
// config -- the same absence extauthzConfig's own doc comment calls out, for the same reason:
// the token that authenticates a forwarded call (plan §P2: gRPC metadata's own
// "authorization: Bearer" key) arrives fresh on every call this process accepts, in the request
// itself, never from a file this process's own operator wrote ahead of a session starting. A
// reader who knows hook's session file should read this absence as that same deliberate design
// carried over to a third transport, not an oversight repeated twice. It is also why authorize
// never attempts reissueAndRetryDecide on a DENY the way hook and mcp do -- see the package doc's
// NO REISSUE ON DENY section above.
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
// relaying protobuf message BODIES too, which extauthz never touches). authorize's denial
// reasons ARE per-call as of this task (the PDP's own resp.GetReason() on a genuine DENY, or
// describeRPCError's fixed vocabulary on a transport failure -- both the identical text hook.go
// and extauthz.go already return their own callers, never text this file invents from a token or
// a metadata value) -- but every one of them is returned to THIS CALL's own caller, inside the
// codes.PermissionDenied status handleStream constructs, never written to stderr or any other log
// this process keeps. decideRequestFromStream builds DecideRequest.RawInput once, from the
// caller's own metadata with every credential header already stripped by omission (see
// extractBearerTokenFromMetadata, below), and hands it to exactly one place -- the PDP, over the
// same gRPC connection Decide already uses -- never to an error string, a log line, or anything
// this process's own stderr ever sees. forward and its two relay helpers still never construct a
// log line or an error string from a proxyFrame's payload or from any metadata.MD value under any
// circumstance; the one thing stderr in this file ever carries is runProxyCmd's own startup
// configuration, the same operator-supplied-not-request-derived line every other mode's runXCmd
// already writes once.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"stratium/internal/pdpgrpc"
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
// escalation poll interval/timeout hook and mcp already require. Task 1 loaded and validated all
// eight before authorize (a fixed function of nothing, then) read any of the latter six, for the
// identical reason extauthzConfig loads PDPAddr, AgentID, Subject, and ConnectTimeout before its
// own Task 1 Check ever read them (see that file's package doc): the ENV VAR CONTRACT an operator
// must satisfy should not change shape between this task and the one that first reads a given
// field. As of this task authorize reads every one of them: PDPAddr is where runProxyCmd now
// dials the PDP client authorize calls, AgentID/Subject become DecideRequest.AgentId/Subject on
// every request decideRequestFromStream builds, ConnectTimeout bounds that call, and
// ApprovalPollInterval/ApprovalTimeout bound resolveApproval's wait (escalation.go) -- here,
// unlike extauthzConfig, because this surface -- like hook and mcp, unlike extauthz -- can hold a
// call open while a human approves (plan §BLOCKING SURFACE, spec §4.6); extauthz never grew them
// because it cannot block at all (E5).
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
// (runProxyCmd) the same lazy way every other mode in this binary dials the PDP. client and cfg
// are this task's own addition -- Task 1 carried neither, since authorize was a fixed function of
// nothing with nothing for either to supply; they arrive now together with the code that first
// reads them, mirroring extauthzServer's identical client/cfg pair one file over (its own doc
// comment explains the same three pieces of configuration -- AgentID, Subject, ConnectTimeout --
// this struct's cfg also supplies to every Decide call authorize makes).
type proxyServer struct {
	targetConn *grpc.ClientConn

	client pdpgrpc.PDPServiceClient
	cfg    proxyConfig
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
// denied without ever touching forward, or -- as of this task, when authorize has something real
// to decide with -- forwarded. stream.Context() is threaded into authorize (not just fullMethod,
// as Task 1 left it) because that context is the only place the caller's own gRPC metadata --
// P2's "authorization: Bearer" token among it -- is reachable; see decideRequestFromStream for
// where it is actually read.
func (p *proxyServer) handleStream(_ any, stream grpc.ServerStream) error {
	fullMethod, ok := grpc.MethodFromServerStream(stream)
	if !ok {
		// Not a shape any real client through a real gRPC transport produces
		// (MethodFromServerStream's own doc comment) -- reachable only if something other than
		// grpc-go's own server ever invoked this handler directly. There is nothing here to
		// identify, let alone forward, so this denies exactly like every other path.
		return status.Error(codes.Internal, "stratium-pep: proxy: could not determine the called method")
	}

	if allowed, reason := p.authorize(stream.Context(), fullMethod); !allowed {
		return status.Error(codes.PermissionDenied, reason)
	}
	return p.forward(fullMethod, stream)
}

// authorize is this task's entire decision surface: it maps ctx and method to a DecideRequest
// (decideRequestFromStream, P1-P3), calls the PDP, and resolves to a final allow/deny -- blocking
// on EFFECT_ESCALATE via resolveApproval (escalation.go) rather than degrading it the way
// extauthz.go's non-blocking checkResponseFromDecide must (see the package doc's ESCALATE BLOCKS
// section). The signature is still (bool, string): handleStream's own call site needed only ctx
// threaded through, not a rework, because method was already accepted here in Task 1 for exactly
// this reason (that function's own prior doc comment said so).
//
// There is still no allowlist, no exemption for a method that looks like introspection
// (grpc.health.v1.Health, grpc.reflection.v1alpha.ServerReflection) or anything else "obviously
// harmless" -- method is read only to build the request, never compared against any name.
// Special-casing a method by name would BE spec defect D1: this process classifying a call's
// meaning locally instead of leaving that entirely to the PDP, the same defect hook.go's and
// mcp.go's own package docs describe for their surfaces.
// TestHandleStream_ReflectionAndHealthCheckMethods_StillDenied (proxy_test.go, unmodified since
// Task 1) is the test the task's own binding constraint asks for by name -- it still passes
// because a health/reflection-shaped method still carries no token in these tests, and denies on
// that alone before authorize ever reaches a branch that could special-case a method name even if
// one existed to reach.
//
// No reissueAndRetryDecide on EFFECT_DENY -- see the package doc's NO REISSUE ON DENY section for
// why this surface has no delegation id to reissue against at all, unlike hook.go and
// mcp_authorize.go.
func (p *proxyServer) authorize(ctx context.Context, method string) (allowed bool, reason string) {
	req, err := decideRequestFromStream(ctx, method, p.cfg.AgentID, p.cfg.Subject)
	if err != nil {
		return false, fmt.Sprintf("stratium-pep: %s", err)
	}

	// Derived from ctx, not context.Background() -- the same reason extauthz.go's Check chains
	// its own Decide call from the incoming Check ctx instead of discarding it (see that
	// function's own doc comment): handleStream IS a gRPC handler with a real caller-supplied
	// ctx already carrying the caller's own deadline/cancellation, and a caller that hangs up on
	// this call should cancel the outbound Decide call too, rather than leaving it running for a
	// response nothing is still waiting for.
	decideCtx, cancel := context.WithTimeout(ctx, p.cfg.ConnectTimeout)
	defer cancel()

	resp, err := p.client.Decide(decideCtx, req)
	if err != nil {
		return false, fmt.Sprintf("stratium-pep: %s", describeRPCError(err, agentOrDelegationUnknownMsg))
	}

	switch resp.GetEffect() {
	case pdpgrpc.Effect_EFFECT_ALLOW:
		return true, ""
	case pdpgrpc.Effect_EFFECT_ESCALATE:
		// resolveApproval (escalation.go) owns everything from here: it polls GetApproval and
		// either retries Decide with the resolved approval id or reports why not, bounding the
		// wait at p.cfg.ApprovalTimeout AT THE LATEST -- the same bound hook.go's and
		// mcp_authorize.go's identical calls rest on -- but, unlike either of those two callers,
		// also ending early if ctx itself ends first: this handler's ctx is a real caller-supplied
		// one (stream.Context(), ultimately), so a caller that disconnects while this call is
		// still escalating stops the poll promptly instead of holding a goroutine and spending
		// GetApproval calls against a stream nothing is listening to anymore (see resolveApproval's
		// own doc comment for why passing ctx here is safe and why hook.go/mcp_authorize.go pass
		// context.Background() instead, not this same ctx variable). A timed-out or denied
		// approval both fall out of resolveApproval's own reason text; this function adds nothing
		// case-specific on top of it.
		effect, escReason := resolveApproval(ctx, p.client, p.cfg.ConnectTimeout, p.cfg.ApprovalPollInterval, p.cfg.ApprovalTimeout, req, resp)
		if effect == pdpgrpc.Effect_EFFECT_ALLOW {
			return true, ""
		}
		return false, escReason
	default:
		// EFFECT_DENY, and any value this build does not recognize (the proto documents
		// EFFECT_DENY as the zero value for exactly this case -- see hook.go's identical default
		// case). Passed through unprefixed: the PDP's own verdict text, not a local diagnostic
		// this process is synthesizing -- the same convention hook.go's and extauthz.go's own
		// default DENY cases follow, so a human reading a denial can tell at a glance whether the
		// PDP refused the call or this process failed before ever asking it one.
		return false, resp.GetReason()
	}
}

// proxyRequestMetadata is raw_input's JSON shape (plan §P3): the called method and the caller's
// own gRPC metadata, with every credential-bearing entry already removed by
// extractBearerTokenFromMetadata -- see that function's own doc comment for which and why. The
// proxy's own counterpart to extauthz.go's requestMetadata (Method + Headers; extauthz also
// carries a Path, which gRPC has no separate concept of -- the full method string already IS
// both). Headers is map[string][]string, not extauthz's map[string]string, because gRPC metadata
// is natively multi-valued (a header may legitimately repeat) and this process has no basis for
// collapsing that before it is hashed into an audit record it was never asked to lose information
// for. Method is carried here redundantly with DecideRequest.Tool for the identical reason
// extauthz's requestMetadata carries its own Method/Path redundantly with DecideRequest.Tool:
// raw_input is self-contained evidence for the audit chain it ends up hashed into, not a value a
// reader must cross-reference a sibling field to make sense of. The json tags exist so this shape
// round-trips predictably for a test (or an auditor's own tooling reading the audit chain) --
// nothing in this binary ever decodes raw_input again after decideRequestFromStream builds it;
// the PDP receives it, and reads it, as opaque bytes, exactly like hook.go's tool_input and
// mcp_authorize.go's arguments.
type proxyRequestMetadata struct {
	Method  string              `json:"method"`
	Headers map[string][]string `json:"headers"`
}

// decideRequestFromStream maps ctx's incoming gRPC metadata and method to the DecideRequest
// authorize sends the PDP, or an error naming why no such request can be built at all -- this
// surface's own counterpart to extauthz.go's decideRequestFromCheck, built from a stream's
// context instead of an *authv3.CheckRequest because a proxied call's credential arrives in gRPC
// metadata (P2), not an HTTP header Envoy has already parsed into a CheckRequest for that
// process.
//
// The only failure mode is extractBearerTokenFromMetadata's own: no authorization metadata, or
// one that is not a well-formed Bearer challenge (P2, spec K4 -- there is no fallback credential
// this function could use instead). Every other field is unconditional: method is read only to
// pass through, never inspected for meaning (see authorize's own doc comment on D1), and
// agentID/subject are this process's own configured identity, never derived from the call.
//
// declared_tier and resource are never set on the returned request, the same omission hook.go,
// mcp_authorize.go, and extauthz.go all make for the identical reason: this process has no real
// tier or resource to declare, and both are re-derived server-side from tool/raw_input against
// the tenant's own catalog regardless of what a caller claims -- see any of those three files'
// own package docs. TestAuthorize_NeverSendsDeclaredTier asserts this on the wire, mirroring the
// other three surfaces' identical tests.
func decideRequestFromStream(ctx context.Context, method, agentID, subject string) (*pdpgrpc.DecideRequest, error) {
	md, _ := metadata.FromIncomingContext(ctx)

	token, stripped, err := extractBearerTokenFromMetadata(md)
	if err != nil {
		return nil, err
	}

	rawInput, err := json.Marshal(proxyRequestMetadata{Method: method, Headers: stripped})
	if err != nil {
		// method is a plain string and stripped is a flat map[string][]string with no cycles --
		// Marshal cannot fail for this shape in practice. Reported rather than assumed away, the
		// same caution decideRequestFromCheck's own identical Marshal call takes (extauthz.go).
		return nil, fmt.Errorf("could not serialize request metadata: %w", err)
	}

	return &pdpgrpc.DecideRequest{
		AgentId:  agentID,
		Subject:  subject,
		Tool:     method, // P1: the full method IS the tool identity.
		RawInput: string(rawInput),
		Token:    token,
	}, nil
}

// extractBearerTokenFromMetadata is extauthz.go's extractCredentials adapted to gRPC's own
// metadata.MD shape (map[string][]string, since a header may repeat) instead of Envoy's flat
// map[string]string -- the same single-pass extract-and-strip loop, the same case-insensitive
// match against credentialHeaderNames (extauthz.go), reused directly rather than re-declared:
// Phase 10 Task 2 already settled which headers count as a credential and why (see that var's own
// doc comment), and this file adds no fourth header to that list for a fourth surface.
//
// md's keys are matched via strings.ToLower, never a direct map lookup on the key as received,
// for the same reason extractCredentials's own doc comment gives for doing the identical thing to
// Envoy's headers: a client or an intermediary between it and this process gets one chance to
// send a metadata key this function must still recognize regardless of how it capitalized the
// name. google.golang.org/grpc/metadata's own FromIncomingContext (called by
// decideRequestFromStream, above, before this function ever sees md) already lower-cases every
// key on ITS way out -- verified directly against this module's own vendored source, not merely
// documented -- which is exactly why relying on it here would look correct in every test that
// only ever calls this function through that path. This function is called directly, with a
// hand-built, deliberately NOT lower-cased metadata.MD, by
// TestExtractBearerTokenFromMetadata_HeaderNameCaseDiffers_TokenStillFound and
// TestExtractBearerTokenFromMetadata_StripsCredentialHeadersCaseInsensitively specifically
// because routing those cases through a real incoming context would launder them through
// FromIncomingContext's own normalization before this function ever ran, silently proving nothing
// about THIS function's own defensiveness -- exercising it directly is the only way to prove it
// does not merely inherit a guarantee a caller three lines up already happens to provide.
//
// An error means there is no credential here worth sending to the PDP at all: no authorization
// metadata, one that is not a Bearer challenge, or one whose token is empty once the scheme is
// removed. token and stripped are both zero values in every error case -- there is no partial
// result a careless caller could mistake for a usable one.
func extractBearerTokenFromMetadata(md metadata.MD) (token string, stripped map[string][]string, err error) {
	stripped = make(map[string][]string, len(md))
	var authValue string
	found := false
	for name, values := range md {
		lower := strings.ToLower(name)
		if credentialHeaderNames[lower] {
			if lower == "authorization" && len(values) > 0 {
				// RFC 7235 defines exactly one credential per Authorization header; a second,
				// repeated value is non-conformant, not a shape this function has grounds to
				// prefer the LAST of over the first. The first is also what every other value in
				// values, credential or not, would have contributed FIRST on the wire, so taking
				// it here is consistent with how a normal single-valued header is read.
				authValue, found = values[0], true
			}
			continue
		}
		stripped[name] = values
	}

	if !found {
		return "", nil, errors.New("no authorization metadata")
	}
	if !strings.HasPrefix(authValue, bearerPrefix) {
		return "", nil, errors.New("authorization metadata is not a Bearer token")
	}
	token = strings.TrimPrefix(authValue, bearerPrefix)
	if token == "" {
		return "", nil, errors.New("authorization metadata carries an empty Bearer token")
	}
	return token, stripped, nil
}

// forward relays fullMethod between serverStream (the caller handleStream accepted) and
// p.targetConn (cfg.TargetAddr) until both directions have ended, copying each message's raw
// wire bytes without ever decoding them -- see the package doc's PASSTHROUGH CODEC section. One
// function is correct for a unary call and a streaming call alike because nothing upstream of
// it preserves that distinction for it to branch on: "unary" here just means "exactly one
// message crossed before the caller's own stub stopped sending," never a separate code path.
//
// Reachable through the real dispatch as of this task, on ALLOW (direct or escalated) --
// handleStream's authorize gate no longer denies every method. proxy_test.go still also exercises
// this function directly, via newProxyGRPCServer with a handler that invokes forward straight
// away (startForwardOnlyServer), bypassing handleStream's gate on purpose while still sharing the
// SAME codec-registering construction srv.handleStream's own callers use -- see
// newProxyGRPCServer's own doc comment for why that sharing matters. That bypass remains useful
// even now that the gate can open: it isolates the relay mechanics (headers, trailers, a target's
// own error status) from PDP wiring entirely, which is what TestForward_RelaysResponseHeaders,
// TestForward_RelaysTrailers, and TestForward_RelaysHeadersEvenWhenTargetErrorsBeforeAnyMessage
// (which also checks the target's own error status/message, alongside the header fix it exists
// for) all use it for -- proving forward "relays the response back faithfully" (this task's own
// brief) as a property of forward alone, before TestHandleStream_Allow_ReachesTargetAndResponseReturns
// and TestHandleStream_AllowedStream_ForwardsBothDirections prove the gate actually reaches it.
// Task 4 still proves the whole thing against a real service.
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

// relayTargetToCaller forwards the target's own response headers, then copies every message the
// target sends back to the caller, until the target's stream ends.
//
// Header() is called exactly once, UNCONDITIONALLY, before the relay loop below ever runs -- not
// lazily on a first successful RecvMsg, which is what Task 1 shipped and which this task's own
// mutation testing (see this task's report) proved drops a target's response headers outright for
// a target that errors, or completes, before ever sending a single message: headerSent stayed
// false forever on that path, so serverStream.SendHeader(md) was simply never reached, and
// grpc-go's own fallback (bundling whatever was set via SetHeader, if anything, with the final
// trailer) still only covers metadata SET on serverStream, never metadata the TARGET sent that
// this file never read in the first place. Calling Header() first instead works for every
// cardinality this relay claims to handle, per its own documented contract
// (grpc.ClientStream.Header's doc comment): "It blocks if the metadata is not ready to read. If
// the metadata is nil and the error is also nil, then the stream was terminated without headers,
// and the status can be discovered by calling RecvMsg" -- so this call resolves correctly whether
// the target goes on to send many messages, one, or none, and a nil md with a nil err (the
// "terminated without headers" case) is handled by simply skipping SendHeader and falling through
// to RecvMsg below, which is where the real terminal error actually surfaces (Header's own
// implementation deliberately swallows a transport error it hit internally rather than returning
// it, per that same doc comment -- "the user should get it by calling Recv()").
//
// Safe to call before the loop despite blocking, because this function already runs on ITS OWN
// goroutine (forward's own CONCURRENCY note, above): relayCallerToTarget's goroutine keeps
// forwarding the caller's own messages to the target concurrently while this one waits here, so a
// client-streaming call (many caller messages before the target sends anything back) cannot
// deadlock against this blocking on Header() first -- the two directions were already independent
// before this change, and nothing about which one starts sending only after the other blocks
// invalidates that.
//
// Returns io.EOF for a clean end (the target's own RPC completed) or the error that ended it
// early; forward's own select reads targetStream.Trailer() only after this returns, per
// grpc.ClientStream.Trailer's own doc comment (valid only once RecvMsg has returned non-nil).
func relayTargetToCaller(serverStream grpc.ServerStream, targetStream grpc.ClientStream) error {
	md, err := targetStream.Header()
	if err != nil {
		return err
	}
	if md != nil {
		if err := serverStream.SendHeader(md); err != nil {
			return err
		}
	}

	for {
		var f proxyFrame
		if err := targetStream.RecvMsg(&f); err != nil {
			return err
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
// logged here like every other required value -- as of this task, authorize reads every one of
// them on every call (see proxyConfig's own doc comment), so a missing or malformed value among
// them must still fail startup, not surface as a confusing per-call denial. This function now
// dials the PDP too, mirroring hook/mcp/extauthz's own runXCmd: authorize (proxy.go) is the first
// code in this file that needs that connection, so the dial arrives together with it, the same
// "add the dial with the first caller, not ahead of one" choice Task 1 made for cfg.TargetAddr's
// own dial below.
func runProxyCmd(stderr io.Writer) int {
	cfg, err := loadProxyConfigFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	// grpc.NewClient dials lazily -- the same non-blocking choice every other mode's PDP dial
	// makes (runHookCmd, runMCPCmd, runExtauthzCmd) -- so this succeeding proves only that
	// cfg.TargetAddr parses as a target, not that anything is listening there yet. An
	// unreachable target is a forward-time failure, not a startup one.
	targetConn, err := grpc.NewClient(cfg.TargetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create target client: %s\n", err)
		return 1
	}
	defer func() { _ = targetConn.Close() }()

	// Dialed lazily the same way -- an unreachable PDP is an authorize-time failure (every call
	// denies on it, per the package doc's FAIL CLOSED section), not a startup failure, the same
	// way hook's and extauthz's own PDP dials never block startup on the PDP being up.
	pdpConn, err := grpc.NewClient(cfg.PDPAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create PDP client: %s\n", err)
		return 1
	}
	defer func() { _ = pdpConn.Close() }()

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not listen on %s: %s\n", cfg.ListenAddr, err)
		return 1
	}

	srv := &proxyServer{targetConn: targetConn, client: pdpgrpc.NewPDPServiceClient(pdpConn), cfg: cfg}
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
