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
// degrades or refuses on EFFECT_ESCALATE (it BLOCKED on one until Phase 15 -- see the ESCALATE
// DOES NOT BLOCK section below), or denies. Task 3 documents this mechanism's remaining limits
// (per-message authorization, opaque message bodies -- plan §P3/P4, consequences A and B); Task
// 4 proves the whole thing against a real service.
//
// ESCALATE DOES NOT BLOCK, AND THIS SURFACE NO LONGER BLOCKS AT ALL. Through Phase 11 it did:
// unlike extauthz.go's Check, which cannot hold a call open (Envoy's ext_authz budget is
// milliseconds, not minutes -- pdpgrpc.DegradeEscalateToDeny) and so degrades EFFECT_ESCALATE
// straight to a denial, this surface held the caller's own stream open exactly like hook and mcp
// still do, by calling escalation.go's resolveApproval. Phase 15 ended that in two steps, for two
// different reasons:
//
//   - A BOUND escalation degrades to a denial naming the approval (K11, degradeEscalation below).
//     The proof it would have to wait with does not survive the wait -- single-use (K8),
//     short-lived (K9), and unmintable by this process, which does not hold the key. The client
//     retries with a fresh proof once approved.
//   - An UNBOUND one is refused outright (K5, in authorize's own ESCALATE branch). K5 refuses the
//     ALLOW an approval could only ever resolve to, so waiting first buys nothing and answers with
//     a timeout instead of with the credential.
//
// So §4.6's blocking/non-blocking split is narrower than it looked, and this is the sentence worth
// carrying: A SURFACE MAY BLOCK ONLY WHILE THE CREDENTIAL IT WOULD WAIT WITH OUTLIVES THE WAIT. A
// bearer token does; a DPoP proof does not; and this surface requires the latter.
//
// resolveApproval itself is untouched and still correct for the surfaces whose credential does
// outlive a human -- hook and mcp, its two remaining callers. What is gone is only this file's
// call to it, which could not be kept once both ESCALATE outcomes returned (go vet rejects
// unreachable code). authorize's own ESCALATE branch carries the recipe for restoring it if K5 is
// ever relaxed.
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
// SENDER-CONSTRAINED TOKENS (Phase 15, spec §4.7.2 K5-K10). Everything above treats the token as
// a bearer credential, which is what §4.1.1 called out as the gap this surface shipped with: a
// token that leaks from a log, a sidecar, or a captured connection is fully usable by whoever
// holds it, on exactly the surface where the request arrives from the party being policed. This
// surface, like extauthz and unlike hook and mcp, now requires proof of possession. Four things
// change, and only here -- the verification itself stays in the PDP (K2/D1), so this file gained
// no crypto:
//
//   - extractCredentialsFromMetadata also reads the RFC 9449 "dpop" metadata key, and
//     decideRequestFromStream forwards it verbatim as DecideRequest.dpop_proof alongside
//     observed_method and observed_uri, the request pair the proof's htm/htu claims bind to (K7).
//   - htu is the PROXY'S OWN address (cfg.PublicURI, required configuration with no default) plus
//     the full method path, with htm the constant "POST" -- gRPC is HTTP/2 POST. Never the
//     target's address, which would let a proof minted for one target be replayed at another
//     behind the same proxy, and never the caller's own ":authority", which is the same hazard
//     one layer in. parsePublicURI's doc comment carries the full case for all three, including
//     why ListenAddr cannot supply it either.
//   - The proof is stripped from raw_input by the same omission that already strips
//     authorization (K10), because raw_input is hashed into an append-only audit chain and a
//     credential written there cannot be edited out. One map (credentialHeaderNames, extauthz.go)
//     decides what a credential is; dpop was added to it in Phase 15, which is the whole of the
//     strip for this surface too.
//   - authorize REFUSES an ALLOW whose token was never bound to a key (K5, allowIfSenderConstrained),
//     reading DecideResponse.sender_constrained. That is the one place in this file that narrows
//     what the PDP said.
//
// ONE STREAM, ONE PROOF. P4's "authorized once, at open" (below) is not weakened by any of this,
// and an operator will assume otherwise, so it is stated here in the terms Phase 15 introduces: a
// stream gets ONE Decide call, carrying ONE proof, whose ONE jti is spent once (K8). Every message
// that stream ever carries -- one, or thousands over hours -- rides that single proof. Per-message
// binding is not merely unimplemented; it is unavailable on this surface for the same reason
// per-message authorization is, and for a second reason on top of it: there is nothing to bind a
// per-message proof TO, since htu is a method path that does not change between messages of one
// stream. docs/pep.md says the same thing in the operator's own terms.
//
// The one place a SECOND proof is genuinely needed is an escalation, and that is exactly why K11
// degrades one rather than blocking: the retry needs a fresh proof and only the client can mint
// it, so the client has to be handed the call back to do so.
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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
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
// PublicURI is Phase 15's one addition, and unlike the eight above it exists to close a specific
// attack rather than to name a dependency -- see parsePublicURI's own doc comment for why neither
// ListenAddr nor TargetAddr nor anything the caller sends could have supplied it.
//
// Every field is required, with no default: loadProxyConfigFromEnv reads all nine via
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
	PublicURI  string

	PDPAddr        string
	AgentID        string
	Subject        string
	ConnectTimeout time.Duration

	ApprovalPollInterval time.Duration
	ApprovalTimeout      time.Duration

	// ForwardCredentials sends the caller's Stratium token, DPoP proof and
	// approval id on to the target (STRATIUM_PEP_PROXY_FORWARD_CREDENTIALS).
	// Off unless set: they are addressed to this proxy and the PDP.
	ForwardCredentials bool

	// MaxStreamDuration is the longest one proxied call may stay open
	// (STRATIUM_PEP_PROXY_MAX_STREAM_DURATION, default 1h). A call is decided
	// once, when it opens, so this is also the longest a stream can outlive a
	// change to that decision, a revocation included. Zero, which the loader
	// never produces, means no limit.
	MaxStreamDuration time.Duration
}

// forwardCredentialsVar names the optional setting behind
// proxyConfig.ForwardCredentials.
const forwardCredentialsVar = "STRATIUM_PEP_PROXY_FORWARD_CREDENTIALS" //nolint:gosec // G101: the name of a setting, not a credential

// stratiumMetadataKey reports whether a lower-cased metadata key carries
// something this proxy reads for the PDP: the token, the DPoP proof or an
// approval id. Narrower than consumedRequestKey on purpose: a cookie or a
// proxy-authorization value is kept out of the audit record, but it is the
// caller's credential for the target, not Stratium's.
func stratiumMetadataKey(lower string) bool {
	return lower == authorizationHeaderName || lower == dpopHeaderName || lower == approvalIDHeader
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
	publicURIRaw := requiredEnv("STRATIUM_PEP_PROXY_PUBLIC_URI", &missing)
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

	publicURI, err := parsePublicURI(publicURIRaw)
	if err != nil {
		return proxyConfig{}, err
	}
	cfg.PublicURI = publicURI

	if v := os.Getenv(forwardCredentialsVar); v != "" {
		forward, err := strconv.ParseBool(v)
		if err != nil {
			return proxyConfig{}, fmt.Errorf("%s: %w", forwardCredentialsVar, err)
		}
		cfg.ForwardCredentials = forward
	}

	cfg.MaxStreamDuration = time.Hour
	if v := os.Getenv(maxStreamDurationVar); v != "" {
		d, err := requiredDuration(maxStreamDurationVar, v)
		if err != nil {
			return proxyConfig{}, err
		}
		cfg.MaxStreamDuration = d
	}

	return cfg, nil
}

// publicURIVar is the one variable name parsePublicURI's errors quote, named rather than repeated
// so the string an operator greps for cannot drift between the read and the six refusals below.
const publicURIVar = "STRATIUM_PEP_PROXY_PUBLIC_URI"

const maxStreamDurationVar = "STRATIUM_PEP_PROXY_MAX_STREAM_DURATION"

// parsePublicURI validates STRATIUM_PEP_PROXY_PUBLIC_URI -- already confirmed non-empty by
// requiredEnv -- and returns the scheme-and-authority prefix decideRequestFromStream builds
// observed_uri from. Required, no default, refused at startup rather than per call: a wrong value
// here denies EVERY bound call this process ever sees, at the PDP's htu comparison, with a reason
// no operator reading a denial could trace back to a configuration string.
//
// # Why a CONFIGURED value, and why none of the three obvious sources could supply it
//
// Spec §4.7.2 K7 makes htu on this surface the PROXY'S OWN address plus the full method path.
// Three things in reach look like that address, and all three are wrong:
//
//   - The CALLER'S ":authority" metadata. This is the hazard K7 exists to close, one layer in
//     from where the sibling surface met it: extauthz built htu's authority from Envoy's Host
//     field, which Envoy's own generated doc defines as the caller's Host/:authority header, so
//     the authority component of the binding was whatever the presenter claimed (see
//     matchAllowedHost, extauthz.go, for the full replay). gRPC hands this process the same
//     caller-written value in incoming metadata. Reading it would reproduce the same defect
//     verbatim, and DecideRequest.observed_uri's own proto comment forbids it in as many words:
//     the pair must be "what the ENFORCEMENT SURFACE saw, never anything the caller asserted."
//   - TargetAddr. This is the defect K7 names outright: "Reporting the TARGET's address instead
//     would let a proof minted for one target be replayed at another behind the same proxy."
//     One proxy fleet fronting two targets would mint proofs interchangeable between them.
//   - ListenAddr. Not caller-controlled, and still unusable: a listen address is a BIND
//     specification, not an identity. ":9292" -- this deployment's own shape, and the ordinary
//     one for a containerized listener -- carries no host at all, so an htu built from it reads
//     "http://:9292/pkg.Svc/M", whose authority is empty. "0.0.0.0:9292" is worse: it names every
//     interface and therefore no address a client could have signed.
//
// What a client signs into htu is the address it ADDRESSED. That is a fact about this deployment
// -- which hostname resolves here, whether a load balancer or TLS terminator sits in front, which
// port that front announces -- and nothing inside this process can observe it. So it is
// configuration. Unlike extauthz's list, this is ONE value: extauthz MATCHES caller input, and a
// gateway legitimately fronts several hostnames, so it needs a set to match within. This surface
// matches nothing. It states its own identity, unconditionally, on every request -- and a set of
// candidate identities would immediately raise "which one goes in htu?", a question with no
// answer that does not end in reading the caller's own :authority to choose. A single value has
// no such question to answer, which is precisely why it is the safe shape here.
//
// # What is validated, and why each refusal is a startup failure
//
// The scheme must be http or https: those are the only two RFC 9110 defines for HTTP target URIs,
// and the only two internal/dpop's canonicalURI applies default-port removal to, so any third
// would compare unequal to itself across the two sides of the binding. The host must be present.
// Userinfo is refused because canonicalURI refuses it (RFC 9110 §4.2.1) -- accepting it here
// would move a guaranteed denial from startup to every request. A path, query, or fragment is
// refused because the method path is appended to this value verbatim: "http://p.example/api" plus
// "/pkg.Svc/M" is "http://p.example/api/pkg.Svc/M", which is not what any client signed.
//
// A bare trailing "/" is accepted and dropped rather than refused. It is unambiguous, it is what
// half of all operators will type, and a startup refusal for it would be this file inventing a
// spelling rule with no security content.
//
// The returned value is rebuilt from the parsed scheme and host rather than echoed, so what
// reaches observed_uri provably carries nothing but those two components. It is NOT case- or
// port-normalized here: canonicalURI applies RFC 3986 §6.2.2.1 and §6.2.3 to both sides of the
// comparison one hop later, so normalizing again here would be a second, independently
// maintained copy of a rule that already has one home -- the drift extauthz.go's own
// credentialHeaderNames comment argues against, in the one place it would be invisible.
func parsePublicURI(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		// The raw value is deliberately not echoed: it is operator configuration rather than
		// request data, but url.Parse errors quote their input, and a value carrying userinfo
		// would put a password in this process's own startup log.
		return "", fmt.Errorf("%s is not a URI: %w", publicURIVar, err)
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return "", fmt.Errorf("%s must have scheme http or https", publicURIVar)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s must name a host, e.g. https://proxy.example:9292", publicURIVar)
	}
	if u.User != nil {
		return "", fmt.Errorf("%s must not carry userinfo (RFC 9110 §4.2.1)", publicURIVar)
	}
	if path := u.EscapedPath(); path != "" && path != "/" {
		return "", fmt.Errorf("%s must be scheme and authority only, with no path: the gRPC method path is appended to it", publicURIVar)
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", fmt.Errorf("%s must be scheme and authority only, with no query or fragment", publicURIVar)
	}
	return u.Scheme + "://" + u.Host, nil
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
func newProxyGRPCServer(handler grpc.StreamHandler, opts ...grpc.ServerOption) *grpc.Server {
	return grpc.NewServer(append([]grpc.ServerOption{
		grpc.UnknownServiceHandler(handler),
		grpc.ForceServerCodec(proxyCodec{}),
	}, opts...)...)
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

	allowed, reason, approvalID := p.authorize(stream.Context(), fullMethod)
	if !allowed {
		if approvalID != "" {
			// K11's degraded escalation. Two channels for the same id, the same pair and the same
			// reasoning extauthz's denyCheckResponse already uses for its own HTTP surface: a
			// trailer is what a retry tool or a wrapper can extract deterministically, key by key,
			// without parsing prose that might be reworded later; the status MESSAGE below is what
			// a human staring at a captured error sees -- in a client log, a `grpcurl` transcript,
			// a stack trace that kept only the message. Neither channel alone serves both readers.
			//
			// Trailing metadata rather than status details (google.rpc.Status's own details field):
			// details would mean choosing a proto message type to carry one string -- either a new
			// one in this repo's proto, or genproto's errdetails, a dependency and a vocabulary
			// this binary has no other use for. A trailer is gRPC's own direct analogue of the
			// response header extauthz already sends, it reuses that surface's own header name
			// (approvalIDHeader) so an operator sees ONE key across both, and grpc-go delivers
			// trailers with the status on a failed RPC exactly as it does on a successful one.
			//
			// SetTrailer returns nothing to check -- it appends to metadata the transport has not
			// sent yet -- so there is no failure here that could suppress the denial below. The
			// denial is returned whether or not an operator ever sees the id.
			stream.SetTrailer(metadata.Pairs(approvalIDHeader, approvalID))
		}
		return status.Error(codes.PermissionDenied, reason)
	}
	return p.forward(fullMethod, stream)
}

// authorize is this task's entire decision surface: it maps ctx and method to a DecideRequest
// (decideRequestFromStream, P1-P3), calls the PDP, and resolves to a final allow/deny. An
// EFFECT_ESCALATE never blocks here as of Phase 15 -- a bound token degrades to a denial naming
// the approval (K11), an unbound one is refused outright (K5) -- and the package doc's ESCALATE
// DOES NOT BLOCK section carries why each. The signature is still (bool, string): handleStream's own call site needed only ctx
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
//
// K5 (Phase 15) is the one place this function narrows what the PDP said, and it narrows it in
// exactly one direction: an ALLOW whose token was never bound to a key is refused
// (allowIfSenderConstrained, below). That is not a D1 violation -- D1 forbids a PEP DECIDING that
// something is permitted, and refusing something the PDP permitted is the direction a PEP is
// always free to move in, the same direction an unreachable PDP already denies in here. A PEP may
// narrow; it may never widen.
func (p *proxyServer) authorize(ctx context.Context, method string) (allowed bool, reason string, approvalID string) {
	req, err := decideRequestFromStream(ctx, method, p.cfg)
	if err != nil {
		return false, fmt.Sprintf("stratium-pep: %s", err), ""
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
		return false, fmt.Sprintf("stratium-pep: %s", describeRPCError(err, agentOrDelegationUnknownMsg)), ""
	}

	switch resp.GetEffect() {
	case pdpgrpc.Effect_EFFECT_ALLOW:
		allowed, reason := allowIfSenderConstrained(resp)
		return allowed, reason, ""
	case pdpgrpc.Effect_EFFECT_ESCALATE:
		// NEITHER outcome blocks, and the two reasons are different. sender_constrained carries
		// its real answer on an ESCALATE -- every three-leg outcome reaches Decide's tail, where
		// the PDP sets it -- so this branch can tell the two apart, which the field's own proto
		// comment now sanctions explicitly for exactly these two rules.
		if resp.GetSenderConstrained() {
			// K11: a BOUND escalation degrades to a denial naming the approval. The client
			// retries with a fresh proof once approved. See degradeEscalation for the whole case.
			return degradeEscalation(resp)
		}
		// K5: an UNBOUND escalation is refused HERE rather than waited on.
		//
		// This is a narrowing, which a PEP may always do, and it is the same refusal
		// allowIfSenderConstrained applies one branch up -- moved earlier, not invented.
		//
		// BE PRECISE ABOUT WHAT THIS DOES NOT PREVENT, because an earlier version of this comment
		// overreached and claimed it stopped a human being paged. It does not. Decide creates the
		// pending approval row itself, inside resolveEscalation, BEFORE the tail that sets
		// sender_constrained -- so by the time any surface can read that field the row already
		// exists, and whatever queue an operator watches has already seen it. Polling GetApproval
		// is a read; it pages nobody.
		//
		// What refusing here actually buys is the wait and the answer. Blocking would hold the
		// caller's stream and a polling goroutine for up to ApprovalTimeout and then deny anyway,
		// because the ALLOW an approval resolves to is refused by K5 -- so a legacy bearer-token
		// caller hitting an escalating action would hang for the full timeout and be told it timed
		// out, when the real and fixable problem is its credential. Refusing now costs it nothing
		// it was ever going to get and names the one thing it can act on.
		//
		// The residue is worth stating rather than hiding: the pending row survives and nothing
		// will ever retry against it, so an operator approving it achieves nothing. That was
		// equally true of the blocking version -- a timed-out escalation left the same orphan --
		// so this changes the wait, not the row.
		//
		// THE BLOCKING PATH ITSELF IS NOT GONE, and it is still the right behaviour for the
		// condition it serves -- which is not "unbound" but "a credential that outlives the
		// wait" (degradeEscalation's own comment carries that rule). It lives in escalation.go's
		// resolveApproval, unchanged, still called by hook.go and mcp_authorize.go, and still
		// carrying both reshapes proxy itself forced on it: the by-value durations and the
		// caller-supplied ctx that lets a poll stop when the caller disconnects. proxyConfig
		// keeps ApprovalPollInterval and ApprovalTimeout for the same reason.
		//
		// What is gone is only THIS call site, and it could not be kept: with both outcomes above
		// returning, a call to resolveApproval below them is unreachable, which `go vet`'s own
		// unreachable check rejects outright -- it is not a style question. If K5 is ever
		// relaxed, restoring it is four lines: call resolveApproval with (ctx, p.client,
		// ConnectTimeout, ApprovalPollInterval, ApprovalTimeout, req, resp), and on
		// EFFECT_ALLOW hand the RETRY's own response -- never resp -- to allowIfSenderConstrained,
		// because the retry is the ALLOW being acted on. resolveApproval no longer returns that
		// response (it was added for this caller and removed when this caller went away, see its
		// own doc comment), so restoring the call means restoring that return value too.
		return false, unboundTokenReason, ""
	default:
		// EFFECT_DENY, and any value this build does not recognize (the proto documents
		// EFFECT_DENY as the zero value for exactly this case -- see hook.go's identical default
		// case). Passed through unprefixed: the PDP's own verdict text, not a local diagnostic
		// this process is synthesizing -- the same convention hook.go's and extauthz.go's own
		// default DENY cases follow, so a human reading a denial can tell at a glance whether the
		// PDP refused the call or this process failed before ever asking it one.
		return false, resp.GetReason(), ""
	}
}

// degradeEscalation is spec §4.7.2 K11: on this surface, an escalation carrying a
// SENDER-CONSTRAINED token degrades to a denial naming the pending approval, exactly as
// extauthz's checkResponseFromDecide does for every escalation on its own surface. The client
// retries once approved, with a FRESH proof, minted by the only party that can mint one.
//
// # Why this surface stopped blocking, starting with this credential
//
// spec §4.6 splits the surfaces into blocking (hook, mcp, proxy) and non-blocking (extauthz), and
// until Phase 15 that split was purely about whether the transport could hold a call open for a
// human. K11 narrows it, and the narrowing is the useful part to carry: A SURFACE MAY BLOCK ONLY
// WHILE THE CREDENTIAL IT WOULD WAIT WITH OUTLIVES THE WAIT. A bearer token does. A DPoP proof
// does not -- it is single-use (K8) and short-lived (K9), and a human approval is neither.
//
// Concretely, and this was measured rather than predicted (Task 6's own integration run):
// resolveApproval must resend req BYTE-IDENTICAL, because resolveEscalation binds the approval to
// input_digest -- so it resends the same dpop_proof, whose jti the ORIGINAL call already spent,
// and the PDP refuses the retry with "store: dpop proof already spent". Had it not, a human
// slower than STRATIUM_DPOP_FRESHNESS_WINDOW would have put the same proof outside the window
// instead. This process cannot mint a replacement: the client holds the private key, and a
// surface that is still blocking has by definition not returned to the client.
//
// # The alternative that was rejected, and why it is worse than the deny
//
// Skipping the proof check on a retry carrying an approval_id was considered and refused.
// Approvals are NOT consumed (resolveEscalation, internal/pdpgrpc/escalation.go), so anyone
// holding the token plus the approval id could re-execute the approved action for the approval's
// entire TTL WITHOUT EVER PROVING POSSESSION -- which is exactly what K5 exists to close on this
// surface. Degrading costs one extra round trip; that costs the property.
//
// # Reading sender_constrained on an ESCALATE
//
// The field's proto comment leads with "CONSULT IT ONLY WHEN effect IS EFFECT_ALLOW", and this
// reads it on an ESCALATE, so the exception is stated rather than taken quietly. That headline
// rests on a stated premise -- "a surface refuses a denied decision anyway, so an ALLOW is the
// only case in which this field has to be asked at all" -- and K11 is a second case, which did
// not exist when that sentence was written. The comment's own enumeration directly below it
// already sanctions this read in as many words: a decision that REACHED the three-leg evaluation
// carries the real answer, "or that escalates -- reports true". An escalation always reaches it
// (server.go sets the field on Decide's tail, which the escalate branch flows through), so the
// value here is the real one, never the "not established" false that the six early denials
// report. The rule the headline is really protecting -- do not read this on a DENIAL -- is
// untouched: this reads it on an escalation and nowhere else.
//
// req.GetDpopProof() != "" was weighed as an alternative condition needing no exception at all,
// and rejected as the wrong fact: it says the caller SENT something, where what makes the retry
// impossible is that the PDP VERIFIED and SPENT it. Those differ for an unbound token that
// attached a proof anyway -- matchProof ignores it and spends nothing, so that call could safely
// have blocked -- and picking the caller-shaped proxy for a PDP-shaped fact is how a surface ends
// up enforcing something subtly other than the rule it cites.
//
// A PDP that escalates without attaching an id has violated DecideResponse.approval_id's own
// contract and left nothing to find; that denies with a reason saying so rather than pointing an
// operator at an id that names nothing, mirroring extauthz's checkResponseFromDecide and hook.go's
// resolveApproval, which both defend the identical shape.
func degradeEscalation(resp *pdpgrpc.DecideResponse) (allowed bool, reason string, approvalID string) {
	approvalID = resp.GetApprovalId()
	if approvalID == "" {
		return false, fmt.Sprintf(
			"stratium-pep: PDP escalated this call but returned no approval id to attach; denying (PDP reason: %s)",
			resp.GetReason()), ""
	}
	// The reason names what the caller must actually DO, and the instruction is not the same one
	// extauthz gives: "retry after approval" would send a client back with the proof it already
	// used, which the PDP refuses as a replay (K8). A FRESH proof is the whole point of the
	// ruling, so the text says so rather than leaving it to be discovered from a second denial.
	return false, fmt.Sprintf(
		"stratium-pep: this call requires approval and is pending (approval id %s); once approved, retry it "+
			"with a FRESH DPoP proof -- the proof presented with this call is single-use (RFC 9449, spec K8) "+
			"and cannot be replayed on the retry -- PDP: %s",
		approvalID, resp.GetReason()), approvalID
}

// allowIfSenderConstrained is K5: this surface forwards only a call whose token was bound to a
// key and whose DPoP proof of possession of that key the PDP verified for this exact request.
// Both of authorize's two allow paths -- a direct EFFECT_ALLOW and an escalation resolved to one
// -- go through this, because both end in the same act, forwarding the caller's own stream to the
// target, and K5 is a property of that act rather than of which branch reached it.
//
// # Why the refusal lives here and not in the PDP
//
// Spec §4.7.2 K5 requires the two NETWORK surfaces -- proxy and extauthz -- to refuse a token
// carrying no cnf.jkt, and states outright that the refusal lives at the surface. IssueToken
// cannot know which surface will present the token it mints, so it cannot decide at issuance
// whether binding is required; and refusing a bearer token inside Decide would break hook and
// mcp, where a bearer token is legitimate (the caller already holds the session file it lives in,
// so binding buys nothing). The PDP therefore REPORTS -- DecideResponse.sender_constrained -- and
// this is what acts on the report. A PEP cannot read cnf.jkt for itself: that means parsing a
// token it holds no key to verify, and a PEP that decides a credential is genuine is a PEP making
// an authorization decision (D1).
//
// # This is the converse of C25, not the same property
//
// C25 covers a BOUND token presented without a proof, which the PDP itself denies. K5 adds that
// an UNBOUND token -- one that was never bound to anything, so no proof for it could exist -- is
// refused here too. A suite written from C25's own sentence leaves the second wide open, and it
// is the easier of the two to walk through: an attacker who simply asks for an ordinary bearer
// token never has to defeat a binding at all.
//
// # Reading sender_constrained where it means what it says
//
// resp is always a response whose effect is EFFECT_ALLOW, which is the only case
// DecideResponse.sender_constrained's own proto comment permits the field to be read in. On a
// denial it is populated inconsistently by construction: the PDP sets it on Decide's tail, so
// every denial that returns early -- a token that failed to verify, a proof that failed, a jti
// that could not be spent, and three catalog/tier load failures -- reports false regardless of
// what the caller actually presented. False on a denial means "not established", never "the
// caller presented a bearer token". Restricting the read to this function costs nothing, because
// every other path in authorize denies anyway.
//
// unboundTokenReason (extauthz.go) is shared verbatim with the sibling surface rather than
// re-worded here: it is the same refusal, for the same reason, and an operator hitting it on one
// surface should not have to recognize a second phrasing of it on the other. Its text names
// dpop_jwk, which is the one action available to a caller holding an unbound token -- the
// distinction that makes it actionable rather than a wall, and what keeps it distinguishable from
// C25's own "you sent no proof" denial, which is fixed by producing a proof instead.
func allowIfSenderConstrained(resp *pdpgrpc.DecideResponse) (allowed bool, reason string) {
	if !resp.GetSenderConstrained() {
		return false, unboundTokenReason
	}
	return true, ""
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
// It fails in two ways: extractCredentialsFromMetadata's own (no authorization metadata, or one
// that is not a well-formed Bearer challenge -- P2, spec K4, there is no fallback credential this
// function could use instead), and a method name that is not a gRPC method path (see the leading-
// slash guard below, which exists because that string becomes part of htu). Every other field is
// unconditional: method is otherwise read only to pass through, never inspected for meaning (see
// authorize's own doc comment on D1), and cfg supplies this process's own configured identity and
// address, never anything derived from the call.
//
// dpop_proof/observed_method/observed_uri (Phase 15, spec §4.7.2 K7) are the three fields this
// surface adds for proof-of-possession, and none of them is conditional: a call carrying no proof
// sends an empty dpop_proof and the pair the PDP then ignores, rather than this function deciding
// a proof was required. Whether it was required is the PDP's answer for a bound token (C25) and
// allowIfSenderConstrained's for an unbound one (K5). A local "no proof, no entry" shortcut here
// would deny bearer traffic with a reason naming the wrong defect, and would deny it before the
// PDP ever recorded the attempt in the audit chain.
//
// observed_method is the constant "POST", not anything read off the call: gRPC is HTTP/2 POST
// (spec §4.7.2 K7, and DecideRequest.observed_method's own proto comment says so for this surface
// by name), so there is no per-call variation for a source to be chosen among. Nothing on this
// wire even carries an HTTP method -- grpc-go's own server refuses a :method other than POST
// before this handler is ever reached -- so a value read from the request would be a value
// invented from one.
//
// declared_tier and resource are never set on the returned request, the same omission hook.go,
// mcp_authorize.go, and extauthz.go all make for the identical reason: this process has no real
// tier or resource to declare, and both are re-derived server-side from tool/raw_input against
// the tenant's own catalog regardless of what a caller claims -- see any of those three files'
// own package docs. TestAuthorize_NeverSendsDeclaredTier asserts this on the wire, mirroring the
// other three surfaces' identical tests.
func decideRequestFromStream(ctx context.Context, method string, cfg proxyConfig) (*pdpgrpc.DecideRequest, error) {
	md, _ := metadata.FromIncomingContext(ctx)

	token, proof, approvalID, stripped, err := extractCredentialsFromMetadata(md)
	if err != nil {
		return nil, err
	}

	// The one thing about method that IS inspected, and only because method is concatenated onto
	// cfg.PublicURI below. A gRPC method path always begins with "/" and grpc-go's own server
	// rejects a :path that does not before this handler is reached (server.go's
	// strings.CutPrefix(stream.Method(), "/") and its found check, v1.83.0) -- so this guard is
	// unreachable through a real transport today. It is here anyway because the failure it
	// prevents is the exact one this whole surface exists to prevent: "pkg.Svc/M" appended to
	// "http://proxy.example" is "http://proxy.examplepkg.Svc/M", an htu whose AUTHORITY the
	// caller chose. Depending on a dependency's input validation to hold that shut is depending
	// on it never changing. Denying is the only safe answer: a method this function cannot bind
	// is a method it cannot honestly report a request pair for.
	if !strings.HasPrefix(method, "/") {
		return nil, errors.New("called method is not a gRPC method path")
	}

	rawInput, err := json.Marshal(proxyRequestMetadata{Method: method, Headers: stripped})
	if err != nil {
		// method is a plain string and stripped is a flat map[string][]string with no cycles --
		// Marshal cannot fail for this shape in practice. Reported rather than assumed away, the
		// same caution decideRequestFromCheck's own identical Marshal call takes (extauthz.go).
		return nil, fmt.Errorf("could not serialize request metadata: %w", err)
	}

	req := &pdpgrpc.DecideRequest{
		AgentId:  cfg.AgentID,
		Subject:  cfg.Subject,
		Tool:     method, // P1: the full method IS the tool identity.
		RawInput: string(rawInput),
		Token:    token,

		DpopProof:      proof,
		ObservedMethod: grpcObservedMethod,
		// K7: the PROXY'S OWN address, from configuration, plus the full method path. Not
		// cfg.TargetAddr and not the caller's ":authority" -- see parsePublicURI's doc comment
		// for what each of those would open. Nothing on the right-hand side of this expression
		// can be influenced by the caller except the method path itself, which is the part of
		// htu that is SUPPOSED to vary per call.
		ObservedUri: cfg.PublicURI + method,
	}
	// The consuming half of K11's degrade: a caller retrying an approved escalation sends back the
	// id the denial handed it, and this forwards it so the PDP resolves that approval instead of
	// creating a second one.
	//
	// Forwarded ONLY if it is shaped like an approval id at all -- see forwardableApprovalID.
	// Accepting a well-formed one from the caller is safe and decides nothing: the PDP re-verifies
	// the approval in full (resolveEscalation -> Approval.Verify) against tenant (via RLS), root
	// principal, agent, delegation, tool, verb, derived tier, input_digest, expiry, and status. A
	// forged, expired, or borrowed id fails there and denies -- audited. Nothing about this
	// request's own authorization is decided here, which is what D1 forbids.
	if id, ok := forwardableApprovalID(approvalID); ok {
		req.ApprovalId = &id
	}
	return req, nil
}

// forwardableApprovalID reports whether raw is shaped like an approval id, and is the guard that
// keeps a caller from switching off its own audit trail.
//
// # The hole it closes
//
// Decide rejects an unparseable approval_id with InvalidArgument from parseNonNilUUID
// (internal/pdpgrpc/server.go) BEFORE authenticateToken runs -- so that path never reaches
// denyAndAudit and NO AUDIT ROW IS WRITTEN. Without this guard an agent could attach
// "stratium-approval-id: x" to every call and have every attempt denied, correctly and
// fail-closed, while leaving nothing behind: an operator asking "did agent X attempt method Y?"
// gets no row. Decide's own comment promises the opposite for a bad token -- it "still produces
// an audited DENY, not a bare RPC error... the audit trail is exactly where 'someone tried and
// failed to authenticate' belongs" -- and forwarding an unvalidated string made that guarantee
// switchable by the caller.
//
// # Why it DROPS rather than denies, which is the whole point
//
// Denying locally would close nothing. A local denial never reaches the PDP either, so it writes
// no audit row and leaves exactly the same switch in the caller's hand. Dropping the field lets
// the call proceed to a real decision, which IS audited -- allow, deny, or escalate -- so the
// header cannot suppress a row no matter what a caller puts in it. That is the property, and only
// dropping has it.
//
// Silently ignoring caller input is a real cost and is accepted knowingly: an approval id this
// surface cannot parse as an id names no approval, so "unusable value" and "absent" are the same
// fact for an OPTIONAL field, and the caller is not misled -- it gets the truthful answer for a
// request naming no valid approval, which is a fresh escalation telling it to obtain one. The
// alternative, a bespoke denial, trades that for the audit gap above.
//
// Contrast the malformed-CREDENTIAL paths, which do deny locally without an audit row
// (extractCredentialsFromMetadata's errors, K4/M2): those requests are UNDECIDABLE -- there is no
// token, so there is no delegation, no agent, and nothing for an audit row to be about. A
// malformed approval id leaves the request perfectly decidable. Audit away only what cannot be
// decided.
//
// # The check
//
// Exactly parseNonNilUUID's own two conditions, deliberately: parses as a UUID, and is not the
// nil UUID. Any narrower and a value the PDP would have accepted gets dropped; any wider and the
// InvalidArgument this exists to prevent comes back. This is shape validation, not classification
// -- it decides nothing about the approval, only whether the string can be one -- and it follows
// the same in-file precedent as the leading-slash guard above, which shape-validates for a
// strictly weaker reason.
func forwardableApprovalID(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil {
		return "", false
	}
	return raw, true
}

// grpcObservedMethod is DecideRequest.observed_method's value on this surface, always: gRPC is
// carried over HTTP/2 POST (gRPC's own HTTP/2 protocol specification; RFC 9449 §4.2's htm is an
// HTTP method, and POST is the only one a gRPC call ever uses). Uppercase, and not normalized
// anywhere: dpop.Proof.MatchesRequest compares htm case-sensitively because RFC 9110 §9.1 makes
// methods case-sensitive.
const grpcObservedMethod = "POST"

// extractCredentialsFromMetadata is extauthz.go's extractCredentials adapted to gRPC's own
// metadata.MD shape (map[string][]string, since a header may repeat) instead of Envoy's flat
// map[string]string -- the same single-pass extract-and-strip loop, the same case-insensitive
// match against credentialHeaderNames (extauthz.go), reused directly rather than re-declared:
// Phase 10 Task 2 already settled which headers count as a credential and why (see that var's own
// doc comment), and this file adds no fifth entry to that list for a fourth surface.
//
// Named for the two credentials it reads rather than for one of them (it was
// extractBearerTokenFromMetadata through Phase 11, when there was only one), the same rename
// extractCredentials took one file over and for the same reason: a function that silently also
// returned a proof under the old name would be the kind of misdirection a reader auditing K10 has
// to defeat before trusting anything else here.
//
// STRIP BY OMISSION, not by deletion (K10). stripped is built up from the non-credential entries,
// so a credential is never written into it in the first place -- there is no window in which the
// returned map holds a proof, and no delete() call whose absence a future edit could quietly
// introduce. raw_input is hashed into an append-only audit chain, and a credential written there
// cannot be edited out afterwards, so "the proof never reaches raw_input" has to be structural
// rather than a step someone remembers.
//
// The read side is structural in the same way: credential VALUES are read only out of the local
// creds map, which is populated only for names in credentialHeaderNames. A header not listed
// there has no value for any read below to find, so "everything this function reads is also
// stripped" holds by construction rather than by a test. An earlier version read authorization
// out of a conditional inside the same loop, where a second credential could have been read
// without a credentialHeaderNames entry and nothing would have noticed.
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
// TestExtractCredentialsFromMetadata_HeaderNameCaseDiffers_CredentialsStillFound and
// TestExtractCredentialsFromMetadata_StripsCredentialHeadersCaseInsensitively specifically
// because routing those cases through a real incoming context would launder them through
// FromIncomingContext's own normalization before this function ever ran, silently proving nothing
// about THIS function's own defensiveness -- exercising it directly is the only way to prove it
// does not merely inherit a guarantee a caller three lines up already happens to provide. It
// matters more for dpop than it ever did for authorization: RFC 9449 spells the metadata key
// "DPoP", with an interior capital nothing else in HTTP looks like.
//
// An error means there is no credential here worth sending to the PDP at all: no authorization
// metadata, one that is not a Bearer challenge, or one whose token is empty once the scheme is
// removed. token, proof, and stripped are all zero values in every error case -- there is no
// partial result a careless caller could mistake for a usable one. A MISSING dpop key is not one
// of those errors: proof comes back "" and DecideRequest.dpop_proof carries the empty string,
// which its own proto doc defines as "the caller presented none".
func extractCredentialsFromMetadata(md metadata.MD) (token, proof, approvalID string, stripped map[string][]string, err error) {
	stripped = make(map[string][]string, len(md))
	// consumed is the ONLY thing the reads below draw from, and it is populated only for names
	// consumedRequestKey (extauthz.go) reports -- see that predicate's own doc comment for the two
	// reasons a key qualifies, and for what this containment does and does not guarantee.
	//
	// A key present with no values at all is not stored: it carries nothing, and leaving it out
	// keeps "an entry exists" and "a value exists" the same fact, so the reads below can index [0]
	// without a second length check each. It is still consumed by the loop, so it is still absent
	// from stripped.
	consumed := make(map[string][]string, len(credentialHeaderNames)+1)
	for name, values := range md {
		lower := strings.ToLower(name)
		if consumedRequestKey(lower) {
			if len(values) > 0 {
				consumed[lower] = values
			}
			continue
		}
		stripped[name] = values
	}

	// values[0], for both credentials. RFC 7235 defines exactly one credential per Authorization
	// header and RFC 9449 §4.1 the same for DPoP; a second, repeated value is non-conformant, not
	// a shape this function has grounds to prefer the LAST of over the first. The first is also
	// what every one of those values would have contributed FIRST on the wire, so taking it here
	// is consistent with how a normal single-valued header is read.
	if v, ok := consumed[dpopHeaderName]; ok {
		proof = v[0]
	}
	if v, ok := consumed[approvalIDHeader]; ok {
		approvalID = v[0]
	}
	authValues, found := consumed[authorizationHeaderName]
	if !found {
		return "", "", "", nil, errors.New("no authorization metadata")
	}
	authValue := authValues[0]
	if !strings.HasPrefix(authValue, bearerPrefix) {
		return "", "", "", nil, errors.New("authorization metadata is not a Bearer token")
	}
	token = strings.TrimPrefix(authValue, bearerPrefix)
	if token == "" {
		return "", "", "", nil, errors.New("authorization metadata carries an empty Bearer token")
	}
	return token, proof, approvalID, stripped, nil
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
	// The whole call, both directions, ends when it has run as long as a
	// proxied call may. A timer here, not a deadline on ctx: a deadline would
	// travel to the target, which would then end the call itself at the same
	// moment, and which of the two the caller heard from would be a race.
	// tooLong stays nil, and so never ready, when there is no limit.
	var tooLong <-chan time.Time
	if p.cfg.MaxStreamDuration > 0 {
		timer := time.NewTimer(p.cfg.MaxStreamDuration)
		defer timer.Stop()
		tooLong = timer.C
	}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		out := md.Copy()
		if !p.cfg.ForwardCredentials {
			// grpc-go lower-cases incoming keys, but nothing here relies on it.
			for key := range out {
				if stratiumMetadataKey(strings.ToLower(key)) {
					delete(out, key)
				}
			}
		}
		ctx = metadata.NewOutgoingContext(ctx, out)
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
		case <-tooLong:
			cancel() // ends the target stream, and with it both relay goroutines
			return status.Errorf(codes.DeadlineExceeded,
				"stratium-pep: proxy: the call was ended because it ran longer than %s, the most this proxy allows one; open a new one",
				p.cfg.MaxStreamDuration)
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
	transportDetail = stderr // see transportFailure (hook.go)
	cfg, err := loadProxyConfigFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}
	limits, err := loadListenerLimitsFromEnv()
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
	pdpConn, err := dialPDP(cfg.PDPAddr)
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
	grpcServer := newProxyGRPCServer(srv.handleStream, limits.serverOptions()...)

	// This process's own startup configuration, not request data -- see the package doc's NEVER
	// LOG section, which this line does not touch. Logged once, the same way runExtauthzCmd logs
	// its own cfg.
	_, _ = fmt.Fprintf(stderr, "stratium-pep: proxy listening on %s (public URI %s, target %s, PDP %s, agent %s, subject %s, connect timeout %s, approval poll %s, approval timeout %s)\n",
		cfg.ListenAddr, cfg.PublicURI, cfg.TargetAddr, cfg.PDPAddr, cfg.AgentID, cfg.Subject, cfg.ConnectTimeout, cfg.ApprovalPollInterval, cfg.ApprovalTimeout)

	if err := grpcServer.Serve(lis); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: proxy server: %s\n", err)
		return 1
	}
	return 0
}
