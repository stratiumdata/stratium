// extauthz.go implements the "extauthz" subcommand: a gRPC server answering
// envoy.service.auth.v3.Authorization/Check, the contract Envoy's ext_authz
// filter calls, synchronously, on every request it fronts, before deciding
// whether to forward it. Every other mode in this binary is the PEP sitting
// beside the thing it enforces -- a hook Claude Code invokes, a proxy the
// agent's harness launches in place of a real MCP server. extauthz is the
// PEP sitting beside Envoy instead: Envoy calls Check, and this server
// answers allow or deny.
//
// REQUEST MAPPING (Task 2). Task 1 left Check reading nothing: no code path
// could produce an honest ALLOW yet, so the only answer that did not lie
// about what was decided was an unconditional deny. Task 2 added the
// request side of a real decision -- decideRequestFromCheck extracts the
// tool identity, the bearer token, and a credential-stripped raw_input from
// a CheckRequest (plan §§M1-M3) -- and Check calls the PDP with whatever
// that produces, when it produces anything at all: a request with no usable
// credential denies before the PDP is ever dialed (M2, K4 -- see
// decideRequestFromCheck's and extractBearerToken's own doc comments).
//
// RESPONSE MAPPING (Task 3). Task 2's Check still denied unconditionally
// even after a successful PDP round trip, on purpose, because turning what
// the PDP actually said into a real answer was left for this task.
// checkResponseFromDecide (below) is that mapping: EFFECT_ALLOW becomes an
// OkResponse; EFFECT_DENY -- and any effect this build does not recognize,
// including an entirely unset one, the proto's own deliberate zero-value
// invariant -- becomes a PERMISSION_DENIED carrying the PDP's own reason
// verbatim; and EFFECT_ESCALATE degrades to that same PERMISSION_DENIED
// shape plus a pending approval's id, attached in both a dedicated response
// header and the denial's own body text (see checkResponseFromDecide's and
// denyCheckResponse's own doc comments for why both, and why an unset
// Effect is asserted rather than assumed to decode as deny). That degrade
// is pdpgrpc.DegradeEscalateToDeny's first real caller -- Phase 5 wrote it
// for exactly this surface before this surface existed; see
// nonblocking.go's own doc comment for what using it for real confirmed,
// and checkResponseFromDecide's for the one thing it does not by itself
// decide (which reason text to show).
//
// DEPENDENCY: github.com/envoyproxy/go-control-plane/envoy v1.37.0 as of
// this writing (see go.mod) -- Envoy's own canonical, versioned source for
// the ext_authz contract, generated straight from the .proto Envoy itself
// ships and versions alongside every release. That module is a split of the
// upstream github.com/envoyproxy/go-control-plane project: the top-level
// module (v0.14.0, also in go.mod, but only ever indirect -- nothing in
// this codebase imports a package from it) is the xDS control-plane
// server/cache library, which the project split its generated protobuf/gRPC
// types out of specifically so a consumer that wants only the wire types --
// this server, exactly -- does not have to pull in snapshot-cache machinery
// it will never use. Importing the "/envoy" submodule alone keeps the added
// tree to what Check's own request/response shapes actually need: the
// service types themselves, envoy/type/v3 for HttpStatus, and their proto
// validation/reflection plumbing -- not the client_model or OTLP proto
// packages the full project's go.mod lists for parts of the API this server
// never touches.
//
// A hand-rolled copy of CheckRequest/CheckResponse was rejected: Envoy owns
// this contract, this project only answers it, and a hand-written copy of
// its wire shape can only drift from what a real Envoy actually sends,
// never improve on it -- divergence here is a risk with no possible upside.
// Contrast with mcp.go's stdlib-only choice, which this is deliberately
// NOT the same argument: mcp.go rejected every MCP library because a PROXY
// needs an id to round-trip through it exactly byte-for-byte, and no
// library's typed re-encoder can promise that for every input it has never
// seen (see mcp.go's own package doc, "LIBRARY VS STDLIB"). This server is
// not a proxy relaying someone else's framing -- it TERMINATES a single,
// versioned RPC contract that Envoy defines and controls end to end, the
// same relationship internal/pdpgrpc already has with proto/pdp/v1
// (generated, not hand-rolled, for the identical reason). There is no
// id-fidelity argument to make here, because there is no id passing through
// this process unexamined -- only a request this server is the intended
// final reader of.
//
// NO SESSION FILE. hook and mcp both read a session file session-start
// wrote before either process ever ran (session_file.go) -- the token that
// authenticates every Decide call comes from a file this process's own
// operator provisioned ahead of time, never from whatever asked to run a
// tool. extauthz has no such file, and extauthzConfig below has no
// SessionFilePath field -- not an oversight, a reader who knows hook should
// look for one and its absence should read as deliberate: Envoy forwards
// whatever `authorization: Bearer` header arrived on the request it is
// fronting (plan §M2), which means the token now genuinely comes from the
// party being policed, fresh on every single Check call -- the first
// surface in this binary where that is true. That is also why this surface
// could not exist before Phase 9: presenting a caller-supplied token as
// authority only works once the PDP verifies it cryptographically (spec
// A10, K4) rather than trusting a bare id, and Decide only grew that
// verification in Phase 9 Task 4. Reading that header is this task's own
// addition -- see extractBearerToken, which is where it happens.
//
// FAIL CLOSED. Every constraint every other mode in this binary already
// follows applies here with more force, not less: no default for any
// required value (loadExtauthzConfigFromEnv, below, names every missing one
// at once -- see config.go's requiredEnv), and a missing or malformed value
// stops the process before it ever binds a listener. Every other mode in
// this binary fails one tool call at a time; extauthz, unstarted, is every
// request behind whatever Envoy deployment points at it -- there is no
// "start degraded and log a warning" option here, because there is no
// operator left watching once Envoy has already decided this process is up
// and started routing traffic at it.
//
// NEVER LOG REQUEST METADATA. Envoy's CheckRequest carries the full
// attributes of the request it is fronting -- every header, including
// whatever scheme the caller uses to identify themselves -- which is
// strictly more than any surface in this binary has handled before now
// (hook.go's own tool_input is one JSON blob; this is an entire HTTP
// request). This task is the first to parse a CheckRequest at all, which is
// exactly where this rule starts binding, the same way hook.go's package
// doc binds raw_input and mcp.go's binds frame contents: nothing derived
// from a request this server receives may ever reach stderr, a log line, or
// an error string. decideRequestFromCheck and extractBearerToken's own
// deny reasons hold to this already -- "no authorization header" and
// "authorization header is not a Bearer token" describe WHICH check failed,
// never the header's own value or the token itself. The one line this file
// writes to stderr unconditionally (runExtauthzCmd's startup line) is this
// process's own operator-supplied configuration, never anything from a
// Check call.
//
// The same rule binds a fact this task introduces on the RESPONSE side: a
// degraded ESCALATE's approval id names a live pending authorization (spec
// E5) exactly as a token names a live delegation, and this file's stderr
// stays as free of it as it already is of every credential above --
// checkResponseFromDecide places it only on the CheckResponse handed back
// to Envoy, never in an error string or a log line this process itself
// writes.
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

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stratium/internal/pdpgrpc"
)

// extauthzConfig is what runExtauthzCmd needs to serve Check: where to
// listen, plus the PDP address, agent identity, subject, and connect
// timeout every Decide call needs. The latter four sat unread by Task 1's
// Check, which called nothing -- loaded then rather than added only once
// Task 2 first needed them, so this config never had to change shape
// between the two tasks. This task is what starts reading them: PDPAddr is
// where runExtauthzCmd now dials the PDP client Check calls,
// AgentID/Subject become DecideRequest.AgentId/Subject on every request
// decideRequestFromCheck builds, and ConnectTimeout bounds that call the
// same way it bounds every other surface's own Decide call (hook.go,
// mcp_authorize.go).
//
// Every field is required, with no default, for the same reason hookConfig
// gives none (hook.go): a listener bound to a guessed address, or a later
// Decide call aimed at a guessed PDP, is worse than a process that refuses
// to start (config.go's requiredEnv doc comment states the general rule
// this repeats).
//
// There is deliberately no SessionFilePath field here, unlike hookConfig
// and sessionStartConfig -- see the package doc's NO SESSION FILE section
// for why: this surface's token arrives fresh on every Check call, in the
// request Envoy is forwarding, never from a file this process's own
// operator wrote ahead of time. There is also no ApprovalPollInterval or
// ApprovalTimeout, unlike hookConfig: this is a non-blocking surface (plan
// §M4) -- an escalation degrades straight to a deny plus a pending record
// rather than polling for a human, so there is nothing here to bound a wait
// for. That degrade lives in checkResponseFromDecide, not in this config --
// extauthzConfig needed no new field to serve it, then or now.
type extauthzConfig struct {
	ListenAddr     string
	PDPAddr        string
	AgentID        string
	Subject        string
	ConnectTimeout time.Duration
}

// loadExtauthzConfigFromEnv reads extauthzConfig from the environment, or
// returns an error naming every missing variable at once -- see
// loadHookConfigFromEnv (hook.go) for the identical convention this
// repeats, sharing config.go's requiredEnv/requiredDuration/
// missingConfigError rather than a fourth copy of the same presence-
// checking loop.
func loadExtauthzConfigFromEnv() (extauthzConfig, error) {
	var missing []string
	cfg := extauthzConfig{
		ListenAddr: requiredEnv("STRATIUM_PEP_EXTAUTHZ_LISTEN_ADDR", &missing),
		PDPAddr:    requiredEnv("STRATIUM_PEP_PDP_ADDR", &missing),
		AgentID:    requiredEnv("STRATIUM_PEP_AGENT_ID", &missing),
		Subject:    requiredEnv("STRATIUM_PEP_SUBJECT", &missing),
	}
	timeoutRaw := requiredEnv("STRATIUM_PEP_CONNECT_TIMEOUT", &missing)
	if len(missing) > 0 {
		return extauthzConfig{}, missingConfigError(missing)
	}

	timeout, err := requiredDuration("STRATIUM_PEP_CONNECT_TIMEOUT", timeoutRaw)
	if err != nil {
		return extauthzConfig{}, err
	}
	cfg.ConnectTimeout = timeout

	return cfg, nil
}

// runExtauthzCmd loads configuration, binds cfg.ListenAddr, and serves the
// Authorization service until Serve itself returns. Unlike every other
// runXCmd in this binary, this one does not return under normal operation:
// hook and session-start each do one thing and exit, mcp relays until its
// stdin closes, but extauthz is a long-running server for as long as Envoy
// is pointed at it.
//
// There is deliberately no signal-handling or graceful-shutdown wiring
// here: an unhandled SIGTERM kills the process outright. That is an
// acceptable default for THIS surface specifically, not a gap left for
// later -- a connection Envoy loses mid-request because this process died
// is a transport fault Envoy's own ext_authz configuration already has to
// handle for any number of ordinary reasons (a restart, a crash, a network
// blip), and this binary's job is to make sure that fault denies rather
// than silently allows, not to make the process itself unkillable. Whether
// this surface eventually wants a graceful drain is a question for
// whichever task first has a reason to care what happens to a request
// in-flight at shutdown -- Task 1 does not have one, since Check's only
// answer today is the same unconditional deny regardless of when it runs.
func runExtauthzCmd(stderr io.Writer) int {
	cfg, err := loadExtauthzConfigFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	// grpc.NewClient dials lazily -- the same non-blocking choice hook.go's
	// runHookCmd makes for the identical call -- so this succeeding proves
	// only that cfg.PDPAddr parses as a target, not that a PDP is actually
	// listening there yet. An unreachable PDP is a Check-time failure (every
	// Decide call denies on it, per the package doc's FAIL CLOSED section),
	// not a startup failure, the same way hook's own dial never blocks
	// startup on the PDP being up.
	conn, err := grpc.NewClient(cfg.PDPAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create PDP client: %s\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not listen on %s: %s\n", cfg.ListenAddr, err)
		return 1
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, &extauthzServer{
		client: pdpgrpc.NewPDPServiceClient(conn),
		cfg:    cfg,
	})

	// This process's own startup configuration, not request data -- see the
	// package doc's NEVER LOG REQUEST METADATA section, which this line does
	// not touch. Logged once, the same way cmd/stratium-pdp/main.go logs
	// cfg.TenantID and cfg.ListenAddr at startup. PDPAddr, AgentID, Subject,
	// and ConnectTimeout are all live, read on every Check call as of this
	// task (extauthzServer.cfg, above) -- this line gives an operator
	// debugging a misconfigured fleet the same startup visibility hook and
	// mcp already have into the identity and PDP address they enforce
	// against.
	_, _ = fmt.Fprintf(stderr, "stratium-pep: extauthz listening on %s (PDP %s, agent %s, subject %s, connect timeout %s)\n",
		cfg.ListenAddr, cfg.PDPAddr, cfg.AgentID, cfg.Subject, cfg.ConnectTimeout)

	if err := grpcServer.Serve(lis); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: extauthz server: %s\n", err)
		return 1
	}
	return 0
}

// extauthzServer implements authv3.AuthorizationServer. client is the PDP
// connection Check calls once decideRequestFromCheck has something worth
// sending; cfg supplies the agent identity stamped onto every such request
// (AgentID, Subject) and the timeout bounding the call (ConnectTimeout) --
// the same three pieces of configuration hook.go's runHook and
// mcp_authorize.go's mcpAuthorizer each thread through their own Decide
// calls, read here from extauthzConfig instead of hookConfig only because
// this surface has no session file to also carry (see the package doc's NO
// SESSION FILE section). UnimplementedAuthorizationServer is embedded for
// the forward compatibility its own doc comment asks implementations to
// provide (a future Authorization RPC this build does not know about fails
// clearly rather than failing to compile), unrelated to the two fields
// below.
type extauthzServer struct {
	authv3.UnimplementedAuthorizationServer

	client pdpgrpc.PDPServiceClient
	cfg    extauthzConfig
}

// requestMetadata is raw_input's JSON shape (plan §M3): the request's
// method, path, and headers, with every credential-bearing header already
// removed by extractBearerToken -- see that function's own doc comment for
// which headers that is and why. Nothing in this binary ever decodes
// raw_input again after decideRequestFromCheck builds it: the PDP receives
// it, and reads it, as opaque bytes, exactly like hook.go's tool_input and
// mcp_authorize.go's arguments (see the package doc). The json tags exist
// so this shape round-trips predictably for a test (or an auditor's own
// tooling reading the audit chain this ends up hashed into) -- not because
// anything in this file reads them back.
type requestMetadata struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// bearerPrefix is the one authorization scheme extractBearerToken accepts,
// matched exactly, case-sensitively: RFC 6750 spells the scheme "Bearer",
// and plan §M2 writes the header the same way. This is a different axis
// from the header NAME match below, which must fold case (HTTP header names
// are case-insensitive per RFC 7230) -- the scheme token is not a header
// name, no conformant client sends anything but this exact spelling, and no
// test here asks for anything wider.
const bearerPrefix = "Bearer "

// credentialHeaderNames is every HTTP header extractBearerToken treats as
// carrying live authority rather than descriptive request metadata, matched
// against an incoming header's name case-insensitively -- see that
// function's own doc comment for why case sensitivity here would be a strip
// that silently fails. authorization is plan §M2's own credential, and the
// value this function also reads to build DecideRequest.Token; cookie (RFC
// 6265) and proxy-authorization (RFC 7235) carry the identical kind of
// bearer authority by the same RFC-fixed meaning, just under a different
// name -- a session cookie or a credential aimed at an upstream proxy is
// exactly as dangerous sitting in raw_input as an Authorization value would
// be. The list stops at headers whose credential-bearing meaning is fixed
// by a standard: guessing further -- an X-Api-Key-shaped header, say --
// would be this server deciding a deployment's own custom auth scheme is
// security-relevant, which is a classification judgment, and Check has no
// authority to classify anything (see the package doc's D1 rule).
// TestCheck_RawInputPreservesNonCredentialHeaders defends the boundary this
// stops at: a header that merely LOOKS auth-related (x-auth-context) must
// still reach raw_input, not be swept up by an over-broad match.
var credentialHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"proxy-authorization": true,
}

// extractBearerToken reads headers (an AttributeContext_HttpRequest's own
// Headers map) for a bearer token, and in the same pass builds the map that
// becomes raw_input's own "headers" field with every credentialHeaderNames
// entry removed -- one loop, one place in this file that decides which
// headers count as a credential, rather than two lists (one for extraction,
// one for stripping) that could drift apart and strip a different set than
// the one actually read from.
//
// Header names are matched via strings.ToLower, never a direct map lookup
// on the key as sent: HTTP header names are case-insensitive (RFC 7230),
// and Envoy's own contract documents that it normally lower-cases the
// headers field's keys before this server ever sees them
// (AttributeContext_HttpRequest's own field doc) -- but "normally" is a
// property of Envoy's implementation, not a guarantee this function is
// entitled to lean on, and every intermediary between a caller and this
// server gets one chance to send a header this process must still
// recognize regardless of how it capitalized the name.
// TestExtractBearerToken_HeaderNameCaseDiffers_TokenStillFound and
// TestCheck_RawInputNeverCarriesAuthorization_AnyHeaderCasing both send a
// header this function would silently miss, or silently fail to strip, if
// it ever trusted that guarantee instead.
//
// An error means there is no credential here worth sending to the PDP at
// all: no authorization header, one that is not a Bearer challenge, or one
// whose token is empty once the scheme is removed (an "authorization:
// Bearer" header with nothing after it). token and stripped are both zero
// values in every error case -- there is no partial result a careless
// caller could mistake for a usable one.
func extractBearerToken(headers map[string]string) (token string, stripped map[string]string, err error) {
	stripped = make(map[string]string, len(headers))
	var authValue string
	found := false
	for name, value := range headers {
		lower := strings.ToLower(name)
		if credentialHeaderNames[lower] {
			if lower == "authorization" {
				authValue, found = value, true
			}
			continue
		}
		stripped[name] = value
	}

	if !found {
		return "", nil, errors.New("no authorization header")
	}
	if !strings.HasPrefix(authValue, bearerPrefix) {
		return "", nil, errors.New("authorization header is not a Bearer token")
	}
	token = strings.TrimPrefix(authValue, bearerPrefix)
	if token == "" {
		return "", nil, errors.New("authorization header carries an empty Bearer token")
	}
	return token, stripped, nil
}

// decideRequestFromCheck maps req to the DecideRequest Check sends the PDP,
// or an error naming why req cannot be mapped to one at all. The only two
// ways this function fails are the two extractBearerToken itself can fail
// with (no credential, or a malformed one): every other field req can carry
// maps unconditionally, because req's own Get* accessors are nil-safe all
// the way down -- a nil Attributes, Request, or Http yields "" for
// method/path and a nil headers map, never a panic. A CheckRequest with no
// HTTP attributes at all (Task 1's own TestCheck_NoDecisionLogicYet_
// DeniesEveryRequestUnconditionally fixture, still exercised today) is
// therefore not a third failure mode -- it is simply a request with an
// empty path and no headers, which already fails the SAME "no authorization
// header" check extractBearerToken applies to any other request.
//
// declared_tier is never set on the returned request, deliberately, the
// same reasoning as hook.go's and mcp_authorize.go's identical omission
// (see the package doc): this server has no real tier to declare, and a
// guessed one only creates a chance to be wrong that the PDP's own
// re-derivation (from tool and raw_input, against the tenant's catalog)
// does not need. resource is left unset for the same reason those two
// files leave it unset: nothing in this repo extracts it locally anymore
// (spec §4.4.2 T3).
func decideRequestFromCheck(req *authv3.CheckRequest, agentID, subject string) (*pdpgrpc.DecideRequest, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()

	token, headers, err := extractBearerToken(httpReq.GetHeaders())
	if err != nil {
		return nil, err
	}

	rawInput, err := json.Marshal(requestMetadata{
		Method:  httpReq.GetMethod(),
		Path:    httpReq.GetPath(),
		Headers: headers,
	})
	if err != nil {
		// Method and path are plain strings and headers is a flat
		// map[string]string with no cycles -- Marshal cannot fail for this
		// shape in practice. Reported rather than assumed away, the same
		// caution jsonrpcErrorFrame's own marshal takes in
		// mcp_authorize.go for an equally can't-really-fail encode.
		return nil, fmt.Errorf("could not serialize request metadata: %w", err)
	}

	return &pdpgrpc.DecideRequest{
		AgentId:  agentID,
		Subject:  subject,
		Tool:     httpReq.GetPath(), // M1: the request path IS the tool identity.
		RawInput: string(rawInput),
		Token:    token,
	}, nil
}

// approvalIDHeader is the response header name checkResponseFromDecide
// attaches a pending approval's id to, on a denial degraded from
// EFFECT_ESCALATE (E5/M4). No "x-" prefix: RFC 6648 deprecates minting new
// x-prefixed headers, and there is no ambiguity here to hedge against --
// stratium-pep both defines this header and is the only thing that ever
// sets it. Lowercase because HTTP header names are case-insensitive and
// this is the spelling this file itself sends, the same convention
// extractBearerToken's own doc comment already applies to every header name
// this file reads.
const approvalIDHeader = "stratium-approval-id"

// Check maps req to a DecideRequest (decideRequestFromCheck, per plan
// §§M1-M3), calls the PDP with it when that mapping succeeds, and maps
// whatever comes back onto the one contract Envoy's ext_authz filter
// understands (checkResponseFromDecide, denyCheckResponse, okCheckResponse,
// below) -- the response-mapping half of this surface Task 1 and Task 2
// both deliberately left denying unconditionally until it existed. See the
// package doc's RESPONSE MAPPING section for why that boundary held for two
// tasks and what closes it here.
//
// Task 2's own TestCheck_ValidCredential_StillDeniesUntilTask3MapsTheResponse
// existed specifically to prove a well-formed request the PDP allows still
// denied; that test is gone now, not merely widened, because its premise no
// longer holds -- TestCheck_Allow_ReturnsOkResponse proves the replacement
// claim.
//
// The one branch that changed observable behavior from Task 1 to Task 2
// still holds unchanged here: a request this server cannot extract a
// credential from -- no authorization header, or one that is not a
// well-formed Bearer challenge -- denies WITHOUT ever calling client.Decide
// (plan §M2, spec K4: there is no fallback credential to try instead, so a
// PDP round trip could not answer anything a missing credential does not
// already answer). TestCheck_MissingAuthorizationHeader_DeniesWithoutContactingPDP
// and TestCheck_MalformedAuthorizationHeader_DeniesWithoutContactingPDP both
// assert this against the PDP's own received-call count, not merely against
// Check's response.
//
// Returning (resp, nil) rather than (nil, status.Error(codes.PermissionDenied, ...))
// for every outcome -- including a failed PDP call -- is the same
// deliberate choice Task 1's version made, for the same reason: ext_authz
// communicates a policy denial through CheckResponse.Status (an
// application-level "the call succeeded, and the answer is deny"), and
// reserves a returned Go error for the RPC itself failing -- a distinction
// Envoy's own failure_mode_allow setting treats very differently (a failed
// RPC can be configured to fail open; a well-formed PERMISSION_DENIED
// response cannot). An unreachable PDP, and separately a PDP that answers
// with an application-level error, are both folded into that SAME
// ordinary-denial shape, exactly like a missing credential or a policy
// DENY, never surfaced as a transport-level Go error -- doing the latter
// would hand failure_mode_allow precisely the fail-open option this rule
// exists to take away from it.
// TestCheck_UnreachablePDP_DeniesAsOrdinaryResponse_NotTransportError and
// TestCheck_PDPError_DeniesAsOrdinaryResponse assert the two cases
// separately: a mutation could plausibly catch one and not the other, since
// they take different branches inside describeRPCError (hook.go).
func (s *extauthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	decideReq, err := decideRequestFromCheck(req, s.cfg.AgentID, s.cfg.Subject)
	if err != nil {
		return denyCheckResponse(fmt.Sprintf("stratium-pep: %s", err), ""), nil
	}

	// Derived from ctx, not context.Background(): unlike hook.go and
	// mcp_authorize.go, which have no incoming RPC context to chain from
	// (a CLI invocation, and a stdio relay, respectively), Check IS a gRPC
	// handler with a real caller-supplied ctx already carrying Envoy's own
	// deadline/cancellation. Bounding it further with ConnectTimeout keeps
	// this call from outliving that budget; chaining from ctx instead of
	// discarding it means a caller that hangs up mid-Check (Envoy itself
	// timing out, a client disconnect) cancels the outbound Decide call
	// too, rather than leaving it running for a response nothing is still
	// waiting for.
	callCtx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
	defer cancel()

	resp, decideErr := s.client.Decide(callCtx, decideReq)
	if decideErr != nil {
		// describeRPCError/agentOrDelegationUnknownMsg (hook.go) are shared
		// across every surface that calls Decide with this same
		// agent_id/subject/token shape, so an operator sees one
		// vocabulary for "PDP unreachable" or "unknown agent/delegation"
		// no matter which of hook, mcp, or extauthz hit it.
		return denyCheckResponse(fmt.Sprintf("stratium-pep: %s", describeRPCError(decideErr, agentOrDelegationUnknownMsg)), ""), nil
	}

	return checkResponseFromDecide(resp), nil
}

// checkResponseFromDecide is the response-side counterpart to
// decideRequestFromCheck: it maps what the PDP decided onto the
// CheckResponse Envoy understands, and is the only place in this file that
// does. It never inspects req, tool, or raw_input -- only resp -- because by
// the time Check calls this, the PDP has already made the only
// classification/decision this binary is allowed to make (the package
// doc's D1 rule): this function transcribes an answer, it does not compute
// one, and it overrides nothing the PDP decided in either direction.
//
// EFFECT_ALLOW becomes okCheckResponse(). Everything else -- EFFECT_DENY,
// EFFECT_ESCALATE degraded per E5, and an entirely unset Effect -- becomes a
// PERMISSION_DENIED denyCheckResponse. pdpgrpc.DegradeEscalateToDeny (Phase
// 5; this is its first real caller) supplies exactly the first of those two
// facts: deny is literally "not ALLOW," and this function asks it no second
// question. TestCheck_UnsetEffect_DeniesAsOrdinaryResponse asserts the
// zero-value case specifically over a real gRPC round trip -- a
// DecideResponse whose Effect field a fake PDP never sets, marshaled, sent,
// and unmarshaled for real -- rather than trusting the proto's own
// doc-comment claim that an unset field decodes to EFFECT_DENY; the wire
// either holds that invariant or it does not, and that test checks rather
// than assumes it does.
//
// What DegradeEscalateToDeny does NOT decide is which of DENY or a degraded
// ESCALATE this is -- a plain bool for "should this deny" was the entire
// brief it was written to, and reason-framing was never part of that. This
// function reads resp.GetEffect() itself for that, rather than inferring
// "this was an escalation" from approvalID being non-empty a second time:
// DecideResponse.approval_id's own doc comment promises the field is
// populated only on EFFECT_ESCALATE, and the real Decide implementation
// upholds that structurally (server.go's Decide sets it from a local
// newApprovalID that stays "" on every path but a fresh escalation) -- but
// this file does not get to assume a promise about the OTHER end of this
// RPC holds, any more than it gets to assume Effect's own zero-value
// promise holds without checking. A DENY that happened to carry a stray
// approval id -- impossible from this repo's own PDP, not impossible from
// this function's own type signature -- must still read as an ordinary
// denial, not a misleading "pending, wait for approval" message pointing an
// operator at an id that names nothing escalated.
// TestCheckResponseFromDecide_DenyWithStrayApprovalID_NotTreatedAsEscalation
// asserts exactly this: a mutation nobody asked for.
//
// A degraded ESCALATE's reason and approvalID both go on the response --
// see denyCheckResponse's own doc comment for the header, and this
// function's own reason text below for the body -- because "the approval
// must be findable" has two different readers with two different needs. A
// header is what a retry tool or gateway can extract deterministically, key
// by key, without parsing prose that might be reworded later; the body is
// what a human staring at a captured 403 -- in a browser, a curl
// transcript, a log line that only kept the body -- can read without first
// knowing to look for a header named stratium-approval-id. Neither channel
// alone serves both readers, so this sends both: the same
// self-describing-without-a-convention-memorized reasoning
// denyCheckResponse's own doc comment already applies to Status versus
// DeniedResponse, applied a second time to this one field.
//
// A PDP that escalates without attaching an id (approvalID == "" despite
// EFFECT_ESCALATE) has violated DecideResponse.approval_id's own contract
// and left nothing to find -- this denies with a reason that says so,
// mirroring hook.go's resolveApproval, which defends the identical shape
// for the blocking surfaces (see its own doc comment), rather than sending
// a pending-approval message that names an id which does not exist.
func checkResponseFromDecide(resp *pdpgrpc.DecideResponse) *authv3.CheckResponse {
	deny, approvalID := pdpgrpc.DegradeEscalateToDeny(resp)
	if !deny {
		return okCheckResponse()
	}

	if resp.GetEffect() == pdpgrpc.Effect_EFFECT_ESCALATE {
		if approvalID == "" {
			return denyCheckResponse(fmt.Sprintf(
				"stratium-pep: PDP escalated this action but returned no approval id to attach; denying (PDP reason: %s)",
				resp.GetReason()), "")
		}
		reason := fmt.Sprintf(
			"stratium-pep: this action requires approval and is pending (approval id %s); a retry after approval succeeds -- PDP: %s",
			approvalID, resp.GetReason())
		return denyCheckResponse(reason, approvalID)
	}

	// EFFECT_DENY, and any value this build does not recognize (including
	// entirely unset -- see this function's own doc comment). Passed
	// through unprefixed, exactly as the PDP wrote it: this is the PDP's
	// own verdict text, not a local diagnostic this process is
	// synthesizing, and the two must stay visually distinguishable to a
	// human reading the denial -- the same convention hook.go's own default
	// DENY case follows, for the same reason (see its own doc comment).
	return denyCheckResponse(resp.GetReason(), "")
}

// okCheckResponse is the ALLOW mapping: an OkResponse carrying no header or
// body content of its own. This server never asks Envoy to rewrite,
// inject, or strip anything from a forwarded request -- it has no
// authority to (the package doc's D1 rule again: this server classifies
// nothing, so it has nothing of its own to add to an allowed request
// either) -- so an empty OkHttpResponse is not a placeholder for
// functionality left out; it is the complete, correct answer.
func okCheckResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(rpccode.Code_OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{},
		},
	}
}

// denyCheckResponse builds an ext_authz denial carrying reason in both the
// top-level google.rpc.Status (what the Authorization service contract
// itself treats as the allow/deny signal -- any Status.Code other than OK
// denies, per CheckResponse's own doc comment) and in a DeniedHttpResponse
// (what Envoy's HTTP filter forwards to the downstream caller as the actual
// denied response body). Setting both, rather than relying on Envoy's
// documented default (403, when DeniedResponse.Status is left unset), is
// what makes a captured response self-describing to a human or a test
// reading it directly, without first needing to know that default by
// heart.
//
// approvalID, when non-empty, is also attached as a dedicated response
// header (approvalIDHeader) on the same DeniedHttpResponse -- see
// checkResponseFromDecide's own doc comment for why a degraded ESCALATE
// needs a channel a retry tool can read deterministically, on top of the
// prose reason that already carries the id for a human. Every other caller
// in this file passes "" and gets back exactly the shape Task 1 and Task 2
// already had. This signature grew one parameter for the one case that
// needed it, rather than gaining a second, near-identical response
// constructor alongside this one -- the risk this function's own original
// comment already named, before there was a second case to weigh it
// against.
func denyCheckResponse(reason, approvalID string) *authv3.CheckResponse {
	denied := &authv3.DeniedHttpResponse{
		Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
		Body:   reason,
	}
	if approvalID != "" {
		denied.Headers = []*corev3.HeaderValueOption{
			{Header: &corev3.HeaderValue{Key: approvalIDHeader, Value: approvalID}},
		}
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code:    int32(rpccode.Code_PERMISSION_DENIED),
			Message: reason,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: denied,
		},
	}
}
