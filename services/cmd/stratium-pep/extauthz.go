// extauthz.go implements the "extauthz" subcommand: a gRPC server answering
// envoy.service.auth.v3.Authorization/Check, the contract Envoy's ext_authz
// filter calls, synchronously, on every request it fronts, before deciding
// whether to forward it. Every other mode in this binary is the PEP sitting
// beside the thing it enforces -- a hook Claude Code invokes, a proxy the
// agent's harness launches in place of a real MCP server. extauthz is the
// PEP sitting beside Envoy instead: Envoy calls Check, and this server
// answers allow or deny.
//
// TASK 2 ADDITIONS. Task 1 left Check reading nothing: no code path could
// produce an honest ALLOW yet, so the only answer that did not lie about
// what was decided was an unconditional deny. This task adds the request
// side of a real decision -- decideRequestFromCheck extracts the tool
// identity, the bearer token, and a credential-stripped raw_input from a
// CheckRequest (plan §§M1-M3) -- and Check now calls the PDP with whatever
// that produces, when it produces anything at all: a request with no usable
// credential denies before the PDP is ever dialed (M2, K4 -- see
// decideRequestFromCheck's and extractBearerToken's own doc comments). Check
// still never returns an honest ALLOW, on purpose: turning what the PDP
// actually said into an OkResponse, a DENY carrying its reason, or an
// ESCALATE degraded to a pending approval is Task 3's addition, not this
// one's -- see Check's own doc comment for why this task's version denies
// even after a successful PDP round trip that said yes.
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
// for. That degrade is Task 3's addition, not this one's.
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

// Check maps req to a DecideRequest (decideRequestFromCheck, per plan
// §§M1-M3) and, when that mapping succeeds, calls the PDP with it -- but it
// still answers every request with a deny, exactly like Task 1's version,
// regardless of what the PDP says or whether it could be reached at all.
// That is deliberate, not an oversight left for later: turning
// EFFECT_ALLOW into an OkResponse, EFFECT_DENY into a PERMISSION_DENIED
// carrying the PDP's own reason, and EFFECT_ESCALATE into a degraded
// deny-plus-pending-approval is Task 3's addition (see the package doc's
// TASK 2 ADDITIONS section) -- this function's job ends at proving the
// request this server builds and sends is correct, never at acting on what
// comes back. Returning ALLOW from here, even once, for any reason, would
// be exactly the open-proxy failure Task 1's own doc comment describes --
// calling the PDP does not change that rule, it just means this task can
// prove the call it makes is the right one.
// TestCheck_ValidCredential_StillDeniesUntilTask3MapsTheResponse asserts
// this even when the PDP itself answers EFFECT_ALLOW.
//
// The one branch that changes observable behavior from Task 1: a request
// this server cannot extract a credential from -- no authorization header,
// or one that is not a well-formed Bearer challenge -- denies WITHOUT ever
// calling client.Decide (plan §M2, spec K4: there is no fallback credential
// to try instead, so a PDP round trip could not answer anything a missing
// credential does not already answer).
// TestCheck_MissingAuthorizationHeader_DeniesWithoutContactingPDP and
// TestCheck_MalformedAuthorizationHeader_DeniesWithoutContactingPDP both
// assert this against the PDP's own received-call count, not merely
// against Check's response -- a build that let a stray call through before
// denying anyway would still pass a test that only inspected the
// CheckResponse.
//
// Returning (resp, nil) rather than (nil, status.Error(codes.PermissionDenied, ...))
// for every outcome -- including a failed PDP call -- is the same
// deliberate choice Task 1's version made, for the same reason: ext_authz
// communicates a policy denial through CheckResponse.Status (an
// application-level "the call succeeded, and the answer is deny"), and
// reserves a returned Go error for the RPC itself failing -- a distinction
// Envoy's own failure_mode_allow setting treats very differently (a failed
// RPC can be configured to fail open; a well-formed PERMISSION_DENIED
// response cannot). An unreachable PDP is folded into that SAME
// ordinary-denial shape, exactly like a missing credential or a policy
// DENY, never surfaced as a transport-level Go error -- doing the latter
// would hand failure_mode_allow precisely the fail-open option this rule
// exists to take away from it.
func (s *extauthzServer) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	decideReq, err := decideRequestFromCheck(req, s.cfg.AgentID, s.cfg.Subject)
	if err != nil {
		return denyCheckResponse(fmt.Sprintf("stratium-pep: %s", err)), nil
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
	reason := "stratium-pep: extauthz has no response-mapping logic yet (Task 2 skeleton); denying unconditionally"
	if _, decideErr := s.client.Decide(callCtx, decideReq); decideErr != nil {
		// describeRPCError/agentOrDelegationUnknownMsg (hook.go) are shared
		// across every surface that calls Decide with this same
		// agent_id/subject/token shape, so an operator sees one
		// vocabulary for "PDP unreachable" or "unknown agent/delegation"
		// no matter which of hook, mcp, or extauthz hit it.
		reason = fmt.Sprintf("stratium-pep: %s", describeRPCError(decideErr, agentOrDelegationUnknownMsg))
	}
	return denyCheckResponse(reason), nil
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
// heart. Parameterized by reason rather than hardcoding Task 1's own
// skeleton text is what should let Task 3 reuse this unchanged for a real
// PDP denial reason, rather than this function growing a second, near-
// identical copy of itself once one exists.
func denyCheckResponse(reason string) *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{
			Code:    int32(rpccode.Code_PERMISSION_DENIED),
			Message: reason,
		},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   reason,
			},
		},
	}
}
