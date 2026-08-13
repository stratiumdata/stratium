// extauthz.go implements the "extauthz" subcommand: a gRPC server answering
// envoy.service.auth.v3.Authorization/Check, the contract Envoy's ext_authz
// filter calls, synchronously, on every request it fronts, before deciding
// whether to forward it. Every other mode in this binary is the PEP sitting
// beside the thing it enforces -- a hook Claude Code invokes, a proxy the
// agent's harness launches in place of a real MCP server. extauthz is the
// PEP sitting beside Envoy instead: Envoy calls Check, and this server
// answers allow or deny.
//
// TASK 1 SCOPE. This file is the server, its dependency, and its
// configuration -- nothing that reads a CheckRequest's contents and nothing
// that calls the PDP. Check denies every request it receives,
// unconditionally, regardless of what is in it: there is not yet a code
// path that could produce an honest ALLOW, and a skeleton that allows by
// default is an open proxy the moment it is reachable, not a placeholder to
// tighten up later. See runExtauthzCmd's own doc comment for the
// fail-closed half of the same rule at startup, and Check's own doc comment
// for why denying unconditionally is the only answer a server with no
// decision logic can give without lying about what it decided. Extracting a
// CheckRequest's method/path/token and mapping a real PDP decision back to
// a CheckResponse are Task 2 and Task 3's additions to this same file, not
// this one's.
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
// verification in Phase 9 Task 4. Reading that header is Task 2's addition
// to this file, not this task's -- Check does not read the request at all
// yet, see its own doc comment.
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
// request). Task 1 does not parse a CheckRequest at all, so this rule costs
// nothing yet, but it binds every task after this one exactly as hook.go's
// package doc binds raw_input and mcp.go's binds frame contents: nothing
// derived from a request this server receives may ever reach stderr, a log
// line, or an error string. The one line this file does write to stderr
// (runExtauthzCmd's startup line) is this process's own operator-supplied
// configuration, never anything from a Check call.
package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	rpccode "google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
)

// extauthzConfig is what runExtauthzCmd needs to serve Check: where to
// listen, and -- unused by Task 1's Check, which calls nothing, but
// required now rather than added when Task 2/3 first need it, so loading
// this config never has to change shape again -- the PDP address, agent
// identity, subject, and connect timeout every later Decide call will need.
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

	lis, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not listen on %s: %s\n", cfg.ListenAddr, err)
		return 1
	}

	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, &extauthzServer{})

	// This process's own startup configuration, not request data -- see the
	// package doc's NEVER LOG REQUEST METADATA section, which this line does
	// not touch. Logged once, the same way cmd/stratium-pdp/main.go logs
	// cfg.TenantID and cfg.ListenAddr at startup. It also gives PDPAddr,
	// AgentID, Subject, and ConnectTimeout -- all unread by Check until Task
	// 2/3 -- a real production purpose in this task rather than sitting in
	// extauthzConfig unused until then: an operator debugging a
	// misconfigured fleet wants this line before those tasks land, not only
	// after.
	_, _ = fmt.Fprintf(stderr, "stratium-pep: extauthz listening on %s (PDP %s, agent %s, subject %s, connect timeout %s)\n",
		cfg.ListenAddr, cfg.PDPAddr, cfg.AgentID, cfg.Subject, cfg.ConnectTimeout)

	if err := grpcServer.Serve(lis); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: extauthz server: %s\n", err)
		return 1
	}
	return 0
}

// extauthzServer implements authv3.AuthorizationServer. It holds nothing
// yet: Task 1's Check needs no PDP client, no config, and no state, so
// there is nothing here for Task 2/3 to find already stubbed out --
// UnimplementedAuthorizationServer is embedded only for the forward
// compatibility its own doc comment asks implementations to provide (a
// future Authorization RPC this build does not know about fails clearly
// rather than failing to compile), not because this task needs it for
// anything Check itself does.
type extauthzServer struct {
	authv3.UnimplementedAuthorizationServer
}

// Check answers every request with the same unconditional deny. This is
// Task 1's entire decision logic, and it is not a placeholder standing in
// for "call the PDP" -- it is the one answer a server with no decision
// logic at all can give without lying about what it decided. Returning OK
// here, even temporarily, would make this server an open proxy from the
// moment it is reachable: anything Envoy fronts would pass every request
// through unconditionally until Task 2 and Task 3 land, and "ships for a
// while as an open proxy" is not a phase this project's fail-closed rule
// allows (see the package doc's FAIL CLOSED section).
//
// Nothing here reads req -- not its path, not its method, not any header,
// which is what the blank identifier below enforces structurally rather
// than merely by promise. There is no path allowlist, health-check
// shortcut, or method-based shortcut in this function, and there must
// never be one: any of those would be spec defect D1 (classifying a
// request's meaning locally instead of asking the PDP) even before this
// surface ever calls the PDP once. TestCheck_RequestShapeIsIrrelevant_StillDenies
// (extauthz_test.go) proves a request shaped exactly like a health check
// gets no special treatment.
//
// Returning (resp, nil) rather than (nil, status.Error(codes.PermissionDenied, ...))
// is deliberate, not incidental: ext_authz communicates a policy denial
// through CheckResponse.Status (an application-level "the call succeeded,
// and the answer is deny"), and reserves a returned Go error for the RPC
// itself failing -- a distinction Envoy's own failure_mode_allow setting
// treats very differently (a failed RPC can be configured to fail open; a
// well-formed PERMISSION_DENIED response cannot). Task 1's Check cannot
// fail -- it does no I/O, reads nothing -- so this is the only branch that
// exists, but the shape it returns is the one every later task must keep:
// a transport-level Go error here is reserved for a transport-level fault,
// never for an ordinary denial.
func (s *extauthzServer) Check(_ context.Context, _ *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	return denyCheckResponse("stratium-pep: extauthz has no authorization decision logic yet (Task 1 skeleton); denying unconditionally"), nil
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
