// mcp_authorize.go is mcp.go's interceptAgentFrame grown up: everything one tools/call decision
// needs beyond the relay mechanics mcp.go itself owns -- turning a frame into a DecideRequest,
// calling the PDP, and turning its answer into either "forward the original frame" or a JSON-RPC
// error correlated to the request's own id. See mcp.go's package doc for the relay properties this
// must not disturb (id fidelity, no serialization, fail-closed on transport faults), and hook.go's
// package doc for the classification boundary this file draws identically: an MCP tool name is
// never assumed to mean anything by itself, and -- after spec §4.4.2 T3 deleted this file's own
// field-name lookups alongside hook.go's normalize.go/resource.go/toolVerbs -- nothing here inspects
// a tool's arguments at all. The request this file builds carries only the tool name and the
// arguments verbatim, as raw_input; everything else the PDP once received as a caller's claim
// (verb, normalized_input, resource) it now derives itself, server-side, from the tenant's own
// tool_catalog row for that tool (internal/authz.ExtractFromCatalog / ApplyExtraction) when one
// exists, exactly as it does for hook.go's requests.
//
// EVERY REQUEST THIS FILE BUILDS OMITS declared_tier, THE SAME AS hook.go's. The PDP re-derives the
// tier from tool, raw_input, and the tenant's own catalog regardless of what a caller claims, so a
// caller that has no real tier to declare (this proxy, exactly like the hook, never does) gains
// nothing by guessing and risks exactly the defect this whole binary exists not to reintroduce (D1)
// if a future edit ever adds one "just to be helpful." TestDecideAndRelay_RequestCarriesRawInputAndNoDeclaredTier
// asserts this on the wire, mirroring hook_test.go's identical assertion for the other surface.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// mcpErrorCodeAuthorizationDenied is this proxy's JSON-RPC error code for a tools/call the PDP
// denied, failed to approve, or that could not be evaluated at all (an unreachable PDP, a missing
// session file -- every fail-closed path in decideAndRelay uses this same code; the agent is told
// WHY in the error's message, never via a different code per failure mode, matching hook.go's own
// single deny path -- see writeDeny -- for the same reasons).
//
// JSON-RPC 2.0 reserves -32768..-32000 for predefined errors, and MCP's own specification further
// partitions -32000..-32099 for itself: -32000..-32019 is legacy (new codes MUST NOT be allocated
// there), and -32020..-32099 is reserved exclusively for codes the MCP spec itself defines.
// Inventing a code anywhere in -32000..-32099 -- -32001 would have been the obvious first guess --
// would violate that reservation even though it is not one of the five standard JSON-RPC codes.
// -31003 sits outside the entire reserved block, following the informal but documented -3Nxxx
// per-category convention several MCP server implementations use for application-defined errors
// (authentication/authorization cluster around -31xxx). The standard -32603 Internal Error was
// deliberately not reused for this: that code tells a client "the server broke," and the whole
// point of returning a real JSON-RPC error here instead of some other shape is so an agent can tell
// "you may not do this" apart from a crash -- reusing Internal Error would erase exactly that
// distinction on the one axis (the code) a client is likely to branch on programmatically, even with
// a message field that says otherwise.
const mcpErrorCodeAuthorizationDenied = -31003

// toolsCallFrame is the subset of a tools/call request this file reads: id (to correlate a denial,
// or simply ride along unexamined inside the forwarded frame on ALLOW) and params.name/
// params.arguments (to build a DecideRequest). Nothing else -- jsonrpc, method itself -- matters
// here: frameMethod (mcp.go) has already confirmed the frame is a well-formed JSON object and named
// its method before intercept ever sees it, and this file never re-validates that.
//
// ID is json.RawMessage, not string/int/interface{}, for the same reason frameMethod's own doc
// comment gives for never decoding an id through a Go type: unmarshaling a JSON number into
// interface{} yields a float64 that does not round-trip exactly for every integer, and deny's
// response must carry back the exact bytes this request arrived with, not a re-encoded
// approximation of them.
type toolsCallFrame struct {
	ID     json.RawMessage `json:"id"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

// jsonrpcErrorFrame is the JSON-RPC 2.0 error response shape this file ever constructs -- the ONLY
// frame this proxy authors itself rather than relays unexamined bytes for; see mcp.go's package doc
// for why every OTHER frame is handled as opaque bytes instead of a typed struct. ID stays
// json.RawMessage all the way to the wire: json.Marshal emits a RawMessage field's bytes verbatim,
// so the id this proxy invented for itself here is never the point -- it is always the caller's own
// id, carried through, not reconstructed.
type jsonrpcErrorFrame struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Error   jsonrpcErrorObj `json:"error"`
}

type jsonrpcErrorObj struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpAuthorizer holds what every tools/call decision needs, built once per runMCP call and reused
// for every frame in that session: the PDP client and the identity/timing configuration hook.go's
// own enforcement path already uses (cfg is a hookConfig value, not a parallel mcp-only shape --
// see the task report for why reusing the type, rather than inventing a second one with the same
// seven fields, was the right call), cacheCfg for how long a cached decision may still be served
// (cache.go's cacheConfig, loaded once by runMCPCmd exactly like cfg already is, not re-read per
// frame), cache for the decisions themselves, and the two destinations a decision can write to.
//
// cache is created empty by runMCP and lives exactly as long as this process: it holds only
// decisions this process itself received from the PDP, and nothing is ever loaded into it from
// disk (cache.go's package doc, "Memory only"). It is shared by every decideAndRelay goroutine and
// does its own locking.
//
// Both writers are expected to already serialize concurrent callers (see mcp.go's syncWriter) --
// this struct does not add its own locking, because relayDirection's own loop-driven writes to
// upstreamIn (every non-tools/call frame) share the SAME destination as this struct's writes and
// must be serialized against those too, not merely against each other.
type mcpAuthorizer struct {
	client     pdpgrpc.PDPServiceClient
	cfg        hookConfig
	cacheCfg   cacheConfig
	cache      *decisionCache
	upstreamIn io.Writer
	agentOut   io.Writer

	// wg tracks every decideAndRelay goroutine this authorizer has started but not yet finished.
	// runMCP waits on it before returning, for the same reason it already waits on its own two
	// relay goroutines: nothing may still be touching upstreamIn/agentOut once the caller believes
	// the relay session is over.
	wg sync.WaitGroup
}

// intercept is relayDirection's agent->upstream hook -- interceptAgentFrame's Task-1 placeholder,
// replaced by this method value. Every method but tools/call returns immediately, unchanged,
// exactly like Task 1's version did for everything. tools/call is the one exception, and even it
// returns immediately: the actual decision runs on its own goroutine
// (decideAndRelay) precisely so a slow PDP round trip or an escalation wait can never block any
// OTHER frame queued behind it in this direction -- see mcp.go's package doc CONCURRENCY note, and
// TestDecideAndRelay_ConcurrentToolsCalls_DoNotSerialize for the property this exists to hold.
// Returning nil here reuses relayDirection's existing "nothing to relay FROM THIS CALL" convention
// (a malformed frame already takes this same path, one level up) -- it does not mean the frame is
// dropped, only that this function is not the one relaying it.
func (a *mcpAuthorizer) intercept(method string, line []byte) []byte {
	if !mcpMethodIsDecided(method) {
		return line
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if method == "tools/call" {
			a.decideAndRelay(line)
		} else {
			a.decideMethodAndRelay(method, line)
		}
	}()
	return nil
}

// mcpMethodIsDecided reports whether the PDP is asked before a request with
// this method reaches the MCP server. Besides tools/call these are the
// requests that hand the agent a server's data: a resource's contents, now or
// on every change, and a prompt's text. Each is decided as a tool named after
// its method, with the request's params as its input, so a delegation that
// does not list "resources/read" refuses it. Listing methods are not decided,
// as tools/list is not.
//
// ponytail: a server could name a tool "resources/read", and a grant for that
// tool would then cover reading resources. Give the methods a name no tool
// can have if that ever matters.
func mcpMethodIsDecided(method string) bool {
	switch method {
	case "tools/call", "resources/read", "resources/subscribe", "prompts/get":
		return true
	}
	return false
}

// decideMethodAndRelay is decideAndRelay for a decided method other than
// tools/call.
func (a *mcpAuthorizer) decideMethodAndRelay(method string, line []byte) {
	var frame struct {
		ID     json.RawMessage `json:"id"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(line, &frame); err != nil || len(frame.Params) == 0 {
		a.deny(frame.ID, "stratium-pep: malformed "+method+": params are required")
		return
	}
	if ok, reason := a.authorize(context.Background(), method, string(frame.Params)); !ok {
		a.deny(frame.ID, reason)
		return
	}
	a.forward(line)
}

// decideAndRelay is the whole of one tools/call decision: parse the frame's id/tool/arguments,
// build a DecideRequest exactly like hook.go's runHook does for its own surface (same field
// derivation, same fail-closed defaults), call the PDP, and either forward the ORIGINAL frame bytes
// unchanged to upstream (ALLOW, including an ESCALATE that resolves to ALLOW) or write a JSON-RPC
// error correlated to id back to the agent (every other outcome, including one this file cannot
// even identify a tool for). Runs on its own goroutine -- see intercept's doc comment for why -- so
// nothing it does may assume it is the only such call in flight.
func (a *mcpAuthorizer) decideAndRelay(line []byte) {
	var frame toolsCallFrame
	if err := json.Unmarshal(line, &frame); err != nil || frame.Params.Name == "" {
		// A request with no id is a notification: deny has nowhere to send an
		// error and drops it, which is the fail-closed answer for a call that
		// could not be decided.
		a.deny(frame.ID, "stratium-pep: malformed tools/call: params.name is required")
		return
	}
	if ok, reason := a.authorize(context.Background(), frame.Params.Name, string(frame.Params.Arguments)); !ok {
		a.deny(frame.ID, reason)
		return
	}
	a.forward(line)
}

// authorize is the decision itself, with no transport in it: the session
// file, the cache, the PDP call, one token reissue, and the wait on an
// approval. decideAndRelay (stdio) and extmcpServer.CheckRequest
// (extmcp.go) both enforce exactly what this returns, so the two surfaces
// cannot drift. ok is true only on an allow; reason is set on every refusal.
func (a *mcpAuthorizer) authorize(ctx context.Context, tool, rawInput string) (ok bool, reason string) {
	// Read fresh on THIS call, deliberately, exactly as hook.go's runHook does and for the same
	// reason (see loadSessionFile's own doc comment and session_file.go): mcp is a long-lived
	// process handling many tool calls over one session, not exec'd fresh per call the way hook is,
	// which makes caching this across calls a MORE tempting shortcut here than it ever was for
	// hook, not a less dangerous one -- a cached token or delegation id would mean a revocation
	// takes effect only after this process restarts rather than on the very next tool call. sess
	// stays in scope past this check, unlike before Phase 9 Task 4: it is now the only source for
	// the token and delegation id the request below and a possible reissue use, not merely this
	// binary's own local fail-closed gate on "a session was actually started" -- and the only
	// source consultCache (local_cache.go) accepts for the cache key and the token-expiry check.
	sess, err := loadSessionFile(a.cfg.SessionFilePath)
	if err != nil {
		return false, fmt.Sprintf("stratium-pep: %s", err)
	}

	// mcp is the one surface that consults the decision cache -- see local_cache.go's own package
	// doc for the boundary this call is part of enforcing structurally. now is captured once and
	// reused below for storeCacheResult's own CachedAt. On a hit, a.client.Decide is never called
	// at all. The cache is this process's own memory (a.cache); the session file above is still
	// re-read per call, so an expired or replaced token takes effect on the very next call.
	now := time.Now()
	if entry, hit := consultCache(a.cache, a.cacheCfg.StalenessWindow, sess, tool, rawInput, now); hit {
		switch entry.Decision {
		case pdpgrpc.Effect_EFFECT_ALLOW:
			return true, ""
		default:
			// A default, not an explicit DENY, case: cacheEntryUsable already
			// refuses to report a hit for an ESCALATE entry, so this is reached
			// only by a cached DENY in practice, but nothing this function cannot
			// positively identify as ALLOW may ever be treated as one.
			return false, cacheHitDenyReason
		}
	}

	req := &pdpgrpc.DecideRequest{
		AgentId:  a.cfg.AgentID,
		Subject:  a.cfg.Subject,
		Tool:     tool,
		RawInput: rawInput,
		Token:    sess.GetToken(),
		// Verb, NormalizedInput, Resource: none of these exist on the wire
		// (Verb, NormalizedInput) or are ever set here (Resource) anymore --
		// see this file's own package doc. DeclaredTier: deliberately never
		// set -- see this file's own package doc and hook.go's; the
		// reasoning is identical for both surfaces.
	}

	callCtx, cancel := context.WithTimeout(ctx, a.cfg.ConnectTimeout)
	defer cancel()
	resp, err := a.client.Decide(callCtx, req)
	if err != nil {
		// cacheMissUnreachableReason (local_cache.go) prefixes describeRPCError's own text with the
		// one fact unique to this cache-wired surface: this denial follows a MISS, not merely a failed
		// RPC -- the distinction an operator debugging an outage needs from an ordinary policy denial.
		return false, cacheMissUnreachableReason(describeRPCError(err, agentOrDelegationUnknownMsg))
	}

	if resp.GetEffect() == pdpgrpc.Effect_EFFECT_DENY {
		// The cached token may simply have expired -- see reissue.go's own package doc for why this
		// does not try to tell that apart from an ordinary policy denial before attempting exactly
		// one reissue and retry, mirroring hook.go's runHook one call site over. A failure here (the
		// reissue call itself, or the retried Decide) denies; a success replaces resp with the
		// retry's own response and falls through to the same switch below.
		reissued, reissueErr := reissueAndRetryDecide(a.client, a.cfg.ConnectTimeout, sess.GetDelegationId(), req) //nolint:contextcheck // bounds its own two calls by ConnectTimeout, as it did before authorize took a ctx
		if reissueErr != nil {
			return false, fmt.Sprintf("stratium-pep: %s", reissueErr)
		}
		resp = reissued
	}

	// Called unconditionally, including when resp is itself an ESCALATE: storeCacheResult's own
	// internal check (local_cache.go) is the only guard this needs. The STRICTER "not even a
	// resolved escalation" property holds by construction: this is the only storeCacheResult call
	// site in this function, and it runs before the switch below ever reaches resolveApproval,
	// never again afterward. req.GetToken(), not sess.GetToken(): the reissue branch above may have
	// mutated req.Token in place to a freshly issued one, and storeCacheResult must record the
	// expiry of whichever token actually produced resp.
	storeCacheResult(a.cache, sess.GetDelegationId(), tool, rawInput, req.GetToken(), resp, now)

	switch resp.GetEffect() {
	case pdpgrpc.Effect_EFFECT_ALLOW:
		return true, ""
	case pdpgrpc.Effect_EFFECT_ESCALATE:
		// resolveApproval (escalation.go) owns everything from here: it polls GetApproval and
		// either retries Decide with the resolved approval id or denies. This file still
		// classifies nothing and decides nothing -- it blocks, then relays whatever resolveApproval
		// decided, exactly as hook.go's awaitApproval does for its own transport. ctx,
		// not some ctx this goroutine invents: decideAndRelay has no incoming per-frame context to
		// propagate -- mcp.go relays over stdio, not a cancellable per-request transport -- see
		// resolveApproval's own doc comment for why every caller passes what it actually has,
		// never a locally-scoped ctx built for an unrelated, shorter budget.
		effect, reason := resolveApproval(ctx, a.client, a.cfg.ConnectTimeout, a.cfg.ApprovalPollInterval, a.cfg.ApprovalTimeout, req, resp)
		if effect == pdpgrpc.Effect_EFFECT_ALLOW {
			return true, ""
		}
		return false, reason
	default:
		// EFFECT_DENY, and any value this build does not recognize (the proto documents
		// EFFECT_DENY as the zero value for exactly this case).
		return false, resp.GetReason()
	}
}

// forward relays line -- the ORIGINAL tools/call frame, unchanged -- to the upstream server. Never
// called for anything but an ALLOW (direct or escalated); see decideAndRelay.
//
// A write failure here is treated as best-effort, not reported anywhere: the one way it happens in
// practice is the agent having already hung up and upstreamIn having been closed by runMCP's own
// shutdown path (mcp.go) while this decision was still in flight, which makes the call moot rather
// than a new failure -- there is nobody left this goroutine could usefully tell. relayDirection's
// OWN writes fail differently on a closed destination (it returns an error that stops that relay
// direction and feeds into runMCP's return value) precisely because that function's caller is
// waiting on its result; this goroutine's caller is not, by construction -- see intercept's doc
// comment.
func (a *mcpAuthorizer) forward(line []byte) {
	_, _ = a.upstreamIn.Write(append(line, '\n'))
}

// deny writes a JSON-RPC error response for id, carrying reason as the error's message, to the
// agent -- and nothing else: the call this answers never reaches upstream (forward is simply never
// called on this path, not called and then somehow undone). id is spliced in as the exact bytes the
// original request carried; see jsonrpcErrorFrame's own doc comment for why that is safe to do
// through json.Marshal here despite mcp.go's rule against decoding an id through any Go type
// elsewhere in this proxy.
//
// An id-less frame -- a malformed tools/call sent as a notification, which a conformant MCP client
// never does, since tools/call always expects a reply -- has nothing to correlate a response to.
// This drops it instead of guessing, the same fate a malformed frame already meets one layer up in
// relayDirection: a fabricated id would be worse than no response, because it would look like an
// answer to a call the agent never actually made in a form it can match against anything.
func (a *mcpAuthorizer) deny(id json.RawMessage, reason string) {
	if len(id) == 0 {
		return
	}
	body, err := json.Marshal(jsonrpcErrorFrame{
		JSONRPC: "2.0",
		ID:      id,
		Error:   jsonrpcErrorObj{Code: mcpErrorCodeAuthorizationDenied, Message: reason},
	})
	if err != nil {
		// id is a json.RawMessage already proven parseable (line, of which it is a field, passed
		// frameMethod's json.Unmarshal before intercept ever ran) and reason is a plain string --
		// Marshal cannot fail in practice for this shape. If it somehow did, there is no second
		// channel to report it on that would not itself risk corrupting the JSON-RPC stream (see
		// mcp.go's package doc on why stderr, never stdout, carries this proxy's own diagnostics);
		// dropping the frame is the fail-closed outcome either way, since the call already never
		// reached upstream.
		return
	}
	_, _ = a.agentOut.Write(append(body, '\n'))
}
