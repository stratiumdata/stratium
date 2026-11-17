// hook.go implements the "hook" subcommand: a Claude Code PreToolUse hook.
//
// Contract (Claude Code's, not this project's to redefine): stdin carries
// JSON with tool_name and tool_input; exit 0 allows with no output required;
// exit 2 denies, with JSON on stdout carrying
// hookSpecificOutput.permissionDecision ("deny") and
// hookSpecificOutput.permissionDecisionReason.
//
// The boundary that matters: runHook reads tool_name and forwards
// tool_input verbatim, as bytes, into DecideRequest.raw_input — always,
// unconditionally — and sends nothing else derived from it. This file used
// to also compute DecideRequest.normalized_input and .resource (normalize.go
// and resource.go, both field-name lookups keyed on tool_name: "the shell
// tool's argument lives under .command," never "this text looks like
// rm -rf") and DecideRequest.verb (toolVerbs, a per-tool-name label, defined
// below this comment until this file's own task deleted it). Spec §4.4.2 T3
// deleted all three: the per-tenant tool_catalog table (Task 1) and the
// PDP's own server-side extraction (internal/authz.ExtractFromCatalog /
// ApplyExtraction, Task 2) now do everything those three tables did — read a
// tenant-registered field name or verb for a tool, never infer one from
// tool_input's content — from data the PDP itself trusts, rather than a
// guess this process sent it. Nothing in this file parses what tool_input's
// content *means*, and after this task there is nothing left in this file
// that even parses tool_input's *shape*: no per-tool special-casing of what
// a dangerous call looks like. That classification is, and was always meant
// to be, entirely the PDP's job, server-side (internal/authz.BuiltinTier);
// doing any of it here would be exactly the predecessor's local-classifier
// defect (spec D1) in a new coat of paint.
//
// declared_tier is never set on the outgoing request, deliberately: the
// field exists in the proto for callers that have a real tier to declare,
// and this hook does not have one — sending a guessed value would only
// create a chance to be wrong, and a wrong-but-plausible-looking tier is
// more dangerous than no tier at all. TestRunHook_RequestCarriesRawInputAndNoDeclaredTier
// asserts this on the wire.
//
// The token sent on DecideRequest is never read from configuration either:
// it comes from SessionFilePath (loadSessionFile, session_file.go), read
// fresh on every invocation, because this process is exec'd new for every
// tool call and caching it in an env var would mean a revoked or
// never-started session looks identical to a healthy one until something
// re-reads the file. As of Phase 9 Task 4 this token is what authenticates
// the call at all (spec §4.7.1 K4) — there is no field left on the wire
// for a bare delegation id to fall back to, and this file never builds one:
// see reissue.go for the one case where the cached token itself has expired
// mid-session, and TestRunHook_NoCodePathSendsABareDelegationID for the
// assertion that no path here ever tries.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// hookStdin is the subset of Claude Code's PreToolUse payload this hook
// reads. ToolInput is captured as raw JSON — the exact bytes Claude Code
// sent, byte for byte — and never unmarshaled further; see the package doc
// for why.
type hookStdin struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// hookConfig is what runHook needs beyond stdin: the identity presented to
// the PDP, where to reach it, where the session file session-start
// (session_start.go) wrote lives, how long to wait for a reply before giving
// up, and how to wait out an escalation.
//
// Every value here is required, with no default — the same rule
// internal/config.Load uses for the PDP itself, for the same reason: a hook
// that starts against a guessed PDP address, or that waits forever (or not
// at all) for a reply, fails at the first tool call in a way that looks
// like a policy denial rather than a misconfiguration. DelegationID is
// deliberately not a field here — see the package doc.
type hookConfig struct {
	PDPAddr         string
	AgentID         string
	Subject         string
	SessionFilePath string
	ConnectTimeout  time.Duration

	// ApprovalPollInterval and ApprovalTimeout bound escalation.go's poll
	// loop (E6: the PEP blocks, the PDP never parks a connection). Required,
	// no default, for the same reason as every field above — and unlike
	// ConnectTimeout, guessing wrong here has no safe direction: too short a
	// timeout denies escalations no human could realistically clear in time,
	// too long one leaves a tool call silently blocked well past what an
	// operator would expect "no response" to mean. Neither is a value this
	// binary should pick on an operator's behalf.
	ApprovalPollInterval time.Duration
	ApprovalTimeout      time.Duration
}

// loadHookConfigFromEnv reads hookConfig from the environment, or returns an
// error naming every missing variable at once rather than stopping at the
// first. Shares requiredEnv/requiredDuration/missingConfigError (config.go)
// with loadSessionStartConfigFromEnv (session_start.go), which loads five of
// these same values the same way (everything but the two escalation-only
// fields below, which session-start has no use for: it never polls).
func loadHookConfigFromEnv() (hookConfig, error) {
	var missing []string
	cfg := hookConfig{
		PDPAddr:         requiredEnv("STRATIUM_PEP_PDP_ADDR", &missing),
		AgentID:         requiredEnv("STRATIUM_PEP_AGENT_ID", &missing),
		Subject:         requiredEnv("STRATIUM_PEP_SUBJECT", &missing),
		SessionFilePath: requiredEnv("STRATIUM_PEP_SESSION_FILE", &missing),
	}
	timeoutRaw := requiredEnv("STRATIUM_PEP_CONNECT_TIMEOUT", &missing)
	pollRaw := requiredEnv("STRATIUM_PEP_APPROVAL_POLL_INTERVAL", &missing)
	approvalTimeoutRaw := requiredEnv("STRATIUM_PEP_APPROVAL_TIMEOUT", &missing)
	if len(missing) > 0 {
		return hookConfig{}, missingConfigError(missing)
	}

	timeout, err := requiredDuration("STRATIUM_PEP_CONNECT_TIMEOUT", timeoutRaw)
	if err != nil {
		return hookConfig{}, err
	}
	cfg.ConnectTimeout = timeout

	pollInterval, err := requiredDuration("STRATIUM_PEP_APPROVAL_POLL_INTERVAL", pollRaw)
	if err != nil {
		return hookConfig{}, err
	}
	cfg.ApprovalPollInterval = pollInterval

	approvalTimeout, err := requiredDuration("STRATIUM_PEP_APPROVAL_TIMEOUT", approvalTimeoutRaw)
	if err != nil {
		return hookConfig{}, err
	}
	cfg.ApprovalTimeout = approvalTimeout

	return cfg, nil
}

// runHookCmd wires the real PDP client from environment configuration and
// runs the hook. It is the only function in this file main's dispatch
// calls; everything it wires is exercised directly by hook_test.go against
// a fake PDP server instead.
//
// Loads TWO configs, not one -- hookConfig and cacheConfig (cache.go) --
// composed via combineConfigErrors exactly as runMCPCmd (mcp.go) already
// composes mcpConfig with hookConfig: both loaders always run, even if the
// first fails, so an operator missing values in both groups sees every gap
// in one run. cacheConfig stays cache.go's own separate type rather than a
// field folded into hookConfig -- see cache.go's own doc comment on why that
// composition question was left to this task, and local_cache.go's package
// doc for how the two values are threaded into runHook from here.
func runHookCmd(stdin io.Reader, stdout io.Writer) int {
	cfg, hookErr := loadHookConfigFromEnv()
	cacheCfg, cacheErr := loadCacheConfigFromEnv()
	if err := combineConfigErrors(hookErr, cacheErr); err != nil {
		// Missing configuration is not distinguishable from any other reason
		// this hook cannot be trusted to decide — see the package doc's
		// fail-closed rule. Deny rather than guess at identity.
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", err))
	}

	conn, err := dialPDP(cfg.PDPAddr)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: could not create PDP client: %s", err))
	}
	defer func() { _ = conn.Close() }()

	return runHook(stdin, stdout, pdpgrpc.NewPDPServiceClient(conn), cfg, cacheCfg)
}

// runHook is the hook's decision logic end to end: read stdin, consult the
// decision cache, and -- on a miss -- build a request that carries raw_input
// and never declared_tier, call the PDP, store the result, and map the
// effect to an exit code the Claude Code hook contract defines.
//
// Every failure path here denies. PDP unreachable, malformed stdin, and an
// effect this switch does not recognize are all, alike, reasons this
// function cannot vouch for the call — none of them earns the benefit of
// the doubt. A hook that fails open on any of these looks like enforcement
// while providing none.
func runHook(stdin io.Reader, stdout io.Writer, client pdpgrpc.PDPServiceClient, cfg hookConfig, cacheCfg cacheConfig) int {
	body, err := io.ReadAll(stdin)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: could not read stdin: %s", err))
	}

	var in hookStdin
	if err := json.Unmarshal(body, &in); err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: malformed stdin: %s", err))
	}
	if in.ToolName == "" {
		return writeDeny(stdout, "stratium-pep: malformed stdin: tool_name is required")
	}
	rawInput := string(in.ToolInput)

	// Read fresh every call, deliberately — see the package doc. Any of
	// "session-start never ran", "someone hand-edited the file", "an old
	// build wrote a different shape", or now "the cached token is empty"
	// denies here, before any network call: see loadSessionFile's own doc
	// comment (session_file.go) for why each gets its own distinct reason.
	// sess is this binary's own local fail-closed gate on "a session was
	// actually started," independent of whatever the PDP itself goes on to
	// decide — and, as of Phase 9 Task 4, also the only source for the token
	// and delegation id the request below and a possible reissue use, and,
	// as of this task, the only source consultCache/storeCacheResult
	// (local_cache.go) need for the cache's own key and validity checks.
	sess, err := loadSessionFile(cfg.SessionFilePath)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", err))
	}

	// W6: hook is one of the two surfaces spec §4.8.3 permits to consult the
	// cache at all — see local_cache.go's own package doc for the boundary
	// this call is part of enforcing structurally, not merely documenting.
	// now is captured once and reused below for storeCacheResult's own
	// CachedAt, the same one-instant-per-flow discipline cache.go's own
	// cacheEntry doc comment establishes. On a hit, the PDP is never dialed
	// at all — that is the whole of the outage tolerance this phase exists
	// to buy — and the switch below never falls through to the request this
	// function would otherwise build.
	now := time.Now()
	cachePath := cacheFilePathFor(cfg.SessionFilePath)
	if entry, hit := consultCache(cachePath, cacheCfg.StalenessWindow, sess, in.ToolName, rawInput, now); hit {
		switch entry.Decision {
		case pdpgrpc.Effect_EFFECT_ALLOW:
			return 0
		default:
			// cacheEntryUsable (cache.go) already refuses to ever report a hit
			// for an ESCALATE entry, so this default case is reached only by a
			// cached DENY in practice — but stays a default, not an explicit
			// DENY case, for the identical fail-closed reason hook.go's other
			// switch below does: nothing this function cannot positively
			// identify as ALLOW may ever be treated as one.
			return writeDeny(stdout, cacheHitDenyReason)
		}
	}

	req := &pdpgrpc.DecideRequest{
		AgentId:  cfg.AgentID,
		Subject:  cfg.Subject,
		Tool:     in.ToolName,
		RawInput: rawInput,
		Token:    sess.GetToken(),
		// Verb, NormalizedInput, Resource: none of these exist on the wire
		// (Verb, NormalizedInput) or are ever set here (Resource) anymore —
		// see the package doc. DeclaredTier: deliberately never set, same doc.
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	resp, err := client.Decide(ctx, req)
	if err != nil {
		// cacheMissUnreachableReason (local_cache.go) prefixes describeRPCError's
		// own text with the one fact unique to a cache-wired surface: this
		// denial follows a MISS, not merely a failed RPC — the distinction an
		// operator debugging an outage needs from an ordinary policy denial.
		return writeDeny(stdout, cacheMissUnreachableReason(describeRPCError(err, agentOrDelegationUnknownMsg)))
	}

	if resp.GetEffect() == pdpgrpc.Effect_EFFECT_DENY {
		// The cached token may simply have expired — see reissue.go's own
		// package doc for why this does not try to tell that apart from an
		// ordinary policy denial before attempting exactly one reissue and
		// retry. A failure here (the reissue call itself, or the retried
		// Decide) denies; a success replaces resp with the retry's own
		// response and falls through to the same switch below, which may
		// then see ALLOW, ESCALATE, or a fresh DENY.
		reissued, reissueErr := reissueAndRetryDecide(client, cfg.ConnectTimeout, sess.GetDelegationId(), req)
		if reissueErr != nil {
			return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", reissueErr))
		}
		resp = reissued
	}

	// Called unconditionally, including when resp is itself an ESCALATE:
	// storeCacheResult's own doc comment (local_cache.go) is where W4's "never
	// cache an ESCALATE" guard actually lives, and it is the ONLY place that
	// checks -- there is no second, redundant check here, because there is
	// nothing this call site protects that storeCacheResult does not already
	// protect identically for its only two callers (this and
	// decideAndRelay's identical call). The STRICTER property this task adds
	// -- a RESOLVED escalation is not cached either, not only the raw
	// ESCALATE value -- is not enforced by any check on resp's effect at all;
	// it holds because this is the only storeCacheResult call site in this
	// function, and it runs BEFORE the switch below ever reaches
	// awaitApproval, never again afterward. req.GetToken(), not
	// sess.GetToken(): the reissue branch above may have mutated req.Token in
	// place to a freshly issued one, and storeCacheResult must record the
	// expiry of whichever token actually produced resp.
	storeCacheResult(cachePath, sess.GetDelegationId(), in.ToolName, rawInput, req.GetToken(), resp, now)

	switch resp.GetEffect() {
	case pdpgrpc.Effect_EFFECT_ALLOW:
		return 0
	case pdpgrpc.Effect_EFFECT_ESCALATE:
		// escalation.go's awaitApproval owns everything from here: it polls
		// GetApproval and either retries Decide with the resolved approval id
		// or denies. This hook still classifies nothing and decides nothing —
		// it waits, it retries once, it reports (see escalation.go's own
		// package doc for why that boundary still holds here). Whatever this
		// resolves to is never cached — the store above already ran, on the
		// PRE-escalation response, and is not called again afterward.
		return awaitApproval(stdout, client, cfg, req, resp)
	default:
		// EFFECT_DENY, and any value this build does not recognize (the
		// proto documents EFFECT_DENY as the zero value for exactly this
		// case — an unset or unrecognized field must read back as deny).
		return writeDeny(stdout, resp.GetReason())
	}
}

// pdpUserAgent identifies this PEP on every connection it opens to the PDP,
// so a PDP operator reading gRPC metadata or proxy logs can tell which
// client is calling. grpc-go appends its own version after it.
const pdpUserAgent = "stratium-pep (+https://docs.stratium.dev)"

// agentOrDelegationUnknownMsg is describeRPCError's notFoundMsg for every
// Decide call this hook makes (the first ask and, from escalation.go, the
// approved retry): a NotFound from Decide always means LoadAgent or
// LoadChain failed server-side (server.go), never anything about an
// approval — resolveEscalation turns an approval-side NotFound into an
// ordinary DENY response, not an RPC error (escalation.go's own doc
// comment), so this message never needs to hedge between the two meanings.
const agentOrDelegationUnknownMsg = "PDP says the delegation or agent this request names is unknown to it"

// describeRPCError turns a failed call to the PDP into a reason that
// distinguishes "we could not ask" from "we asked and were told something
// specific" — the difference between a useful denial and a mysterious one.
// Without this, every one of these cases would produce the same flat "could
// not reach PDP" text, which is simply wrong for a NotFound or any other
// application-level error: those mean the PDP *was* reached and *did*
// answer, and conflating them with an unreachable PDP would send a developer
// chasing a network problem that does not exist. Every branch here still
// denies identically; only the text differs.
//
// DeadlineExceeded is the exception, and it belongs with the unreachable
// cases rather than the answered ones. A dropped SYN — a stopped container,
// a blackholed route — never refuses the connection; it hangs until the dial
// deadline and surfaces as DeadlineExceeded with nothing having been reached.
// Whether an unreachable PDP presents as Unavailable or DeadlineExceeded is
// decided by how the socket dies, which is why
// TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies asserts the
// CLASSIFICATION rather than the branch: an earlier version pinned the
// Unavailable wording and flaked whenever the deadline won the race. See that
// test's own comment. Do not "correct" this back — the flake it fixes is
// real and was measured.
//
// There is deliberately no codes.Canceled case: every context this hook
// builds (runHook's ConnectTimeout budget, escalation.go's pollCtx and its
// own per-retry ConnectTimeout budget) derives from context.Background()
// with only a deadline, never a cancellable parent, so nothing in this
// binary can produce a Canceled that is not also caught earlier by ctx.Err()
// at its own call site (pollApproval's own doc comment explains why that
// check exists and comes first). A Canceled this function ever did see would
// fall through to the default case below, which is still an honest, if
// less specific, fail-closed answer — not a silent gap.
//
// Shared by every PDP call this hook makes — the initial Decide, escalation.go's
// GetApproval poll, and its post-approval retry Decide — so a developer sees
// the same vocabulary for the same underlying failure no matter which call
// hit it. notFoundMsg supplies the one piece that cannot be phrased
// identically for every caller: "unknown to it" always begs the question
// "which id" (agentOrDelegationUnknownMsg above for Decide; escalation.go's
// own message for GetApproval's approval_id).
func describeRPCError(err error, notFoundMsg string) string {
	switch status.Code(err) {
	case codes.Unavailable:
		return fmt.Sprintf("could not reach PDP: %s", err)
	case codes.DeadlineExceeded:
		return fmt.Sprintf("PDP did not respond in time: %s", err)
	case codes.NotFound:
		return fmt.Sprintf("%s: %s", notFoundMsg, err)
	default:
		return fmt.Sprintf("PDP returned an error: %s", err)
	}
}

// hookOutput is Claude Code's PreToolUse structured-output contract for a
// deny: JSON on stdout naming the decision and why. Every deny in this file
// — a PDP verdict, an unreachable PDP, malformed stdin, missing
// configuration — routes through writeDeny below, so this shape is built in
// exactly one place.
type hookOutput struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// writeDeny writes the deny JSON and returns 2, the hook's only deny exit
// code. reason must never carry raw_input — see the package doc; every
// caller above builds reason from the PDP's own response text or from this
// process's own control-flow errors (a read failure, a dial failure, a
// JSON syntax error), never from the tool_input bytes themselves.
func writeDeny(stdout io.Writer, reason string) int {
	out := hookOutput{HookSpecificOutput: hookSpecificOutput{
		HookEventName:            "PreToolUse",
		PermissionDecision:       "deny",
		PermissionDecisionReason: reason,
	}}
	enc, err := json.Marshal(out)
	if err != nil {
		// out is built entirely from plain strings; Marshal cannot fail in
		// practice. If it somehow does, the exit code alone still denies.
		return 2
	}
	// Best-effort write: a broken pipe here cannot be recovered from, and the
	// exit code alone is what actually denies the tool call.
	_, _ = fmt.Fprintln(stdout, string(enc))
	return 2
}
