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
// unconditionally. It also extracts DecideRequest.normalized_input
// (normalize.go), but only by a field-name lookup keyed on tool_name: "the
// shell tool's argument lives under .command," never "this text looks like
// rm -rf." Nothing here — in this file or in normalize.go — parses what
// tool_input's content *means*: no per-tool special-casing of what a
// dangerous call looks like. That classification is the PDP's job,
// server-side, from raw_input and normalized_input together
// (internal/authz.BuiltinTier); doing any of it here would be exactly the
// predecessor's local-classifier defect (spec D1) in a new coat of paint.
// toolVerbs below derives a verb from the tool *name* only, which is not
// the same thing — see its doc comment.
//
// normalized_input can only help classification, never hurt it:
// BuiltinTier's combining rule lets a positive destructive-or-external match
// on raw_input win outright, before normalized_input is even consulted — so
// a tool this hook does not recognize, or a field extraction that misses or
// under-reports, degrades to raw-only classification, never below it. See
// normalize.go's doc comment for the extraction table itself.
//
// declared_tier is never set on the outgoing request, deliberately: the
// field exists in the proto for callers that have a real tier to declare,
// and this hook does not have one — sending a guessed value would only
// create a chance to be wrong, and a wrong-but-plausible-looking tier is
// more dangerous than no tier at all. TestRunHook_RequestCarriesRawInputAndNoDeclaredTier
// asserts this on the wire.
//
// delegation_id is never read from configuration either: it comes from
// SessionFilePath (loadSessionFile, session_file.go), read fresh on every
// invocation, because this process is exec'd new for every tool call and
// caching it in an env var would mean a revoked or never-started session
// looks identical to a healthy one until something re-reads the file.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"stratium/internal/pdpgrpc"
)

// hookStdin is the subset of Claude Code's PreToolUse payload this hook
// reads. ToolInput is captured as raw JSON — the exact bytes Claude Code
// sent, byte for byte — and never unmarshaled further; see the package doc
// for why.
type hookStdin struct {
	ToolName  string          `json:"tool_name"`
	ToolInput json.RawMessage `json:"tool_input"`
}

// toolVerbs labels a known Claude Code tool name with a generic verb.
//
// This is not classification. It is a label whose meaning the PDP's own
// tier table is authoritative for, and BuiltinTier (internal/authz/tier.go)
// classifies raw_input first and takes precedence over any verb whenever
// raw_input is non-empty — so this map cannot itself soften or sharpen a
// decision, only annotate it. An unrecognized tool name (every MCP tool,
// "mcp__server__method", and anything added to Claude Code after this map
// was written) deliberately maps to the zero value "": that is an honest
// "unknown", left for the PDP to resolve from raw_input, not a guess.
var toolVerbs = map[string]string{
	"Bash":         "execute",
	"BashOutput":   "read",
	"KillShell":    "execute",
	"Read":         "read",
	"NotebookEdit": "write",
	"Write":        "write",
	"Edit":         "write",
	"Glob":         "read",
	"Grep":         "read",
	"WebFetch":     "read",
	"WebSearch":    "read",
	"Task":         "execute",
	"TodoWrite":    "write",
	"SlashCommand": "execute",
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
func runHookCmd(stdin io.Reader, stdout io.Writer) int {
	cfg, err := loadHookConfigFromEnv()
	if err != nil {
		// Missing configuration is not distinguishable from any other reason
		// this hook cannot be trusted to decide — see the package doc's
		// fail-closed rule. Deny rather than guess at identity.
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", err))
	}

	conn, err := grpc.NewClient(cfg.PDPAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: could not create PDP client: %s", err))
	}
	defer func() { _ = conn.Close() }()

	return runHook(stdin, stdout, pdpgrpc.NewPDPServiceClient(conn), cfg)
}

// runHook is the hook's decision logic end to end: read stdin, build a
// request that carries raw_input and never declared_tier, call the PDP, and
// map its effect to an exit code the Claude Code hook contract defines.
//
// Every failure path here denies. PDP unreachable, malformed stdin, and an
// effect this switch does not recognize are all, alike, reasons this
// function cannot vouch for the call — none of them earns the benefit of
// the doubt. A hook that fails open on any of these looks like enforcement
// while providing none.
func runHook(stdin io.Reader, stdout io.Writer, client pdpgrpc.PDPServiceClient, cfg hookConfig) int {
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

	// Read fresh every call, deliberately — see the package doc. Any of
	// "session-start never ran", "someone hand-edited the file", or "an old
	// build wrote a different shape" denies here, before any network call:
	// see loadSessionFile's own doc comment (session_file.go) for why each
	// gets its own distinct reason.
	session, err := loadSessionFile(cfg.SessionFilePath)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", err))
	}

	req := &pdpgrpc.DecideRequest{
		DelegationId:    session.GetDelegationId(),
		AgentId:         cfg.AgentID,
		Subject:         cfg.Subject,
		Tool:            in.ToolName,
		Verb:            toolVerbs[in.ToolName],
		RawInput:        string(in.ToolInput),
		NormalizedInput: extractNormalizedInput(in.ToolName, in.ToolInput),
		// DeclaredTier: deliberately never set. See the package doc.
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	resp, err := client.Decide(ctx, req)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", describeRPCError(err, agentOrDelegationUnknownMsg)))
	}

	switch resp.GetEffect() {
	case pdpgrpc.Effect_EFFECT_ALLOW:
		return 0
	case pdpgrpc.Effect_EFFECT_ESCALATE:
		// escalation.go's awaitApproval owns everything from here: it polls
		// GetApproval and either retries Decide with the resolved approval id
		// or denies. This hook still classifies nothing and decides nothing —
		// it waits, it retries once, it reports (see escalation.go's own
		// package doc for why that boundary still holds here).
		return awaitApproval(stdout, client, cfg, req, resp)
	default:
		// EFFECT_DENY, and any value this build does not recognize (the
		// proto documents EFFECT_DENY as the zero value for exactly this
		// case — an unset or unrecognized field must read back as deny).
		return writeDeny(stdout, resp.GetReason())
	}
}

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
// not reach PDP" text, which is simply wrong for three of the four: a
// NotFound, a DeadlineExceeded, or any other application-level error all
// mean the PDP *was* reached and *did* answer — conflating them with an
// unreachable PDP would send a developer chasing a network problem that does
// not exist. Every branch here still denies identically; only the text
// differs.
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
