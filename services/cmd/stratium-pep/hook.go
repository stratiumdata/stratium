// hook.go implements the "hook" subcommand: a Claude Code PreToolUse hook.
//
// Contract (Claude Code's, not this project's to redefine): stdin carries
// JSON with tool_name and tool_input; exit 0 allows with no output required;
// exit 2 denies, with JSON on stdout carrying
// hookSpecificOutput.permissionDecision ("deny") and
// hookSpecificOutput.permissionDecisionReason.
//
// The boundary that matters: runHook reads tool_name and forwards
// tool_input verbatim, as bytes, into DecideRequest.raw_input. Nothing here
// parses tool_input's structure or its content — no "the command field
// looks like rm -rf", no per-tool special-casing of what a dangerous call
// looks like. That parsing is the PDP's job, server-side, from raw_input;
// doing any of it here would be exactly the predecessor's local-classifier
// defect (spec D1) in a new coat of paint. verbForTool below derives a verb
// from the tool *name* only, which is not the same thing — see its doc
// comment.
//
// declared_tier is never set on the outgoing request, deliberately: the
// field exists in the proto for callers that have a real tier to declare,
// and this hook does not have one — sending a guessed value would only
// create a chance to be wrong, and a wrong-but-plausible-looking tier is
// more dangerous than no tier at all. TestRunHook_RequestCarriesRawInputAndNoDeclaredTier
// asserts this on the wire.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stratium/internal/pdpgrpc"
)

// decideTimeout bounds the Decide RPC so an unreachable or hung PDP fails
// closed in finite time instead of wedging the tool call forever. Task 3
// makes this configurable; this is a conservative fixed default until then.
const decideTimeout = 5 * time.Second

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
// the PDP and where to reach it.
//
// Task 3 owns loading this for real — a session file for DelegationID, a
// configurable connect timeout, and a full fail-closed test matrix around
// all of it. loadHookConfigFromEnv below is a minimal, honestly-scoped
// stand-in so this subcommand is a runnable, real binary in the meantime:
// every value is required, with no default, the same rule
// internal/config.Load uses for the PDP itself — a hook that starts with a
// guessed identity is worse than one that refuses to start.
type hookConfig struct {
	PDPAddr      string
	AgentID      string
	Subject      string
	DelegationID string
}

// loadHookConfigFromEnv reads hookConfig from the environment, or returns an
// error naming every missing variable at once rather than stopping at the
// first.
func loadHookConfigFromEnv() (hookConfig, error) {
	cfg := hookConfig{
		PDPAddr:      os.Getenv("STRATIUM_PEP_PDP_ADDR"),
		AgentID:      os.Getenv("STRATIUM_PEP_AGENT_ID"),
		Subject:      os.Getenv("STRATIUM_PEP_SUBJECT"),
		DelegationID: os.Getenv("STRATIUM_PEP_DELEGATION_ID"),
	}

	var missing []string
	if cfg.PDPAddr == "" {
		missing = append(missing, "STRATIUM_PEP_PDP_ADDR")
	}
	if cfg.AgentID == "" {
		missing = append(missing, "STRATIUM_PEP_AGENT_ID")
	}
	if cfg.Subject == "" {
		missing = append(missing, "STRATIUM_PEP_SUBJECT")
	}
	if cfg.DelegationID == "" {
		missing = append(missing, "STRATIUM_PEP_DELEGATION_ID")
	}
	if len(missing) > 0 {
		return hookConfig{}, fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}
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

	req := &pdpgrpc.DecideRequest{
		DelegationId: cfg.DelegationID,
		AgentId:      cfg.AgentID,
		Subject:      cfg.Subject,
		Tool:         in.ToolName,
		Verb:         toolVerbs[in.ToolName],
		RawInput:     string(in.ToolInput),
		// DeclaredTier: deliberately never set. See the package doc.
	}

	ctx, cancel := context.WithTimeout(context.Background(), decideTimeout)
	defer cancel()

	resp, err := client.Decide(ctx, req)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: could not reach PDP: %s", err))
	}

	switch resp.GetEffect() {
	case pdpgrpc.Effect_EFFECT_ALLOW:
		return 0
	case pdpgrpc.Effect_EFFECT_ESCALATE:
		// No local approval prompt — that subsystem does not exist yet. Say
		// so honestly and deny; inventing one here would let this hook grant
		// itself the authority the escalation design has not been given yet.
		return writeDeny(stdout, fmt.Sprintf(
			"stratium-pep: this action requires human approval, which is not yet implemented; denying (PDP reason: %s)",
			resp.GetReason()))
	default:
		// EFFECT_DENY, and any value this build does not recognize (the
		// proto documents EFFECT_DENY as the zero value for exactly this
		// case — an unset or unrecognized field must read back as deny).
		return writeDeny(stdout, resp.GetReason())
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
