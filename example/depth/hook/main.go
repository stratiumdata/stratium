// Command hook is the depth suite's first consumer of agent.BuildChain (example/agent/chain.go):
// it proves that a delegation chain's DEPTH, not just what a single delegation holds, changes what
// the SAME tool call is answered on the hook surface -- `stratium-pep hook`, the real PreToolUse
// binary example/hook documents but ships no program for (see that directory's own README for why
// hook alone has no program of its own: its harness is Claude Code, which this directory does not
// pretend to be).
//
// This program is deliberately NOT agent.Run driving a live model: example/hook's own claim is
// about the wire contract a real harness feeds `stratium-pep hook` on stdin, and probing that
// contract directly, with fixed JSON, is what makes the three claims below deterministic rather
// than dependent on whether llama3.2 feels like calling Grep twice. See docs/pep/hook.md for the
// stdin/stdout contract this program feeds and reads exactly as a harness would.
//
// THE THREE CLAIMS:
//
//  1. Grep is ALLOWED at depth 0 -- the orchestrator's own root delegation holds it.
//  2. The SAME Grep, same tool, same tool_input shape, is DENIED at depth 1 -- the worker's child
//     delegation narrowed it away -- and the denial reason names the depth ("at depth 1"). This is
//     the whole point: a denial for a tool the parent never held would just be example/proxy one
//     level deeper. Showing the PARENT can do what the CHILD cannot is what only a real two-hop
//     chain can prove.
//  3. A child asking for MORE than its parent granted is refused at CREATION time, before any hook
//     ever runs -- store.CreateDelegation's own models.ScopeNarrows check -- and the refusal names
//     the dimension that failed (the tool the parent never held).
//
// Read at depth 1 is probed too, alongside claim 2's Grep, to show the child is not simply broken:
// it still works for what it does hold.
//
// Run from the example/ directory: `cd example && go run ./depth/hook`. Needs the Docker Compose
// stack up (pdp-pap, stratium-pap, keycloak) and the real `stratium-pep` binary built -- see
// Precheck below for the exact fixes if either is missing. Needs no Ollama, no LiteLLM, and no
// live model at all: this surface probes directly, deterministically, per the package doc above.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"stratium/example/agent"
	"stratium/internal/pdpgrpc"
)

const (
	// parentSessionFile/childSessionFile are relative to the CWD `go run
	// ./depth/hook` is launched from (example/, per the task brief every
	// other example in this suite follows), each named uniquely to this
	// program: mcp/proxy/extauthz all default to the shared ".session.json"
	// and must never run concurrently with each other (example/README.md's
	// own "One session file per example" section) -- this program shares a
	// tenant with none of them and needs two files of its own regardless,
	// one per depth.
	parentSessionFile = "depth/hook/.session-parent.json"
	childSessionFile  = "depth/hook/.session-child.json"

	orchestratorAgentName = "depth-hook-orchestrator"
	workerAgentName       = "depth-hook-worker"

	// subject is this program's own, not reused from example/mcp's
	// "agent-tester@example.com": a delegation chain is one subject's
	// authority narrowing hop over hop (BuildChain's own doc comment), and
	// this program registers its own scoped policy for it below rather than
	// depending on another example's pre-seeded grant.
	subject = "depth-hook@example.com"

	// readOnlyTier is models.ActionTierReadOnly's own wire value (1) --
	// Read and Grep are both catalogued READ_ONLY by BuiltinTier's own
	// verb table (services/internal/authz/catalog.go), so this is the
	// natural ceiling for a chain that only ever holds read tools. A local
	// int32 constant, not an import of stratium/pkg/models, matching
	// example/proxy's own destructiveTier precedent (main.go there) for the
	// identical reason: one int worth naming does not earn a new import.
	readOnlyTier int32 = 1

	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"

	policyName = "example-depth-hook-permit"
	// policyContent is scoped to THIS example's own subject, not a tenant-
	// wide blanket permit like example/proxy's or example/extauthz's own
	// setup: this program shares its tenant (tenant-pap-e2e-integration,
	// the same one example/mcp already uses) with another example's own
	// setup and delegations, and an unconditioned permit(principal, action,
	// resource) would silently widen what every OTHER principal in that
	// tenant may be granted, not just this one's.
	policyContent = `permit(principal == User::"depth-hook@example.com", action, resource);`
)

func main() {
	os.Exit(run())
}

func run() int {
	pdpAddr := os.Getenv("EXAMPLE_DEPTH_PDP_ADDR")
	papAddr := os.Getenv("EXAMPLE_DEPTH_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	if pdpAddr == "" || papAddr == "" || kcAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_DEPTH_PDP_ADDR, EXAMPLE_DEPTH_PAP_ADDR and "+
			"EXAMPLE_KC_ADDR must be set — this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_DEPTH_PDP_ADDR="localhost:$(dc port pdp-pap 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_DEPTH_PAP_ADDR="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"`)
		return 1
	}

	fmt.Println("stratium-example: prechecking the PDP, the PAP, and the stratium-pep binary...")
	if err := agent.Precheck(
		agent.Check{Name: "pdp-pap", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_DEPTH_PDP_ADDR not set or not reachable; export EXAMPLE_DEPTH_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "stratium-pap", Probe: agent.AddrProbe(papAddr),
			Fix: `EXAMPLE_DEPTH_PAP_ADDR not set or not reachable; export EXAMPLE_DEPTH_PAP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"`},
		agent.Check{Name: "keycloak", Probe: agent.AddrProbe(kcAddr),
			Fix: `EXAMPLE_KC_ADDR not set or not reachable; export EXAMPLE_KC_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"`},
		agent.Check{Name: "stratium-pep binary", Probe: binaryExecutableProbe(pepBin),
			Fix: "build it: cd services && go build -o ../bin/stratium-pep ./cmd/stratium-pep (or set EXAMPLE_PEP_BIN)"},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Println("stratium-example: registering the orchestrator and worker agents, and this example's own scoped policy...")
	tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	orchestratorID, err := ensureAgent(papAddr, tok, orchestratorAgentName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	tok, err = agent.MintToken(kcAddr, editorUser, editorPass) // minted fresh -- operator tokens expire after five minutes
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	workerID, err := ensureAgent(papAddr, tok, workerAgentName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	tok, err = agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	if err := agent.EnsurePolicy(papAddr, tok, policyName, policyContent); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: building the two-link chain: orchestrator (depth 0, Read+Grep) -> worker (depth 1, Read only)...")
	parentScope := &pdpgrpc.RequestedScope{MaxActionTier: readOnlyTier, Tools: []string{"Read", "Grep"}}
	childScope := &pdpgrpc.RequestedScope{MaxActionTier: readOnlyTier, Tools: []string{"Read"}}
	chain, err := agent.BuildChain(pdpAddr, subject, orchestratorID, workerID, parentScope, childScope,
		"stratium depth-hook example", 3600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: building the delegation chain:", err)
		return 1
	}
	paint := painter(agent.ColourEnabled(os.Stdout))
	printChainSummary(os.Stdout, paint, chain)
	printDelegationTokens(os.Stdout, paint, chain)

	if err := chain.Parent.WriteSessionFile(parentSessionFile); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}
	if err := chain.Child.WriteSessionFile(childSessionFile); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	want := []agent.Expectation{
		{Tool: "Grep", ArgContains: "depth0-marker", Want: agent.Allow},
		{Tool: "Grep", ArgContains: "depth1-marker", Want: agent.Deny, ReasonContains: "at depth 1"},
		{Tool: "Read", ArgContains: "depth1-ok-marker", Want: agent.Allow},
		{Tool: "create_delegation", Want: agent.Deny, ReasonContains: "not in parent approved_tools"},
	}
	rep := agent.NewReport(want)

	// CLAIM 3 first, deliberately: it happens at CREATION time, before any hook probe runs at all,
	// and reuses chain.Parent.DelegationID that was just minted above.
	fmt.Println("\nstratium-example: attempting to create a child that WIDENS its parent (expect refusal at creation)...")
	widenArgs := map[string]any{"tools": "Read,Grep,Write"}
	_, widenErr := agent.CreateDelegation(pdpAddr, &pdpgrpc.CreateDelegationRequest{
		Subject: subject,
		AgentId: workerID,
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: readOnlyTier, // same tier as the parent -- isolates the widening to the TOOL dimension alone
			Tools:         []string{"Read", "Grep", "Write"},
		},
		ParentDelegationId: chain.Parent.DelegationID,
		Purpose:            "stratium depth-hook example (deliberately widening child, expected to be refused)",
		TtlSeconds:         3600,
	})
	widenResult, err := denialFromCreateAttempt(widenErr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: creating a widening child:", err)
		return 1
	}
	printDecision(os.Stdout, "create_delegation", widenArgs, widenResult)
	rep.Record(agent.ToolCall{Name: "create_delegation", Args: widenArgs}, widenResult)

	fmt.Println("\nstratium-example: probing the hook surface directly (no live model -- deterministic)...")
	printDecisionPath(os.Stdout, paint)

	parentEnv := hookEnv(pdpAddr, orchestratorID, parentSessionFile)
	childEnv := hookEnv(pdpAddr, workerID, childSessionFile)

	if !probe(rep, pepBin, parentEnv, "Grep", map[string]any{"pattern": "depth0-marker"}) {
		return 1
	}
	if !probe(rep, pepBin, childEnv, "Grep", map[string]any{"pattern": "depth1-marker"}) {
		return 1
	}
	if !probe(rep, pepBin, childEnv, "Read", map[string]any{"file_path": "/tmp/depth1-ok-marker.txt"}) {
		return 1
	}

	rep.Print(os.Stdout)
	return rep.ExitCode()
}

// probe runs one hook invocation, prints and records its outcome, and returns false only on a
// TRANSPORT failure (a dead process, a malformed response) -- never on a policy DENY, which is
// recorded and printed exactly like an ALLOW. See runHookProbe's own doc comment for why that
// distinction is load-bearing here.
func probe(rep *agent.Report, pepBin string, env []string, tool string, input map[string]any) bool {
	res, err := runHookProbe(pepBin, env, tool, input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "stratium-example: probing %s: %v\n", tool, err)
		return false
	}
	printDecision(os.Stdout, tool, input, res)
	rep.Record(agent.ToolCall{Name: tool, Args: input}, res)
	return true
}

// printDecision matches agent.Run's own ALLOW/DENY line format (agent/agent.go) exactly, so this
// program's transcript reads the same way every other example's does, even though nothing here
// drives agent.Run's model loop.
func printDecision(out io.Writer, name string, args map[string]any, res agent.Result) {
	argsJSON, _ := json.Marshal(args)
	if res.Allowed {
		fmt.Fprintf(out, "  ALLOW  %-18s %s\n", name, argsJSON)
	} else {
		fmt.Fprintf(out, "  DENY   %-18s %s\n         %s\n", name, argsJSON, res.Reason)
	}
}

// denialFromCreateAttempt turns a CreateDelegation error into a policy Result, or returns it
// unchanged as a Go error if it is anything other than the PermissionDenied ScopeNarrows refusal
// this probe expects -- a transport error (PDP unreachable) or any other status code is this
// example being broken, not the store answering, and must never be recorded as a decision. Mirrors
// example/proxy's own proxyTransport.Call, which draws the identical line for Decide's own
// PermissionDenied.
func denialFromCreateAttempt(err error) (agent.Result, error) {
	if err == nil {
		return agent.Result{}, errors.New("a widening child delegation was GRANTED -- this should never happen")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.PermissionDenied {
		return agent.Result{}, err
	}
	return agent.Result{Allowed: false, Reason: st.Message()}, nil
}

// hookEnv is the child environment for one `stratium-pep hook` invocation: the seven decision
// variables hook.go's own loadHookConfigFromEnv requires, plus the cache staleness window
// loadCacheConfigFromEnv requires alongside it (docs/pep/hook.md's own env table). ApprovalTimeout
// is short, matching example/mcp's own reasoning: no ESCALATE path is exercised by this example
// (neither delegation carries an escalate_at), so a surprise one fails fast rather than hanging.
func hookEnv(pdpAddr, agentID, sessionFile string) []string {
	return append(os.Environ(),
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_AGENT_ID="+agentID,
		"STRATIUM_PEP_SUBJECT="+subject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s",
		"STRATIUM_PEP_APPROVAL_TIMEOUT=10s",
		"STRATIUM_PEP_CACHE_STALENESS_WINDOW=5s",
	)
}

// hookStdin is the subset of Claude Code's own PreToolUse payload this program feeds on stdin,
// matching services/cmd/stratium-pep/hook.go's own hookStdin exactly (tool_name, tool_input) --
// see that file's package doc for why nothing else on the wire is ever inspected.
type hookStdin struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

// hookDenyOutput decodes the JSON `stratium-pep hook` writes to stdout on an exit-2 deny,
// matching hook.go's own hookOutput/hookSpecificOutput wire shape.
type hookDenyOutput struct {
	HookSpecificOutput struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// runHookProbe execs the real `stratium-pep hook` binary, feeds it stdin exactly as Claude Code's
// PreToolUse hook would, and turns its exit code into an agent.Result -- or a Go error if the exit
// code is neither 0 (allow) nor 2 (deny), or the deny JSON does not parse. That error path is the
// one place this file honors the suite's own rule that a transport failure is never a decision
// (agent/agent.go's own doc comment, and example/proxy's proxyTransport.Call): a crashed or
// hanging stratium-pep process must abort this program, never be recorded as either an ALLOW or
// a DENY it never actually answered.
func runHookProbe(pepBin string, env []string, toolName string, toolInput map[string]any) (agent.Result, error) {
	stdin, err := json.Marshal(hookStdin{ToolName: toolName, ToolInput: toolInput})
	if err != nil {
		return agent.Result{}, fmt.Errorf("encode hook stdin: %w", err)
	}

	cmd := exec.Command(pepBin, "hook") //nolint:gosec // G204: pepBin is this example's own fixed configuration, never request data.
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr == nil {
		return agent.Result{Allowed: true}, nil
	}

	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		// The process never even ran to completion (binary missing, permission denied, killed) --
		// unambiguously this example being broken, not the PDP answering.
		return agent.Result{}, fmt.Errorf("running stratium-pep hook: %w (stderr: %s)", runErr, stderr.String())
	}
	if exitErr.ExitCode() != 2 {
		return agent.Result{}, fmt.Errorf("stratium-pep hook exited %d, want 0 (allow) or 2 (deny) (stderr: %s)",
			exitErr.ExitCode(), stderr.String())
	}

	var out hookDenyOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return agent.Result{}, fmt.Errorf("decode hook deny JSON: %w (stdout: %s)", err, stdout.String())
	}
	return agent.Result{Allowed: false, Reason: out.HookSpecificOutput.PermissionDecisionReason}, nil
}

// binaryExecutableProbe is a Precheck probe (agent.Precheck) confirming pepBin exists and is
// executable before this program ever tries to exec it -- a missing or non-executable binary must
// read as a setup problem with a build command as its fix, never as a mysterious transport error
// out of runHookProbe.
func binaryExecutableProbe(pepBin string) func() error {
	return func() error {
		info, err := os.Stat(pepBin)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory, not a binary", pepBin)
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("%s is not executable", pepBin)
		}
		return nil
	}
}

// ensureAgent registers this example's agent, or finds the one a previous run already created --
// UNIQUE(tenant_id, name) makes the second POST 409, so this run is idempotent across repeats too.
// Duplicated from example/mcp/main.go's own identical function rather than shared: every runnable
// example in this suite keeps its own PAP setup calls local (example/proxy's own
// agentSeededProbe is the same story from the other direction), reserving example/agent for
// helpers every surface needs, which "ensure one specific named agent exists" is not.
func ensureAgent(papAddr, token, name string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name": name, "provider": "example", "model_id": "n/a",
		"trust_tier": 3, "enabled": true, "suspended": false, "allowed_tools": []string{},
	})
	req, err := http.NewRequest(http.MethodPost, "http://"+papAddr+"/v1/agents", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("agents: create %q: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusCreated:
		var out struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return "", fmt.Errorf("agents: decode create response: %w", err)
		}
		return out.ID, nil
	case http.StatusConflict:
		return findAgentByName(papAddr, token, name)
	default:
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("agents: create %q: %s: %s", name, resp.Status, b)
	}
}

func findAgentByName(papAddr, token, name string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+papAddr+"/v1/agents", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("agents: list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var agents []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return "", fmt.Errorf("agents: decode list: %w", err)
	}
	for _, a := range agents {
		if a.Name == name {
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("agents: %q reported a conflict on create but is not in the list", name)
}
