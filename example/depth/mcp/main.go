// Command mcp is the depth suite's second consumer of agent.BuildChain (example/agent/chain.go):
// it proves that a delegation chain's DEPTH changes what the SAME MCP tool call is answered on the
// mcp surface -- `stratium-pep mcp`, the real transparent proxy example/mcp already documents in
// full (see that directory's own README first if this one is unfamiliar; this file follows its
// shape closely and does not re-explain what it explains). Where example/depth/hook probes
// `stratium-pep hook` directly with fixed JSON (no live model needed, because hook's own harness is
// Claude Code, not something this suite writes), this file DOES drive a live local model, twice --
// once per depth -- because mcp's own harness (an MCP client loop) IS something this suite writes,
// exactly as example/mcp's own package doc explains for the flagship example.
//
// THE THREE CLAIMS:
//
//  1. search_files is ALLOWED at depth 0 -- the orchestrator's own root delegation holds it.
//  2. The SAME search_files -- same tool, same task, same tools OFFERED to the model -- is DENIED
//     at depth 1 -- the worker's child delegation narrowed it away -- and the denial reason names
//     the depth ("at depth 1"). This is the whole point: a denial for a tool the parent never held
//     would just be example/mcp one level deeper. Showing the PARENT can do what the CHILD cannot
//     is what only a real two-hop chain can prove.
//  3. A child asking for MORE than its parent granted is refused at CREATION time, before either
//     mcp run ever starts -- store.CreateDelegation's own permset.ScopeNarrows check -- and the
//     refusal names the dimension that failed (the tool the parent never held).
//
// read_text_file at depth 1 is probed too, alongside claim 2's search_files, to show the child is
// not simply broken: it still works for what it does hold.
//
// THE RUN-TWICE SHAPE. main() launches `stratium-pep mcp` wrapping the identical real
// @modelcontextprotocol/server-filesystem, against the identical directory, TWICE: once configured
// with the parent's session file and agent id (depth 0), once with the child's (depth 1). Both runs
// hand agent.Run the identical taskSearch string and the identical upstream tool list (mcp's own
// tools/list is never filtered by depth -- see stratium-pep's mcp.go package doc, "TOOLS/LIST IS
// DELIBERATELY NOT FILTERED") -- identical request, two depths, two answers, and the reason on the
// deny says which depth decided.
//
// TWO SEPARATE SINGLE-TOOL TASKS, NOT ONE CHAINED TASK. taskSearch (search_files) and taskRead
// (read_text_file) are each their own one-shot agent.Run call -- the "still works" read_text_file
// probe at depth 1 is a SECOND, fresh conversation against the same child transport, not a second
// turn continuing the search conversation. Confirmed empirically against a live litellm/ollama:
// llama3.2 reliably emits a genuine tool_calls entry for either tool on the FIRST turn of a fresh
// conversation, but reliably degrades to prose describing a fake tool call on the turn immediately
// AFTER it has already made one real tool call and been handed that call's result back -- a
// multi-turn, tool-switching weakness distinct from (and additional to) the map-key-ordering defect
// agent/litellm.go's own toolDef/toolFunction doc comment fixed. Splitting the two probes into two
// one-shot conversations sidesteps that weakness entirely rather than working around it.
//
// Run from the example/ directory: `cd example && go run ./depth/mcp`. Needs everything
// example/mcp needs (Ollama with llama3.2 pulled, LiteLLM, npx, the Docker Compose stack, a built
// stratium-pep binary) -- see Precheck below for the exact fixes for any that are missing.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/example/agent"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

const (
	// exampleDataDir/sentinelPath are this program's own -- a fresh directory, not example/mcp's
	// /tmp/example-data, so a concurrent run of that example (a different tenant, a different
	// agent, but the same real filesystem) never collides with this one's own seeded file.
	exampleDataDir = "/tmp/example-depth-mcp"
	sentinelPath   = exampleDataDir + "/sentinel.txt"

	// parentSessionFile/childSessionFile are relative to the CWD `go run ./depth/mcp` is launched
	// from (example/), named uniquely to this program for the same reason example/depth/hook's own
	// two session files are: mcp/proxy/extauthz all default to the shared ".session.json" and must
	// never run concurrently with each other or with this program (example/README.md's own "One
	// session file per example" section).
	parentSessionFile = "depth/mcp/.session-parent.json"
	childSessionFile  = "depth/mcp/.session-child.json"

	orchestratorAgentName = "depth-mcp-orchestrator"
	workerAgentName       = "depth-mcp-worker"

	// subject is this program's own, not example/mcp's "agent-tester@example.com" and not
	// example/depth/hook's "depth-hook@example.com": a delegation chain is one subject's authority
	// narrowing hop over hop (BuildChain's own doc comment), and this program registers its own
	// scoped policy for it below rather than depending on another example's pre-seeded grant.
	subject = "depth-mcp@example.com"

	// readOnlyTier is models.ActionTierReadOnly's own wire value (1). Both search_files and
	// read_text_file are cataloged READ_ONLY for this tenant already (deploy/seed/tool-catalog-mcp-
	// filesystem.sql, applied as a prerequisite of example/mcp itself -- see this program's own
	// Precheck, which confirms rather than re-seeds it), so this is the natural ceiling for a chain
	// that only ever holds read tools.
	readOnlyTier int32 = 1

	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"

	policyName = "example-depth-mcp-permit"
	// policyContent is scoped to THIS example's own subject, not a tenant-wide blanket permit:
	// this program shares its tenant (tenant-pap-e2e-integration) with example/mcp and
	// example/depth/hook's own setup and delegations, and an unconditioned
	// permit(principal, action, resource) would silently widen what every OTHER principal in that
	// tenant may be granted, not just this one's.
	policyContent = `permit(principal == User::"depth-mcp@example.com", action, resource);`
)

func main() {
	os.Exit(run())
}

func run() int {
	pdpAddr := os.Getenv("EXAMPLE_DEPTH_PDP_ADDR")
	papAddr := os.Getenv("EXAMPLE_DEPTH_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")
	litellmAddr := os.Getenv("EXAMPLE_LITELLM_ADDR")
	ollamaAddr := os.Getenv("EXAMPLE_OLLAMA_ADDR")
	if ollamaAddr == "" {
		ollamaAddr = "127.0.0.1:11434" // fixed, per this suite's own prerequisites -- not ephemeral like the compose ports
	}
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	// Reusing example/depth/hook's own EXAMPLE_DEPTH_PDP_ADDR/EXAMPLE_DEPTH_PAP_ADDR names,
	// deliberately: this program shares the identical pdp-pap/stratium-pap pair (tenant-pap-e2e-
	// integration) that example/depth/hook already established as the depth suite's own tenant --
	// see that example's own README, "Why this shares pdp-pap/stratium-pap with example/mcp" -- so
	// a shell already exporting these for depth/hook needs nothing new to run this program too.
	if pdpAddr == "" || papAddr == "" || kcAddr == "" || litellmAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_DEPTH_PDP_ADDR, EXAMPLE_DEPTH_PAP_ADDR, "+
			"EXAMPLE_KC_ADDR and EXAMPLE_LITELLM_ADDR must be set — this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_DEPTH_PDP_ADDR="localhost:$(dc port pdp-pap 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_DEPTH_PAP_ADDR="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_LITELLM_ADDR="localhost:$(dc port litellm 4000 | sed -E 's/.*://')"`)
		return 1
	}

	fmt.Println("stratium-example: prechecking ollama, litellm, the PDP, the PAP, npx, and the stratium-pep binary...")
	if err := agent.Precheck(
		agent.Check{Name: "ollama", Probe: agent.DialCheck(ollamaAddr),
			Fix: "start Ollama and `ollama pull llama3.2` (expected at " + ollamaAddr + ")"},
		agent.Check{Name: "litellm", Probe: agent.AddrProbe(litellmAddr),
			Fix: `EXAMPLE_LITELLM_ADDR not set or not reachable; export EXAMPLE_LITELLM_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"`},
		agent.Check{Name: "pdp-pap", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_DEPTH_PDP_ADDR not set or not reachable; export EXAMPLE_DEPTH_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "stratium-pap", Probe: agent.AddrProbe(papAddr),
			Fix: `EXAMPLE_DEPTH_PAP_ADDR not set or not reachable; export EXAMPLE_DEPTH_PAP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"`},
		agent.Check{Name: "npx", Probe: func() error { _, err := exec.LookPath("npx"); return err },
			Fix: "install Node.js — npx ships with it"},
		agent.Check{Name: "stratium-pep binary", Probe: binaryExecutableProbe(pepBin),
			Fix: "build it: cd services && go build -o ../bin/stratium-pep ./cmd/stratium-pep (or set EXAMPLE_PEP_BIN)"},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err := seedData(); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: seeding data:", err)
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

	fmt.Println("stratium-example: building the two-link chain: orchestrator (depth 0, read_text_file+search_files) -> worker (depth 1, read_text_file only)...")
	parentScope := &pdpgrpc.RequestedScope{MaxActionTier: readOnlyTier, Tools: []string{"read_text_file", "search_files"}}
	childScope := &pdpgrpc.RequestedScope{MaxActionTier: readOnlyTier, Tools: []string{"read_text_file"}}
	chain, err := agent.BuildChain(pdpAddr, subject, orchestratorID, workerID, parentScope, childScope,
		"stratium depth-mcp example", 3600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: building the delegation chain:", err)
		return 1
	}
	fmt.Printf("  parent (depth 0): delegation %s, granted %v\n", chain.Parent.DelegationID, chain.Parent.GrantedScope.GetTools())
	fmt.Printf("  child  (depth 1): delegation %s, granted %v\n", chain.Child.DelegationID, chain.Child.GrantedScope.GetTools())

	if err := chain.Parent.WriteSessionFile(parentSessionFile); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}
	if err := chain.Child.WriteSessionFile(childSessionFile); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	// CLAIM 3 first, deliberately: it happens at CREATION time, before either mcp run below ever
	// starts, and reuses chain.Parent.DelegationID that was just minted above.
	fmt.Println("\nstratium-example: attempting to create a child that WIDENS its parent (expect refusal at creation)...")
	widenArgs := map[string]any{"tools": "read_text_file,search_files,write_file"}
	_, widenErr := agent.CreateDelegation(pdpAddr, &pdpgrpc.CreateDelegationRequest{
		Subject: subject,
		AgentId: workerID,
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: readOnlyTier, // same tier as the parent -- isolates the widening to the TOOL dimension alone
			Tools:         []string{"read_text_file", "search_files", "write_file"},
		},
		ParentDelegationId: chain.Parent.DelegationID,
		Purpose:            "stratium depth-mcp example (deliberately widening child, expected to be refused)",
		TtlSeconds:         3600,
	})
	widenResult, err := denialFromCreateAttempt(widenErr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: creating a widening child:", err)
		return 1
	}
	widenWant := []agent.Expectation{{Tool: "create_delegation", Want: agent.Deny, ReasonContains: "not in parent approved_tools"}}
	widenRep := agent.NewReport(widenWant)
	printDecision(os.Stdout, "create_delegation", widenArgs, widenResult)
	widenRep.Record(agent.ToolCall{Name: "create_delegation", Args: widenArgs}, widenResult)

	// Two LLM values, not one, each forcing (agent.LLM's own ToolChoice) the one tool its own
	// conversation exists to probe -- see that field's own doc comment for why this is a
	// model-reliability knob, never a policy one: the real PDP still decides ALLOW/DENY on every
	// call exactly as it would for a call the model chose on its own. llama3.2's own free-form
	// choice of search_files, offered alongside the upstream server's full 14-tool catalog, was
	// confirmed (repeatedly, over time, with an otherwise byte-for-byte identical request) to drift
	// between fully reliable and fully unreliable with no code-path difference behind the drift.
	// Forcing removes that source of flakiness from this file's own two enforcement claims.
	searchLLM := &agent.LLM{BaseURL: "http://" + litellmAddr, Model: "llama3.2", ToolChoice: "search_files"}
	readLLM := &agent.LLM{BaseURL: "http://" + litellmAddr, Model: "llama3.2", ToolChoice: "read_text_file"}

	// Phrased as a near-literal call, not natural prose, for the same reason the ToolChoice fields
	// above exist: a clearer instruction measurably helps even when tool_choice is doing the actual
	// forcing. The pattern is a glob, not a substring (search_files' own contract -- confirmed
	// against the real server: pattern "sentinel" against a file literally named sentinel.txt
	// answers "No matches found"; "sentinel*" matches it), so the wildcard is not decorative.
	taskSearch := `Call search_files(path="/tmp/example-depth-mcp", pattern="sentinel*") to find matching files.`
	// taskRead is its own, separate one-shot conversation -- see this file's own package doc, "TWO
	// SEPARATE SINGLE-TOOL TASKS", for why this is never turn two of taskSearch's own conversation.
	taskRead := `Call read_text_file(path="/tmp/example-depth-mcp/sentinel.txt") to read the file and tell me exactly what it says.`

	fmt.Println("\nstratium-example: running the agent at DEPTH 0 (parent session -- holds both tools)...")
	parentTransport, err := startMCP(pepBin, []string{"mcp"}, mcpEnv(pdpAddr, orchestratorID, parentSessionFile), os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: launching stratium-pep mcp (parent):", err)
		return 1
	}
	wantParent := []agent.Expectation{
		{Tool: "search_files", ArgContains: "sentinel", Want: agent.Allow},
	}
	parentReport := agent.Run(context.Background(), searchLLM, parentTransport, taskSearch, wantParent, os.Stdout)
	_ = parentTransport.Close()
	parentReport.Print(os.Stdout)

	fmt.Println("\nstratium-example: running the SAME task at DEPTH 1 (child session -- search_files narrowed away)...")
	childTransport, err := startMCP(pepBin, []string{"mcp"}, mcpEnv(pdpAddr, workerID, childSessionFile), os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: launching stratium-pep mcp (child):", err)
		return 1
	}
	wantChildSearch := []agent.Expectation{
		{Tool: "search_files", ArgContains: "sentinel", Want: agent.Deny, ReasonContains: "at depth 1"},
	}
	childSearchReport := agent.Run(context.Background(), searchLLM, childTransport, taskSearch, wantChildSearch, os.Stdout)
	childSearchReport.Print(os.Stdout)

	fmt.Println("\nstratium-example: same DEPTH 1 session, a tool the child DOES hold -- proving it still works...")
	wantChildRead := []agent.Expectation{
		{Tool: "read_text_file", ArgContains: "sentinel.txt", Want: agent.Allow},
	}
	childReadReport := agent.Run(context.Background(), readLLM, childTransport, taskRead, wantChildRead, os.Stdout)
	_ = childTransport.Close()
	childReadReport.Print(os.Stdout)

	fmt.Println("\nstratium-example: claim 3 (child creation refused for widening its parent):")
	widenRep.Print(os.Stdout)

	exit := 0
	if parentReport.ExitCode() != 0 || childSearchReport.ExitCode() != 0 || childReadReport.ExitCode() != 0 || widenRep.ExitCode() != 0 {
		exit = 1
	}
	return exit
}

func seedData() error {
	if err := os.MkdirAll(exampleDataDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", exampleDataDir, err)
	}
	if err := os.WriteFile(sentinelPath, []byte("The sentinel value is 42.\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", sentinelPath, err)
	}
	return nil
}

// mcpEnv is the child environment for `stratium-pep mcp`, matching example/mcp/main.go's own
// mcpEnv exactly except for which directory the upstream server is pointed at.
func mcpEnv(pdpAddr, agentID, sessionFile string) []string {
	return append(os.Environ(),
		"STRATIUM_PEP_MCP_UPSTREAM_COMMAND=npx",
		"STRATIUM_PEP_MCP_UPSTREAM_ARGS=-y,@modelcontextprotocol/server-filesystem,"+exampleDataDir,
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_AGENT_ID="+agentID,
		"STRATIUM_PEP_SUBJECT="+subject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s",
		"STRATIUM_PEP_APPROVAL_TIMEOUT=30s", // no ESCALATE path is exercised here; short so a surprise one fails fast rather than hanging the demo
		"STRATIUM_PEP_CACHE_STALENESS_WINDOW=5s",
	)
}

// printDecision matches agent.Run's own ALLOW/DENY line format (agent/agent.go) exactly, so this
// program's claim-3 line reads the same way every ALLOW/DENY line from the two live runs does.
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
// example being broken, not the store answering, and must never be recorded as a decision.
// Duplicated from example/depth/hook/main.go's own identical function rather than shared: every
// runnable example in this suite keeps its own claim-3 probe local.
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

// binaryExecutableProbe is a Precheck probe (agent.Precheck) confirming pepBin exists and is
// executable before this program ever tries to exec it. Duplicated from
// example/depth/hook/main.go's own identical function -- see that file's own doc comment on
// ensureAgent for why every runnable example in this suite keeps this kind of small helper local
// rather than promoting it into example/agent.
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
// Duplicated from example/mcp/main.go's own identical function rather than shared -- see that
// file's own doc comment on why "ensure one specific named agent exists" is not example/agent's
// concern.
func ensureAgent(papAddr, token, name string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name": name, "provider": "example", "model_id": "llama3.2",
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
