// Command mcp is the flagship example: a real local model decides its own tool calls, speaking
// plain MCP to what it believes is a filesystem server. `stratium-pep mcp` sits in between,
// authorizing every tools/call against the PDP. What matters most about this program is what is
// ABSENT from it: nothing in mcpclient.go or agent.Run knows Stratium exists. The only Stratium
// awareness in this whole example lives right here in main, in the setup before the agent loop
// ever starts -- registering a resource label, capping the agent, starting a session -- and in
// which two strings are handed to startMCP. See README.md for the substitution test that proves
// it.
//
// Run from the example/ directory: `cd example && go run ./mcp`. It resolves nothing about the
// stack's ephemeral ports itself -- those are read once per `docker compose ... up` and passed in
// as environment variables, the same discipline docs/user-guide.md asks a human operator to follow
// (`export PAP=...`, `export PDP=...`) applied to a program instead of a shell session:
//
//	dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }
//	export EXAMPLE_MCP_PAP_ADDR="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"
//	export EXAMPLE_MCP_PDP_ADDR="localhost:$(dc port pdp-pap 50051   | sed -E 's/.*://')"
//	export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080    | sed -E 's/.*://')"
//	export EXAMPLE_LITELLM_ADDR="localhost:$(dc port litellm 4000 | sed -E 's/.*://')"
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/stratiumdata/stratium/example/agent"
)

const (
	exampleDataDir = "/tmp/example-data"
	notesPath      = exampleDataDir + "/notes.txt"
	secretDir      = exampleDataDir + "/secret-x"
	secretPath     = secretDir + "/plans.txt"

	// sessionFile is relative to the CWD `go run ./mcp` is launched from (example/), per the task
	// brief's own instruction to write into example/.session.json.
	sessionFile = ".session.json"

	agentName = "mcp-flagship-example-agent"

	// subject is already granted delegation by this tenant's own seeded policy
	// ("agent-trial-grant" -- see docs/testing/2026-08-20-agent-integration-test.md §0b). Reusing
	// it, rather than registering a second grant for a subject of our own, is deliberate: a
	// resource-label rule and a classification cap are this example's own concern and are
	// registered below, idempotently, but a delegation-granting policy is tenant setup this
	// example does not own and should not silently duplicate.
	subject = "agent-tester@example.com"

	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"
	adminUser  = "pap-admin"
	adminPass  = "pap_admin_local_dev_only"
)

// readTools is the filesystem server's own read-tier tool vocabulary (tool_catalog action_tier 1
// -- see deploy/seed/tool-catalog-mcp-filesystem.sql), requested by NAME because the tool names on
// this surface are the upstream server's, not a harness's built-in ones (docs/user-guide.md §6.4).
var readTools = []string{
	"read_file", "read_text_file", "read_media_file", "read_multiple_files",
	"list_directory", "list_directory_with_sizes", "directory_tree",
	"search_files", "get_file_info", "list_allowed_directories",
}

func main() {
	os.Exit(run())
}

func run() int {
	papAddr := os.Getenv("EXAMPLE_MCP_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")
	litellmAddr := os.Getenv("EXAMPLE_LITELLM_ADDR")
	pdpAddr := os.Getenv("EXAMPLE_MCP_PDP_ADDR")
	ollamaAddr := os.Getenv("EXAMPLE_OLLAMA_ADDR")
	if ollamaAddr == "" {
		ollamaAddr = "127.0.0.1:11434" // fixed, per this example's own prerequisites -- not ephemeral like the compose ports
	}
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	// PAP and Keycloak addresses are configuration this program cannot guess -- their ports are
	// ephemeral -- but they are not one of the four prerequisites the task calls out for Precheck
	// (Ollama, LiteLLM, the PDP, npx). Missing here is still setup, not a policy denial, so it is
	// reported the same way: named plainly, with the exact fix, before anything else runs.
	if papAddr == "" || kcAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_MCP_PAP_ADDR and EXAMPLE_KC_ADDR must be set — this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_MCP_PAP_ADDR="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"`)
		return 1
	}

	if err := agent.Precheck(
		agent.Check{Name: "ollama", Probe: agent.DialCheck(ollamaAddr),
			Fix: "start Ollama and `ollama pull llama3.2` (expected at " + ollamaAddr + ")"},
		agent.Check{Name: "litellm", Probe: agent.AddrProbe(litellmAddr),
			Fix: `EXAMPLE_LITELLM_ADDR not set or not reachable; export EXAMPLE_LITELLM_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"`},
		agent.Check{Name: "pdp", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_MCP_PDP_ADDR not set or not reachable; export EXAMPLE_MCP_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "npx", Probe: func() error { _, err := exec.LookPath("npx"); return err },
			Fix: "install Node.js — npx ships with it"},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	if err := seedData(); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: seeding data:", err)
		return 1
	}

	if err := setUpPolicy(papAddr, kcAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	agentTok, err := agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	agentID, err := ensureAgent(papAddr, agentTok, agentName)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	// The cap applies at next issuance (docs/user-guide.md §5.7) -- it must be set BEFORE
	// session-start below mints the delegation, or this run's delegation would come back
	// uncapped.
	capTok, err := agent.MintToken(kcAddr, adminUser, adminPass) // ADMIN, not editor -- this route is RoleAdmin
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting admin token:", err)
		return 1
	}
	if err := capClassification(papAddr, capTok, agentID, "nato", "CONFIDENTIAL"); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	if err := runSessionStart(pepBin, pdpAddr, agentID, subject, sessionFile, readTools); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	// THE SUBSTITUTION POINT. Everything above this line exists so that what follows works;
	// everything below neither knows nor cares. Swap these two arguments for
	// ("npx", []string{"-y", "@modelcontextprotocol/server-filesystem", exampleDataDir}) and the
	// agent, the transport, and the enforcement expectations below are all unchanged -- see
	// README.md.
	transport, err := startMCP(pepBin, []string{"mcp"}, mcpEnv(pdpAddr, agentID, subject, sessionFile), os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: launching stratium-pep mcp:", err)
		return 1
	}
	defer func() { _ = transport.Close() }()

	llm := &agent.LLM{BaseURL: "http://" + litellmAddr, Model: "llama3.2"}

	task := "Read /tmp/example-data/notes.txt and tell me what it says. " +
		"Then read /tmp/example-data/secret-x/plans.txt and tell me what that says."
	want := []agent.Expectation{
		{Tool: "read_text_file", ArgContains: "notes.txt", Want: agent.Allow},
		{Tool: "read_text_file", ArgContains: "secret-x", Want: agent.Deny, ReasonContains: "exceeds delegation cap"},
	}

	report := agent.Run(context.Background(), llm, transport, task, want, os.Stdout)
	report.Print(os.Stdout)
	return report.ExitCode()
}

func seedData() error {
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", secretDir, err)
	}
	if err := os.WriteFile(notesPath, []byte("Grocery list: eggs, milk, bread.\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", notesPath, err)
	}
	if err := os.WriteFile(secretPath, []byte("Operation Moonrise launches Friday at dawn.\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", secretPath, err)
	}
	return nil
}

// mcpEnv is the child environment for `stratium-pep mcp`: the upstream server it wraps, plus the
// eight decision variables mcp shares with hook (docs/user-guide.md §3.3). Args are
// comma-separated, not shell-quoted -- STRATIUM_PEP_MCP_UPSTREAM_ARGS is split on commas
// (services/cmd/stratium-pep/mcp.go's splitAndTrim), never passed through a shell.
func mcpEnv(pdpAddr, agentID, subject, sessionFile string) []string {
	return append(os.Environ(),
		"STRATIUM_PEP_MCP_UPSTREAM_COMMAND=npx",
		"STRATIUM_PEP_MCP_UPSTREAM_ARGS=-y,@modelcontextprotocol/server-filesystem,"+exampleDataDir,
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_PDP_INSECURE=true", // the local stack's PDP serves plaintext
		"STRATIUM_PEP_AGENT_ID="+agentID,
		"STRATIUM_PEP_SUBJECT="+subject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s",
		"STRATIUM_PEP_APPROVAL_TIMEOUT=30s", // no ESCALATE path is exercised here; short so a surprise one fails fast rather than hanging the demo
		"STRATIUM_PEP_CACHE_STALENESS_WINDOW=5s",
	)
}

// runSessionStart shells out to the real `stratium-pep session-start`, exactly as an operator
// would from a shell (docs/user-guide.md §6.2 step 4) -- this example runs the real binary, not a
// reimplementation of what it does.
func runSessionStart(pepBin, pdpAddr, agentID, subject, sessionFile string, tools []string) error {
	cmd := exec.Command(pepBin, "session-start") //nolint:gosec // G204: pepBin is this example's own fixed configuration, never request data.
	cmd.Env = append(os.Environ(),
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_PDP_INSECURE=true", // the local stack's PDP serves plaintext
		"STRATIUM_PEP_AGENT_ID="+agentID,
		"STRATIUM_PEP_SUBJECT="+subject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_REQUESTED_TOOLS="+strings.Join(tools, ","),
		"STRATIUM_PEP_REQUESTED_TIER=1", // READ_ONLY -- every tool requested above is a read
		"STRATIUM_PEP_PURPOSE=stratium mcp flagship example",
		"STRATIUM_PEP_TTL_SECONDS=3600",
	)
	var diag bytes.Buffer
	cmd.Stderr = &diag // session-start writes nothing to stdout; every diagnostic is on stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("session-start: %w: %s", err, diag.String())
	}
	return nil
}

// setUpPolicy registers the two resource-label rules this example needs: the empty-prefix
// catch-all (without which ANY classification cap denies every unmatched resource --
// docs/user-guide.md §5.7 trap 1) and the secret- prefix at SECRET. Both POSTs are idempotent: a
// 409 means the rule already exists and is treated as success, exactly like the brief specifies.
func setUpPolicy(papAddr, kcAddr string) error {
	// ADMIN, not editor: creating a label rule is RoleAdmin.
	tok, err := agent.MintToken(kcAddr, adminUser, adminPass)
	if err != nil {
		return fmt.Errorf("minting admin token: %w", err)
	}
	if err := ensureResourceLabelRule(papAddr, tok, "", "nato", "UNCLASSIFIED"); err != nil {
		return err
	}

	tok, err = agent.MintToken(kcAddr, adminUser, adminPass) // minted fresh -- operator tokens expire after five minutes; never cache one
	if err != nil {
		return fmt.Errorf("minting admin token: %w", err)
	}
	return ensureResourceLabelRule(papAddr, tok, exampleDataDir+"/secret-", "nato", "SECRET")
}

func ensureResourceLabelRule(papAddr, token, prefix, hierarchy, level string) error {
	body, _ := json.Marshal(map[string]string{"prefix": prefix, "hierarchy": hierarchy, "level": level})
	req, err := http.NewRequest(http.MethodPost, "http://"+papAddr+"/v1/resource-label-rules", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("resource-label-rules %q: %w", prefix, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("resource-label-rules %q: %s: %s", prefix, resp.Status, b)
}

// ensureAgent registers the example's agent, or finds the one a previous run already created --
// UNIQUE(tenant_id, name) makes the second POST 409, so this run is idempotent across repeats too.
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

// capClassification is the admin-only route (docs/user-guide.md §5.7): a classification ceiling is
// not ordinary agent configuration.
func capClassification(papAddr, token, agentID, hierarchy, level string) error {
	body, _ := json.Marshal(map[string]any{"classification_caps": map[string]string{hierarchy: level}})
	req, err := http.NewRequest(http.MethodPut,
		fmt.Sprintf("http://%s/v1/agents/%s/classification-caps", papAddr, agentID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("classification-caps: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("classification-caps: %s: %s", resp.Status, b)
	}
	return nil
}
