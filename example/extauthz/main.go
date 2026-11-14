// Command extauthz is the pep-examples suite's fourth enforcement surface: Envoy's ext_authz
// filter, backed by `stratium-pep extauthz`, polices which LLM model THIS AGENT ITSELF may call.
// ask_model(model, prompt) goes over HTTP to Envoy's published port; Envoy calls pep-extauthz's
// Check RPC before ever routing to LiteLLM, and pep-extauthz asks the PDP. llama3.2 is allowed;
// gpt-4o is declared in LiteLLM but deliberately unreachable, so a passing run proves policy
// refused it before reachability was ever consulted. Everything about wiring a session and running
// the agent loop follows example/proxy/main.go's own shape -- mint what a session needs, run
// session-start exactly as an operator would, hand a Transport to agent.Run, get out of the way.
// See that file first if this one is unfamiliar.
//
// TWO DIFFERENT ADDRESSES, ON PURPOSE. agent.LLM (the model this program's own agent loop reasons
// with) points DIRECTLY at LiteLLM's published port; the ask_model Transport (below) points at
// ENVOY's published port. See the verbatim comment above the LLM's own construction in run() for
// why routing both through Envoy would deadlock this example the moment the deny fires.
//
// TOOL IDENTITY IS THE REQUEST PATH, INCLUDING THE QUERY -- not a friendly name mapped to it, the
// way proxy's "fetch"/"purge" map to a full gRPC method. cmd/stratium-pep/extauthz.go's own
// decideRequestFromCheck sets DecideRequest.Tool to httpReq.GetPath() ("M1: the request path IS the
// tool identity"), and Envoy's ext_authz filter never sees the request BODY (envoy.yaml sets no
// with_request_body on the filter, and decideRequestFromCheck never reads one) -- so a model name
// sent only in the JSON body would be invisible to the PDP no matter what it said. The only place a
// caller can put "which model" where policy can see it is the PATH, and the one route envoy.yaml
// already wires for this task (a "/chat/completions" PREFIX match, shared by every model) does not
// create a per-model path on its own. toolIdentity(model) closes that gap without touching Envoy's
// route table: it appends the model as a query parameter -- "/chat/completions?model=llama3.2" --
// which becomes a DIFFERENT DecideRequest.Tool per model (GetPath() includes the query --
// extauthz.go's own observedURI doc comment says so and records it observed live) while Envoy's path
// PREFIX match ignores it entirely (prefix matching operates on the path component only).
//
// THE QUERY IS NOT MERELY VISIBLE TO LITELLM -- IT IS WHAT LITELLM ROUTES ON, AHEAD OF THE BODY.
// LiteLLM's own model-resolution precedence (proxy_server.py) is
// `general_settings["completion_model"] or user_model or model or data.get("model")`, where `model`
// is this request's OWN query parameter and `data.get("model")` is the body -- the query wins
// whenever both are present. That is why Call (below) sends the model ONLY in the query and OMITS
// it from the body entirely: the policed identity (the query, because that is what toolIdentity
// puts in the path) and the ROUTED identity must be the same value by construction, not merely by
// this program's own care to keep two copies in sync. Confirmed live: an "?model=gpt-4o" request
// with no "model" key in the body still selects gpt-4o's dead upstream. If LiteLLM instead preferred
// the body, sending both would let a caller police one model while an unpoliced body value routed to
// another -- the exact bypass this design has to avoid, not a hypothetical: this is precisely why
// the body's own "model" key is deleted rather than merely duplicated.
//
// One function, toolIdentity, builds the seeded tool_catalog row name, the delegation's requested
// tool, and the literal path+query this program actually requests -- so those three can never drift
// into three different spellings of the same model.
//
// THE DPOP PROOF'S htu DOES NOT CARRY THE QUERY. observedURI (extauthz.go) strips everything from
// the first "?" onward before comparing against a proof's htu claim (RFC 9449 §4.3 item 9 defines
// htu comparison that way) -- so both models' calls sign the SAME htu,
// "http://envoy.stratium.test/chat/completions", even though they carry different Tool identities.
// Only htu is fixed across the two models; the query -- and therefore the tool_catalog row, and
// whether the delegation holds it -- still varies per model. htm is the actual method this program
// sends (POST), not gRPC's constant "POST" borrowed unexamined from proxy's own htm -- it happens to
// be the same value here because ask_model only ever issues POSTs, not because HTTP and gRPC share a
// convention.
//
// SENDER-CONSTRAINED TOKENS, NOT JUST A BEARER ONE. extauthz refuses an unbound token exactly as
// proxy's own K5 does (extauthz.go's own package doc, SENDER-CONSTRAINED TOKENS) -- see
// example/proxy/main.go's own package doc for the fuller case. mintBoundToken here is copied from
// that file with only the PDP address changed.
//
// A PAP FOR THIS TENANT ALREADY EXISTS: pap-extauthz, serving tenant-extauthz-integration
// (docker-compose.yml) -- provisioned for the suite's own live-Envoy proof before this example
// existed. setUpCatalogAndPolicy seeds this program's own tool_catalog rows and permit policy
// through its real HTTP API, exactly like example/proxy's own setUpCatalogAndPolicy.
//
// ONE ROW STILL CANNOT GO THROUGH THAT API: pep-extauthz's own STRATIUM_PEP_AGENT_ID is a literal
// baked into docker-compose.yml, for the identical reason pep-proxy's is (see example/proxy/main.go's
// own package doc, ONE ROW STILL CANNOT GO THROUGH THAT API) -- deploy/seed/extauthz-example-
// agent.sql is that fixture's stack-level home, and agentSeededProbe (below) only ever checks it is
// there; this program holds no database credential and imports no SQL driver.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/example/agent"
)

const (
	// sessionFile is relative to the CWD `go run ./extauthz` is launched from (example/), matching
	// mcp/main.go's and proxy/main.go's own sessionFile exactly.
	sessionFile = ".session.json"

	// exampleAgentID and exampleSubject are fixed, not generated -- see the package doc's ONE ROW
	// STILL CANNOT GO THROUGH THAT API section for why they must equal docker-compose.yml's
	// pep-extauthz STRATIUM_PEP_AGENT_ID / STRATIUM_PEP_SUBJECT exactly. The same two values are
	// independently hardcoded as extauthzAgentID/extauthzSubject in
	// services/internal/store/extauthz_integration_test.go; this file, that test suite, and
	// docker-compose.yml must all agree, and none of the three may invent a different value.
	exampleAgentID = "72d38ebe-2e5c-4918-9e73-b0de3607fbfa"
	exampleSubject = "extauthz-integration@example.com"

	// exampleTenant is pdp-extauthz's own STRATIUM_TENANT_ID (docker-compose.yml) -- also
	// pap-extauthz's own tenant, and the one deploy/seed/extauthz-example-agent.sql seeds into.
	exampleTenant = "tenant-extauthz-integration"

	// extauthzHost must equal docker-compose.yml's pep-extauthz STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS
	// exactly: Envoy reports the caller's own Host header as the request's authority, and
	// pep-extauthz refuses any authority it is not configured to serve BEFORE the PDP is ever
	// dialed (extauthz.go's own matchAllowedHost) -- a request addressed to anything else denies for
	// the wrong reason and reads as a policy refusal it is not. Every request this program sends
	// sets http.Request.Host to this value explicitly (extauthzTransport.Call).
	extauthzHost = "envoy.stratium.test"

	// chatCompletionsPath is the one route envoy.yaml wires to LiteLLM (a "/chat/completions" prefix
	// match) -- see the package doc's TOOL IDENTITY section for why toolIdentity appends a query
	// parameter to it rather than a path segment.
	chatCompletionsPath = "/chat/completions"

	// askModelTier is models.ActionTierExternalComms's own wire value: asking an external LLM
	// reaches outside the trust boundary. Both tool_catalog rows below are cataloged at this same
	// tier, and session-start requests it too, so a tier ceiling can never explain why gpt-4o denies
	// while llama3.2 allows -- only approved_tools can (see the package doc's TOOL IDENTITY
	// section).
	askModelTier = 3

	// editorUser/editorPass are the same shared, tenant-agnostic Keycloak fixture
	// example/mcp/main.go and example/proxy/main.go already authenticate against (agent.MintToken's
	// own realm/client): Keycloak proves identity and role membership only, never a tenant --
	// tenant scoping lives entirely in which PAP instance (here, pap-extauthz) a token is presented
	// to.
	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"
)

// dpopHTU is the fixed, query-free URI every proof this program mints signs as htu -- see the
// package doc's THE DPOP PROOF'S htu DOES NOT CARRY THE QUERY section for why it is the same string
// for both models even though their requests carry different tool identities.
const dpopHTU = "http://" + extauthzHost + chatCompletionsPath

// modelNames is every model LiteLLM declares (deploy/docker/litellm/config.yaml): llama3.2, served
// by the host's Ollama, and gpt-4o, declared but deliberately unreachable (api_base
// http://127.0.0.1:1) so a call to it can only ever fail for the reason this example exists to
// prove -- policy refused it before LiteLLM ever tried to reach it. Both get a tool_catalog row;
// only llama3.2's is named in session-start's own STRATIUM_PEP_REQUESTED_TOOLS, below.
var modelNames = []string{"llama3.2", "gpt-4o"}

// toolIdentity is the ONE spelling used for a model's tool_catalog row name, its entry (or
// deliberate absence) in STRATIUM_PEP_REQUESTED_TOOLS, and the literal request path+query this
// program sends through Envoy -- see the package doc's TOOL IDENTITY section for why all three must
// stay the same string, character for character.
func toolIdentity(model string) string {
	return chatCompletionsPath + "?model=" + model
}

func main() {
	os.Exit(run())
}

func run() int {
	pdpAddr := os.Getenv("EXAMPLE_EXTAUTHZ_PDP_ADDR")
	envoyAddr := os.Getenv("EXAMPLE_ENVOY_ADDR")
	litellmAddr := os.Getenv("EXAMPLE_LITELLM_ADDR")
	papAddr := os.Getenv("EXAMPLE_EXTAUTHZ_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")
	ollamaAddr := os.Getenv("EXAMPLE_OLLAMA_ADDR")
	if ollamaAddr == "" {
		ollamaAddr = "127.0.0.1:11434" // fixed, per this suite's own prerequisites -- not ephemeral like the compose ports
	}
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	if pdpAddr == "" || envoyAddr == "" || litellmAddr == "" || papAddr == "" || kcAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_EXTAUTHZ_PDP_ADDR, EXAMPLE_ENVOY_ADDR, EXAMPLE_LITELLM_ADDR, "+
			"EXAMPLE_EXTAUTHZ_PAP_ADDR and EXAMPLE_KC_ADDR must be set -- this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_EXTAUTHZ_PDP_ADDR="localhost:$(dc port pdp-extauthz 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_ENVOY_ADDR="localhost:$(dc port envoy 10000 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_LITELLM_ADDR="localhost:$(dc port litellm 4000 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_EXTAUTHZ_PAP_ADDR="localhost:$(dc port pap-extauthz 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"`)
		return 1
	}

	fmt.Println("stratium-example: prechecking ollama, litellm, envoy, the PDP, pap-extauthz, and the seeded agent fixture...")
	if err := agent.Precheck(
		agent.Check{Name: "ollama", Probe: agent.DialCheck(ollamaAddr),
			Fix: "start Ollama and `ollama pull llama3.2` (expected at " + ollamaAddr + ")"},
		agent.Check{Name: "litellm", Probe: agent.AddrProbe(litellmAddr),
			Fix: `EXAMPLE_LITELLM_ADDR not set or not reachable; export EXAMPLE_LITELLM_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"`},
		agent.Check{Name: "envoy", Probe: agent.AddrProbe(envoyAddr),
			Fix: `EXAMPLE_ENVOY_ADDR not set or not reachable; export EXAMPLE_ENVOY_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port envoy 10000 | sed -E 's/.*://')"`},
		agent.Check{Name: "pdp-extauthz", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_EXTAUTHZ_PDP_ADDR not set or not reachable; export EXAMPLE_EXTAUTHZ_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-extauthz 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "pap-extauthz", Probe: agent.AddrProbe(papAddr),
			Fix: `EXAMPLE_EXTAUTHZ_PAP_ADDR not set or not reachable -- bring it up: docker compose -f deploy/docker/docker-compose.yml up -d pap-extauthz --wait`},
		agent.Check{Name: "extauthz-example-agent", Probe: agentSeededProbe(papAddr, kcAddr),
			Fix: `dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }; dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres psql -h 127.0.0.1 -U stratium_migrate -d stratium -q -f /dev/stdin < deploy/seed/extauthz-example-agent.sql`},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// The tool catalog and the permit policy go through pap-extauthz's own HTTP API -- the control
	// plane, not a direct table write. See setUpCatalogAndPolicy's own doc comment. The one agent
	// row that API cannot create was already confirmed present by Precheck, above -- this program
	// never writes it.
	fmt.Println("stratium-example: seeding the tool catalog and permit policy via pap-extauthz...")
	if err := setUpCatalogAndPolicy(papAddr, kcAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: starting a delegation session (llama3.2 only, gpt-4o deliberately absent)...")
	if err := runSessionStart(pepBin, pdpAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	delegationID, err := agent.ReadDelegationID(sessionFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: minting a DPoP-bound token for the extauthz surface (K5)...")
	key, boundToken, err := agent.MintBoundToken(pdpAddr, delegationID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	transport := &extauthzTransport{
		envoyAddr: envoyAddr, token: boundToken, key: key,
		http: &http.Client{Timeout: 60 * time.Second},
	}

	// The agent's own reasoning goes direct to LiteLLM, bypassing Envoy on
	// purpose. Only the ask_model TOOL takes the policed path. Route both through
	// Envoy and this example deadlocks the moment the deny fires: the agent needs
	// a model call in order to tell you its model call was refused.
	llm := &agent.LLM{BaseURL: "http://" + litellmAddr, Model: "llama3.2"}

	task := "Ask the llama3.2 model what 2+2 is. Then ask the gpt-4o model the same thing. " +
		"Report what each said, or why you could not."
	want := []agent.Expectation{
		{Tool: "ask_model", ArgContains: "llama3.2", Want: agent.Allow},
		{Tool: "ask_model", ArgContains: "gpt-4o", Want: agent.Deny, ReasonContains: "not in delegation approved_tools"},
	}

	fmt.Println("stratium-example: running the agent...")
	report := agent.Run(context.Background(), llm, transport, task, want, os.Stdout)
	report.Print(os.Stdout)
	return report.ExitCode()
}

// agentSeededProbe is a Precheck probe, not a seeder: it confirms -- via pap-extauthz's own
// GET /v1/agents/{id} -- that the one agent row this surface needs already exists, and returns an
// error naming exactly what is missing if it does not. This program holds no database credential
// and imports no SQL driver; the row itself is a STACK fixture (deploy/seed/extauthz-example-
// agent.sql), applied once with psql, because POST /v1/agents cannot create it at all -- see the
// package doc's ONE ROW STILL CANNOT GO THROUGH THAT API section. Modelled directly on
// example/proxy/main.go's own agentSeededProbe.
func agentSeededProbe(papAddr, kcAddr string) func() error {
	return func() error {
		tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
		if err != nil {
			return fmt.Errorf("minting a token to check: %w", err)
		}
		req, err := http.NewRequest(http.MethodGet, "http://"+papAddr+"/v1/agents/"+exampleAgentID, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("querying pap-extauthz: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		switch resp.StatusCode {
		case http.StatusOK:
			return nil
		case http.StatusNotFound:
			return fmt.Errorf("agent %s does not exist in %s yet", exampleAgentID, exampleTenant)
		default:
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("pap-extauthz: %s: %s", resp.Status, b)
		}
	}
}

// setUpCatalogAndPolicy seeds one tool_catalog row per modelNames entry, plus one tenant-wide
// blanket-permit cedar policy, through pap-extauthz's own HTTP API -- POST /v1/tool-catalog and
// POST /v1/policies -- the same idempotent-POST convention example/mcp's setUpPolicy and
// example/proxy's own setUpCatalogAndPolicy already use: a 201 or a 409 (already exists) both count
// as success. A fresh editor token is minted before each POST group, never cached, per mintToken's
// own doc comment: an operator token expires after five minutes.
func setUpCatalogAndPolicy(papAddr, kcAddr string) error {
	for _, model := range modelNames {
		tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
		if err != nil {
			return fmt.Errorf("minting editor token: %w", err)
		}
		if err := ensureToolCatalogEntry(papAddr, tok, toolIdentity(model), "ask_model"); err != nil {
			return err
		}
	}

	tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		return fmt.Errorf("minting editor token: %w", err)
	}
	// A tenant-wide blanket permit, exactly like example/proxy's own tenant carries: the principal
	// leg always allows, so this example's own DENY is unambiguously the delegation leg's
	// approved_tools check, never a cedar refusal underneath it.
	return agent.EnsurePolicy(papAddr, tok, "example-extauthz-blanket-permit", `permit(principal, action, resource);`)
}

func ensureToolCatalogEntry(papAddr, token, toolName, verb string) error {
	body, _ := json.Marshal(map[string]any{"tool_name": toolName, "action_tier": askModelTier, "verb": verb})
	req, err := http.NewRequest(http.MethodPost, "http://"+papAddr+"/v1/tool-catalog", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("tool-catalog %q: %w", toolName, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("tool-catalog %q: %s: %s", toolName, resp.Status, b)
}

// runSessionStart shells out to the real `stratium-pep session-start`, exactly as mcp/main.go's and
// proxy/main.go's own runSessionStart do -- this example runs the real binary, not a
// reimplementation of what it does. Requesting ONLY llama3.2's tool identity (never gpt-4o's) is
// what makes gpt-4o deny with "not in delegation approved_tools" later: both are cataloged at the
// same action tier (setUpCatalogAndPolicy, above), so a tier ceiling can never be the reason.
func runSessionStart(pepBin, pdpAddr string) error {
	cmd := exec.Command(pepBin, "session-start") //nolint:gosec // G204: pepBin is this example's own fixed configuration, never request data.
	cmd.Env = append(os.Environ(),
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_AGENT_ID="+exampleAgentID,
		"STRATIUM_PEP_SUBJECT="+exampleSubject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_REQUESTED_TOOLS="+toolIdentity("llama3.2"),
		fmt.Sprintf("STRATIUM_PEP_REQUESTED_TIER=%d", askModelTier),
		"STRATIUM_PEP_PURPOSE=stratium extauthz example",
		"STRATIUM_PEP_TTL_SECONDS=3600",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("session-start: %w: %s", err, out)
	}
	return nil
}

// askModelSchema is the JSON Schema for ask_model's one argument object: {"model": string, "prompt":
// string}. The model advertised here chooses WHICH model to ask by NAME; extauthzTransport.Call maps
// that name to the tool identity (path+query) the choice actually is. A json.RawMessage literal,
// not map[string]any -- see agent.ToolSpec's own Schema field for why a Go map's key order (always
// alphabetized on marshal) is not safe to round-trip through when a tool schema reaches the model.
var askModelSchema = json.RawMessage(`{"type":"object","properties":{"model":{"type":"string"},"prompt":{"type":"string"}},"required":["model","prompt"]}`)

// extauthzTransport is this surface's agent.Transport. It advertises a single "ask_model" tool --
// the model under test picks WHICH model to ask via its own "model" argument -- and Call turns that
// into an HTTP POST through Envoy at toolIdentity(model), the literal path+query that IS this call's
// tool identity (see the package doc's TOOL IDENTITY section).
type extauthzTransport struct {
	envoyAddr string
	token     string
	key       *ecdsa.PrivateKey
	http      *http.Client
}

func (t *extauthzTransport) Tools() []agent.ToolSpec {
	return []agent.ToolSpec{
		{Name: "ask_model", Description: "Ask a named LLM model a prompt and return what it said.", Schema: askModelSchema},
	}
}

// Call builds a fresh RFC 9449 DPoP proof (jti is single-use -- K8 -- so a proof cannot be reused
// across the two models' calls, or across a retry of either) and POSTs {"messages"} -- deliberately
// no "model" key -- to Envoy at toolIdentity(model), NOT at the bare chatCompletionsPath, with Host
// set to extauthzHost: Envoy reports the caller's own Host header as the request's authority, and
// pep-extauthz refuses any authority it is not configured to serve BEFORE the PDP is ever dialed.
//
// THE MODEL RIDES ONLY IN THE QUERY, NEVER IN THE BODY. LiteLLM resolves the model to call from
// `... or model or data.get("model")` (proxy_server.py) -- `model` is this request's query
// parameter, checked BEFORE `data.get("model")`, the body -- so sending it in the query alone is
// sufficient for routing (see the package doc's own citation) and omitting it from the body is what
// makes the policed value and the routed value the SAME value BY CONSTRUCTION rather than by this
// program's own care to keep two copies in sync. Sending both would still work today, but would
// degrade silently into a bypass surface the moment a future LiteLLM release reverses that
// precedence -- nothing in this example would fail, because body and query would always agree with
// each other, never with an attacker's intent to have them differ. With the body empty of "model",
// there is only one value in the request for the PDP's decision and LiteLLM's routing to possibly
// disagree about, and that value is the one in the path this program already asked policy about.
//
// A 403 is a DECISION: Envoy's ext_authz filter, or the PDP behind it, looked at this exact call and
// said no. That becomes agent.Result{Allowed:false, Reason: <body>}. A 500, 502, or 503 means Envoy
// let the request through to LiteLLM and LiteLLM then failed to reach the model's own upstream --
// exactly gpt-4o's deliberately-unreachable api_base, which LiteLLM reports as a 500
// (litellm.InternalServerError, "Connection error") not a 502/503 -- either way this means ext_authz
// did NOT refuse the call; that is this example failing to hold the delegation's approved_tools list
// where it should, not policy working, and is returned as a Go error rather than a denial. Any other
// transport failure -- a dead connection, a malformed response -- is returned as a Go error too, so
// agent.Run aborts instead of recording a broken example as an enforcement decision.
func (t *extauthzTransport) Call(ctx context.Context, call agent.ToolCall) (agent.Result, error) {
	model, ok := call.Args["model"].(string)
	if !ok {
		return agent.Result{}, fmt.Errorf("extauthz transport: ask_model: args[\"model\"] = %#v, want a string", call.Args["model"])
	}
	prompt, ok := call.Args["prompt"].(string)
	if !ok {
		return agent.Result{}, fmt.Errorf("extauthz transport: ask_model: args[\"prompt\"] = %#v, want a string", call.Args["prompt"])
	}

	// No "model" key here -- see this function's own doc comment, THE MODEL RIDES ONLY IN THE QUERY.
	body, err := json.Marshal(map[string]any{
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	if err != nil {
		return agent.Result{}, fmt.Errorf("extauthz transport: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://"+t.envoyAddr+toolIdentity(model), bytes.NewReader(body))
	if err != nil {
		return agent.Result{}, fmt.Errorf("extauthz transport: build request: %w", err)
	}
	// The AUTHORITY this request ADDRESSES, not the host:port it dials -- see this function's own
	// doc comment. Go puts req.Host on the wire as the Host header when it is non-empty.
	req.Host = extauthzHost
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+t.token)

	proof, err := t.proof()
	if err != nil {
		return agent.Result{}, fmt.Errorf("extauthz transport: build dpop proof: %w", err)
	}
	req.Header.Set("DPoP", proof)

	resp, err := t.http.Do(req)
	if err != nil {
		return agent.Result{}, fmt.Errorf("extauthz transport: %s: %w", model, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return agent.Result{}, fmt.Errorf("extauthz transport: %s: read response: %w", model, err)
	}

	switch resp.StatusCode {
	case http.StatusForbidden:
		return agent.Result{Allowed: false, Reason: string(respBody)}, nil
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable:
		// 500 is LiteLLM's OWN reported status for an unreachable api_base
		// (litellm.InternalServerError, "Connection error") -- gpt-4o's exact deliberately-broken
		// deployment -- confirmed live; 502/503 are also caught here for the same "let through, not
		// refused" reading in case a future LiteLLM version reports the failure differently.
		return agent.Result{}, fmt.Errorf(
			"%s returned %s -- that is LiteLLM failing to reach the upstream, NOT a policy denial. "+
				"Envoy let the request through, which means ext_authz did not refuse it. "+
				"Check the delegation does not hold the %s tool", model, resp.Status, model)
	case http.StatusOK:
		// Model is decoded too, not just choices[].message.content: without it, this proves only
		// that the POLICED value (the query this program itself sent) was the only "model" present
		// on the wire, never that the model which actually answered was the one policy approved.
		// Reading LiteLLM's own response envelope back closes that gap -- the transcript names
		// which model really replied, not just which model was asked.
		var out struct {
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Content string `json:"content"`
				} `json:"message"`
			} `json:"choices"`
		}
		if err := json.Unmarshal(respBody, &out); err != nil {
			return agent.Result{}, fmt.Errorf("extauthz transport: %s: decode response: %w", model, err)
		}
		if len(out.Choices) == 0 {
			return agent.Result{}, fmt.Errorf("extauthz transport: %s: no choices in response: %s", model, respBody)
		}
		return agent.Result{Allowed: true, Output: fmt.Sprintf("answered as %s: %s", out.Model, out.Choices[0].Message.Content)}, nil
	default:
		return agent.Result{}, fmt.Errorf("extauthz transport: %s: unexpected status %s: %s", model, resp.Status, respBody)
	}
}

// proof builds one RFC 9449 DPoP proof, signed by t.key: htm is the actual method this call uses
// (POST -- every ask_model call is a POST, not gRPC's constant "POST" borrowed unexamined from
// proxy), and htu is dpopHTU, the fixed, query-free URI pep-extauthz's own observedURI reconstructs
// from Envoy's report -- see the package doc's THE DPOP PROOF'S htu DOES NOT CARRY THE QUERY section
// for why both models sign the identical htu even though they carry different Tool identities. jti
// is fresh every call so K8's single-use rule never collides with itself across the two models, or
// across a retry of either.
func (t *extauthzTransport) proof() (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: t.key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		return "", fmt.Errorf("new dpop signer: %w", err)
	}
	return josejwt.Signed(signer).Claims(map[string]any{
		"htm": http.MethodPost,
		"htu": dpopHTU,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}).Serialize()
}
