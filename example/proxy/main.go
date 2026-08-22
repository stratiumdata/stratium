// Command proxy is the pep-examples suite's third enforcement surface: `stratium-pep proxy`
// sits between an agent's own gRPC client and a real backend service (grpc-target), authorizing
// each RPC by its FULL METHOD PATH -- "/stratium.target.v1.TargetService/Fetch" and
// "/stratium.target.v1.TargetService/Purge" -- before forwarding it. Everything else about this
// program follows example/mcp/main.go's own shape: mint what a session needs, run session-start
// exactly as an operator would, then hand a Transport to agent.Run and get out of the way. See
// that file first if this one is unfamiliar.
//
// WHAT DIFFERS FROM mcp, AND WHY. proxy is a live docker-compose service (pep-proxy, already
// running -- this program never spawns it), fronting grpc-target on a connection this program
// dials directly for one reason only: reading grpc-target's own call counter, never through the
// proxy. See the package doc's THE PUNCHLINE section, below.
//
// SENDER-CONSTRAINED TOKENS, NOT JUST A BEARER ONE. cmd/stratium-pep/proxy.go's own K5 refuses to
// forward ANY call whose token was not minted bound to a caller-held key (spec §4.7.2) -- an
// ordinary bearer token, the kind session-start's CreateDelegation call alone produces, is refused
// even for an action the delegation would otherwise permit, with a denial that is real but reads
// as an authorization failure ("... not bound to a key ... dpop_jwk") rather than as the missing
// proof of possession it actually is. So this program does two things past the delegation the task
// brief's own outline names: it generates its own P-256 keypair, calls the PDP's IssueToken RPC
// directly (there is no session-start flag for this -- see runSessionStart's own comment) to mint
// a SECOND, bound token naming the same delegation, and attaches a fresh RFC 9449 DPoP proof to
// every call. session-start still runs, unmodified in spirit: it is still what creates the
// delegation and still what this program reads granted scope from -- it is only the token that
// gets superseded, for a reason this surface's own package doc names outright and this file does
// not relitigate.
//
// TOOL IDENTITY IS THE FULL METHOD, NOT A FRIENDLY NAME. session-start's own requested-tools list
// below names "/stratium.target.v1.TargetService/Fetch" and NOT Purge's -- that is what makes
// Purge deny with "not in delegation approved_tools" while Fetch allows, both cataloged at the
// identical action tier so a tier ceiling never explains the difference. The model itself never
// sees a method path; proxyTransport.Tools() advertises "fetch" and "purge", and Call maps each to
// its real method, the same friendly-name/wire-identity split hook and mcp already draw for their
// own surfaces.
//
// THIS EXAMPLE'S TENANT NOW HAS A CONTROL PLANE: pap-proxy (docker-compose.yml), a second PAP
// instance bound to pdp-proxy's own tenant "tenant-proxy-integration" -- modelled directly on
// pap-extauthz, which already establishes the pattern of a second PAP on a second dedicated
// tenant. setUpCatalogAndPolicy seeds both tool_catalog rows and one blanket-permit cedar policy
// through pap-proxy's real HTTP API (POST /v1/tool-catalog, POST /v1/policies) -- the same
// idempotent-POST convention example/mcp/main.go's own setUpPolicy already uses, not a direct
// table write.
//
// ONE ROW STILL CANNOT GO THROUGH THAT API, AND THIS PROGRAM DOES NOT WRITE IT EITHER. proxy.go
// reads its own identity from a literal STRATIUM_PEP_AGENT_ID baked into docker-compose.yml at
// startup, never from anything a caller's session names (proxy.go's package doc, NO SESSION
// FILE) -- so the only agent row its principal leg will ever resolve is the one whose id matches
// that exact literal. POST /v1/agents cannot produce that row: store.CreateAgent's own doc
// comment states outright that id (with tenant_id/created_at/updated_at) is ignored on input, and
// the row's id always comes from the table's own uuid_generate_v4() default, never from a caller.
// That is a property of the STACK -- pep-proxy's own fixed configuration -- not of this example,
// so the fixture that satisfies it lives at the stack level too: deploy/seed/proxy-example-
// agent.sql, applied once with psql, the same "data, not code" precedent
// deploy/seed/tool-catalog-*.sql already establish and the same literal id services/internal/
// store/proxy_integration_test.go's own proxyAgentID hardcodes. This program only ever CHECKS
// that row exists (agentSeededProbe, part of Precheck) and tells the operator the exact command
// to run if it does not -- it holds no database credential and imports no SQL driver. See
// task-6-report.md for the fuller case, including the version of this file that did seed it
// directly and why that was wrong.
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"stratium/example/agent"
	"stratium/pkg/grpctarget"
)

const (
	// sessionFile is relative to the CWD `go run ./proxy` is launched from (example/), matching
	// mcp/main.go's own sessionFile exactly.
	sessionFile = ".session.json"

	// exampleAgentID and exampleSubject are fixed, not generated -- see the package doc's ONE ROW
	// STILL CANNOT GO THROUGH THAT API section for why they must equal docker-compose.yml's
	// pep-proxy STRATIUM_PEP_AGENT_ID / STRATIUM_PEP_SUBJECT exactly.
	exampleAgentID = "04ef809a-849f-404a-9a5c-015b7f73a014"
	exampleSubject = "proxy-integration@example.com"

	// exampleTenant is pdp-proxy's own STRATIUM_TENANT_ID (docker-compose.yml) -- also
	// pap-proxy's own tenant, and the one deploy/seed/proxy-example-agent.sql seeds into.
	exampleTenant = "tenant-proxy-integration"

	// publicURI must equal docker-compose.yml's pep-proxy STRATIUM_PEP_PROXY_PUBLIC_URI exactly:
	// proxy.go builds htu from that ONE configured value plus the method path (spec §4.7.2 K7),
	// never from the address this program dials or from anything a caller sends, so a DPoP proof
	// signed against any other string is refused at the PDP's htu comparison regardless of
	// everything else about the call.
	publicURI = "http://proxy.stratium.test:9292"

	// destructiveTier is models.ActionTierDestructive's own wire value. Both grpc-target methods
	// are cataloged at this tier below, and session-start requests it too, so a tier ceiling can
	// never explain why Purge denies -- only approved_tools can (see the package doc).
	destructiveTier = 4

	// editorUser/editorPass are the same shared, tenant-agnostic Keycloak fixture
	// example/mcp/main.go already authenticates against (agent.MintToken's own realm/client):
	// Keycloak proves identity and role membership only, never a tenant -- tenant scoping lives
	// entirely in which PAP instance (here, pap-proxy) a token is presented to.
	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"
)

func main() {
	os.Exit(run())
}

func run() int {
	pdpAddr := os.Getenv("EXAMPLE_PROXY_PDP_ADDR")
	proxyAddr := os.Getenv("EXAMPLE_PEP_PROXY_ADDR")
	targetAddr := os.Getenv("EXAMPLE_GRPC_TARGET_ADDR")
	litellmAddr := os.Getenv("EXAMPLE_LITELLM_ADDR")
	papAddr := os.Getenv("EXAMPLE_PROXY_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")
	ollamaAddr := os.Getenv("EXAMPLE_OLLAMA_ADDR")
	if ollamaAddr == "" {
		ollamaAddr = "127.0.0.1:11434" // fixed, per this suite's own prerequisites -- not ephemeral like the compose ports
	}
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	if pdpAddr == "" || proxyAddr == "" || targetAddr == "" || papAddr == "" || kcAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_PROXY_PDP_ADDR, EXAMPLE_PEP_PROXY_ADDR, EXAMPLE_GRPC_TARGET_ADDR, "+
			"EXAMPLE_PROXY_PAP_ADDR and EXAMPLE_KC_ADDR must be set -- this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           dc up -d pap-proxy --wait`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_PROXY_PDP_ADDR="localhost:$(dc port pdp-proxy 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_PEP_PROXY_ADDR="localhost:$(dc port pep-proxy 9292 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_GRPC_TARGET_ADDR="localhost:$(dc port grpc-target 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_PROXY_PAP_ADDR="localhost:$(dc port pap-proxy 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"`)
		return 1
	}

	fmt.Println("stratium-example: prechecking ollama, litellm, the PDP, pap-proxy, and the seeded agent fixture...")
	if err := agent.Precheck(
		agent.Check{Name: "ollama", Probe: agent.DialCheck(ollamaAddr),
			Fix: "start Ollama and `ollama pull llama3.2` (expected at " + ollamaAddr + ")"},
		agent.Check{Name: "litellm", Probe: agent.AddrProbe(litellmAddr),
			Fix: `EXAMPLE_LITELLM_ADDR not set or not reachable; export EXAMPLE_LITELLM_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port litellm 4000 | sed -E 's/.*://')"`},
		agent.Check{Name: "pdp", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_PROXY_PDP_ADDR not set or not reachable; export EXAMPLE_PROXY_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-proxy 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "pap-proxy", Probe: agent.AddrProbe(papAddr),
			Fix: `EXAMPLE_PROXY_PAP_ADDR not set or not reachable -- bring it up: docker compose -f deploy/docker/docker-compose.yml up -d pap-proxy --wait`},
		agent.Check{Name: "proxy-example-agent", Probe: agentSeededProbe(papAddr, kcAddr),
			Fix: `dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }; dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres psql -h 127.0.0.1 -U stratium_migrate -d stratium -q -f /dev/stdin < deploy/seed/proxy-example-agent.sql`},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	// The tool catalog and the permit policy go through pap-proxy's own HTTP API -- the control
	// plane, not a direct table write. See setUpCatalogAndPolicy's own doc comment. The one agent
	// row that API cannot create was already confirmed present by Precheck, above -- this program
	// never writes it.
	fmt.Println("stratium-example: seeding the tool catalog and permit policy via pap-proxy...")
	if err := setUpCatalogAndPolicy(papAddr, kcAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: starting a delegation session (fetch only, purge deliberately absent)...")
	if err := runSessionStart(pepBin, pdpAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	delegationID, err := agent.ReadDelegationID(sessionFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: minting a DPoP-bound token for the proxy surface (K5)...")
	key, boundToken, err := agent.MintBoundToken(pdpAddr, delegationID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	proxyConn, err := grpc.NewClient(proxyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: dialing pep-proxy:", err)
		return 1
	}
	defer func() { _ = proxyConn.Close() }()

	// THE PUNCHLINE. This second connection goes STRAIGHT to grpc-target, bypassing pep-proxy
	// entirely -- it exists for exactly one call, CallCount, and never for Fetch or Purge.
	//
	// A proxy that forwards and THEN errors has already leaked the request. A caller reading only
	// its own response cannot tell that apart from a proper refusal -- both look like an error.
	// Asking the service what it actually received is the only check that distinguishes them, and
	// routing that question through the proxy would make the check depend on the component under
	// test.
	targetConn, err := grpc.NewClient(targetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: dialing grpc-target directly:", err)
		return 1
	}
	defer func() { _ = targetConn.Close() }()

	direct := grpctarget.NewTargetServiceClient(targetConn)
	before, err := direct.CallCount(context.Background(), &grpctarget.CallCountRequest{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: reading grpc-target's call count before the run:", err)
		return 1
	}

	transport := &proxyTransport{
		viaProxy: grpctarget.NewTargetServiceClient(proxyConn),
		token:    boundToken,
		key:      key,
	}

	llm := &agent.LLM{BaseURL: "http://" + litellmAddr, Model: "llama3.2"}
	task := "Call fetch with the message 'hello'. Then call purge with the message 'wipe it'. " +
		"Tell me what happened to each."
	want := []agent.Expectation{
		{Tool: "fetch", Want: agent.Allow},
		{Tool: "purge", Want: agent.Deny, ReasonContains: "not in delegation approved_tools"},
	}

	fmt.Println("stratium-example: running the agent...")
	report := agent.Run(context.Background(), llm, transport, task, want, os.Stdout)
	report.Print(os.Stdout)

	after, err := direct.CallCount(context.Background(), &grpctarget.CallCountRequest{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: reading grpc-target's call count after the run:", err)
		return 1
	}
	delta := after.GetCount() - before.GetCount()
	fmt.Printf("\n  grpc-target received %d call(s) during this run; this client forwarded %d.\n", delta, transport.forwarded)
	fmt.Println("  Read directly from the service, NOT through the proxy: a proxy that")
	fmt.Println("  forwards and then errors has already leaked the request, and a caller")
	fmt.Println("  reading only its own response cannot tell that apart from a refusal.")

	exit := report.ExitCode()
	// delta is grpc-target's OWN count of calls it actually received; transport.forwarded is
	// how many of THIS client's calls ever got a genuine (non-error) answer back. They must be
	// exactly equal: every call this client saw succeed really did reach grpc-target (no fewer),
	// and grpc-target received nothing this client did not itself see succeed (no more) -- which
	// is exactly what "a proxy that forwards and then errors" would violate, regardless of how
	// many times a chatty model repeats an already-ALLOWED fetch.
	if want := int64(transport.forwarded); delta != want {
		fmt.Fprintf(os.Stderr, "stratium-example: grpc-target's call count moved by %d, but this client only "+
			"ever saw %d call(s) succeed -- something reached the target that this client was never told about\n",
			delta, transport.forwarded)
		exit = 1
	}
	return exit
}

// agentSeededProbe is a Precheck probe, not a seeder: it confirms -- via pap-proxy's own
// GET /v1/agents/{id} -- that the one agent row this surface needs already exists, and returns an
// error naming exactly what is missing if it does not. This program holds no database credential
// and imports no SQL driver; the row itself is a STACK fixture (deploy/seed/proxy-example-
// agent.sql), applied once with psql, because POST /v1/agents cannot create it at all --
// store.CreateAgent's own doc comment states plainly that a caller-supplied id is ignored on
// input, and this example needs one specific, pre-known id: the literal
// STRATIUM_PEP_AGENT_ID docker-compose.yml's pep-proxy is configured with, which
// services/internal/store/proxy_integration_test.go's own proxyAgentID independently hardcodes
// too (see the package doc's ONE ROW STILL CANNOT GO THROUGH THAT API section). A missing fixture
// is setup, exactly like a missing Ollama model or an unreachable PDP -- never a policy denial --
// which is why this is a Precheck entry, in the same style as every other one in this file,
// rather than a special-cased error deeper in the run.
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
			return fmt.Errorf("querying pap-proxy: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()
		switch resp.StatusCode {
		case http.StatusOK:
			return nil
		case http.StatusNotFound:
			return fmt.Errorf("agent %s does not exist in %s yet", exampleAgentID, exampleTenant)
		default:
			b, _ := io.ReadAll(resp.Body)
			return fmt.Errorf("pap-proxy: %s: %s", resp.Status, b)
		}
	}
}

// setUpCatalogAndPolicy seeds both tool_catalog rows and one tenant-wide blanket-permit cedar
// policy through pap-proxy's own HTTP API -- POST /v1/tool-catalog and POST /v1/policies -- the
// same idempotent-POST convention example/mcp/main.go's own setUpPolicy uses for resource-label
// rules: a 201 or a 409 (already exists) both count as success. A fresh editor token is minted
// before each POST group, never cached, per mintToken's own doc comment: an operator token expires
// after five minutes, and this program's own setup plus a live model conversation can outlast it.
func setUpCatalogAndPolicy(papAddr, kcAddr string) error {
	for _, row := range []struct{ tool, verb string }{
		{grpctarget.TargetService_Fetch_FullMethodName, "fetch"},
		{grpctarget.TargetService_Purge_FullMethodName, "purge"},
	} {
		tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
		if err != nil {
			return fmt.Errorf("minting editor token: %w", err)
		}
		if err := ensureToolCatalogEntry(papAddr, tok, row.tool, row.verb); err != nil {
			return err
		}
	}

	tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		return fmt.Errorf("minting editor token: %w", err)
	}
	// A tenant-wide blanket permit, exactly like the earlier examples' own tenants carry (see
	// example/mcp's setUpPolicy) -- the principal leg always allows, so this example's own DENY is
	// unambiguously the delegation leg's approved_tools check, never a cedar refusal underneath it.
	return agent.EnsurePolicy(papAddr, tok, "example-proxy-blanket-permit", `permit(principal, action, resource);`)
}

func ensureToolCatalogEntry(papAddr, token, toolName, verb string) error {
	tier := destructiveTier
	body, _ := json.Marshal(map[string]any{"tool_name": toolName, "action_tier": tier, "verb": verb})
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

// runSessionStart shells out to the real `stratium-pep session-start`, exactly as mcp/main.go's
// own runSessionStart does -- this example runs the real binary, not a reimplementation of what it
// does. Requesting ONLY Fetch's full method path (never Purge's) is what makes Purge deny with
// "not in delegation approved_tools" later: both methods are cataloged at the same action tier
// (setUpCatalogAndPolicy, above), so a tier ceiling can never be the reason.
func runSessionStart(pepBin, pdpAddr string) error {
	cmd := exec.Command(pepBin, "session-start") //nolint:gosec // G204: pepBin is this example's own fixed configuration, never request data.
	cmd.Env = append(os.Environ(),
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_AGENT_ID="+exampleAgentID,
		"STRATIUM_PEP_SUBJECT="+exampleSubject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_REQUESTED_TOOLS="+grpctarget.TargetService_Fetch_FullMethodName,
		fmt.Sprintf("STRATIUM_PEP_REQUESTED_TIER=%d", destructiveTier),
		"STRATIUM_PEP_PURPOSE=stratium proxy example",
		"STRATIUM_PEP_TTL_SECONDS=3600",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("session-start: %w: %s", err, out)
	}
	return nil
}

// messageSchema is the JSON Schema both tools share: {"message": string}, matching
// grpctarget.EchoRequest's own single field.
var messageSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"message": map[string]any{"type": "string"},
	},
	"required": []string{"message"},
}

// proxyTransport is this surface's agent.Transport. It advertises "fetch"/"purge" -- friendly
// names, exactly the shape mcp's tool names already take -- and maps each to the real gRPC method
// grpc-target and pep-proxy both know it by (grpctarget.TargetService_Fetch_FullMethodName /
// _Purge_FullMethodName). The full method path IS the tool identity on this surface
// (cmd/stratium-pep/proxy.go's own package doc, P1): it is what decideRequestFromStream sends the
// PDP as DecideRequest.Tool, and what session-start's own STRATIUM_PEP_REQUESTED_TOOLS names.
type proxyTransport struct {
	viaProxy grpctarget.TargetServiceClient
	token    string
	key      *ecdsa.PrivateKey

	// forwarded counts every call THIS client watched complete successfully (err == nil,
	// Allowed) -- never a denial, and never a call this client merely attempted. Every one of
	// those successes is a response only grpc-target itself could have produced (it is the only
	// thing behind pep-proxy that can echo call_number back), so main()'s own delta assertion
	// checks this against grpc-target's OWN CallCount delta: the two must match exactly, or a
	// request reached the target that this client was never told about -- THE PUNCHLINE, above
	// main(). Nothing here suppresses a repeat: llama3.2 sometimes calls fetch several times
	// instead of stopping, and every one of those repeats is genuinely re-authorized and
	// genuinely re-forwarded, exactly as it would be for a real caller -- forwarded simply grows
	// to match, so a chatty model changes the delta's absolute value without ever breaking the
	// equality the assertion actually checks.
	forwarded int
}

func (t *proxyTransport) Tools() []agent.ToolSpec {
	return []agent.ToolSpec{
		{Name: "fetch", Description: "Fetch a message from the target service.", Schema: messageSchema},
		{Name: "purge", Description: "Purge a message from the target service.", Schema: messageSchema},
	}
}

// Call attaches this run's one bound token plus a FRESH DPoP proof (RFC 9449 jti is single-use --
// K8 -- so a proof cannot be reused across calls, or even across a retry of the same call) to the
// caller's own ctx as gRPC metadata -- this surface has no session file, so the token has to ride
// the wire itself (proxy.go's package doc, NO SESSION FILE) -- then invokes the real method.
//
// A gRPC status of PermissionDenied is a DECISION: the PDP (or this surface's own K5
// proof-of-possession gate, which never gets a chance to fire here because every call already
// carries a valid proof) looked at this exact call and said no. That becomes
// agent.Result{Allowed:false, Reason: st.Message()}. Anything else -- Unavailable, a dead
// connection, a malformed response -- is this example being broken, not policy answering, and is
// returned as a Go error so agent.Run aborts instead of recording a transport failure as a
// decision, which would let a down stack report "enforcement working".
func (t *proxyTransport) Call(ctx context.Context, call agent.ToolCall) (agent.Result, error) {
	var fullMethod string
	switch call.Name {
	case "fetch":
		fullMethod = grpctarget.TargetService_Fetch_FullMethodName
	case "purge":
		fullMethod = grpctarget.TargetService_Purge_FullMethodName
	default:
		return agent.Result{}, fmt.Errorf("proxy transport: unknown tool %q", call.Name)
	}

	// The schema advertised to the model (messageSchema) is not enforced by anything upstream of
	// this line -- a model that emits a non-string "message" must be surfaced as the transport
	// error it is, not silently degraded to an empty-string call that would look like a genuine,
	// deliberate request for "".
	msg, ok := call.Args["message"].(string)
	if !ok {
		return agent.Result{}, fmt.Errorf("proxy transport: %s: args[\"message\"] = %#v, want a string",
			call.Name, call.Args["message"])
	}

	proof, err := t.proof(fullMethod)
	if err != nil {
		return agent.Result{}, fmt.Errorf("proxy transport: build dpop proof: %w", err)
	}
	outCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+t.token, "dpop", proof)

	req := &grpctarget.EchoRequest{Message: msg}
	var resp *grpctarget.EchoResponse
	if call.Name == "fetch" {
		resp, err = t.viaProxy.Fetch(outCtx, req)
	} else {
		resp, err = t.viaProxy.Purge(outCtx, req)
	}
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied {
			return agent.Result{Allowed: false, Reason: st.Message()}, nil
		}
		return agent.Result{}, fmt.Errorf("proxy transport: %s: %w", call.Name, err)
	}
	t.forwarded++
	return agent.Result{Allowed: true, Output: fmt.Sprintf("%s (grpc-target call #%d)", resp.GetMessage(), resp.GetCallNumber())}, nil
}

// proof builds one RFC 9449 DPoP proof for fullMethod, signed by t.key: htm is the constant "POST"
// (gRPC is HTTP/2 POST -- spec §4.7.2 K7), htu is publicURI+fullMethod (the SAME string proxy.go
// builds server-side from its own configuration -- see publicURI's own doc comment), and jti is
// fresh every call so K8's single-use rule never collides with itself across fetch and purge, or
// across a retry of either.
func (t *proxyTransport) proof(fullMethod string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: t.key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		return "", fmt.Errorf("new dpop signer: %w", err)
	}
	return josejwt.Signed(signer).Claims(map[string]any{
		"htm": "POST",
		"htu": publicURI + fullMethod,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}).Serialize()
}
