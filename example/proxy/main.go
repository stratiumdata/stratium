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
// THIS EXAMPLE OWNS ITS OWN TENANT ROW BY ROW. pdp-proxy (docker-compose.yml) is fixed to tenant
// "tenant-proxy-integration", and unlike stratium-pap's own tenant, nothing exposes an HTTP
// control plane for it -- no PAP instance is wired to it in this compose file at all. So this
// program seeds the one agent, the two tool_catalog rows, and one blanket-permit cedar policy it
// needs with direct, idempotent SQL (ON CONFLICT DO NOTHING throughout), the identical shape
// services/internal/store/proxy_integration_test.go's own ensureProxyAgent/ensureProxyCatalog/
// ensureProxyPermitPolicy use to set up the exact same tenant for Go's own integration suite. The
// agent id is fixed, not generated, because it must equal docker-compose.yml's own
// STRATIUM_PEP_AGENT_ID for pep-proxy exactly -- proxy.go reads its own identity from ITS OWN
// startup configuration, never from anything a caller's session names (proxy.go's package doc, NO
// SESSION FILE), so a session-start naming any other agent id would be authorizing a call proxy
// never asks the PDP about.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"stratium/example/agent"
	"stratium/internal/pdpgrpc"
	"stratium/pkg/grpctarget"
)

const (
	// sessionFile is relative to the CWD `go run ./proxy` is launched from (example/), matching
	// mcp/main.go's own sessionFile exactly.
	sessionFile = ".session.json"

	// exampleAgentID and exampleSubject are fixed, not generated -- see the package doc's THIS
	// EXAMPLE OWNS ITS OWN TENANT section for why they must equal docker-compose.yml's pep-proxy
	// STRATIUM_PEP_AGENT_ID / STRATIUM_PEP_SUBJECT exactly.
	exampleAgentID = "04ef809a-849f-404a-9a5c-015b7f73a014"
	exampleSubject = "proxy-integration@example.com"

	// exampleTenant is pdp-proxy's own STRATIUM_TENANT_ID (docker-compose.yml). This example is
	// the only thing in this repo that ever writes to it outside `go test -tags integration`.
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
)

func main() {
	os.Exit(run())
}

func run() int {
	pdpAddr := os.Getenv("EXAMPLE_PDP_ADDR")
	proxyAddr := os.Getenv("EXAMPLE_PEP_PROXY_ADDR")
	targetAddr := os.Getenv("EXAMPLE_GRPC_TARGET_ADDR")
	litellmAddr := os.Getenv("EXAMPLE_LITELLM_ADDR")
	pgAddr := os.Getenv("EXAMPLE_POSTGRES_ADDR")
	ollamaAddr := os.Getenv("EXAMPLE_OLLAMA_ADDR")
	if ollamaAddr == "" {
		ollamaAddr = "127.0.0.1:11434" // fixed, per this suite's own prerequisites -- not ephemeral like the compose ports
	}
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	if pdpAddr == "" || proxyAddr == "" || targetAddr == "" || pgAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_PDP_ADDR, EXAMPLE_PEP_PROXY_ADDR, EXAMPLE_GRPC_TARGET_ADDR "+
			"and EXAMPLE_POSTGRES_ADDR must be set -- this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_PDP_ADDR="localhost:$(dc port pdp-proxy 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_PEP_PROXY_ADDR="localhost:$(dc port pep-proxy 9292 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_GRPC_TARGET_ADDR="localhost:$(dc port grpc-target 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_POSTGRES_ADDR="localhost:$(dc port postgres 5432 | sed -E 's/.*://')"`)
		return 1
	}

	fmt.Println("stratium-example: prechecking ollama, litellm, the PDP, and postgres...")
	if err := agent.Precheck(
		agent.Check{Name: "ollama", Probe: agent.DialCheck(ollamaAddr),
			Fix: "start Ollama and `ollama pull llama3.2` (expected at " + ollamaAddr + ")"},
		agent.Check{Name: "litellm", Probe: addrProbe(litellmAddr),
			Fix: `EXAMPLE_LITELLM_ADDR not set or not reachable`},
		agent.Check{Name: "pdp", Probe: addrProbe(pdpAddr),
			Fix: `EXAMPLE_PDP_ADDR not set or not reachable`},
		agent.Check{Name: "postgres", Probe: addrProbe(pgAddr),
			Fix: `EXAMPLE_POSTGRES_ADDR not set or not reachable`},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Println("stratium-example: seeding this example's own tenant (agent, catalog, permit policy)...")
	db, err := sql.Open("postgres", "postgres://stratium:stratium_local_dev_only@"+pgAddr+"/stratium?sslmode=disable")
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: opening postgres:", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	if err := seedTenant(db); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: starting a delegation session (fetch only, purge deliberately absent)...")
	if err := runSessionStart(pepBin, pdpAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	delegationID, err := readDelegationID(sessionFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: minting a DPoP-bound token for the proxy surface (K5)...")
	key, boundToken, err := mintBoundToken(pdpAddr, delegationID)
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
		{Tool: "purge", Want: agent.Deny},
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
	fmt.Printf("\n  grpc-target received %d call(s) during this run.\n", delta)
	fmt.Println("  Read directly from the service, NOT through the proxy: a proxy that")
	fmt.Println("  forwards and then errors has already leaked the request, and a caller")
	fmt.Println("  reading only its own response cannot tell that apart from a refusal.")

	exit := report.ExitCode()
	if delta != 1 {
		fmt.Fprintf(os.Stderr, "stratium-example: call-count delta = %d, want 1 (Fetch only) -- "+
			"Purge must never reach grpc-target\n", delta)
		exit = 1
	}
	return exit
}

func addrProbe(addr string) func() error {
	return func() error {
		if addr == "" {
			return fmt.Errorf("address not configured")
		}
		return agent.DialCheck(addr)()
	}
}

// seedTenant idempotently inserts the one agent, the two tool_catalog rows, and one blanket-permit
// cedar policy this example needs into exampleTenant -- see the package doc's THIS EXAMPLE OWNS
// ITS OWN TENANT section for why direct SQL, rather than an HTTP control plane, is the only way to
// reach it. All three inserts are ON CONFLICT DO NOTHING, so re-running this program is safe.
// set_config('app.tenant_id', ..., true) is Postgres row-level security's own per-transaction
// tenant switch (every table here forces RLS keyed to current_tenant()) -- true (LOCAL) so it
// applies to this transaction only, the identical mechanism
// services/internal/store/store_integration_test.go's own withTenantTx uses for the same tables.
func seedTenant(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin seed tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`SELECT set_config('app.tenant_id', $1, true)`, exampleTenant); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}

	if _, err := tx.Exec(
		`INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools, classification_caps)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING`,
		exampleAgentID, exampleTenant, "proxy-example-agent", "example", "llama3.2", 3, true, false, []byte(`[]`), []byte(`{}`),
	); err != nil {
		return fmt.Errorf("seed agent: %w", err)
	}

	for _, row := range []struct{ tool, verb string }{
		{grpctarget.TargetService_Fetch_FullMethodName, "fetch"},
		{grpctarget.TargetService_Purge_FullMethodName, "purge"},
	} {
		if _, err := tx.Exec(
			`INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb) VALUES ($1,$2,$3,$4)
			 ON CONFLICT (tenant_id, tool_name) DO NOTHING`,
			exampleTenant, row.tool, destructiveTier, row.verb,
		); err != nil {
			return fmt.Errorf("seed tool_catalog %s: %w", row.tool, err)
		}
	}

	// A tenant-wide blanket permit, exactly like the earlier examples' own tenants carry (see
	// example/mcp's setUpPolicy) -- the principal leg always allows, so this example's own DENY is
	// unambiguously the delegation leg's approved_tools check, never a cedar refusal underneath it.
	if _, err := tx.Exec(
		`INSERT INTO policies (tenant_id, name, language, policy_content, effect) VALUES ($1,$2,'cedar',$3,'allow')
		 ON CONFLICT (tenant_id, name) DO NOTHING`,
		exampleTenant, "example-proxy-blanket-permit", `permit(principal, action, resource);`,
	); err != nil {
		return fmt.Errorf("seed permit policy: %w", err)
	}

	return tx.Commit()
}

// runSessionStart shells out to the real `stratium-pep session-start`, exactly as mcp/main.go's
// own runSessionStart does -- this example runs the real binary, not a reimplementation of what it
// does. Requesting ONLY Fetch's full method path (never Purge's) is what makes Purge deny with
// "not in delegation approved_tools" later: both methods are cataloged at the same action tier
// (seedTenant, above), so a tier ceiling can never be the reason.
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

// readDelegationID reads the delegation id session-start just cached -- the same file and the
// same wire shape session_file.go's own loadSessionFile reads (plain encoding/json over
// *pdpgrpc.CreateDelegationResponse; that file writes it with encoding/json too, not protojson).
// Only the delegation id is used from it: the file's own token is an ordinary bearer token, and
// this surface (unlike hook and mcp) refuses one outright -- see mintBoundToken, below, and the
// package doc's SENDER-CONSTRAINED TOKENS section for why a second, bound token is minted instead
// of sending this one.
func readDelegationID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read session file %s: %w", path, err)
	}
	var resp pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("decode session file %s: %w", path, err)
	}
	if resp.GetDelegationId() == "" {
		return "", fmt.Errorf("session file %s names no delegation", path)
	}
	return resp.GetDelegationId(), nil
}

// mintBoundToken generates a fresh P-256 keypair and calls the PDP's IssueToken RPC directly --
// there is no session-start flag for this; STRATIUM_PEP_REQUESTED_TOOLS and its five siblings are
// session-start's entire env var contract (session_start.go's loadSessionStartConfigFromEnv) and
// none of them names a DPoP key -- to mint a token bound to that key's public half (spec §4.7.2
// K6). Mirrors services/internal/store/proxy_integration_test.go's own mintProxyBoundToken.
func mintBoundToken(pdpAddr, delegationID string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate dpop key: %w", err)
	}
	jwkDoc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		return nil, "", fmt.Errorf("marshal dpop public jwk: %w", err)
	}
	jwk := string(jwkDoc)

	conn, err := grpc.NewClient(pdpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, "", fmt.Errorf("dial pdp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := pdpgrpc.NewPDPServiceClient(conn).IssueToken(ctx, &pdpgrpc.IssueTokenRequest{
		DelegationId: delegationID,
		TtlSeconds:   3600,
		DpopJwk:      &jwk,
	})
	if err != nil {
		return nil, "", fmt.Errorf("issue bound token: %w", err)
	}
	return key, resp.GetToken(), nil
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

	msg, _ := call.Args["message"].(string)

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
