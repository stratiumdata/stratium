// Command proxy is the depth suite's third consumer of agent.BuildChain (example/agent/chain.go):
// it proves that a delegation chain's DEPTH changes what the SAME gRPC call is answered on the
// proxy surface -- `stratium-pep proxy`, the real transparent gRPC proxy example/proxy already
// documents in full (see that directory's own README first if the proxy surface, sender-constrained
// tokens, or the CallCount punchline are unfamiliar; this file follows its shape closely and does
// not re-explain what it explains).
//
// THE THREE CLAIMS:
//
//  1. purge is ALLOWED at depth 0 -- the root delegation holds both Fetch and Purge.
//  2. The SAME purge -- same full method, same tier -- is DENIED at depth 1 -- the narrowed child
//     delegation dropped Purge -- and the denial reason names the depth ("at depth 1"). A denial
//     for a method the parent never held would just be example/proxy one level deeper; only a real
//     two-hop chain shows the PARENT holding what the CHILD does not.
//  3. A child asking for more than its parent granted is refused at CREATION time, before either
//     probe below ever runs -- store.CreateDelegation's own permset.ScopeNarrows check -- naming the
//     dimension that failed (the method the parent never held).
//
// fetch at depth 1 is probed too, alongside claim 2's purge, to show the child is not simply
// broken: it still works for what it does hold.
//
// THE ASYMMETRY THIS EXAMPLE HAS THAT example/depth/hook AND example/depth/mcp DO NOT: pep-proxy
// (docker-compose.yml) is a running service configured with a LITERAL, HARDCODED
// STRATIUM_PEP_AGENT_ID -- read once at startup, never from anything a caller's own request names
// (cmd/stratium-pep/proxy.go's own package doc, NO SESSION FILE). Any delegation this surface will
// ever act under must therefore be issued to that exact same agent id, for both hops -- there is no
// "worker" agent to delegate to, because pep-proxy would never resolve one. This chain is ONE AGENT
// NARROWING ITS OWN AUTHORITY: agent.BuildChain is called with the identical agent id as BOTH
// parentAgentID and childAgentID. It is still a genuine depth-1 chain -- the child's delegation
// still has ParentDelegationId set to the parent's own id, and store.CreateDelegation still runs
// the identical permset.ScopeNarrows check it would for a true orchestrator/worker pair -- but it
// proves "the same principal, one step later, with less" rather than "a different principal,
// downstream, with less." See README.md for the fuller case.
//
// NO SESSION FILE, DPoP-BOUND TOKENS. Exactly like example/proxy: a bearer token (the only kind
// CreateDelegation itself can mint) is refused outright by this surface's own K5 proof-of-
// possession gate. agent.MintBoundToken is called once per hop -- once for the parent's own
// delegation id, once for the child's -- and every call below attaches a fresh RFC 9449 DPoP proof
// built from the matching hop's own key.
//
// CallCount, DIALLED DIRECTLY AT grpc-target, IS THE EXTRA EVIDENCE. A proxy that forwards a denied
// call and then errors has already leaked it; a caller reading only its own response cannot tell
// that apart from a proper refusal. This program reads grpc-target's own call counter directly,
// bypassing pep-proxy entirely, around each probe: it must rise by exactly one for the depth-0
// purge (ALLOWED, genuinely forwarded) and NOT AT ALL for the depth-1 purge (DENIED, never
// forwarded) -- that difference, not just the gRPC status code this program itself observed, is
// the proof.
//
// Run from the example/ directory: `cd example && go run ./depth/proxy`. No live model, no Ollama,
// no LiteLLM: every probe below is a fixed, direct gRPC call, deterministic the same way
// example/depth/hook's own hook probes are. Needs the Docker Compose stack up (pdp-proxy, pap-proxy,
// pep-proxy, grpc-target, keycloak) and deploy/seed/proxy-example-agent.sql already applied -- see
// Precheck below for the exact fixes for either.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/example/agent"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/grpctarget"
)

const (
	// exampleAgentID and exampleSubject are example/proxy's own -- not this program's to invent --
	// because they must equal docker-compose.yml's pep-proxy STRATIUM_PEP_AGENT_ID/
	// STRATIUM_PEP_SUBJECT exactly (see the package doc's THE ASYMMETRY section). Both hops of this
	// chain use this SAME agent id, deliberately: there is no second identity pep-proxy would ever
	// resolve.
	exampleAgentID = "04ef809a-849f-404a-9a5c-015b7f73a014"
	exampleSubject = "proxy-integration@example.com"

	// exampleTenant is pdp-proxy's own STRATIUM_TENANT_ID (docker-compose.yml) -- also pap-proxy's
	// own tenant, and the one deploy/seed/proxy-example-agent.sql seeds into.
	exampleTenant = "tenant-proxy-integration"

	// publicURI must equal docker-compose.yml's pep-proxy STRATIUM_PEP_PROXY_PUBLIC_URI exactly --
	// see example/proxy/main.go's own identical constant for why: proxy.go builds htu from this ONE
	// configured value plus the method path (spec §4.7.2 K7), so a DPoP proof signed against any
	// other string is refused at the PDP's htu comparison regardless of everything else.
	publicURI = "http://proxy.stratium.test:9292"

	// destructiveTier is models.ActionTierDestructive's own wire value. Both grpc-target methods
	// are cataloged at this tier (setUpCatalogAndPolicy, below), and both delegations in this
	// chain request it too, so a tier ceiling can never explain why depth 1's purge denies --
	// only approved_tools, narrowed hop over hop, can.
	destructiveTier int32 = 4

	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"
)

func main() {
	os.Exit(run())
}

func run() int {
	// Reusing example/proxy's own env var names exactly, not a new EXAMPLE_DEPTH_PROXY_* family:
	// this program dials the identical pdp-proxy, pap-proxy, pep-proxy and grpc-target that example
	// already names these variables for -- there is only one of each running, and a shell already
	// exporting these for example/proxy needs nothing new to run this program too.
	pdpAddr := os.Getenv("EXAMPLE_PROXY_PDP_ADDR")
	proxyAddr := os.Getenv("EXAMPLE_PEP_PROXY_ADDR")
	targetAddr := os.Getenv("EXAMPLE_GRPC_TARGET_ADDR")
	papAddr := os.Getenv("EXAMPLE_PROXY_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")

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

	fmt.Println("stratium-example: prechecking the PDP, pep-proxy, grpc-target, pap-proxy, keycloak, and the seeded agent fixture...")
	if err := agent.Precheck(
		agent.Check{Name: "pdp-proxy", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_PROXY_PDP_ADDR not set or not reachable; export EXAMPLE_PROXY_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-proxy 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "pep-proxy", Probe: agent.DialCheck(proxyAddr),
			Fix: `EXAMPLE_PEP_PROXY_ADDR not set or not reachable; export EXAMPLE_PEP_PROXY_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pep-proxy 9292 | sed -E 's/.*://')"`},
		agent.Check{Name: "grpc-target", Probe: agent.DialCheck(targetAddr),
			Fix: `EXAMPLE_GRPC_TARGET_ADDR not set or not reachable; export EXAMPLE_GRPC_TARGET_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port grpc-target 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "pap-proxy", Probe: agent.AddrProbe(papAddr),
			Fix: `EXAMPLE_PROXY_PAP_ADDR not set or not reachable -- bring it up: docker compose -f deploy/docker/docker-compose.yml up -d pap-proxy --wait`},
		agent.Check{Name: "keycloak", Probe: agent.AddrProbe(kcAddr),
			Fix: `EXAMPLE_KC_ADDR not set or not reachable; export EXAMPLE_KC_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"`},
		agent.Check{Name: "proxy-example-agent", Probe: agentSeededProbe(papAddr, kcAddr),
			Fix: `dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }; dc exec -T -e PGPASSWORD=stratium_migrate_local_dev_only postgres psql -h 127.0.0.1 -U stratium_migrate -d stratium -q -f /dev/stdin < deploy/seed/proxy-example-agent.sql`},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Println("stratium-example: seeding the tool catalog and permit policy via pap-proxy...")
	if err := setUpCatalogAndPolicy(papAddr, kcAddr); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	fmt.Println("stratium-example: building the two-link chain: one agent, depth 0 (Fetch+Purge) -> depth 1 (Fetch only)...")
	parentScope := &pdpgrpc.RequestedScope{MaxActionTier: destructiveTier, Tools: []string{
		grpctarget.TargetService_Fetch_FullMethodName, grpctarget.TargetService_Purge_FullMethodName}}
	childScope := &pdpgrpc.RequestedScope{MaxActionTier: destructiveTier, Tools: []string{
		grpctarget.TargetService_Fetch_FullMethodName}}
	// parentAgentID and childAgentID are the SAME literal -- see the package doc's THE ASYMMETRY
	// section for why this chain has no second identity to delegate to.
	chain, err := agent.BuildChain(pdpAddr, exampleSubject, exampleAgentID, exampleAgentID, parentScope, childScope,
		"stratium depth-proxy example (one agent narrowing its own authority)", 3600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: building the delegation chain:", err)
		return 1
	}
	fmt.Printf("  parent (depth 0): delegation %s, granted %v\n", chain.Parent.DelegationID, chain.Parent.GrantedScope.GetTools())
	fmt.Printf("  child  (depth 1): delegation %s, granted %v\n", chain.Child.DelegationID, chain.Child.GrantedScope.GetTools())

	want := []agent.Expectation{
		{Tool: "create_delegation", Want: agent.Deny, ReasonContains: "not in parent approved_tools"},
		{Tool: "purge", ArgContains: "depth0-purge-probe", Want: agent.Allow},
		{Tool: "purge", ArgContains: "depth1-purge-probe", Want: agent.Deny, ReasonContains: "at depth 1"},
		{Tool: "fetch", ArgContains: "depth1-fetch-probe", Want: agent.Allow},
	}
	rep := agent.NewReport(want)

	// CLAIM 3 first, deliberately: it happens at CREATION time, before any probe below runs, and
	// reuses chain.Parent.DelegationID and the SAME exampleAgentID that was just used for both hops
	// above -- widening is refused on the TOOL dimension alone, isolated by requesting the identical
	// tier as the parent and adding CallCount's own full method (a real method neither hop's own
	// scope names) rather than raising the tier too.
	fmt.Println("\nstratium-example: attempting to create a child that WIDENS its parent (expect refusal at creation)...")
	widenArgs := map[string]any{"tools": "Fetch,Purge,CallCount"}
	_, widenErr := agent.CreateDelegation(pdpAddr, &pdpgrpc.CreateDelegationRequest{
		Subject: exampleSubject,
		AgentId: exampleAgentID,
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: destructiveTier,
			Tools: []string{
				grpctarget.TargetService_Fetch_FullMethodName,
				grpctarget.TargetService_Purge_FullMethodName,
				grpctarget.TargetService_CallCount_FullMethodName,
			},
		},
		ParentDelegationId: chain.Parent.DelegationID,
		Purpose:            "stratium depth-proxy example (deliberately widening child, expected to be refused)",
		TtlSeconds:         3600,
	})
	widenResult, err := denialFromCreateAttempt(widenErr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: creating a widening child:", err)
		return 1
	}
	printDecision(os.Stdout, "create_delegation", widenArgs, widenResult)
	rep.Record(agent.ToolCall{Name: "create_delegation", Args: widenArgs}, widenResult)

	fmt.Println("\nstratium-example: minting a DPoP-bound token for each hop (K5)...")
	parentKey, parentToken, err := agent.MintBoundToken(pdpAddr, chain.Parent.DelegationID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting the parent's bound token:", err)
		return 1
	}
	childKey, childToken, err := agent.MintBoundToken(pdpAddr, chain.Child.DelegationID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting the child's bound token:", err)
		return 1
	}

	proxyConn, err := grpc.NewClient(proxyAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: dialing pep-proxy:", err)
		return 1
	}
	defer func() { _ = proxyConn.Close() }()
	viaProxy := grpctarget.NewTargetServiceClient(proxyConn)

	// DIALLED DIRECTLY AT grpc-target, bypassing pep-proxy entirely -- see the package doc's own
	// CallCount section for why this, and not pep-proxy's own response, is the evidence that
	// matters.
	targetConn, err := grpc.NewClient(targetAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: dialing grpc-target directly:", err)
		return 1
	}
	defer func() { _ = targetConn.Close() }()
	direct := grpctarget.NewTargetServiceClient(targetConn)

	ctx := context.Background()
	callCount := func() (int64, error) {
		resp, err := direct.CallCount(ctx, &grpctarget.CallCountRequest{})
		if err != nil {
			return 0, err
		}
		return resp.GetCount(), nil
	}

	checkpoint, err := callCount()
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: reading grpc-target's call count:", err)
		return 1
	}

	exit := 0
	probeAndCheckCount := func(label, toolName string, key *ecdsa.PrivateKey, token, message string, wantDelta int64) {
		fmt.Printf("\nstratium-example: %s...\n", label)
		res, err := callProxyMethod(ctx, viaProxy, key, token, toolName, message)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stratium-example: %s: %v\n", label, err)
			os.Exit(1)
		}
		printDecision(os.Stdout, toolName, map[string]any{"message": message}, res)
		rep.Record(agent.ToolCall{Name: toolName, Args: map[string]any{"message": message}}, res)

		after, err := callCount()
		if err != nil {
			fmt.Fprintln(os.Stderr, "stratium-example: reading grpc-target's call count:", err)
			os.Exit(1)
		}
		delta := after - checkpoint
		fmt.Printf("  grpc-target's own call count moved by %d (dialled directly, bypassing the proxy); want %d\n", delta, wantDelta)
		if delta != wantDelta {
			fmt.Fprintf(os.Stderr, "stratium-example: %s: call count moved by %d, want %d -- the proxy's own response and grpc-target's own state disagree\n",
				label, delta, wantDelta)
			exit = 1
		}
		checkpoint = after
	}

	probeAndCheckCount("DEPTH 0: purge with the parent's bound token (holds both Fetch and Purge)",
		"purge", parentKey, parentToken, "depth0-purge-probe", 1)
	probeAndCheckCount("DEPTH 1: the SAME purge, with the child's bound token (Purge narrowed away)",
		"purge", childKey, childToken, "depth1-purge-probe", 0)
	probeAndCheckCount("DEPTH 1: fetch, which the child DOES hold -- proving it still works",
		"fetch", childKey, childToken, "depth1-fetch-probe", 1)

	rep.Print(os.Stdout)
	if rep.ExitCode() != 0 {
		exit = 1
	}
	return exit
}

// fullMethodFor maps this program's own friendly tool names to grpc-target's real full method
// paths -- the same friendly-name/wire-identity split example/proxy's own proxyTransport draws
// (main.go there, P1): the full method IS the tool identity DecideRequest.Tool carries and
// STRATIUM_PEP_REQUESTED_TOOLS/agent.BuildChain's own Tools list name, never a friendly name.
func fullMethodFor(toolName string) (string, error) {
	switch toolName {
	case "fetch":
		return grpctarget.TargetService_Fetch_FullMethodName, nil
	case "purge":
		return grpctarget.TargetService_Purge_FullMethodName, nil
	default:
		return "", fmt.Errorf("unknown tool %q", toolName)
	}
}

// callProxyMethod attaches token plus a FRESH DPoP proof (RFC 9449 jti is single-use -- K8 -- so a
// proof cannot be reused across calls) to a call through pep-proxy, and turns a gRPC
// PermissionDenied into a policy Result -- or a Go error for anything else, per this suite's own
// rule that a transport fault is never a decision (agent/agent.go's own doc comment; example/proxy's
// identical proxyTransport.Call draws the same line).
func callProxyMethod(ctx context.Context, viaProxy grpctarget.TargetServiceClient, key *ecdsa.PrivateKey, token, toolName, message string) (agent.Result, error) {
	fullMethod, err := fullMethodFor(toolName)
	if err != nil {
		return agent.Result{}, err
	}
	proof, err := dpopProof(key, fullMethod)
	if err != nil {
		return agent.Result{}, fmt.Errorf("build dpop proof: %w", err)
	}
	outCtx := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token, "dpop", proof)

	req := &grpctarget.EchoRequest{Message: message}
	var resp *grpctarget.EchoResponse
	if toolName == "fetch" {
		resp, err = viaProxy.Fetch(outCtx, req)
	} else {
		resp, err = viaProxy.Purge(outCtx, req)
	}
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() == codes.PermissionDenied {
			return agent.Result{Allowed: false, Reason: st.Message()}, nil
		}
		return agent.Result{}, fmt.Errorf("proxy call %s: %w", toolName, err)
	}
	return agent.Result{Allowed: true, Output: fmt.Sprintf("%s (grpc-target call #%d)", resp.GetMessage(), resp.GetCallNumber())}, nil
}

// dpopProof builds one RFC 9449 DPoP proof for fullMethod, signed by key: htm is the constant
// "POST" (gRPC is HTTP/2 POST -- spec §4.7.2 K7), htu is publicURI+fullMethod (the SAME string
// proxy.go builds server-side from its own fixed configuration), and jti is fresh every call so
// K8's single-use rule never collides with itself. Duplicated from example/proxy/main.go's own
// (*proxyTransport).proof rather than shared: that method is a receiver on proxyTransport's own
// single fixed key, and this program needs the identical construction for TWO different keys, one
// per hop, which a shared helper taking the key as a parameter (this function) serves more directly
// than forcing a second proxyTransport-shaped value into existence just to call a method on it.
func dpopProof(key *ecdsa.PrivateKey, fullMethod string) (string, error) {
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
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

// printDecision matches agent.Run's own ALLOW/DENY line format (agent/agent.go) exactly, so this
// program's transcript reads the same way every other example's does, even though nothing here
// drives agent.Run's model loop -- every probe in this file is a fixed, direct gRPC call.
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
// this probe expects. Duplicated from example/depth/hook/main.go's own identical function -- every
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

// agentSeededProbe is a Precheck probe, not a seeder: it confirms -- via pap-proxy's own
// GET /v1/agents/{id} -- that the one agent row this surface needs already exists, and returns an
// error naming exactly what is missing if it does not. This program holds no database credential
// and imports no SQL driver; the row itself is a STACK fixture (deploy/seed/proxy-example-
// agent.sql), applied once with psql, exactly as example/proxy's own identical function documents
// in full (main.go there). Duplicated rather than shared: every runnable example in this suite
// keeps this kind of small, example-specific helper local.
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
// same idempotent-POST convention example/proxy/main.go's own identical function uses: a 201 or a
// 409 (already exists) both count as success. Duplicated rather than shared for the same reason
// agentSeededProbe is: this program must run standalone, whether or not example/proxy has ever run
// against this stack.
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
	return agent.EnsurePolicy(papAddr, tok, "example-proxy-blanket-permit", `permit(principal, action, resource);`)
}

func ensureToolCatalogEntry(papAddr, token, toolName, verb string) error {
	body, _ := json.Marshal(map[string]any{"tool_name": toolName, "action_tier": destructiveTier, "verb": verb})
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
