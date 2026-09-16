// Command widening is the example suite's sixth directory, and the first
// that connects the other five's own story to containment/'s. Every
// hook/mcp/proxy/extauthz example polices a tool call; containment/ asks the
// admin plane, in isolation, whether a candidate grant is wider than a
// baseline. Nothing before this program ever showed those two things
// happening to the SAME agent, in order:
//
//  1. An agent calls a tool through `stratium-pep hook` -> DENIED, because
//     the tool is not in its allowlist.
//  2. An operator widens that agent's grant via PUT /v1/agents/{id}, adding
//     the tool.
//  3. That write appends a `containment` audit row: "agent grant widened:
//     <reason>" -- internal/store/containment_audit.go's own recordWideningTx,
//     running inside the SAME transaction as the PUT, so the row commits with
//     the write it describes or not at all.
//  4. The identical tool call, on the SAME delegation minted before step 1,
//     now -> ALLOWED. No new session is minted between steps 1 and 4 -- see
//     "Same session, not a new one" below for why that is not a given.
//  5. This program reads the containment row back out of Postgres directly
//     and prints it.
//
// # Step 5 is the point, and it is deliberately awkward
//
// There is no audit READ endpoint. `stratium-pap` writes eventTypeContainment
// rows into audit_chain (internal/store/containment_audit.go) and exposes no
// route that returns them: GET /v1/delegations, /v1/agents, and every other
// admin-plane read this suite's other five examples use are all
// forward-looking config, not history. To show its own record, this program
// opens a direct `lib/pq` connection to the same Postgres instance
// `stratium-pap` itself writes to, as the `postgres` superuser -- exactly
// what an operator reaching for `psql` would do, because there is nothing
// else to reach for. That is a documented gap (containment_audit.go's own
// package doc names a `permset`-level containment operation as follow-up
// work; a read endpoint is a narrower version of the same debt), and the
// honest way to show a reader a gap is to make them watch the workaround,
// not to describe it in prose they can skim past.
//
// # Same session, not a new one
//
// A delegation's own approved_tools is fixed at mint time
// (models.Delegation.HasTool); an agent's allowed_tools is read fresh on
// every decision (models.Agent.HasTool, consulted by authz.AgentLeg, and
// internal/pdpgrpc/server.go's own Decide calls store.LoadAgent with no
// caching layer in front of it -- see that file's own doc comment). Those
// are different lifetimes, and this program's delegation is minted
// DELIBERATELY wider than the agent's own starting allowlist: approved for
// [Read Write] from the very first CreateDelegation call, while the agent
// itself starts restricted to [Read] alone. The tool call in step 1 fails
// the AGENT leg, not the delegation leg -- the delegation was never the
// bottleneck. Widening the agent's own allowlist in step 2 removes the one
// leg that was failing, and the SAME session -- the SAME delegation id,
// asserted below -- answers differently on the very next call. Nothing about
// this required minting a second delegation. Had this program instead
// minted the delegation narrowly (approved_tools: [Read], matching the
// agent's own starting allowlist), step 4 would need a brand-new session:
// the delegation leg would still refuse Write, no matter how wide the
// agent's own allowlist became, because that leg's ceiling was fixed the
// moment session-start ran. Which of those two shapes an operator is
// actually holding is not visible from the outside -- it is worth knowing
// which one you have before promising a colleague "it'll work as soon as I
// widen the grant."
//
// # What is real here and what is local
//
// Every ALLOW/DENY below comes from a real `stratium-pep hook` subprocess
// talking to a real PDP; the PUT that widens the grant is a real HTTP call
// to a real stratium-pap; the containment row in step 5 is read back from
// the real Postgres instance that PUT wrote to, not recomputed locally.
// Every expectation is asserted, the same discipline example/containment's
// own package doc describes: if the engine's answer stops matching what this
// program claims, it fails loudly rather than printing a story that is no
// longer true.
//
// Run from the example/ directory: `cd example && go run ./widening`. Needs
// the Docker Compose stack up (postgres, keycloak, pdp-pap, stratium-pap)
// and the real `stratium-pep` binary built -- see Precheck below for the
// exact fixes if any is missing.
package main

import (
	"fmt"
	"os"

	"stratium/example/agent"
	"stratium/internal/pdpgrpc"
)

const (
	// sessionFile is unique to this example, per example/README.md's own
	// "One session file per example" rule -- mcp, proxy and extauthz all
	// default to the shared ".session.json" in example/ and must never run
	// concurrently with each other; this one lives in its own directory and
	// under its own name regardless, so it can never collide with any of
	// them even if that rule is ever relaxed.
	sessionFile = "widening/.session.json"

	agentName = "widening-example-agent"

	// subject is this program's own -- not example/mcp's
	// "agent-tester@example.com" or example/depth/hook's "depth-hook@example.com"
	// -- and gets its own scoped policy below, for the identical reason
	// depth/hook's own subject constant gives: this program shares tenant
	// tenant-pap-e2e-integration with two other examples and must not widen
	// what every OTHER principal in that tenant may be granted.
	subject = "widening-example@example.com"

	// tool is the one call this whole story turns on. It is deliberately
	// NOT a read: catalog.go's DefaultCatalog fixes Write at
	// ActionTierInternalModify (internalModifyTier below), high enough that
	// a restricted allowlist denying it is unsurprising, and low enough that
	// this example's agent (trust_tier 3, PlatformTrusted) clears the trust
	// floor (authz.DefaultTrustTable: INTERNAL_MODIFY needs only
	// TrustTierRegistered) without needing a tier discussion of its own.
	tool = "Write"

	// internalModifyTier is models.ActionTierInternalModify's own wire value
	// (2) -- a local int32 constant, not an import of stratium/pkg/models,
	// matching example/depth/hook's own readOnlyTier precedent (main.go
	// there) for the identical reason: one int worth naming does not earn a
	// new import.
	internalModifyTier int32 = 2

	editorUser = "pap-editor"
	editorPass = "pap_editor_local_dev_only"

	policyName = "example-widening-permit"
	// policyContent is scoped to THIS example's own subject, matching
	// depth/hook's own policyContent for the identical reason (see that
	// file's own comment): an unconditioned tenant-wide permit would widen
	// what every other principal sharing this tenant may be granted, not
	// just this one's.
	policyContent = `permit(principal == User::"widening-example@example.com", action, resource);`
)

func main() {
	os.Exit(run())
}

func run() int {
	papAddr := os.Getenv("EXAMPLE_WIDENING_PAP_ADDR")
	pdpAddr := os.Getenv("EXAMPLE_WIDENING_PDP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")
	pgAddr := os.Getenv("EXAMPLE_WIDENING_PG_ADDR")
	pepBin := os.Getenv("EXAMPLE_PEP_BIN")
	if pepBin == "" {
		pepBin = "../bin/stratium-pep"
	}

	if papAddr == "" || pdpAddr == "" || kcAddr == "" || pgAddr == "" {
		fmt.Fprintln(os.Stderr, "stratium-example: EXAMPLE_WIDENING_PAP_ADDR, EXAMPLE_WIDENING_PDP_ADDR, "+
			"EXAMPLE_KC_ADDR and EXAMPLE_WIDENING_PG_ADDR must be set — this is setup, not a policy denial:")
		fmt.Fprintln(os.Stderr, `      fix: dc() { docker compose -f deploy/docker/docker-compose.yml "$@"; }`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_WIDENING_PAP_ADDR="localhost:$(dc port stratium-pap 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_WIDENING_PDP_ADDR="localhost:$(dc port pdp-pap 50051 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_KC_ADDR="localhost:$(dc port keycloak 8080 | sed -E 's/.*://')"`)
		fmt.Fprintln(os.Stderr, `           export EXAMPLE_WIDENING_PG_ADDR="localhost:$(dc port postgres 5432 | sed -E 's/.*://')"`)
		return 1
	}

	fmt.Println("stratium-example: prechecking the PDP, the PAP, Postgres, and the stratium-pep binary...")
	if err := agent.Precheck(
		agent.Check{Name: "pdp-pap", Probe: agent.AddrProbe(pdpAddr),
			Fix: `EXAMPLE_WIDENING_PDP_ADDR not set or not reachable; export EXAMPLE_WIDENING_PDP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port pdp-pap 50051 | sed -E 's/.*://')"`},
		agent.Check{Name: "stratium-pap", Probe: agent.AddrProbe(papAddr),
			Fix: `EXAMPLE_WIDENING_PAP_ADDR not set or not reachable; export EXAMPLE_WIDENING_PAP_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"`},
		agent.Check{Name: "keycloak", Probe: agent.AddrProbe(kcAddr),
			Fix: `EXAMPLE_KC_ADDR not set or not reachable; export EXAMPLE_KC_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"`},
		agent.Check{Name: "postgres", Probe: agent.AddrProbe(pgAddr),
			Fix: `EXAMPLE_WIDENING_PG_ADDR not set or not reachable; export EXAMPLE_WIDENING_PG_ADDR="localhost:$(docker compose -f deploy/docker/docker-compose.yml port postgres 5432 | sed -E 's/.*://')"`},
		agent.Check{Name: "stratium-pep binary", Probe: binaryExecutableProbe(pepBin),
			Fix: "build it: cd services && go build -o ../bin/stratium-pep ./cmd/stratium-pep (or set EXAMPLE_PEP_BIN)"},
	); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	fmt.Println("stratium-example: registering the agent and this example's own scoped policy...")
	tok, err := agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	agentID, err := ensureAgent(papAddr, tok)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	tok, err = agent.MintToken(kcAddr, editorUser, editorPass) // minted fresh -- operator tokens expire after five minutes
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	if err := agent.EnsurePolicy(papAddr, tok, policyName, policyContent); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	// Idempotent reset, not narration: a previous run of THIS example may
	// have already widened widening-example-agent's own allowlist and left
	// it that way (this program never narrows it back down on its own). A
	// PUT that replaces [Write? Read] with [Read] is itself a narrowing (or,
	// on a fresh agent, a no-op) — recordWideningTx appends nothing for
	// either, so this never pollutes the audit trail step 5 goes on to read.
	fmt.Println("stratium-example: resetting the agent's allowed_tools to [Read] (idempotent — a previous run may have widened it)...")
	tok, err = agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	if err := resetAgentTools(papAddr, tok, agentID, []string{"Read"}); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}

	// The delegation is minted WIDER than the agent's own starting
	// allowlist, on purpose — see the package doc's "Same session, not a new
	// one" section for why that is the whole point of what step 4 proves.
	fmt.Println("stratium-example: minting a delegation approved for [Read Write] " +
		"(the agent itself is not yet allowed Write)...")
	resp, err := agent.CreateDelegation(pdpAddr, &pdpgrpc.CreateDelegationRequest{
		Subject: subject,
		AgentId: agentID,
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: internalModifyTier,
			Tools:         []string{"Read", tool},
		},
		Purpose:    "stratium widening example",
		TtlSeconds: 3600,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: creating the delegation:", err)
		return 1
	}
	if err := writeSessionFile(resp, sessionFile); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}
	delegationBefore, err := agent.ReadDelegationID(sessionFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}
	fmt.Printf("  delegation %s minted, approved_tools=%v\n\n", delegationBefore, []string{"Read", tool})

	hookEnv := pepHookEnv(pdpAddr, agentID, sessionFile)
	toolInput := func(marker string) map[string]any {
		return map[string]any{"file_path": "/tmp/widening-example/" + marker + ".txt", "content": "widened"}
	}

	fmt.Println("=== Step 1 — the tool call is denied: Write is not in the agent's allowlist ===")
	before, err := runHookProbe(pepBin, hookEnv, tool, toolInput("before"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: probing before the widening:", err)
		return 1
	}
	printDecision(os.Stdout, tool, toolInput("before"), before)
	if before.Allowed {
		fmt.Fprintln(os.Stderr, "\nstratium-example: the tool call was ALLOWED before any grant was widened — "+
			"the example is wrong, or the engine changed; do not paper over this")
		return 1
	}
	const wantDenyReason = `tool "Write" not in agent allowed_tools`
	if before.Reason != wantDenyReason {
		fmt.Fprintf(os.Stderr, "\nstratium-example: DENY reason was %q, expected %q — "+
			"the example is wrong, or the engine changed; do not paper over this\n", before.Reason, wantDenyReason)
		return 1
	}

	fmt.Println("\n=== Step 2 — an operator widens the agent's grant via PUT /v1/agents/{id} ===")
	tok, err = agent.MintToken(kcAddr, editorUser, editorPass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: minting editor token:", err)
		return 1
	}
	if err := resetAgentTools(papAddr, tok, agentID, []string{"Read", tool}); err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}
	fmt.Printf("  PUT /v1/agents/%s  allowed_tools: [Read] -> [Read %s]\n", agentID, tool)
	fmt.Println("  The write lands whether or not it widens anything — this API never blocks a grant change.")
	fmt.Println("  What differs is what it leaves behind: see step 5.")

	fmt.Println("\n=== Step 3 — that write appends a `containment` row to the audit chain ===")
	fmt.Println("  (nothing to show yet — there is no read endpoint for it. That is step 5.)")

	fmt.Println("\n=== Step 4 — the SAME tool call, on the SAME session, now ALLOWED ===")
	delegationAfter, err := agent.ReadDelegationID(sessionFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example:", err)
		return 1
	}
	if delegationAfter != delegationBefore {
		fmt.Fprintf(os.Stderr, "\nstratium-example: session file's delegation id changed from %s to %s without "+
			"this program minting a new one — the example is wrong\n", delegationBefore, delegationAfter)
		return 1
	}
	after, err := runHookProbe(pepBin, hookEnv, tool, toolInput("after"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: probing after the widening:", err)
		return 1
	}
	printDecision(os.Stdout, tool, toolInput("after"), after)
	if !after.Allowed {
		fmt.Fprintf(os.Stderr, "\nstratium-example: the tool call was still DENIED after widening the agent's "+
			"grant (%s) — the example is wrong, or the engine changed; do not paper over this\n", after.Reason)
		return 1
	}
	fmt.Printf("  same delegation id as step 1 (%s) — no new session was minted. Widening the AGENT's own\n", delegationAfter)
	fmt.Println("  allowlist was enough, because the delegation was already approved for Write; only the agent")
	fmt.Println("  leg was ever the bottleneck. A delegation minted narrowly, matching the agent's own starting")
	fmt.Println("  allowlist, would have needed a brand-new session here instead — see this program's own")
	fmt.Println("  package doc, \"Same session, not a new one,\" for why.")

	fmt.Println("\n=== Step 5 — reading the containment row directly from Postgres (no audit read endpoint exists) ===")
	row, err := readContainmentRow(pgAddr, agentID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "stratium-example: querying audit_chain directly (stratium-pap exposes no "+
			"read endpoint for this event type, so this program connects to its own Postgres instance as the "+
			"postgres superuser — the same thing an operator reaching for psql would do):", err)
		return 1
	}
	fmt.Printf("  occurred_at: %s\n", row.OccurredAt.Format("2006-01-02T15:04:05Z07:00"))
	fmt.Printf("  actor:       %s\n", row.Actor)
	fmt.Printf("  decision:    %s\n", row.Decision)
	fmt.Printf("  reason:      %s\n", row.Reason)
	const wantContainmentReason = "agent grant widened: child tool Write not in parent approved_tools"
	if row.Reason != wantContainmentReason {
		fmt.Fprintf(os.Stderr, "\nstratium-example: containment row's reason was %q, expected %q — "+
			"the example is wrong, or the engine changed; do not paper over this\n", row.Reason, wantContainmentReason)
		return 1
	}
	fmt.Println("\n  That reason is the SAME containmentReason(before, after) computation")
	fmt.Println("  example/containment/main.go's own Act 1 drives through a live POST /v1/containment call — here")
	fmt.Println("  it ran as a side effect of an ordinary PUT, inside the same transaction as the write it")
	fmt.Println("  describes, and the only way to see it afterwards was to open the database directly.")

	fmt.Println("\nAll five steps ran against the live stack: a real denial, a real widening write, a real")
	fmt.Println("containment row, a real re-decision on the same session, and a real read off the audit chain.")
	return 0
}
