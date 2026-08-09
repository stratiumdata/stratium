//go:build integration

// Package store_test is Task 7's end-to-end proof: against a real Postgres
// and a real, containerized stratium-pdp, it confirms the whole slice
// documented in docs/superpowers/plans/2026-08-09-phase-1c-running-pdp.md —
// migrations from the binary's own startup, RLS tenant isolation with no
// WHERE clause in Go, the hash-linked audit chain, and a Decide call that
// denies honestly at the principal leg (the only outcome this slice can
// produce; see that plan's "What it deliberately does not prove").
//
// Build-tagged so `go test ./...` and `golangci-lint run ./...` skip it by
// default. `make integration` (repo root) is what runs it, against
// deploy/docker/docker-compose.yml: bring the stack up on a fresh volume,
// run this file with -tags=integration against the published ports, tear
// the stack down.
//
// It is an external test package (store_test, not store) deliberately: it
// dials the real gRPC server through package pdpgrpc, and pdpgrpc imports
// store — an internal store_test.go could not import pdpgrpc without an
// import cycle.
package store_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq" // registers the "postgres" database/sql driver
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"stratium/internal/authz"
	"stratium/internal/pdpgrpc"
	"stratium/internal/store"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// secondTenantID is a tenant the running PDP is never configured for. It
// only ever needs to be internally consistent within this test, unlike the
// configured tenant (below), which must match whatever
// deploy/docker/docker-compose.yml set STRATIUM_TENANT_ID to — so it is a
// plain constant rather than another environment variable.
const secondTenantID = "tenant-two-integration"

// Package-level: set once in TestMain, read by every subtest. TestMain also
// owns the wait-for-readiness retries described in the task report, and
// closes both connections after m.Run().
//
// testDB deliberately connects as stratium_migrate (STRATIUM_IT_DATABASE_URL
// — see the Makefile's integration target), not as the stratium role the pdp
// container actually serves from. This test needs to seed fixtures directly
// (agents, delegations — there is no gRPC write path for either yet) and, in
// proof6, REVOKE a grant on audit_chain; both need privileges the serving
// identity must not have (see cmd/stratium-pdp's startup check). The system
// under test is only ever exercised through pdpClient, whose backing
// connection is whatever STRATIUM_DATABASE_URL the pdp container was given.
var (
	testDB           *sql.DB
	pdpClient        pdpgrpc.PDPServiceClient
	configuredTenant string
)

func TestMain(m *testing.M) {
	os.Exit(runTestMain(m))
}

// runTestMain exists so deferred cleanup actually runs — os.Exit from
// TestMain itself would skip any defer in that function.
func runTestMain(m *testing.M) int {
	dbURL := os.Getenv("STRATIUM_IT_DATABASE_URL")
	pdpAddr := os.Getenv("STRATIUM_IT_PDP_ADDR")
	configuredTenant = os.Getenv("STRATIUM_IT_TENANT_ID")
	if dbURL == "" || pdpAddr == "" || configuredTenant == "" {
		fmt.Fprintln(os.Stderr,
			"STRATIUM_IT_DATABASE_URL, STRATIUM_IT_PDP_ADDR, and STRATIUM_IT_TENANT_ID must all be set — "+
				"run via `make integration`, not `go test` directly")
		return 1
	}
	if configuredTenant == secondTenantID {
		fmt.Fprintln(os.Stderr, "STRATIUM_IT_TENANT_ID must not equal the test's hardcoded second tenant")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	if err := waitForDB(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "database never became reachable: %v\n", err)
		return 1
	}
	testDB = db

	conn, err := grpc.NewClient(pdpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "create gRPC client: %v\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()
	waited, err := waitForServing(ctx, conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PDP never reported SERVING: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "PDP reported SERVING after %s (this is the measured wait, not an assumption)\n", waited)
	pdpClient = pdpgrpc.NewPDPServiceClient(conn)

	return m.Run()
}

// waitForDB retries PingContext instead of assuming the first attempt
// succeeds: compose's own healthcheck already gates postgres, so this
// exists for robustness against slow CI runners rather than to paper over
// a real race between compose and this test binary starting.
func waitForDB(ctx context.Context, db *sql.DB) error {
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		if lastErr = db.PingContext(ctx); lastErr == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// waitForServing polls the PDP's health service (registered in main.go
// alongside PDPService) until it reports SERVING, and reports how long that
// took — this is the Go-side half of "does the PDP wait correctly for the
// database or race it": migrations.Up() and net.Listen both happen before
// main.go ever marks health SERVING, so a fast, single-digit-second wait
// here is a real signal, not a guess.
func waitForServing(ctx context.Context, conn *grpc.ClientConn) (time.Duration, error) {
	start := time.Now()
	health := grpc_health_v1.NewHealthClient(conn)
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		resp, err := health.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if err == nil && resp.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING {
			return time.Since(start), nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
}

// withTenantTx runs fn inside a transaction with app.tenant_id set for that
// transaction only — the same pattern internal/store.beginTenantTx uses,
// reproduced here because that helper is unexported and this is a
// deliberately external test package (see the package doc). Seeding through
// this, rather than a superuser bypass, means every fixture this test
// writes is itself proof that RLS's WITH CHECK accepts a correctly tenant-
// scoped writer — not just that it rejects a mismatched one.
func withTenantTx(t *testing.T, tenant string, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}
	fn(tx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

const insertAgentQuery = `INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`

func seedAgent(t *testing.T, tenant string, id uuid.UUID, name string) {
	t.Helper()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertAgentQuery,
			id.String(), tenant, name, "anthropic", "claude", int64(models.TrustTierUnverified), true, false, []byte(`[]`),
		); err != nil {
			t.Fatalf("seed agent %s: %v", name, err)
		}
	})
}

const insertDelegationQuery = `INSERT INTO delegations (
		id, tenant_id, user_id, agent_id, approved_tools, max_action_tier,
		classification_caps, resource_constraints, purpose, expires_at,
		revoked, parent_delegation_id, root_delegation_id, depth, chain_agent_ids
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`

// seedDelegation inserts d as one delegations row and returns d unchanged,
// so callers can seed and keep the same *models.Delegation for later
// in-process use (proof 5 below reuses it directly against
// authz.ValidateChain — no read-back required, since a successful INSERT
// under RLS's WITH CHECK already proves the row persisted exactly as this
// struct describes it).
func seedDelegation(t *testing.T, d *models.Delegation) *models.Delegation {
	t.Helper()
	approvedTools, err := json.Marshal(d.ApprovedTools)
	if err != nil {
		t.Fatalf("marshal approved_tools: %v", err)
	}
	caps, err := json.Marshal(d.ClassificationCaps)
	if err != nil {
		t.Fatalf("marshal classification_caps: %v", err)
	}
	constraints, err := json.Marshal(d.ResourceConstraints)
	if err != nil {
		t.Fatalf("marshal resource_constraints: %v", err)
	}
	chainAgentIDs, err := json.Marshal(d.ChainAgentIDs)
	if err != nil {
		t.Fatalf("marshal chain_agent_ids: %v", err)
	}

	var parent interface{}
	if d.ParentDelegationID != nil {
		parent = d.ParentDelegationID.String()
	}

	withTenantTx(t, d.TenantID, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertDelegationQuery,
			d.ID.String(), d.TenantID, d.UserID, d.AgentID.String(), approvedTools, int64(d.MaxActionTier),
			caps, constraints, d.Purpose, d.ExpiresAt,
			d.Revoked, parent, d.RootDelegationID.String(), int64(d.Depth), chainAgentIDs,
		); err != nil {
			t.Fatalf("seed delegation %s: %v", d.ID, err)
		}
	})
	return d
}

// twoHopChain builds a root delegation and one child narrowing it one level
// deeper — the "two-hop delegation chain" the brief asks for — both issued
// to the same agent, and seeds both. Every leg but the principal leg is
// deliberately well-formed (matches internal/pdpgrpc's wellFormedFixture):
// enabled agent, active and sufficiently-tiered delegations, so the DENY
// this test asserts is unambiguously attributable to the principal leg
// alone, not to some other leg that happened to deny first.
func twoHopChain(t *testing.T, tenant string, agentID uuid.UUID) (root, child *models.Delegation) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootID, childID := uuid.New(), uuid.New()

	root = seedDelegation(t, &models.Delegation{
		ID: rootID, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "integration test: root grant", ExpiresAt: now.Add(time.Hour),
		RootDelegationID: rootID, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
	child = seedDelegation(t, &models.Delegation{
		ID: childID, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "integration test: re-delegated one hop deeper", ExpiresAt: now.Add(time.Hour),
		ParentDelegationID: &rootID, RootDelegationID: rootID, Depth: 1, ChainAgentIDs: []uuid.UUID{agentID, agentID},
	})
	return root, child
}

const auditChainQuery = `SELECT prev_hash, tenant_id, occurred_at, event_type, actor,
	agent_id, delegation_id, root_delegation_id, chain_depth,
	tool_name, action, declared_tier, derived_tier,
	decision, denied_leg, denied_at_depth, reason, input_digest
	FROM audit_chain ORDER BY seq ASC`

// fetchAuditChain reads a tenant's entire chain from the first entry,
// ordered oldest first — audit.Verify's own precondition (see its doc
// comment) — scoped by RLS via app.tenant_id, not a WHERE clause, matching
// every other read in this slice.
func fetchAuditChain(t *testing.T, tenant string) []audit.Entry {
	t.Helper()
	var entries []audit.Entry
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		rows, err := tx.QueryContext(t.Context(), auditChainQuery)
		if err != nil {
			t.Fatalf("query audit_chain: %v", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var e audit.Entry
			var prevHash, inputDigest []byte
			if err := rows.Scan(
				&prevHash, &e.TenantID, &e.OccurredAt, &e.EventType, &e.Actor,
				&e.AgentID, &e.DelegationID, &e.RootDelegationID, &e.ChainDepth,
				&e.ToolName, &e.Action, &e.DeclaredTier, &e.DerivedTier,
				&e.Decision, &e.DeniedLeg, &e.DeniedAtDepth, &e.Reason, &inputDigest,
			); err != nil {
				t.Fatalf("scan audit_chain row: %v", err)
			}
			copy(e.PrevHash[:], prevHash)
			if inputDigest != nil {
				copy(e.InputDigest[:], inputDigest)
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate audit_chain rows: %v", err)
		}
	})
	return entries
}

func wantCode(t *testing.T, err error, want codes.Code) *status.Status {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want status code %v", want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status error: %v", err)
	}
	if st.Code() != want {
		t.Fatalf("code = %v, want %v (message: %s)", st.Code(), want, st.Message())
	}
	return st
}

// unconfiguredPrincipalReason mirrors internal/policy.Unconfigured()'s
// literal reason string. Not imported from that package — this test only
// reaches it through the wire response, the same way any real gRPC client
// would — so the exact string is reproduced here deliberately.
const unconfiguredPrincipalReason = "principal: no policy engine configured (Phase 2)"

// TestEndToEnd runs the six proofs, in the brief's own order, plus the
// Phase 2a Task 1 concurrency measurements: a single-call latency baseline,
// the ten-way same-tenant burst (now expected 10/0 under the per-tenant
// advisory lock — see audit.go), and a two-tenant check that the lock does
// not serialize unrelated tenants against each other. Subtests run
// sequentially (never t.Parallel()) because later ones depend on earlier
// state: proof 3 needs proof 2's decision already written; the concurrency
// measurements need proof 2's fixture already seeded; proof 6 deliberately
// revokes the application role's INSERT privilege on audit_chain and must
// run last, since nothing after it could append an audit row again.
func TestEndToEnd(t *testing.T) {
	agentID := uuid.New()
	seedAgent(t, configuredTenant, agentID, "integration-agent-tenant-one")
	_, acting := twoHopChain(t, configuredTenant, agentID)

	// Set by single_decide_latency_baseline, read by
	// measured_concurrent_decide_split_on_the_same_tail — both subtests run
	// sequentially in the same TestEndToEnd, so this ordinary local variable
	// is enough to carry the measurement across them without a package-level
	// var.
	var baselineLatency time.Duration

	t.Run("proof1_migrations_applied_from_pdp_own_startup", func(t *testing.T) {
		// This test never calls migrations.Up() itself — by the time
		// TestMain's health check returned SERVING, the PDP container had
		// already run it from main.go's normal startup path (migrations.Up
		// happens before net.Listen; see cmd/stratium-pdp/main.go). This
		// subtest only OBSERVES the result of that run.
		var version int64
		var dirty bool
		row := testDB.QueryRowContext(t.Context(), `SELECT version, dirty FROM schema_migrations`)
		if err := row.Scan(&version, &dirty); err != nil {
			t.Fatalf("read schema_migrations: %v", err)
		}
		t.Logf("schema_migrations: version=%d dirty=%t", version, dirty)
		if dirty {
			t.Fatalf("schema_migrations.dirty = true, want false")
		}
		if version < 4 {
			t.Fatalf("schema_migrations.version = %d, want >= 4", version)
		}

		wantTables := []string{"agents", "delegations", "policies", "entitlements",
			"tier_overrides", "tenant_epoch", "audit_chain", "schema_migrations"}
		for _, table := range wantTables {
			var exists bool
			err := testDB.QueryRowContext(t.Context(),
				`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
				table).Scan(&exists)
			if err != nil {
				t.Fatalf("check table %s exists: %v", table, err)
			}
			if !exists {
				t.Errorf("table %q does not exist after migrations", table)
			}
		}
		t.Logf("all %d expected tables present", len(wantTables))
	})

	t.Run("proof2_decide_denies_at_principal_leg", func(t *testing.T) {
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			DelegationId: acting.ID.String(),
			AgentId:      agentID.String(),
			Subject:      "alice@example.com",
			Tool:         "Bash",
			Verb:         "read",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() -> effect=%s denied_leg=%q reason=%q principal_reason=%q agent_effect=%s delegation_effect=%s",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetReason(), resp.GetPrincipalReason(),
			resp.GetAgentEffect(), resp.GetDelegationEffect())

		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "principal" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "principal")
		}
		if resp.GetPrincipalReason() != unconfiguredPrincipalReason {
			t.Errorf("PrincipalReason = %q, want %q", resp.GetPrincipalReason(), unconfiguredPrincipalReason)
		}
		// The agent and delegation legs were seeded to independently allow
		// (see twoHopChain) — confirming the DENY really is attributable to
		// principal alone, not a side effect of a different leg also
		// denying and racing it for attribution.
		if resp.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("AgentEffect = %v, want EFFECT_ALLOW (fixture is well-formed on this leg)", resp.GetAgentEffect())
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW (fixture is well-formed on this leg)", resp.GetDelegationEffect())
		}
	})

	t.Run("proof3_audit_row_written_and_chain_verifies", func(t *testing.T) {
		entries := fetchAuditChain(t, configuredTenant)
		t.Logf("audit_chain for %q has %d entr(y/ies) after one Decide call", configuredTenant, len(entries))
		if len(entries) != 1 {
			t.Fatalf("len(entries) = %d, want 1 (one Decide call so far)", len(entries))
		}

		got := entries[0]
		if got.Decision != "DENY" || got.DeniedLeg != "principal" {
			t.Errorf("audit entry decision=%q denied_leg=%q, want DENY/principal", got.Decision, got.DeniedLeg)
		}
		if got.DelegationID == nil || *got.DelegationID != acting.ID {
			t.Errorf("audit entry DelegationID = %v, want %s", got.DelegationID, acting.ID)
		}
		if got.AgentID == nil || *got.AgentID != agentID {
			t.Errorf("audit entry AgentID = %v, want %s", got.AgentID, agentID)
		}

		if err := audit.Verify(entries); err != nil {
			t.Fatalf("audit.Verify() error = %v, want nil", err)
		}
		t.Logf("audit.Verify() passed over the tenant's full %d-entry chain", len(entries))
	})

	t.Run("proof4_cross_tenant_agent_is_not_found", func(t *testing.T) {
		otherAgentID := uuid.New()
		seedAgent(t, secondTenantID, otherAgentID, "integration-agent-tenant-two")

		// delegation_id need not resolve to anything real: LoadAgent runs
		// before LoadChain in Decide (see pdpgrpc/server.go), so an unknown
		// agent short-circuits before the delegation is ever looked up.
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			DelegationId: uuid.New().String(),
			AgentId:      otherAgentID.String(),
			Subject:      "mallory@example.com",
			Tool:         "Bash",
			Verb:         "read",
		})
		if resp != nil {
			t.Fatalf("Decide() response = %+v, want nil", resp)
		}
		st := wantCode(t, err, codes.NotFound)
		t.Logf("Decide() for tenant %q's agent, against a PDP configured for %q -> NotFound: %s",
			secondTenantID, configuredTenant, st.Message())
	})

	t.Run("proof5_cross_tenant_chain_rejected_by_validatechain", func(t *testing.T) {
		otherAgentID := uuid.New()
		seedAgent(t, secondTenantID, otherAgentID, "integration-agent-tenant-two-chain")
		rootID := uuid.New()
		foreignRoot := seedDelegation(t, &models.Delegation{
			ID: rootID, TenantID: secondTenantID, UserID: "integration-test-user", AgentID: otherAgentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose: "integration test: belongs to tenant two", ExpiresAt: time.Now().UTC().Add(time.Hour),
			RootDelegationID: rootID, Depth: 0, ChainAgentIDs: []uuid.UUID{otherAgentID},
		})

		// A successful INSERT above, gated by RLS's WITH CHECK, already
		// proves this row is really persisted under tenant_id=secondTenantID
		// — reused here directly rather than read back, since a fresh SELECT
		// would only reconfirm what the write already guaranteed. This is
		// authz.ValidateChain's own defense-in-depth tenant check (see that
		// function's doc comment): the same property proof 4 established via
		// RLS, exercised here as the second, independent layer that a
		// caller assembling a chain without going through the RLS-scoped
		// store.LoadChain — a batch job, a cache, Phase 2's token-claim
		// derivation — would still be caught by.
		err := authz.ValidateChain([]*models.Delegation{foreignRoot}, configuredTenant, otherAgentID)
		if err == nil {
			t.Fatal("ValidateChain() error = nil, want ErrChainInvalid")
		}
		if !errors.Is(err, authz.ErrChainInvalid) {
			t.Fatalf("ValidateChain() error = %v, want errors.Is(_, ErrChainInvalid)", err)
		}
		t.Logf("ValidateChain(tenant-two's chain, expected tenant=%q) -> %v", configuredTenant, err)
	})

	t.Run("single_decide_latency_baseline", func(t *testing.T) {
		// Uncontended latency for one Decide() call — no other writer
		// racing this tenant's chain tail. This is what the burst
		// subtest's per-call average is compared against below: the
		// difference is the advisory lock's actual per-decision cost,
		// not an assumption.
		callStart := time.Now()
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			DelegationId: acting.ID.String(),
			AgentId:      agentID.String(),
			Subject:      "alice@example.com",
			Tool:         "Bash",
			Verb:         "read",
		})
		baselineLatency = time.Since(callStart)
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		if resp == nil {
			t.Fatal("Decide() response = nil, want a decision")
		}
		t.Logf("single uncontended Decide() call: %s", baselineLatency)
	})

	t.Run("measured_concurrent_decide_split_on_the_same_tail", func(t *testing.T) {
		const n = 10
		var (
			wg                            sync.WaitGroup
			succeeded, aborted, otherFail int64
			start                         = make(chan struct{})
		)
		results := make([]string, n)
		before := fetchAuditChain(t, configuredTenant)

		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
					DelegationId: acting.ID.String(),
					AgentId:      agentID.String(),
					Subject:      "alice@example.com",
					Tool:         "Bash",
					Verb:         "read",
				})
				switch {
				case err == nil && resp != nil:
					atomic.AddInt64(&succeeded, 1)
					results[i] = "ok"
				case status.Code(err) == codes.Aborted:
					atomic.AddInt64(&aborted, 1)
					results[i] = "aborted"
				default:
					atomic.AddInt64(&otherFail, 1)
					results[i] = fmt.Sprintf("other: %v", err)
				}
			}(i)
		}
		burstStart := time.Now()
		close(start) // release every goroutine at once, so they race the same tail
		wg.Wait()
		elapsed := time.Since(burstStart)

		t.Logf("fired %d concurrent Decide() calls for tenant %q in %s (avg %s/call, vs %s single-call baseline): "+
			"%d ok, %d Aborted (ErrConcurrentAppend), %d other failures",
			n, configuredTenant, elapsed, elapsed/n, baselineLatency, succeeded, aborted, otherFail)
		t.Logf("per-call outcomes: %v", results)

		// Post-fix expectation: the per-tenant advisory lock in
		// store.AppendAudit serializes these ten calls onto the same chain
		// tail one at a time, so every one should now succeed and none
		// should collide on UNIQUE(tenant_id, prev_hash). Before that lock
		// existed, Phase 1c measured 3/7, 7/3, 4/6 splits here — a
		// regression to any partial split means the lock has stopped
		// covering this path.
		if succeeded != n || aborted != 0 || otherFail != 0 {
			t.Errorf("succeeded=%d aborted=%d other=%d, want %d/0/0 (advisory lock should serialize every call for one tenant)",
				succeeded, aborted, otherFail, n)
		}

		after := fetchAuditChain(t, configuredTenant)
		if err := audit.Verify(after); err != nil {
			t.Fatalf("audit.Verify() after the concurrent burst error = %v, want nil (chain must stay linked under a race)", err)
		}
		gotNewRows := int64(len(after) - len(before))
		if gotNewRows != succeeded {
			t.Errorf("audit_chain grew by %d rows, want %d (one per successful decision)", gotNewRows, succeeded)
		}
		t.Logf("chain still verifies after the burst: %d total entries (%d new, matching %d successful decisions)",
			len(after), gotNewRows, succeeded)
	})

	t.Run("appendaudit_lock_is_per_tenant_not_global", func(t *testing.T) {
		// The 10/0 result above is necessary but not sufficient: a single
		// GLOBAL lock (not keyed by tenant) would also serialize every
		// tenant's appends through one mutex and would still produce 10/0
		// for each tenant measured individually — it would just also make
		// unrelated tenants queue behind each other, invisibly to a
		// count-only check. audit.go's lock key is hashtext(tenant_id), not
		// a constant; the two checks below confirm that holds against a
		// real database, not just that it reads that way in the source.
		const n = 10
		storeA := store.New(testDB, configuredTenant)
		storeB := store.New(testDB, secondTenantID)

		probe := func(tenant, label string, i int) audit.Entry {
			return audit.Entry{
				TenantID:   tenant,
				OccurredAt: time.Now(),
				EventType:  "decision",
				Actor:      "integration-test:" + label,
				ToolName:   "Bash",
				Action:     "read",
				Decision:   "DENY",
				Reason:     fmt.Sprintf("%s probe %d", label, i),
			}
		}

		// Check 1, informational: both tenants fire a 10-call burst
		// released at the same instant, on independent goroutine sets
		// sharing nothing but *sql.DB and the one Postgres instance
		// underneath it. Both must still land 10/0 — a deadlock or a lock
		// keyed wrongly enough to cross-link two tenants' chains would show
		// up here even though it doesn't by itself distinguish a per-tenant
		// lock from a global one (a global lock still produces 10/0 for
		// each tenant measured separately; see above).
		var wg sync.WaitGroup
		var aOK, aAborted, aOther, bOK, bAborted, bOther int64
		start := make(chan struct{})
		fire := func(st *store.Store, tenant, label string, i int, ok, aborted, other *int64) {
			defer wg.Done()
			<-start
			switch err := st.AppendAudit(t.Context(), probe(tenant, label, i)); {
			case err == nil:
				atomic.AddInt64(ok, 1)
			case errors.Is(err, store.ErrConcurrentAppend):
				atomic.AddInt64(aborted, 1)
			default:
				atomic.AddInt64(other, 1)
				t.Logf("tenant %q AppendAudit unexpected error: %v", tenant, err)
			}
		}
		for i := 0; i < n; i++ {
			wg.Add(2)
			go fire(storeA, configuredTenant, "interleaved-a", i, &aOK, &aAborted, &aOther)
			go fire(storeB, secondTenantID, "interleaved-b", i, &bOK, &bAborted, &bOther)
		}
		burstStart := time.Now()
		close(start)
		wg.Wait()
		burstElapsed := time.Since(burstStart)
		t.Logf("interleaved burst, both tenants at once, %d calls each in %s: tenant %q %d ok/%d aborted/%d other, tenant %q %d ok/%d aborted/%d other",
			n, burstElapsed, configuredTenant, aOK, aAborted, aOther, secondTenantID, bOK, bAborted, bOther)
		if aOK != n || aAborted != 0 || aOther != 0 {
			t.Errorf("tenant %q: %d ok, %d aborted, %d other, want %d/0/0", configuredTenant, aOK, aAborted, aOther, n)
		}
		if bOK != n || bAborted != 0 || bOther != 0 {
			t.Errorf("tenant %q: %d ok, %d aborted, %d other, want %d/0/0", secondTenantID, bOK, bAborted, bOther, n)
		}

		// Check 2, decisive: hold tenant A's lock open on purpose and
		// confirm a concurrent call for tenant A blocks behind it while a
		// concurrent call for tenant B does not. This is deliberately not a
		// throughput/timing-ratio comparison — an earlier version of this
		// test compared aggregate wall-clock for two tenants' bursts run
		// separately vs. interleaved, and it was too noisy in a small local
		// Docker Compose stack to be a reliable signal: server-side
		// contention (WAL fsync, CPU, connection setup) affects both the
		// global-lock and per-tenant-lock cases and can mask the
		// difference at n=10. Controlling one lock holder's duration
		// directly removes that noise: unblocked is a few milliseconds,
		// blocked is at least the hold duration, and there is no middle
		// ground to misread.
		const holdFor = 300 * time.Millisecond
		holderTx, err := testDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin lock-holder tx: %v", err)
		}
		defer func() { _ = holderTx.Rollback() }() // safety net if a Fatal below skips the release timer
		if _, err := holderTx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, configuredTenant); err != nil {
			t.Fatalf("lock-holder set_config: %v", err)
		}
		// Same literal statement and tenant string audit.go's AppendAudit
		// uses, so this acquires the identical lock key a real AppendAudit
		// call for configuredTenant would.
		if _, err := holderTx.ExecContext(t.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, configuredTenant); err != nil {
			t.Fatalf("lock-holder acquire lock: %v", err)
		}
		releaseTimer := time.AfterFunc(holdFor, func() { _ = holderTx.Rollback() })
		defer releaseTimer.Stop()

		call := func(st *store.Store, tenant string) (elapsed time.Duration, err error) {
			callStart := time.Now()
			err = st.AppendAudit(t.Context(), probe(tenant, "hold-probe", 0))
			return time.Since(callStart), err
		}
		var aElapsed, bElapsed time.Duration
		var aErr, bErr error
		wg.Add(2)
		go func() { defer wg.Done(); aElapsed, aErr = call(storeA, configuredTenant) }()
		go func() { defer wg.Done(); bElapsed, bErr = call(storeB, secondTenantID) }()
		wg.Wait()

		if aErr != nil {
			t.Fatalf("tenant %q AppendAudit while its own lock is held error = %v, want nil (should block, then succeed once released)",
				configuredTenant, aErr)
		}
		if bErr != nil {
			t.Fatalf("tenant %q AppendAudit while tenant %q's lock is held error = %v, want nil", secondTenantID, configuredTenant, bErr)
		}
		t.Logf("while tenant %q held its own lock for %s: a same-tenant call took %s, a different-tenant call took %s",
			configuredTenant, holdFor, aElapsed, bElapsed)

		if aElapsed < holdFor {
			t.Errorf("same-tenant call took %s, want >= %s — it should have blocked behind the held lock "+
				"(if it did not, this test's control isn't verifying anything)", aElapsed, holdFor)
		}
		if bElapsed >= holdFor {
			t.Errorf("different-tenant call took %s, want well under %s — it blocked behind another tenant's "+
				"lock, which means the lock is not scoped per tenant", bElapsed, holdFor)
		}

		for _, tenant := range []string{configuredTenant, secondTenantID} {
			entries := fetchAuditChain(t, tenant)
			if err := audit.Verify(entries); err != nil {
				t.Fatalf("audit.Verify() for tenant %q error = %v, want nil", tenant, err)
			}
		}
	})

	t.Run("proof6_failed_audit_append_blocks_the_decision", func(t *testing.T) {
		// A genuine failure, not a mock: revoke the application role's own
		// INSERT privilege on audit_chain, live, on the real database this
		// test is connected to. Both grants are revoked because the role
		// this stack connects as (see deploy/docker/init-db.sql) inherits
		// INSERT via two independent paths — ownership of audit_chain
		// (stratium_audit_owner) and the narrower grant
		// migrations/000004_audit_ownership.up.sql makes to stratium_app —
		// revoking only one would leave the other still granting it.
		// Deliberately irreversible for the rest of this process: nothing
		// after this subtest can append an audit row again, which is why it
		// runs last.
		for _, role := range []string{"stratium_app", "stratium_audit_owner"} {
			if _, err := testDB.ExecContext(t.Context(), fmt.Sprintf("REVOKE INSERT ON audit_chain FROM %s", role)); err != nil {
				t.Fatalf("revoke INSERT from %s: %v", role, err)
			}
		}

		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			DelegationId: acting.ID.String(),
			AgentId:      agentID.String(),
			Subject:      "alice@example.com",
			Tool:         "Bash",
			Verb:         "read",
		})
		if resp != nil {
			t.Fatalf("Decide() response = %+v, want nil: a decision must not escape a failed audit write", resp)
		}
		// codes.Internal, not codes.Aborted: this is a real permission
		// failure (Postgres SQLSTATE 42501), a different failure class from
		// the unique-violation/ErrConcurrentAppend case measured above —
		// store.AppendAudit only maps 23505 specifically to Aborted, so
		// this asserts the two are not being conflated.
		st := wantCode(t, err, codes.Internal)
		t.Logf("Decide() with INSERT revoked on audit_chain -> no decision returned, code=%v message=%q",
			st.Code(), st.Message())

		if _, confirmErr := testDB.ExecContext(t.Context(), "SELECT 1"); confirmErr != nil {
			t.Errorf("test's own database connection broke unexpectedly: %v", confirmErr)
		}
	})
}
