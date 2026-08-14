//go:build integration

// Task 3's real-Postgres proof for the PAP's CRUD
// (.superpowers/sdd/2026-08-14-phase-14-pap/task-3-brief.md). Every
// property that needs a real transaction, a real trigger, or a real CHECK
// constraint to prove — N4's audit-in-the-same-transaction (the positive
// path; see below for what is deliberately NOT re-proven here), the
// tenant_epoch bump, tier_overrides_raise_only as a database-level
// backstop — gets it here, against the real stratium_pap_login role Task 2
// built, the same reason pap_role_integration_test.go exists rather than
// folding into store_integration_test.go.
//
// Role gating (viewer/editor/admin) is deliberately NOT re-proven here:
// internal/store has no concept of a role at all — that boundary lives
// entirely in cmd/stratium-pap's HTTP layer (server_test.go, policies_test.go,
// agents_test.go, tier_overrides_test.go), already proven there with
// sqlmock. The full end-to-end proof against a live, containerized
// stratium-pap process ("a viewer is refused every write") is Task 7's
// stated scope in the phase plan, not this task's — Task 7 is also what
// wires a pap service into deploy/docker/docker-compose.yml; this task adds
// no such service, only Go tests against the already-running Postgres
// container the existing `make integration` target already brings up.
//
// "audit outside the write's transaction" (the required mutation for N4) is
// proven at the unit level (internal/store/policy_test.go, agent_test.go,
// tier_override_test.go's own AuditFailureRollsBackWrite tests), not here:
// sqlmock injects a controlled failure at the exact instant that property
// needs one. Reproducing an audit-insert failure deterministically against
// a live connection — revoking a grant mid-test, or forging a hash
// collision timed to an OccurredAt this file cannot know until the write
// itself runs — would be far more fragile than what it would prove beyond
// the unit-level proof already established. What live Postgres uniquely
// proves instead is the POSITIVE path end to end: RLS, the tenant_epoch
// trigger, and audit_chain's own constraints (UNIQUE (tenant_id,
// prev_hash), tier_overrides_raise_only) all operating together, on the
// literal round trip an operator's browser would drive.
package store_test

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/internal/store"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// TestIntegration_PAPCRUD_PolicyRoundTrip is the brief's own "each resource
// round-trips through create, read, update, delete," proven against real
// Postgres as stratium_pap_login: every step also bumps tenant_epoch
// (Phase 12's trigger, now fired by a third role — see Task 2's own report),
// and by the end audit_chain carries exactly the three entries the three
// writes produced, in order, with the chain still verifying.
func TestIntegration_PAPCRUD_PolicyRoundTrip(t *testing.T) {
	const tenant = "tenant-pap-crud-policy-integration"
	repo := store.New(papDB, tenant)
	before, _ := readTenantEpoch(t, tenant)

	created, err := repo.CreatePolicy(t.Context(), fullRegistry(),
		models.Policy{
			Name: "crud-roundtrip-policy", Description: "created by the integration suite",
			Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "allow", Enabled: true,
		},
		"integration-operator")
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("CreatePolicy() returned the zero UUID for id")
	}
	if created.Version != 1 {
		t.Fatalf("CreatePolicy().Version = %d, want 1", created.Version)
	}
	before = assertEpochBumped(t, tenant, before)

	got, err := repo.GetPolicy(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got.Name != "crud-roundtrip-policy" || got.Description != "created by the integration suite" {
		t.Fatalf("GetPolicy() = %+v, want the just-created row", got)
	}

	listed, err := repo.ListPolicies(t.Context())
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	if !containsPolicyID(listed, created.ID) {
		t.Fatal("ListPolicies() did not include the just-created policy")
	}

	updated, err := repo.UpdatePolicy(t.Context(), fullRegistry(), created.ID,
		models.Policy{
			Name: "crud-roundtrip-policy-renamed", Language: "rego",
			Text: "package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}",
			// Rego is not single-valued (Issue 1, store.validateEffectAgreement's
			// own doc comment): a stored policy in this language can itself
			// produce both an allow and a deny outcome depending on the request,
			// so this field must be store.multiValuedLanguageEffect ("deny"),
			// never an operator's own claim.
			Effect: "deny", Enabled: false,
		},
		"integration-operator")
	if err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}
	if updated.Version != 2 {
		t.Fatalf("UpdatePolicy().Version = %d, want 2 (version = version + 1)", updated.Version)
	}
	if updated.Enabled {
		t.Fatal("UpdatePolicy().Enabled = true, want false (the update set it)")
	}
	before = assertEpochBumped(t, tenant, before)

	if err := repo.DeletePolicy(t.Context(), created.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}
	assertEpochBumped(t, tenant, before)

	if _, err := repo.GetPolicy(t.Context(), created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetPolicy() after delete: error = %v, want ErrNotFound", err)
	}

	assertAuditTrailMatches(t, tenant, "integration-operator", "policy_created", "policy_updated", "policy_deleted")
}

// TestIntegration_PAPCRUD_AgentRoundTrip is the agents-table instance of
// the same round-trip property, live.
func TestIntegration_PAPCRUD_AgentRoundTrip(t *testing.T) {
	const tenant = "tenant-pap-crud-agent-integration"
	repo := store.New(papDB, tenant)
	before, _ := readTenantEpoch(t, tenant)

	created, err := repo.CreateAgent(t.Context(),
		models.Agent{
			Name: "crud-roundtrip-agent", Provider: "anthropic", ModelID: "claude-opus",
			TrustTier: models.TrustTierCertified, Enabled: true, AllowedTools: []string{"Read", "Bash"},
		},
		"integration-operator")
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	before = assertEpochBumped(t, tenant, before)

	got, err := repo.GetAgent(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if len(got.AllowedTools) != 2 {
		t.Fatalf("GetAgent().AllowedTools = %v, want 2 entries round-tripped through JSONB", got.AllowedTools)
	}

	listed, err := repo.ListAgents(t.Context())
	if err != nil {
		t.Fatalf("ListAgents() error = %v", err)
	}
	found := false
	for _, a := range listed {
		found = found || a.ID == created.ID
	}
	if !found {
		t.Fatal("ListAgents() did not include the just-created agent")
	}

	updated, err := repo.UpdateAgent(t.Context(), created.ID,
		models.Agent{
			Name: "crud-roundtrip-agent-renamed", Provider: "anthropic", TrustTier: models.TrustTierPlatformTrusted,
			Suspended: true, AllowedTools: []string{},
		},
		"integration-operator")
	if err != nil {
		t.Fatalf("UpdateAgent() error = %v", err)
	}
	if !updated.Suspended || len(updated.AllowedTools) != 0 {
		t.Fatalf("UpdateAgent() = %+v, want Suspended=true AllowedTools=[]", updated)
	}
	before = assertEpochBumped(t, tenant, before)

	if err := repo.DeleteAgent(t.Context(), created.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("DeleteAgent() error = %v", err)
	}
	assertEpochBumped(t, tenant, before)

	if _, err := repo.GetAgent(t.Context(), created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetAgent() after delete: error = %v, want ErrNotFound", err)
	}

	assertAuditTrailMatches(t, tenant, "integration-operator", "agent_created", "agent_updated", "agent_deleted")
}

// TestIntegration_PAPCRUD_TierOverrideRoundTrip is the tier_overrides
// instance of the round-trip property, live, plus (uniquely to this table)
// live proof that the schema's own tier_overrides_raise_only CHECK backs up
// ValidateOverride at the database level: migrations/000001_baseline.up.sql
// calls that CHECK "a database-level backstop" for "application code
// [that] enforces the same rule against the built-in classifier, which the
// database cannot see" — asserted here by writing directly through papDB,
// bypassing internal/store's own Go-level check entirely, and confirming
// Postgres refuses it independently.
func TestIntegration_PAPCRUD_TierOverrideRoundTrip(t *testing.T) {
	const tenant = "tenant-pap-crud-tier-override-integration"
	repo := store.New(papDB, tenant)
	before, _ := readTenantEpoch(t, tenant)

	// "Read"'s built-in is READ_ONLY; raising to INTERNAL_MODIFY is
	// legitimate.
	created, err := repo.CreateTierOverride(t.Context(),
		models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierInternalModify},
		"integration-operator")
	if err != nil {
		t.Fatalf("CreateTierOverride() error = %v", err)
	}
	if created.BuiltinTier != models.ActionTierReadOnly {
		t.Fatalf("CreateTierOverride().BuiltinTier = %s, want %s (server-computed)", created.BuiltinTier, models.ActionTierReadOnly)
	}
	before = assertEpochBumped(t, tenant, before)

	got, err := repo.GetTierOverride(t.Context(), created.ID)
	if err != nil {
		t.Fatalf("GetTierOverride() error = %v", err)
	}
	if got.CreatedBy != "integration-operator" {
		t.Errorf("GetTierOverride().CreatedBy = %q, want %q", got.CreatedBy, "integration-operator")
	}

	listed, err := repo.ListTierOverrides(t.Context())
	if err != nil {
		t.Fatalf("ListTierOverrides() error = %v", err)
	}
	found := false
	for _, o := range listed {
		found = found || o.ID == created.ID
	}
	if !found {
		t.Fatal("ListTierOverrides() did not include the just-created override")
	}

	updated, err := repo.UpdateTierOverride(t.Context(), created.ID,
		models.TierOverride{ToolOrVerb: "Read", ActionTier: models.ActionTierExternalComms}, "integration-operator", time.Now())
	if err != nil {
		t.Fatalf("UpdateTierOverride() error = %v", err)
	}
	if updated.ActionTier != models.ActionTierExternalComms {
		t.Fatalf("UpdateTierOverride().ActionTier = %s, want %s", updated.ActionTier, models.ActionTierExternalComms)
	}
	if updated.CreatedBy != "integration-operator" {
		t.Errorf("UpdateTierOverride().CreatedBy = %q, want unchanged %q", updated.CreatedBy, "integration-operator")
	}
	before = assertEpochBumped(t, tenant, before)

	if err := repo.DeleteTierOverride(t.Context(), created.ID, "integration-operator", time.Now()); err != nil {
		t.Fatalf("DeleteTierOverride() error = %v", err)
	}
	assertEpochBumped(t, tenant, before)

	if _, err := repo.GetTierOverride(t.Context(), created.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetTierOverride() after delete: error = %v, want ErrNotFound", err)
	}

	assertAuditTrailMatches(t, tenant, "integration-operator",
		"tier_override_created", "tier_override_updated", "tier_override_deleted")
}

// TestIntegration_TierOverridesRaiseOnlyCheck_IsADatabaseBackstop bypasses
// internal/store entirely, writing directly through papDB (the real
// stratium_pap_login connection), to confirm Postgres itself refuses a
// lowering tier_overrides row independent of any Go code: with
// ValidateOverride never called (nothing here calls it — this is precisely
// the "database cannot see the built-in classifier" case the CHECK exists
// as a backstop for, per that migration's own comment), an INSERT with
// action_tier < builtin_tier must still fail its own CHECK constraint.
func TestIntegration_TierOverridesRaiseOnlyCheck_IsADatabaseBackstop(t *testing.T) {
	const tenant = "tenant-pap-raise-only-db-backstop-integration"

	tx := beginPAPTenantTx(t, tenant)
	defer func() { _ = tx.Rollback() }()

	// action_tier (READ_ONLY=1) < builtin_tier (DESTRUCTIVE=4): a lowering,
	// exactly the shape ValidateOverride refuses in Go -- attempted here
	// with no Go-level gate anywhere in the path.
	_, err := tx.ExecContext(t.Context(),
		`INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) VALUES ($1,$2,$3,$4,$5)`,
		tenant, "Bash", int64(models.ActionTierReadOnly), int64(models.ActionTierDestructive), "direct-sql-bypass")
	if err == nil {
		t.Fatal("direct INSERT with action_tier < builtin_tier succeeded, want the tier_overrides_raise_only CHECK to refuse it")
	}
	if !strings.Contains(err.Error(), "tier_overrides_raise_only") {
		t.Errorf("INSERT error = %q, want it to name the tier_overrides_raise_only constraint", err.Error())
	}
}

// TestIntegration_PAPCRUD_InvalidPolicyNeverPersisted is Property 2, live:
// each of the four task-brief-named "syntactically valid but semantically
// dead" fixtures is refused by the real engine against a real database
// connection, and — checked directly against papDB, not inferred from the
// error alone — no row and no epoch bump resulted.
func TestIntegration_PAPCRUD_InvalidPolicyNeverPersisted(t *testing.T) {
	const tenant = "tenant-pap-crud-invalid-policy-integration"
	repo := store.New(papDB, tenant)
	before, existedBefore := readTenantEpoch(t, tenant)

	tests := []struct {
		language string
		text     string
	}{
		{"rego", "package stratium.polic\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}"},
		{"json", `{"effect": "allow", "match": {"tool": {"in": []}}}`},
		{"cedar", `permit(principal, action, resource) when { resource in [] };`},
		{"xacml", `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target><AnyOf><AllOf>
    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">ULTRA_DESTRUCTIVE</AttributeValue>
      <AttributeDesignator AttributeId="derived-tier" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"/>
    </Match>
  </AllOf></AnyOf></Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`},
	}
	for i, tt := range tests {
		name := fmt.Sprintf("dead-on-arrival-%d", i)
		_, err := repo.CreatePolicy(t.Context(), fullRegistry(),
			models.Policy{Name: name, Language: tt.language, Text: tt.text, Effect: "allow", Enabled: true},
			"integration-operator")
		if err == nil {
			t.Errorf("%s: CreatePolicy() error = nil, want a validation refusal", tt.language)
		}
		if !errors.Is(err, store.ErrPolicyInvalid) {
			t.Errorf("%s: CreatePolicy() error = %v, want it to wrap store.ErrPolicyInvalid", tt.language, err)
		}

		var count int
		withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
			if scanErr := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM policies WHERE name = $1`, name).Scan(&count); scanErr != nil {
				t.Fatalf("count policies named %s: %v", name, scanErr)
			}
		})
		if count != 0 {
			t.Errorf("%s: %d rows named %q exist after a refused CreatePolicy, want 0", tt.language, count, name)
		}
	}

	after, existsAfter := readTenantEpoch(t, tenant)
	if existedBefore != existsAfter || (existedBefore && after != before) {
		t.Errorf("tenant_epoch changed (existed=%v epoch=%d before, existed=%v epoch=%d after) though every write was refused",
			existedBefore, before, existsAfter, after)
	}
}

// TestIntegration_PAPCRUD_EffectMismatchNeverPersisted is Issue 1's own live
// proof, the same shape as InvalidPolicyNeverPersisted just above: a Cedar
// policy whose declared effect contradicts what its own text says (permit
// declares "allow"; the request claims "deny") is refused by
// validateEffectAgreement against a real database connection, and — checked
// directly against papDB, not inferred from the error alone — no row and no
// epoch bump resulted. "Fail closed: a failed validation persists nothing"
// is one of this task's own binding constraints; this is that constraint's
// live proof for the property Issue 1 adds, not only the unit-level one
// (internal/store/policy_test.go's TestStore_CreatePolicy_EffectAgreement_
// MismatchRefused) sqlmock already gives it.
func TestIntegration_PAPCRUD_EffectMismatchNeverPersisted(t *testing.T) {
	const tenant = "tenant-pap-crud-effect-mismatch-integration"
	repo := store.New(papDB, tenant)
	before, existedBefore := readTenantEpoch(t, tenant)

	const name = "contradicts-its-own-text"
	_, err := repo.CreatePolicy(t.Context(), fullRegistry(),
		models.Policy{Name: name, Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "deny", Enabled: true},
		"integration-operator")
	if err == nil {
		t.Fatal("CreatePolicy() error = nil, want a refusal for effect/text disagreement")
	}
	if !errors.Is(err, store.ErrEffectMismatch) {
		t.Errorf("CreatePolicy() error = %v, want it to wrap store.ErrEffectMismatch", err)
	}

	var count int
	withPAPTenantTx(t, tenant, func(tx *sql.Tx) {
		if scanErr := tx.QueryRowContext(t.Context(), `SELECT count(*) FROM policies WHERE name = $1`, name).Scan(&count); scanErr != nil {
			t.Fatalf("count policies named %s: %v", name, scanErr)
		}
	})
	if count != 0 {
		t.Errorf("%d rows named %q exist after a refused CreatePolicy, want 0", count, name)
	}

	after, existsAfter := readTenantEpoch(t, tenant)
	if existedBefore != existsAfter || (existedBefore && after != before) {
		t.Errorf("tenant_epoch changed (existed=%v epoch=%d before, existed=%v epoch=%d after) though the write was refused",
			existedBefore, before, existsAfter, after)
	}
}

// TestIntegration_PAPCRUD_ConcurrentCreatesShareTheAdvisoryLock is a bonus
// mutation nobody asked for, run as a real test rather than only reasoned
// about: Task 3's own refactor (audit.go's appendAuditTx, extracted from
// AppendAudit so a governed write and its audit entry share one
// transaction) is the FIRST time this codebase's advisory-lock
// serialization has ever been exercised from more than one call site.
// store_integration_test.go's own "measured_concurrent_decide_split_on_the_
// same_tail" already proved the lock serializes N racing AppendAudit
// callers for the DECISION path; this proves it does the same for N racing
// CreatePolicy callers on the CRUD path this task adds, sharing the
// identical lock key (hashtext(tenant_id)) a concurrent AppendAudit caller
// would use — a real risk this specific refactor could have introduced
// (e.g. taking the lock with a different key, or not at all, on the new
// path) that no single-writer test could catch. All N creates must
// succeed, and audit_chain must end up with N contiguous, correctly linked
// entries — no lost update, no forked chain.
func TestIntegration_PAPCRUD_ConcurrentCreatesShareTheAdvisoryLock(t *testing.T) {
	const tenant = "tenant-pap-crud-concurrent-creates-integration"
	const n = 10
	repo := store.New(papDB, tenant)

	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := repo.CreatePolicy(t.Context(), fullRegistry(),
				models.Policy{
					Name: fmt.Sprintf("concurrent-policy-%d", i), Language: "cedar",
					Text: `permit(principal, action, resource);`, Effect: "allow", Enabled: true,
				},
				"integration-operator")
			errs[i] = err
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("concurrent CreatePolicy[%d] error = %v, want nil", i, err)
		}
	}

	entries := fetchAuditChain(t, tenant)
	if len(entries) != n {
		t.Fatalf("audit_chain has %d entries after %d concurrent creates, want %d", len(entries), n, n)
	}
	if err := audit.Verify(entries); err != nil {
		t.Errorf("audit.Verify() error = %v, want the chain to verify with no fork after concurrent writers", err)
	}
}

// TestIntegration_PAPCRUD_DeniedAtDepthMatchesTheEstablishedSentinel closes
// a gap the bonus mutation round found: every unit test in this package
// that checks an audit entry's DeniedAtDepth does so by constructing its
// own expected audit.Entry from the SAME store.noDenial symbol
// policy.go/agent.go/tier_override.go use to build the real one (see e.g.
// TestStore_DeletePolicy_Success, policy_test.go) — which proves the two
// call sites agree with EACH OTHER, but cannot catch noDenial itself
// drifting to the wrong value, because both sides would drift together.
// Confirmed live: temporarily changing noDenial's definition from -1 to
// -99 left every existing test in internal/store and cmd/stratium-pap
// green. -1 is not an arbitrary choice this package is free to redefine —
// internal/authz/compound.go and internal/pdpgrpc/escalation.go both
// hardcode the literal -1 for the identical "no denial" meaning on the
// decision path, so a PAP entry using any other sentinel would be
// invisible to a query or dashboard built around that existing,
// system-wide convention (e.g. "count denials" as `WHERE denied_at_depth
// != -1`). This test reads the raw column back from Postgres with its own
// hardcoded literal int16(-1), never referencing the noDenial symbol, so a
// future drift in that constant's definition cannot silently carry this
// test's expectation along with it the way the unit-level tests' shared
// symbol does.
func TestIntegration_PAPCRUD_DeniedAtDepthMatchesTheEstablishedSentinel(t *testing.T) {
	const tenant = "tenant-pap-crud-denied-at-depth-sentinel-integration"
	repo := store.New(papDB, tenant)

	if _, err := repo.CreatePolicy(t.Context(), fullRegistry(),
		models.Policy{Name: "sentinel-check-policy", Language: "cedar", Text: `permit(principal, action, resource);`, Effect: "allow"},
		"integration-operator"); err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}

	var got int16
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(),
			`SELECT denied_at_depth FROM audit_chain WHERE event_type = 'policy_created' ORDER BY seq DESC LIMIT 1`,
		).Scan(&got); err != nil {
			t.Fatalf("read back denied_at_depth: %v", err)
		}
	})
	const wantEstablishedSentinel int16 = -1 // hardcoded deliberately -- see this test's own doc comment
	if got != wantEstablishedSentinel {
		t.Errorf("denied_at_depth = %d, want %d (internal/authz.compound.go's and "+
			"internal/pdpgrpc/escalation.go's own hardcoded 'no denial' sentinel)", got, wantEstablishedSentinel)
	}
}

// containsPolicyID reports whether id appears among policies.
func containsPolicyID(policies []models.Policy, id uuid.UUID) bool {
	for _, p := range policies {
		if p.ID == id {
			return true
		}
	}
	return false
}

// assertAuditTrailMatches fetches tenant's whole chain and asserts it has
// exactly len(wantEventTypes) entries, each with actor and the
// corresponding EventType in order, and that the chain verifies end to
// end — the shared tail every *RoundTrip test above runs after its own
// create/update/delete sequence.
func assertAuditTrailMatches(t *testing.T, tenant, actor string, wantEventTypes ...string) {
	t.Helper()
	entries := fetchAuditChain(t, tenant)
	if len(entries) != len(wantEventTypes) {
		t.Fatalf("audit_chain has %d entries, want %d (%v)", len(entries), len(wantEventTypes), wantEventTypes)
	}
	for i, want := range wantEventTypes {
		if entries[i].EventType != want {
			t.Errorf("entries[%d].EventType = %q, want %q", i, entries[i].EventType, want)
		}
		if entries[i].Actor != actor {
			t.Errorf("entries[%d].Actor = %q, want %q", i, entries[i].Actor, actor)
		}
	}
	if err := audit.Verify(entries); err != nil {
		t.Errorf("audit.Verify() error = %v, want the chain to verify end to end", err)
	}
}
