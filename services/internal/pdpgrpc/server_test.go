package pdpgrpc

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"stratium/internal/authz"
	"stratium/internal/config"
	"stratium/internal/policy"
	"stratium/internal/store"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// fakeSigner is a TokenSigner test double. Every CreateDelegation/IssueToken
// test in this package needs SOME signer (both RPCs fail closed with no
// signer at all — see NewServer's own doc comment on why a Decide-only test
// passes nil instead), and no real EC key can be made to fail signing valid
// claims on demand, so signErr is the only way to reach "a signing failure
// fails the call" at all. lastClaims/calls let a test inspect exactly what
// was handed to Sign without decoding a real JWT — used where that is the
// more direct way to state a property (e.g. "Sign was called with a claim
// set containing no scope field") than a full round trip through a real
// Signer would be.
type fakeSigner struct {
	signErr error

	calls      int
	lastClaims jwt.MapClaims
}

func (f *fakeSigner) Sign(claims jwt.MapClaims) (string, error) {
	f.calls++
	f.lastClaims = claims
	if f.signErr != nil {
		return "", f.signErr
	}
	return fmt.Sprintf("fake-token-%d", f.calls), nil
}

const testTenant = "tenant-abc"

// tierPtr builds a fixed-tier ToolCatalogEntry.ActionTier for a test
// fixture. A nil ActionTier means something specific (no fixed tier;
// classify via command_field instead — pkg/models.ToolCatalogEntry's own
// doc comment), so every fixture that wants an ordinary, fixed-tier row
// must say so explicitly through this helper rather than via a bare value.
func tierPtr(t models.ActionTier) *models.ActionTier { return &t }

// fakeStore is the fake required in place of *store.Store. calls counts every
// method invocation so validation-failure tests can assert the store was
// never reached — "do not proceed" needs to be provably true, not just
// asserted by the response code.
type fakeStore struct {
	agent    authz.AgentInfo
	agentErr error
	chain    []*models.Delegation
	chainErr error

	appendErr error
	appended  []audit.Entry

	// createErr/created back CreateDelegation (delegation_test.go). created
	// only grows on a nil createErr, mirroring *store.Store's own
	// transactional all-or-nothing behavior: a failed CreateDelegation
	// commits no row, so a test asserting "no delegation row is written" can
	// check len(created) == 0 rather than trusting the response alone.
	createErr error
	created   []*models.Delegation

	// createApprovalErr/createdApprovals back resolveEscalation's
	// fresh-escalation branch (escalation_test.go), the same
	// grows-only-on-success discipline created above uses: a test asserting
	// "deny overrides escalate, no approval row created" checks
	// len(createdApprovals) == 0 rather than trusting the response alone.
	createApprovalErr error
	createdApprovals  []*models.Approval

	// loadApproval/loadApprovalErr back resolveEscalation's verify branch. A
	// single fixed value, not a map keyed by id, matching every other
	// single-value stub in this fake (agent, chain): no test in this package
	// needs two distinct approvals loaded within one call.
	loadApproval    *models.Approval
	loadApprovalErr error

	// catalog/catalogErr back LoadToolCatalog. catalog's zero value (nil) is
	// deliberately what most tests in this file exercise without setting it
	// at all: a nil slice is what store.LoadToolCatalog returns for a tenant
	// with no rows, so the default fakeStore already stands in for "no
	// catalog rows" — the regression-guard case every pre-existing Decide
	// test in this file depends on continuing to hold.
	catalog    []models.ToolCatalogEntry
	catalogErr error

	// delegation/delegationErr back LoadDelegation (token.go's IssueToken).
	// A single fixed value, not a map keyed by id, matching every other
	// single-value stub in this fake (agent, chain, loadApproval): no test
	// needs two distinct delegations loaded within one call.
	delegation    *models.Delegation
	delegationErr error

	calls int
}

func (f *fakeStore) LoadAgent(context.Context, uuid.UUID) (authz.AgentInfo, error) {
	f.calls++
	if f.agentErr != nil {
		return authz.AgentInfo{}, f.agentErr
	}
	return f.agent, nil
}

func (f *fakeStore) LoadChain(context.Context, uuid.UUID) ([]*models.Delegation, error) {
	f.calls++
	if f.chainErr != nil {
		return nil, f.chainErr
	}
	return f.chain, nil
}

func (f *fakeStore) AppendAudit(_ context.Context, e audit.Entry) error {
	f.calls++
	if f.appendErr != nil {
		return f.appendErr
	}
	f.appended = append(f.appended, e)
	return nil
}

func (f *fakeStore) CreateDelegation(_ context.Context, d *models.Delegation) error {
	f.calls++
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, d)
	return nil
}

func (f *fakeStore) CreateApproval(_ context.Context, a *models.Approval) error {
	f.calls++
	if f.createApprovalErr != nil {
		return f.createApprovalErr
	}
	f.createdApprovals = append(f.createdApprovals, a)
	return nil
}

func (f *fakeStore) LoadApproval(context.Context, uuid.UUID) (*models.Approval, error) {
	f.calls++
	if f.loadApprovalErr != nil {
		return nil, f.loadApprovalErr
	}
	return f.loadApproval, nil
}

func (f *fakeStore) LoadToolCatalog(context.Context) ([]models.ToolCatalogEntry, error) {
	f.calls++
	if f.catalogErr != nil {
		return nil, f.catalogErr
	}
	return f.catalog, nil
}

func (f *fakeStore) LoadDelegation(context.Context, uuid.UUID) (*models.Delegation, error) {
	f.calls++
	if f.delegationErr != nil {
		return nil, f.delegationErr
	}
	return f.delegation, nil
}

// testConfig's ApprovalTTL is a real, positive duration — matching every
// deployed Config, which config.Load() guarantees the same way (a
// non-positive value fails to load at all, config_test.go's
// TestLoad_ApprovalTTLNotPositive) — so a fresh escalation's computed
// expires_at is genuinely in the future rather than the zero-value
// coincidence of now.Add(0) landing exactly on now.
func testConfig() config.Config {
	return config.Config{TenantID: testTenant, MaxDepth: 5, ApprovalTTL: time.Hour}
}

// wellFormedFixture returns a fake store and request that, evaluated
// together against a denyAllPolicy() Multi, clear every leg except the
// principal: the agent is enabled and trusted, the one-hop chain is active
// and within scope. Only the principal policy's unconditional deny stops
// this from being a "well-formed request that reaches ALLOW" fixture — which
// this slice cannot produce (see the plan's ledger); DENY-at-principal is
// the expected reachable decision.
func wellFormedFixture() (*fakeStore, *DecideRequest) {
	agentID := uuid.New()
	delegationID := uuid.New()

	agent := authz.AgentInfo{
		ID:        agentID,
		TrustTier: models.TrustTierCertified,
		Enabled:   true,
	}

	now := time.Now().UTC().Truncate(time.Second)
	root := &models.Delegation{
		ID:               delegationID,
		TenantID:         testTenant,
		AgentID:          agentID,
		RootDelegationID: delegationID,
		Depth:            0,
		MaxActionTier:    models.ActionTierInternalModify,
		ExpiresAt:        now.Add(time.Hour),
	}

	fs := &fakeStore{agent: agent, chain: []*models.Delegation{root}}
	req := &DecideRequest{
		DelegationId: delegationID.String(),
		AgentId:      agentID.String(),
		Subject:      "alice@example.com",
		Tool:         "Bash",
	}
	return fs, req
}

func wantCode(t *testing.T, err error, want codes.Code) {
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
}

// denyAllPolicy returns a policy.Multi with an empty registry and a source
// reporting no policies at all — every test in this file that only exercises
// Decide and does not care which specific deny reason comes back uses this.
// It is the policy.Multi-shaped equivalent of the old policy.Unconfigured()
// fixture, from back when NewServer took a bare policy.PrincipalPolicy:
// NewServer needs PrepareAll (CreateDelegation's grant probes need it, see
// server.go's own doc comment on the policy field), which PrincipalPolicy
// does not expose, so a Server has been built from a concrete policy.Multi
// ever since — and Phase 4a Task 4 deleted Unconfigured itself as
// production-dead once Multi's empty-registry case covered the same "no
// policy engine wired at all" ground. This package never asserted anything
// about Unconfigured() that a zero-policy Multi does not equally prove about
// Server.Decide's plumbing (deny, attributed to principal, with a non-empty
// reason and a "none" source, exercised at
// TestDecide_ProvenanceReflectsZeroPoliciesVerdict below).
func denyAllPolicy() policy.Multi {
	return policy.NewMulti(fakeAllPolicySource{}, policy.Registry{})
}

// noOpinionPolicy returns a policy.Multi with one registered engine that has
// a policy but never matches anything: Evaluate always returns zero
// verdicts, not an error. This is the Multi-shaped equivalent of the old
// emptyPolicy{} fixture (a PrincipalPolicy whose Evaluate returned a bare nil
// slice directly) — the scenario TestDecide_NoVerdictLeavesProvenanceUnset
// needs is "a real evaluation ran and had nothing to say," which is a
// different, more specific case than denyAllPolicy()'s "nothing was even
// loaded" (see policy.Multi's own doc comment on why those two verdicts
// differ).
func noOpinionPolicy() policy.Multi {
	return policy.NewMulti(
		fakeAllPolicySource{policies: []policy.StoredPolicy{{ID: "p1", Language: fakeLanguage}}},
		policy.Registry{fakeLanguage: fakePolicyEngine{set: nilVerdictSet{}}},
	)
}

// nilVerdictSet is a policy.CompiledPolicySet that always evaluates to zero
// verdicts and no error — an engine that ran and had nothing to say, as
// opposed to one that was never consulted at all.
type nilVerdictSet struct{}

func (nilVerdictSet) Evaluate(context.Context, policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	return nil, nil
}

// A well-formed request reaches a decision: DENY, attributed to principal,
// since denyAllPolicy() has nothing configured. This also exercises the
// tenant plumbing end to end — if the server sourced the tenant from
// anywhere but cfg, the chain's TenantID would mismatch and ValidateChain
// would deny at "delegation" instead, failing the DeniedLeg assertion below.
func TestDecide_WellFormedRequestReachesADecision(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Errorf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "principal")
	}
	if resp.GetReason() == "" {
		t.Error("Reason is empty, want the principal policy's reason")
	}

	if len(fs.appended) != 1 {
		t.Fatalf("AppendAudit called %d times, want 1", len(fs.appended))
	}
	if got := fs.appended[0].TenantID; got != testTenant {
		t.Errorf("audit entry TenantID = %q, want %q (the configured tenant)", got, testTenant)
	}
}

// The response's per-leg fields must reflect what was actually computed, not
// be left at their Go zero values. This is the meaningful form of that
// check: EFFECT_DENY is deliberately the zero value (see the proto's Effect
// doc comment), so a leg that is zero-valued *by bug* is indistinguishable
// from one correctly computed as DENY. Only a leg whose true result is
// ALLOW or ESCALATE can prove the field was actually populated — here, agent
// and delegation both legitimately allow, so seeing anything but
// EFFECT_ALLOW back means the field was never wired.
func TestDecide_PopulatesPerLegFields(t *testing.T) {
	fs, req := wellFormedFixture()
	// wellFormedFixture's bare Bash call has no raw_input and, after Task 3,
	// no verb either, so on its own it derives REASONING — indistinguishable
	// from DerivedTier's own zero value, which would silently defeat the
	// assertion below. A bare (not JSON-wrapped; this constructs the wire
	// request directly, not through a real PEP) read-only command gives
	// BuiltinTier's raw-input classifier positive evidence to derive a
	// specific, non-zero tier instead, restoring this test's ability to tell
	// "really computed READ_ONLY" apart from "never set at all".
	req.RawInput = "ls -la"
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetAgentEffect() != Effect_EFFECT_ALLOW {
		t.Errorf("AgentEffect = %v, want EFFECT_ALLOW", resp.GetAgentEffect())
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW", resp.GetDelegationEffect())
	}
	if resp.GetPrincipalEffect() != Effect_EFFECT_DENY {
		t.Errorf("PrincipalEffect = %v, want EFFECT_DENY", resp.GetPrincipalEffect())
	}
	if resp.GetPrincipalReason() == "" {
		t.Error("PrincipalReason is empty, want denyAllPolicy()'s reason")
	}
	if resp.GetDerivedTier() != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d (READ_ONLY)", resp.GetDerivedTier(), models.ActionTierReadOnly)
	}
}

// approval_id must stay empty on every effect but ESCALATE (the proto's own
// doc comment) — toResponse leaves it at the Go zero value for a plain,
// non-optional string rather than needing an explicit clear, so this is a
// genuine check that nothing sets it by mistake, not merely an unexercised
// field. wellFormedFixture's own scenario denies at the principal leg,
// nowhere near the escalation band (internal/pdpgrpc/escalation_test.go
// covers the ESCALATE-populates-it side).
func TestDecide_ApprovalIDEmptyWhenNotEscalating(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetApprovalId() != "" {
		t.Errorf("ApprovalId = %q, want empty for a non-ESCALATE effect", resp.GetApprovalId())
	}
}

// The catalog Task 1 wires into tiers here must reach the real server path,
// not just the pure authz package: a bare Read call — a path, no verb, no
// shell-command-shaped raw_input — must derive READ_ONLY through the
// catalog. Before the catalog was connected, this fell through to
// BuiltinTier's "unrecognized -> assume it modifies" default and came back
// INTERNAL_MODIFY, indistinguishable from what a Write on the same path
// would produce — the exact defect this task closes.
func TestDecide_CatalogDerivesReadOnlyForBareReadCall(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Tool = "Read"
	req.RawInput = "/tmp/notes.txt"
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDerivedTier() != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d (READ_ONLY): the catalog must classify a bare Read call by tool name",
			resp.GetDerivedTier(), models.ActionTierReadOnly)
	}
}

// TestDecide_NoCatalogRowsPassesWireResourceThroughUnchanged is Task 2's
// regression guard for the resource dimension: fakeStore's zero-value
// catalog (nil — no rows for any tenant, the state of every deployment
// before an operator adds a row) must leave req.GetResource() reaching the
// delegation leg exactly as it does today. wellFormedFixture's own bare
// Bash call — no raw_input, and after Task 3 no verb either, since neither
// exists on the wire for an uncataloged tool to supply — has nothing for
// BuiltinTier to classify and derives REASONING (tier 0, DeriveTier's own
// UnknownTier floor), comfortably under the fixture's INTERNAL_MODIFY
// ceiling, so ALLOW here is attributable only to the resource constraint
// actually matching — not to the ceiling check never being reached.
//
// This is the resource half of the property. The tier half — that
// ApplyExtraction's not-cataloged branch leaves Action untouched, byte for
// byte, so a call to an uncataloged tool derives identically to how it did
// before this function existed — is internal/authz's own
// TestApplyExtraction_UncatalogedToolLeavesActionAndResourceUnchanged
// (extract_test.go); TestDecide_CatalogDerivesReadOnlyForBareReadCall just
// above is the real-server-path proof that this holds all the way through
// Decide for an uncataloged tool, with nothing but tool and raw_input on the
// wire. Task 3 retired normalized_input from the wire entirely, so there is
// no longer a dedicated "wire-supplied normalized_input passes through
// unchanged" test to point to here — there is no wire value left for a
// not-cataloged branch to pass through in the first place.
func TestDecide_NoCatalogRowsPassesWireResourceThroughUnchanged(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.chain[0].ResourceConstraints = map[string]string{"id": "wire-supplied-resource-id"}
	req.Resource = map[string]string{"id": "wire-supplied-resource-id"}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Errorf("DelegationEffect = %v (%q), want ALLOW: with no catalog rows, the wire's resource must "+
			"reach the delegation leg's ResourceConstraints check unchanged",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
}

// TestDecide_CatalogedToolReplacesWireResourceForDelegationLeg is Phase 6/7's
// motivating fix, proven end to end: once the tenant catalogs a tool, the
// PDP's OWN reading of raw_input — not whatever resource the wire carried —
// is what the delegation leg's ResourceConstraints checks against. The
// wire's req.Resource is deliberately a DIFFERENT, stale-looking path so a
// mutation that fell back to it (instead of the catalog's extraction) would
// produce a DENY here, not an accidental ALLOW.
func TestDecide_CatalogedToolReplacesWireResourceForDelegationLeg(t *testing.T) {
	fs, req := wellFormedFixture()
	resourceField := "path"
	fs.catalog = []models.ToolCatalogEntry{{
		ToolName: "Bash", ActionTier: tierPtr(models.ActionTierReadOnly), ResourceField: &resourceField,
	}}
	fs.chain[0].ResourceConstraints = map[string]string{"id": "/catalog/extracted/path"}
	req.RawInput = `{"path":"/catalog/extracted/path"}`
	req.Resource = map[string]string{"id": "/stale/wire/supplied/path"}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDerivedTier() != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want READ_ONLY (%d) from the tenant's own catalog row",
			resp.GetDerivedTier(), models.ActionTierReadOnly)
	}
	if resp.GetDelegationEffect() != Effect_EFFECT_ALLOW {
		t.Errorf("DelegationEffect = %v (%q), want ALLOW: a cataloged tool's PDP-derived resource identity "+
			"must reach the delegation leg, not the wire's stale value",
			resp.GetDelegationEffect(), resp.GetDelegationReason())
	}
}

// TestDecide_CatalogedVerbReachesAudit is Task 3's own addition, proving the
// verb decision that task made: DecideRequest no longer carries a verb field
// at all (cmd/stratium-pep's toolVerbs table, which used to populate it, is
// deleted), so the tenant's own tool_catalog row is now the only source —
// internal/authz.ExtractFromCatalog/ApplyExtraction, proven in isolation by
// TestExtractFromCatalog_CarriesVerbFromCatalogRowRegardlessOfRawInput and
// TestApplyExtraction_CatalogedToolReplacesWireValuesEvenWhenExtractionIsEmpty
// (extract_test.go). This is the real-server-path proof that the derived
// verb actually reaches somewhere a caller can observe: appendAudit
// (server.go) writes action.Verb into audit.Entry.Action unconditionally, on
// every decision, so a verb that never left ApplyExtraction would leave
// every audit row for a cataloged tool as uninformative as an uncataloged
// one — the exact plumbed-but-unconsumed shape ToolCatalogEntry.Verb was in
// before this task (pkg/models/catalog.go's own doc comment on that field).
func TestDecide_CatalogedVerbReachesAudit(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		catalog  []models.ToolCatalogEntry
		wantVerb string
	}{
		{
			name:     "cataloged tool: audit carries the catalog's own verb",
			toolName: "search_docs",
			catalog:  []models.ToolCatalogEntry{{ToolName: "search_docs", ActionTier: tierPtr(models.ActionTierReadOnly), Verb: "search"}},
			wantVerb: "search",
		},
		{
			// No catalog row for this tool (or for any tool: fs.catalog is
			// left at its nil zero value) — there is no wire verb left to
			// fall back to either, so the audit row's Action must be "",
			// not a guess. This is the same uncataloged branch
			// TestApplyExtraction_UncatalogedToolLeavesActionAndResourceUnchanged
			// pins at the pure-function layer.
			name:     "uncataloged tool: audit carries no verb",
			toolName: "Bash",
			catalog:  nil,
			wantVerb: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			fs.catalog = tt.catalog
			req.Tool = tt.toolName
			srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

			if _, err := srv.Decide(context.Background(), req); err != nil {
				t.Fatalf("Decide() error = %v", err)
			}
			if len(fs.appended) != 1 {
				t.Fatalf("AppendAudit called %d times, want 1", len(fs.appended))
			}
			if got := fs.appended[0].Action; got != tt.wantVerb {
				t.Errorf("audit entry Action = %q, want %q", got, tt.wantVerb)
			}
		})
	}
}

// TestDecide_CatalogEntryCannotMaskDestructiveEvidence is the evidence-rule
// property proven through the real server wiring, not just the pure authz
// functions (internal/authz/extract_test.go's
// TestApplyExtraction_CatalogCannotMaskDestructiveRawEvidence already covers
// those in isolation). This is what would catch a mutation specifically in
// how server.go assembles the call to DeriveTier — for example, reordering
// so the tier from a cataloged tool's ActionTier, or its own extracted
// command, is used without DeriveTier ever re-scanning the true RawInput.
func TestDecide_CatalogEntryCannotMaskDestructiveEvidence(t *testing.T) {
	fs, req := wellFormedFixture()
	commandField := "safe_summary"
	fs.catalog = []models.ToolCatalogEntry{{
		ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly), CommandField: &commandField,
	}}
	req.Tool = "Read"
	req.RawInput = `{"command":"rm -rf /","safe_summary":"ls"}`
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDerivedTier() != int32(models.ActionTierDestructive) {
		t.Errorf("DerivedTier = %d, want DESTRUCTIVE (%d): a catalog entry rating Read READ_ONLY, plus a "+
			"benign-looking catalog-extracted command, must not mask rm -rf / sitting in this call's own "+
			"raw_input", resp.GetDerivedTier(), models.ActionTierDestructive)
	}
}

// TestDecide_ToolCatalogLoadFailureDeniesAndAudits is the fail-closed
// requirement the phase brief states explicitly: a catalog that could not be
// loaded must deny, audited, rather than the failure being swallowed and the
// decision proceeding as though the tenant had no rows at all (which could
// under-classify whatever the unreadable rows would have raised) or
// surfacing only as an unaudited RPC error.
func TestDecide_ToolCatalogLoadFailureDeniesAndAudits(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.catalogErr = errors.New("connection reset")
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a decision (fail closed, not a bare RPC error)", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}
	if resp.GetReason() == "" {
		t.Error("Reason is empty, want the catalog load failure's message")
	}
	if len(fs.appended) != 1 {
		t.Fatalf("AppendAudit called %d times, want 1 — a catalog load failure must still be audited", len(fs.appended))
	}
	if fs.appended[0].Decision != "DENY" {
		t.Errorf("audit entry Decision = %q, want DENY", fs.appended[0].Decision)
	}
}

// capturingVerdictSet is a policy.CompiledPolicySet that records the last
// EvaluationInput it was handed and returns a fixed, uninteresting verdict.
// It exists because Decide computes the derived tier TWICE (server.go's own
// comment on the "derived ahead of authz.Decide" step explains why): once
// here, early, purely so a policy can condition on it, and again inside
// authz.Decide itself, which is what actually decides the response. That
// second computation is independent and authoritative for
// resp.GetDerivedTier() — so a bug that corrupts ONLY the early value would
// leave the response looking correct while still handing every policy
// engine the wrong tier to reason about. Nothing else in this file's fixture
// set can observe that distinction; this type exists so a test can.
type capturingVerdictSet struct {
	lastInput *policy.EvaluationInput
}

func (c *capturingVerdictSet) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	cp := in
	c.lastInput = &cp
	return []authz.PolicyVerdict{{Effect: authz.EffectDeny, Source: fakeLanguage, Reason: "capturing-fake-deny"}}, nil
}

// TestDecide_PolicySeesEvidenceProtectedDerivedTier closes the gap
// TestDecide_CatalogEntryCannotMaskDestructiveEvidence cannot see: that test
// only asserts the FINAL resp.GetDerivedTier(), which authz.Decide's own
// redundant re-derivation protects independently of the early value this
// method computes for the policy engine (see capturingVerdictSet's own doc
// comment). A tenant policy that conditions on EvaluationInput.DerivedTier —
// "allow anything under EXTERNAL_COMMS," say — would be handed a
// silently-wrong tier if the early derivation were ever corrupted, even
// though the response and the audit row would both still show the correct
// value. This test is what makes that corruption visible.
func TestDecide_PolicySeesEvidenceProtectedDerivedTier(t *testing.T) {
	fs, req := wellFormedFixture()
	commandField := "safe_summary"
	fs.catalog = []models.ToolCatalogEntry{{
		ToolName: "Read", ActionTier: tierPtr(models.ActionTierReadOnly), CommandField: &commandField,
	}}
	req.Tool = "Read"
	req.RawInput = `{"command":"rm -rf /","safe_summary":"ls"}`

	capture := &capturingVerdictSet{}
	srv := NewServer(fs, policy.NewMulti(
		fakeAllPolicySource{policies: []policy.StoredPolicy{{ID: "p1", Language: fakeLanguage}}},
		policy.Registry{fakeLanguage: fakePolicyEngine{set: capture}},
	), testConfig(), nil)

	if _, err := srv.Decide(context.Background(), req); err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if capture.lastInput == nil {
		t.Fatal("policy engine was never invoked; capture.lastInput is nil")
	}
	if capture.lastInput.DerivedTier != models.ActionTierDestructive {
		t.Errorf("policy saw DerivedTier = %v, want DESTRUCTIVE: the tier fed to policy evaluation must be "+
			"evidence-protected exactly like the response's own DerivedTier, not merely the response",
			capture.lastInput.DerivedTier)
	}
}

// The response's provenance fields must carry the principal policy's
// specific reason and source through, not FoldVerdicts's generic
// "default deny: no policy verdict allowed" text — that is the entire point
// of a zero-policies Multi returning one verdict instead of zero (see
// multiSet.Evaluate's own doc comment in internal/policy/multi.go).
func TestDecide_ProvenanceReflectsZeroPoliciesVerdict(t *testing.T) {
	const wantReason = "principal: no policies configured for this tenant"
	fs, req := wellFormedFixture()
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetReason() != wantReason {
		t.Errorf("Reason = %q, want %q", resp.GetReason(), wantReason)
	}
	if resp.GetPrincipalReason() != wantReason {
		t.Errorf("PrincipalReason = %q, want %q", resp.GetPrincipalReason(), wantReason)
	}
	if resp.DecidedSource == nil {
		t.Fatal("DecidedSource is unset, want present (\"none\")")
	}
	if got := resp.GetDecidedSource(); got != "none" {
		t.Errorf("DecidedSource = %q, want %q", got, "none")
	}
	// PolicyID is legitimately empty for a zero-policies Multi verdict — the
	// field must still be present (non-nil) to prove it was populated from a
	// real Deciding verdict, not left unset.
	if resp.DecidedPolicyId == nil {
		t.Fatal("DecidedPolicyId is unset, want present (empty string)")
	}
	if got := resp.GetDecidedPolicyId(); got != "" {
		t.Errorf("DecidedPolicyId = %q, want empty string", got)
	}

	// The audit row must carry the same provenance as the response — that is
	// the entire reason audit.Entry gained these columns (Task 2).
	if len(fs.appended) != 1 {
		t.Fatalf("AppendAudit called %d times, want 1", len(fs.appended))
	}
	if got := fs.appended[0].PolicySource; got != "none" {
		t.Errorf("audit entry PolicySource = %q, want %q", got, "none")
	}
	if got := fs.appended[0].PolicyID; got != "" {
		t.Errorf("audit entry PolicyID = %q, want empty string", got)
	}
}

// When the policy provider consults nothing at all (a nil verdict slice),
// authz.Result.Deciding is nil — no verdict decided the outcome, as opposed
// to a verdict deciding it whose Source/PolicyID happen to be empty. The
// response must leave DecidedSource/DecidedPolicyId unset (nil pointers) in
// that case, not populate them with zero-valued strings that would be
// indistinguishable from TestDecide_ProvenanceReflectsZeroPoliciesVerdict's
// PolicyID case above.
func TestDecide_NoVerdictLeavesProvenanceUnset(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, noOpinionPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY (default-deny with no verdict)", resp.GetEffect())
	}
	if resp.DecidedSource != nil {
		t.Errorf("DecidedSource = %q, want unset (nil): no verdict decided this", resp.GetDecidedSource())
	}
	if resp.DecidedPolicyId != nil {
		t.Errorf("DecidedPolicyId = %q, want unset (nil): no verdict decided this", resp.GetDecidedPolicyId())
	}

	// audit.Entry has no presence tracking (plain strings, not proto3
	// optional) — "" is documented as meaning "no verdict decided this" at
	// that layer (see audit.Entry's doc comment), so both columns should be
	// the Go zero value here, consistent with that documented meaning.
	if len(fs.appended) != 1 {
		t.Fatalf("AppendAudit called %d times, want 1", len(fs.appended))
	}
	if got := fs.appended[0].PolicySource; got != "" {
		t.Errorf("audit entry PolicySource = %q, want empty string: no verdict decided this", got)
	}
	if got := fs.appended[0].PolicyID; got != "" {
		t.Errorf("audit entry PolicyID = %q, want empty string: no verdict decided this", got)
	}
}

// orphanVerdictSet is a policy.CompiledPolicySet that always evaluates to
// one deny verdict carrying UnevaluatedPolicyIDs — standing in for
// policy.Multi's own orphanVerdicts (internal/policy/multi.go) without
// depending on a real Registry gap, the same "cheap test double for a
// specific production shape" reasoning nilVerdictSet above uses.
type orphanVerdictSet struct{ ids []string }

func (s orphanVerdictSet) Evaluate(context.Context, policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	return []authz.PolicyVerdict{{
		Effect:               authz.EffectDeny,
		Source:               fakeLanguage,
		Reason:               "principal: no fake engine registered; cannot evaluate 2 fake policies for this tenant",
		UnevaluatedPolicyIDs: s.ids,
	}}, nil
}

// UnevaluatedPolicyIDs must reach the audit row: appendAudit copies it from
// result.UnevaluatedPolicyIDs unconditionally, not gated on result.Deciding
// (see appendAudit's own doc comment on why gating it would reintroduce the
// loses-the-fold defect the aggregate exists to avoid — the fold-survival
// mechanics themselves are proven at the authz layer, in
// internal/authz/compound_test.go's TestDecide_
// UnevaluatedPolicyIDsSurviveLosingTheFold and live, over gRPC, in
// internal/store's TestIntegration_Live_OrphanLanguageDeniesNamingIt; this
// test only needs to prove appendAudit's own plumbing copies the field).
func TestDecide_UnevaluatedPolicyIDsReachAuditEntry(t *testing.T) {
	fs, req := wellFormedFixture()
	ids := []string{"orphan-a", "orphan-b"}
	srv := NewServer(fs, policy.NewMulti(
		fakeAllPolicySource{policies: []policy.StoredPolicy{{ID: "fake-policy-1", Language: fakeLanguage}}},
		policy.Registry{fakeLanguage: fakePolicyEngine{set: orphanVerdictSet{ids: ids}}},
	), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
	}

	if len(fs.appended) != 1 {
		t.Fatalf("AppendAudit called %d times, want 1", len(fs.appended))
	}
	if got := fs.appended[0].UnevaluatedPolicyIDs; !slices.Equal(got, ids) {
		t.Errorf("audit entry UnevaluatedPolicyIDs = %v, want %v", got, ids)
	}
}

func TestDecide_UnknownAgent_NotFound(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.agentErr = fmt.Errorf("%w: agent %s", store.ErrNotFound, req.GetAgentId())
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
}

func TestDecide_UnknownDelegation_NotFound(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.chainErr = fmt.Errorf("%w: delegation %s", store.ErrNotFound, req.GetDelegationId())
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
}

// Invalid input must be rejected before any store call — malformed UUIDs,
// the zero UUID (well-formed as a string, never a legitimate identifier),
// an empty subject, and an out-of-range declared_tier. calls == 0 after each
// proves "do not proceed," not just that the response code happened to come
// back InvalidArgument.
func TestDecide_InvalidInput_InvalidArgument(t *testing.T) {
	outOfRange := int32(99)
	malformedID := "not-a-uuid"
	zeroID := uuid.Nil.String()
	cases := map[string]func(*DecideRequest){
		"malformed delegation_id": func(r *DecideRequest) { r.DelegationId = "not-a-uuid" },
		"malformed agent_id":      func(r *DecideRequest) { r.AgentId = "not-a-uuid" },
		"zero delegation_id":      func(r *DecideRequest) { r.DelegationId = uuid.Nil.String() },
		"zero agent_id":           func(r *DecideRequest) { r.AgentId = uuid.Nil.String() },
		"empty subject":           func(r *DecideRequest) { r.Subject = "" },
		"declared_tier out of range": func(r *DecideRequest) {
			r.DeclaredTier = &outOfRange
		},
		// approval_id gets the same malformed/zero treatment as
		// delegation_id/agent_id above — a request-shape defect, rejected
		// before any store call, distinct from a verification failure
		// (escalation_test.go), which fails closed to a DENY decision
		// instead of an error.
		"malformed approval_id": func(r *DecideRequest) { r.ApprovalId = &malformedID },
		"zero approval_id":      func(r *DecideRequest) { r.ApprovalId = &zeroID },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			mutate(req)
			srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

			resp, err := srv.Decide(context.Background(), req)
			if resp != nil {
				t.Fatalf("Decide() response = %+v, want nil", resp)
			}
			wantCode(t, err, codes.InvalidArgument)
			if fs.calls != 0 {
				t.Errorf("store was called %d times, want 0 — invalid input must not proceed to a lookup", fs.calls)
			}
		})
	}
}

// This is the D3 guarantee under test: a failed audit write must return an
// error and never a decision, ALLOW least of all. The assertion is written
// against the server's contract (resp is strictly nil on any audit error),
// not against today's policy — denyAllPolicy() means the underlying decision
// here is already DENY, so this fixture cannot exercise an internally
// computed ALLOW being suppressed, but the contract this proves ("no
// DecideResponse escapes on audit failure") is exactly what stops one from
// escaping the day a policy engine wires in a language that can allow.
func TestDecide_AuditWriteFailure_ReturnsErrorNotDecision(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.appendErr = errors.New("disk full")
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if err == nil {
		t.Fatal("Decide() error = nil, want error when the audit append fails")
	}
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil: a decision must not escape a failed audit write", resp)
	}
	if resp.GetEffect() == Effect_EFFECT_ALLOW {
		t.Fatal("no DecideResponse with EFFECT_ALLOW may escape an audit write failure")
	}
	wantCode(t, err, codes.Internal)
}

// toProtoEffect's ESCALATE branch is not otherwise reachable through Decide
// in this slice (nothing here produces an escalation), so it is covered
// directly.
func TestToProtoEffect(t *testing.T) {
	cases := map[authz.Effect]Effect{
		authz.EffectDeny:     Effect_EFFECT_DENY,
		authz.EffectAllow:    Effect_EFFECT_ALLOW,
		authz.EffectEscalate: Effect_EFFECT_ESCALATE,
	}
	for in, want := range cases {
		if got := toProtoEffect(in); got != want {
			t.Errorf("toProtoEffect(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestDecide_ConcurrentAuditAppend_Aborted(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.appendErr = fmt.Errorf("wrapped: %w", store.ErrConcurrentAppend)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), nil)

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Aborted)
}
