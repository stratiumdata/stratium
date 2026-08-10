package pdpgrpc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

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

const testTenant = "tenant-abc"

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

func testConfig() config.Config {
	return config.Config{TenantID: testTenant, MaxDepth: 5}
}

// wellFormedFixture returns a fake store and request that, evaluated
// together against the real policy.Unconfigured(), clear every leg except
// the principal: the agent is enabled and trusted, the one-hop chain is
// active and within scope. Only Unconfigured()'s unconditional deny stops
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
		Verb:         "read",
	}
	return fs, req
}

// emptyPolicy consults no policy at all: Evaluate returns nil. It exercises
// the default-deny-with-no-verdict path (authz.Result.Deciding is nil), which
// is distinct from policy.Unconfigured()'s case (Deciding is non-nil and its
// Source/PolicyID happen to be "none"/""). The response's provenance fields
// must tell these apart rather than collapsing both to empty strings.
type emptyPolicy struct{}

func (emptyPolicy) Evaluate(context.Context, policy.EvaluationInput) []authz.PolicyVerdict {
	return nil
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

// Every NewServer(...) call in this file passes nil, nil for
// policySource/policyEngine: those two only back CreateDelegation's grant
// probes (delegation_test.go), and Decide never reads them, so a nil
// interface value is a safe, honest "unused by this test" rather than a
// fake that would never be exercised.

// A well-formed request reaches a decision: DENY, attributed to principal,
// since policy.Unconfigured() is unconditional. This also exercises the
// tenant plumbing end to end — if the server sourced the tenant from
// anywhere but cfg, the chain's TenantID would mismatch and ValidateChain
// would deny at "delegation" instead, failing the DeniedLeg assertion below.
func TestDecide_WellFormedRequestReachesADecision(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

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
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

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
		t.Error("PrincipalReason is empty, want Unconfigured()'s reason")
	}
	if resp.GetDerivedTier() != int32(models.ActionTierReadOnly) {
		t.Errorf("DerivedTier = %d, want %d (READ_ONLY)", resp.GetDerivedTier(), models.ActionTierReadOnly)
	}
}

// normalized_input must reach the derivation the same way raw_input does.
// internal/authz's TestBuiltinTier_* prove the classification itself (more
// severe of RawInput/NormalizedInput wins); this proves the field actually
// travels from the wire request into the Action Decide derives from, rather
// than being parsed and dropped.
func TestDecide_NormalizedInputReachesDerivation(t *testing.T) {
	fs, req := wellFormedFixture()
	req.RawInput = "ls"
	req.NormalizedInput = "rm -rf /"
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDerivedTier() != int32(models.ActionTierDestructive) {
		t.Errorf("DerivedTier = %d, want %d (DESTRUCTIVE): normalized_input must reach BuiltinTier",
			resp.GetDerivedTier(), models.ActionTierDestructive)
	}
}

// The response's provenance fields must carry policy.Unconfigured()'s
// specific reason and source through, not FoldVerdicts's generic
// "default deny: no policy verdict allowed" text — that is the entire point
// of Unconfigured() returning one verdict instead of zero (see the package
// doc on policy.Unconfigured).
func TestDecide_ProvenanceReflectsUnconfiguredVerdict(t *testing.T) {
	const wantReason = "principal: no policy engine configured (Phase 2)"
	fs, req := wellFormedFixture()
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

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
	// PolicyID is legitimately empty for Unconfigured() — the field must
	// still be present (non-nil) to prove it was populated from a real
	// Deciding verdict, not left unset.
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
// indistinguishable from TestDecide_ProvenanceReflectsUnconfiguredVerdict's
// PolicyID case above.
func TestDecide_NoVerdictLeavesProvenanceUnset(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, emptyPolicy{}, nil, nil, testConfig())

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

func TestDecide_UnknownAgent_NotFound(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.agentErr = fmt.Errorf("%w: agent %s", store.ErrNotFound, req.GetAgentId())
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
}

func TestDecide_UnknownDelegation_NotFound(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.chainErr = fmt.Errorf("%w: delegation %s", store.ErrNotFound, req.GetDelegationId())
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

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
	cases := map[string]func(*DecideRequest){
		"malformed delegation_id": func(r *DecideRequest) { r.DelegationId = "not-a-uuid" },
		"malformed agent_id":      func(r *DecideRequest) { r.AgentId = "not-a-uuid" },
		"zero delegation_id":      func(r *DecideRequest) { r.DelegationId = uuid.Nil.String() },
		"zero agent_id":           func(r *DecideRequest) { r.AgentId = uuid.Nil.String() },
		"empty subject":           func(r *DecideRequest) { r.Subject = "" },
		"declared_tier out of range": func(r *DecideRequest) {
			r.DeclaredTier = &outOfRange
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fs, req := wellFormedFixture()
			mutate(req)
			srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

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
// not against today's policy — Unconfigured() means the underlying decision
// here is already DENY, so this fixture cannot exercise an internally
// computed ALLOW being suppressed, but the contract this proves ("no
// DecideResponse escapes on audit failure") is exactly what stops one from
// escaping the day Phase 2 wires in a policy engine that can allow.
func TestDecide_AuditWriteFailure_ReturnsErrorNotDecision(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.appendErr = errors.New("disk full")
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

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
	srv := NewServer(fs, policy.Unconfigured(), nil, nil, testConfig())

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Aborted)
}
