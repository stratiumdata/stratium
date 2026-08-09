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

// A well-formed request reaches a decision: DENY, attributed to principal,
// since policy.Unconfigured() is unconditional. This also exercises the
// tenant plumbing end to end — if the server sourced the tenant from
// anywhere but cfg, the chain's TenantID would mismatch and ValidateChain
// would deny at "delegation" instead, failing the DeniedLeg assertion below.
func TestDecide_WellFormedRequestReachesADecision(t *testing.T) {
	fs, req := wellFormedFixture()
	srv := NewServer(fs, policy.Unconfigured(), testConfig())

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
	srv := NewServer(fs, policy.Unconfigured(), testConfig())

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

func TestDecide_UnknownAgent_NotFound(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.agentErr = fmt.Errorf("%w: agent %s", store.ErrNotFound, req.GetAgentId())
	srv := NewServer(fs, policy.Unconfigured(), testConfig())

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
}

func TestDecide_UnknownDelegation_NotFound(t *testing.T) {
	fs, req := wellFormedFixture()
	fs.chainErr = fmt.Errorf("%w: delegation %s", store.ErrNotFound, req.GetDelegationId())
	srv := NewServer(fs, policy.Unconfigured(), testConfig())

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
			srv := NewServer(fs, policy.Unconfigured(), testConfig())

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
	srv := NewServer(fs, policy.Unconfigured(), testConfig())

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
	srv := NewServer(fs, policy.Unconfigured(), testConfig())

	resp, err := srv.Decide(context.Background(), req)
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Aborted)
}
