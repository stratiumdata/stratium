package pdpgrpc

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/internal/store"
	"stratium/pkg/models"
)

// grantSet is a policy.CompiledPolicySet under full test control: it allows
// exactly the tools named in allowedTools at any tier, and allows the tier
// dimension (Action.Tool == "", policy.GrantProbe's own "probing the tier
// ceiling" convention — see clamp.go) up to and including maxTier. Every
// Evaluate call fails with err when set, standing in for an engine that is
// simply unreachable — mirrors probe_test.go's own errSet stub, for the same
// reason: nothing about real policy data can be made to fail on demand.
type grantSet struct {
	allowedTools map[string]bool
	maxTier      models.ActionTier
	err          error

	evaluateCalls int
}

func (g *grantSet) Evaluate(_ context.Context, in policy.EvaluationInput) ([]authz.PolicyVerdict, error) {
	g.evaluateCalls++
	if g.err != nil {
		return nil, g.err
	}
	allow := false
	if in.Action.Tool == "" {
		allow = in.DerivedTier <= g.maxTier
	} else {
		allow = g.allowedTools[in.Action.Tool]
	}
	if allow {
		return []authz.PolicyVerdict{{Effect: authz.EffectAllow, Source: "fake"}}, nil
	}
	return []authz.PolicyVerdict{{Effect: authz.EffectDeny, Source: "fake"}}, nil
}

// fakeLanguage is the sole policies.language value every fixture in this
// file registers fakePolicyEngine under — arbitrary, but shared by every
// caller below so a Registry built with one entry always resolves.
const fakeLanguage = "fake"

// fakeAllPolicySource implements policy.AllPolicySource. Its zero value
// reports no policies, and a test that needs PrepareAll to route through a
// specific engine sets policies explicitly — every fixture in this file
// does, since CreateDelegation's grant probes need a compiled set to probe
// against.
type fakeAllPolicySource struct {
	policies []policy.StoredPolicy
	loadErr  error
}

func (f fakeAllPolicySource) LoadAllPolicies(context.Context) ([]policy.StoredPolicy, error) {
	if f.loadErr != nil {
		return nil, f.loadErr
	}
	return f.policies, nil
}

// fakePolicyEngine hands policy.Multi.PrepareAll a fixed policy.CompiledPolicySet
// directly, so a test controls exactly what policy.Probe answers without a
// real engine. prepareCalls counts Prepare invocations (not Evaluate — that
// is grantSet.evaluateCalls) so a test can pin "one compile per
// CreateDelegation call, however many probes Clamp makes against it" — see
// policy.Multi.PrepareAll's own doc comment for why that compile step must
// happen once, not per probe.
type fakePolicyEngine struct {
	set          policy.CompiledPolicySet
	prepareErr   error
	prepareCalls *int
}

func (fakePolicyEngine) Language() string { return fakeLanguage }

func (f fakePolicyEngine) Prepare(context.Context, []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	if f.prepareCalls != nil {
		*f.prepareCalls++
	}
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	return f.set, nil
}

func (fakePolicyEngine) Validate(context.Context, string) error { return nil }

// newDelegationServer wires a Server whose CreateDelegation grant probes are
// answered by set: a policy.Multi with exactly one registered language
// (fakeLanguage), one fake StoredPolicy for it, and the given fakePolicyEngine
// as the engine that prepares it into set. Its signer is a fresh, always-
// succeeding fakeSigner — every test in this file reaches CreateDelegation's
// final mint-a-token step on its success path, so a nil signer (fine for
// Decide-only tests elsewhere in this package) would fail every one of them
// here for a reason unrelated to what each test actually means to exercise.
// Tests that specifically care about signing (a real, verifiable token; a
// signing failure) build their own Server directly instead of through this
// helper.
func newDelegationServer(fs *fakeStore, set policy.CompiledPolicySet) *Server {
	return NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: set}), testConfig(), &fakeSigner{})
}

// singleFakeLanguagePolicy builds the policy.Multi every CreateDelegation
// test in this file needs: one language, one policy row, engine supplied by
// the caller so prepare-failure tests can substitute one whose Prepare call
// itself errors.
//
// The policy row's ID deliberately differs from fakeLanguage ("fake"): if
// policy.Multi ever grouped by StoredPolicy.ID instead of .Language, using
// the same literal for both would let that bug pass every test in this file
// by coincidence — the ID/Name-mixup class of defect this project has hit
// before (see policytest.EngineContract's own fixtures for the same rule).
func singleFakeLanguagePolicy(engine fakePolicyEngine) policy.Multi {
	return policy.NewMulti(
		fakeAllPolicySource{policies: []policy.StoredPolicy{{ID: "fake-policy-1", Language: fakeLanguage}}},
		policy.Registry{fakeLanguage: engine},
	)
}

// wellFormedDelegationFixture returns a fake store (a known, existing agent,
// no parent) and a request that a permissiveGrantSet fully grants: the
// requested tier and every requested tool survive the clamp untouched. Tests
// that want the clamp to actually remove something start here and either
// narrow the grantSet or widen the request.
func wellFormedDelegationFixture() (*fakeStore, *CreateDelegationRequest, uuid.UUID) {
	agentID := uuid.New()
	fs := &fakeStore{agent: authz.AgentInfo{ID: agentID, Enabled: true, TrustTier: models.TrustTierCertified}}
	req := &CreateDelegationRequest{
		Subject: "alice@example.com",
		AgentId: agentID.String(),
		RequestedScope: &RequestedScope{
			MaxActionTier: int32(models.ActionTierInternalModify),
			Tools:         []string{"Bash", "Read"},
		},
		Purpose:    "test delegation",
		TtlSeconds: 3600,
	}
	return fs, req, agentID
}

func permissiveGrantSet() *grantSet {
	return &grantSet{
		allowedTools: map[string]bool{"Bash": true, "Read": true, "Write": true},
		maxTier:      models.ActionTierDestructive,
	}
}

// findRemoval returns the ScopeRemoval matching dimension/value, or nil.
// Scans rather than indexing: Removed's order (tier before tools, tools in
// request order) is an implementation detail of internal/authz.Clamp, not a
// documented contract these tests should couple to.
func findRemoval(removed []*ScopeRemoval, dimension, value string) *ScopeRemoval {
	for _, r := range removed {
		if r.GetDimension() == dimension && r.GetValue() == value {
			return r
		}
	}
	return nil
}

// A clamped request returns the narrowed scope with removals listed, and the
// persisted row matches what the response reported — both required
// assertions from the brief, exercised together since they share the same
// fixture and are two views of the same outcome.
func TestCreateDelegation_ClampedRequestReturnsNarrowedScopeWithRemovals(t *testing.T) {
	fs, req, agentID := wellFormedDelegationFixture()
	req.RequestedScope = &RequestedScope{
		MaxActionTier: int32(models.ActionTierDestructive),
		Tools:         []string{"Bash", "Read", "Write"},
	}
	set := &grantSet{allowedTools: map[string]bool{"Bash": true, "Read": true}, maxTier: models.ActionTierInternalModify}
	srv := newDelegationServer(fs, set)

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateDelegation() error = %v, want a response", err)
	}

	gs := resp.GetGrantedScope()
	if gs.GetMaxActionTier() != int32(models.ActionTierInternalModify) {
		t.Errorf("granted max_action_tier = %d, want %d", gs.GetMaxActionTier(), models.ActionTierInternalModify)
	}
	if !slices.Equal(gs.GetTools(), []string{"Bash", "Read"}) {
		t.Errorf("granted tools = %v, want [Bash Read]", gs.GetTools())
	}

	tierRemoval := findRemoval(gs.GetRemoved(), "tier", models.ActionTierDestructive.String())
	if tierRemoval == nil {
		t.Fatal("no removal recorded for the tier dimension")
	}
	if tierRemoval.GetReason() != "denied" {
		t.Errorf("tier removal reason = %q, want %q", tierRemoval.GetReason(), "denied")
	}

	toolRemoval := findRemoval(gs.GetRemoved(), "tool", "Write")
	if toolRemoval == nil {
		t.Fatal("no removal recorded for tool Write")
	}
	if toolRemoval.GetReason() != "denied" {
		t.Errorf("tool removal reason = %q, want %q", toolRemoval.GetReason(), "denied")
	}
	if got := findRemoval(gs.GetRemoved(), "tool", "Bash"); got != nil {
		t.Errorf("Bash was removed, want it granted")
	}

	// The persisted row must match what the response reported.
	if len(fs.created) != 1 {
		t.Fatalf("delegation rows created = %d, want 1", len(fs.created))
	}
	row := fs.created[0]
	if row.ID.String() != resp.GetDelegationId() {
		t.Errorf("persisted row id = %s, want %s (the response's delegation_id)", row.ID, resp.GetDelegationId())
	}
	if !slices.Equal(row.ApprovedTools, gs.GetTools()) {
		t.Errorf("persisted ApprovedTools = %v, want %v", row.ApprovedTools, gs.GetTools())
	}
	if row.MaxActionTier != models.ActionTierInternalModify {
		t.Errorf("persisted MaxActionTier = %v, want %v", row.MaxActionTier, models.ActionTierInternalModify)
	}
	if row.AgentID != agentID {
		t.Errorf("persisted AgentID = %s, want %s", row.AgentID, agentID)
	}

	// A grant is audited exactly once, as an ALLOW.
	if len(fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1", len(fs.appended))
	}
	if fs.appended[0].Decision != "ALLOW" {
		t.Errorf("audit Decision = %q, want %q", fs.appended[0].Decision, "ALLOW")
	}
}

func TestCreateDelegation_UnknownAgent_NotFound(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	fs.agentErr = fmt.Errorf("%w: agent %s", store.ErrNotFound, req.GetAgentId())
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

func TestCreateDelegation_UnknownParentDelegation_NotFound(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	parentID := uuid.New()
	req.ParentDelegationId = parentID.String()
	fs.chainErr = fmt.Errorf("%w: delegation %s", store.ErrNotFound, parentID)
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

// A child that would widen its parent is PermissionDenied. store.CreateDelegation
// (Task 3) is what actually runs models.ScopeNarrows; this test proves pdpgrpc
// maps store.ErrScopeWidens to the right status code, using the fake to stand
// in for that enforcement — store's own package tests already cover
// ScopeNarrows itself thoroughly.
func TestCreateDelegation_ChildWideningParent_PermissionDenied(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	parentID := uuid.New()
	req.ParentDelegationId = parentID.String()
	fs.chain = []*models.Delegation{{
		ID: parentID, RootDelegationID: parentID, Depth: 0,
		MaxActionTier: models.ActionTierReadOnly, ApprovedTools: []string{"Bash", "Read"},
	}}
	fs.createErr = fmt.Errorf("%w: child max_action_tier INTERNAL_MODIFY exceeds parent READ_ONLY", store.ErrScopeWidens)
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.PermissionDenied)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
	if len(fs.appended) != 0 {
		t.Errorf("audit entries appended = %d, want 0: persist failed before the audit step", len(fs.appended))
	}
}

// Rejection 1: an empty requested tool list is InvalidArgument, and no
// delegation row is written.
func TestCreateDelegation_EmptyToolsRequest_InvalidArgumentNoRowWritten(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	req.RequestedScope.Tools = nil
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.InvalidArgument)
	if fs.calls != 0 {
		t.Errorf("store was called %d times, want 0 — an empty tool list must be rejected before any store call", fs.calls)
	}
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

// Rejection 2: a request whose tools are all removed by the clamp is
// PermissionDenied, not a grant with an empty list, and no delegation row is
// written.
func TestCreateDelegation_AllRequestedToolsRemoved_PermissionDeniedNoRowWritten(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	req.RequestedScope.Tools = []string{"Bash", "Read"}
	set := &grantSet{allowedTools: map[string]bool{}, maxTier: models.ActionTierInternalModify}
	srv := newDelegationServer(fs, set)

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.PermissionDenied)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0: a fully-denied request must not be persisted", len(fs.created))
	}
	if len(fs.appended) != 0 {
		t.Errorf("audit entries appended = %d, want 0", len(fs.appended))
	}
}

// D3's sibling rule: a failed audit write fails the call and no delegation
// id ever escapes, even though the row was in fact persisted (fs.created
// still grows — the point is that nothing about the response says so).
func TestCreateDelegation_AuditWriteFailure_ReturnsErrorAndNoID(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	fs.appendErr = errors.New("disk full")
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err == nil {
		t.Fatal("CreateDelegation() error = nil, want an error when the audit append fails")
	}
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil: no delegation id may escape a failed audit write", resp)
	}
	wantCode(t, err, codes.Internal)
	if len(fs.created) != 1 {
		t.Fatalf("delegation rows created = %d, want 1: the row is persisted before the audit step runs", len(fs.created))
	}
}

// A created delegation returns a token that (a) actually verifies against
// the signer that issued it and (b) names the delegation it came with —
// the brief's own "a created delegation returns a verifiable token naming
// it." Uses a real *token.Signer (testSigner, token_test.go), not
// newDelegationServer's fakeSigner: only a real Verify() proves the wire
// artifact is a genuine, well-formed token, not merely that some string was
// returned. Combined with the same test's exact-claim-key-set assertion
// below for K3's "carries no scope fields" — this is the strongest form of
// that property this package can state, since it inspects the token that
// actually left CreateDelegation, decoded by the same mechanism a real
// caller would use, rather than a claims map intercepted before signing
// (TestTokenClaims_CarriesExactlyTheIdentifyingFields, token_test.go, is
// that narrower, direct-unit-test version of the same property).
func TestCreateDelegation_ReturnsVerifiableTokenNamingTheDelegationWithNoScopeFields(t *testing.T) {
	signer := testSigner(t)
	fs, req, _ := wellFormedDelegationFixture()
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: permissiveGrantSet()}), testConfig(), signer)

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateDelegation() error = %v, want a response", err)
	}
	if resp.GetToken() == "" {
		t.Fatal("CreateDelegation() returned an empty token")
	}

	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() of the returned token = %v, want success", err)
	}
	if got := claims[subjectClaim]; got != resp.GetDelegationId() {
		t.Errorf("token sub = %v, want %s (the delegation this token was returned alongside)",
			got, resp.GetDelegationId())
	}
	if got := claimKeys(claims); !slices.Equal(got, identifyingClaimKeys) {
		t.Fatalf("token claim keys = %v, want exactly %v: no scope field may ride along "+
			"(spec K3 — a token is a reference, not a capability)", got, identifyingClaimKeys)
	}
}

// A fresh delegation's token expires exactly when the delegation does — not
// a moment later (which would be the "outlive its delegation" mutation this
// task's brief names) and not a moment earlier either (which would silently
// grant less than what CreateDelegation is documented to hand back).
func TestCreateDelegation_TokenExpiryEqualsDelegationExpiry(t *testing.T) {
	signer := testSigner(t)
	fs, req, _ := wellFormedDelegationFixture()
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: permissiveGrantSet()}), testConfig(), signer)

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateDelegation() error = %v, want a response", err)
	}
	if len(fs.created) != 1 {
		t.Fatalf("delegation rows created = %d, want 1", len(fs.created))
	}

	claims, err := signer.Verify(resp.GetToken())
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	wantExp := fs.created[0].ExpiresAt.Unix()
	gotExp, ok := claims[expiryClaim].(float64)
	if !ok || int64(gotExp) != wantExp {
		t.Errorf("token exp = %v, want exactly %d (the persisted delegation's own expires_at)", claims[expiryClaim], wantExp)
	}
}

// The signing-failure sibling of TestCreateDelegation_AuditWriteFailure_
// ReturnsErrorAndNoID: a delegation with no token to go with it must never
// reach a caller, even though the row was in fact persisted and audited by
// the time signing is attempted (mintToken runs last — see CreateDelegation's
// own doc comment on why). fs.created and fs.appended both still grow by
// one: the point under test is that nothing about the RESPONSE says so.
func TestCreateDelegation_SigningFailure_ReturnsErrorAndNoToken(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: permissiveGrantSet()}), testConfig(),
		&fakeSigner{signErr: errors.New("hsm unavailable")})

	resp, err := srv.CreateDelegation(context.Background(), req)
	if err == nil {
		t.Fatal("CreateDelegation() error = nil, want an error when signing fails")
	}
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil: no delegation id may escape without a token", resp)
	}
	wantCode(t, err, codes.Internal)
	if len(fs.created) != 1 {
		t.Errorf("delegation rows created = %d, want 1: the row is persisted before signing is attempted", len(fs.created))
	}
	if len(fs.appended) != 1 {
		t.Errorf("audit entries appended = %d, want 1: the grant is audited before signing is attempted", len(fs.appended))
	}
}

func TestCreateDelegation_ConcurrentAuditAppend_Aborted(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	fs.appendErr = fmt.Errorf("wrapped: %w", store.ErrConcurrentAppend)
	srv := newDelegationServer(fs, permissiveGrantSet())

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Aborted)
}

// Invalid input must be rejected before any store call, mirroring
// TestDecide_InvalidInput_InvalidArgument's discipline for the same reason:
// calls == 0 proves "do not proceed," not just that the code happened to
// come back InvalidArgument.
func TestCreateDelegation_InvalidInput_InvalidArgument(t *testing.T) {
	outOfRangeTier := int32(99)
	cases := map[string]func(*CreateDelegationRequest){
		"empty subject":      func(r *CreateDelegationRequest) { r.Subject = "" },
		"malformed agent_id": func(r *CreateDelegationRequest) { r.AgentId = "not-a-uuid" },
		"zero agent_id":      func(r *CreateDelegationRequest) { r.AgentId = uuid.Nil.String() },
		"malformed parent_delegation_id": func(r *CreateDelegationRequest) {
			r.ParentDelegationId = "not-a-uuid"
		},
		"zero parent_delegation_id": func(r *CreateDelegationRequest) {
			r.ParentDelegationId = uuid.Nil.String()
		},
		"max_action_tier out of range": func(r *CreateDelegationRequest) {
			r.RequestedScope.MaxActionTier = outOfRangeTier
		},
		"empty tools":          func(r *CreateDelegationRequest) { r.RequestedScope.Tools = nil },
		"zero ttl_seconds":     func(r *CreateDelegationRequest) { r.TtlSeconds = 0 },
		"negative ttl_seconds": func(r *CreateDelegationRequest) { r.TtlSeconds = -1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fs, req, _ := wellFormedDelegationFixture()
			mutate(req)
			srv := newDelegationServer(fs, permissiveGrantSet())

			resp, err := srv.CreateDelegation(context.Background(), req)
			if resp != nil {
				t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
			}
			wantCode(t, err, codes.InvalidArgument)
			if fs.calls != 0 {
				t.Errorf("store was called %d times, want 0 — invalid input must not proceed to a lookup", fs.calls)
			}
		})
	}
}

// A child inherits its parent's classification caps, resource constraints,
// and chain agent ids unchanged, and its audit entry carries the parent's
// root and depth+1 — the bookkeeping CreateDelegation must get right even
// though none of it comes from the request (RequestedScope only carries
// tier and tools).
func TestCreateDelegation_ChildInheritsParentClassificationAndChainAgentIDs(t *testing.T) {
	fs, req, agentID := wellFormedDelegationFixture()
	parentID, parentAgentID, rootID := uuid.New(), uuid.New(), uuid.New()
	req.ParentDelegationId = parentID.String()
	fs.chain = []*models.Delegation{{
		ID: parentID, RootDelegationID: rootID, Depth: 2,
		AgentID:             parentAgentID,
		MaxActionTier:       models.ActionTierDestructive,
		ApprovedTools:       []string{"Bash", "Read"},
		ClassificationCaps:  map[string]string{"nato": "CONFIDENTIAL"},
		ResourceConstraints: map[string]string{"project": "alpha"},
		ChainAgentIDs:       []uuid.UUID{parentAgentID},
	}}
	srv := newDelegationServer(fs, permissiveGrantSet())

	if _, err := srv.CreateDelegation(context.Background(), req); err != nil {
		t.Fatalf("CreateDelegation() error = %v, want a response", err)
	}

	if len(fs.created) != 1 {
		t.Fatalf("delegation rows created = %d, want 1", len(fs.created))
	}
	row := fs.created[0]
	if !maps.Equal(row.ClassificationCaps, map[string]string{"nato": "CONFIDENTIAL"}) {
		t.Errorf("ClassificationCaps = %v, want inherited from parent unchanged", row.ClassificationCaps)
	}
	if !maps.Equal(row.ResourceConstraints, map[string]string{"project": "alpha"}) {
		t.Errorf("ResourceConstraints = %v, want inherited from parent unchanged", row.ResourceConstraints)
	}
	if !slices.Equal(row.ChainAgentIDs, []uuid.UUID{parentAgentID, agentID}) {
		t.Errorf("ChainAgentIDs = %v, want [%s %s]", row.ChainAgentIDs, parentAgentID, agentID)
	}

	if len(fs.appended) != 1 {
		t.Fatalf("audit entries appended = %d, want 1", len(fs.appended))
	}
	entry := fs.appended[0]
	if entry.RootDelegationID == nil || *entry.RootDelegationID != rootID {
		t.Errorf("audit RootDelegationID = %v, want %s (the parent's root)", entry.RootDelegationID, rootID)
	}
	if entry.ChainDepth != 3 {
		t.Errorf("audit ChainDepth = %d, want 3 (parent depth 2 + 1)", entry.ChainDepth)
	}
}

// The policy set is prepared exactly once per call, however many probes
// Clamp makes against it (here: a four-step tier walk plus two tool
// probes) — the reason CreateDelegation calls policy.Multi.PrepareAll once
// up front rather than letting the allows closure recompile per probe. A
// regression back to per-probe preparation would reintroduce, at RPC-call
// granularity, exactly the recompile-per-request cost spec defect D5 named
// (see policy.Multi.PrepareAll's own doc comment).
func TestCreateDelegation_PreparesPolicySetOnceRegardlessOfProbeCount(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	req.RequestedScope = &RequestedScope{
		MaxActionTier: int32(models.ActionTierDestructive),
		Tools:         []string{"Bash", "Read"},
	}
	set := &grantSet{allowedTools: map[string]bool{"Bash": true, "Read": true}, maxTier: models.ActionTierDestructive}
	prepareCalls := 0
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{set: set, prepareCalls: &prepareCalls}), testConfig(), &fakeSigner{})

	if _, err := srv.CreateDelegation(context.Background(), req); err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}

	if prepareCalls != 1 {
		t.Errorf("policy set prepared %d times, want 1", prepareCalls)
	}
	if set.evaluateCalls < 2 {
		t.Errorf("policy.Probe evaluated the set %d times, want at least 2 (a tier probe and 2 tool probes)", set.evaluateCalls)
	}
}

// A policy-engine outage (Prepare failing outright, before any probe can
// even be attempted) is Internal, not folded into PermissionDenied — see
// policy.Multi.PrepareAll's own doc comment for why conflating "we could not
// ask" with "you may not hold this" would misreport an outage as a normal
// authorization outcome to anything watching gRPC status codes.
func TestCreateDelegation_PolicySetPrepareFailure_Internal(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	srv := NewServer(fs, singleFakeLanguagePolicy(fakePolicyEngine{prepareErr: errors.New("cedar: boom")}), testConfig(), &fakeSigner{})

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Internal)
	if len(fs.created) != 0 {
		t.Errorf("delegation rows created = %d, want 0", len(fs.created))
	}
}

// TestCreateDelegationRPC_CarriesNoClassificationCapField and
// TestCreateDelegation_RootIsCreatedWithNoClassificationCap are the other two
// guards for docs/pep.md's section "Nothing in the admin plane can change a
// cap" (the third is TestRouteTable_ExposesNoWriteSurfaceForAClassificationCap,
// cmd/stratium-pap/server_test.go — it cannot live here, because routeTable is
// unexported in a main package).
//
// Between them they pin the three NEGATIVE facts that section asserts and
// that nothing checked: no route writes a cap, the RPC carries no field for
// one, and a root comes back with none. Only the fourth — a child inherits
// its parent's map unchanged — already had a test
// (TestCreateDelegation_ChildInheritsParentClassificationAndChainAgentIDs,
// above).
//
// The claim that makes these load-bearing rather than tidy is the warning
// built on top of them: revoking a capped delegation returns a session with
// NO cap, so revocation removes classification enforcement instead of
// adjusting it. That is true only while every one of these holds.

// TestCreateDelegationRPC_CarriesNoClassificationCapField pins that the
// issuance RPC gives a caller no way to name a cap.
//
// An exact field-set comparison, not a search for cap-shaped names. A field
// that set a cap could be called anything — SecurityLevel, Clearance,
// Labels — and a keyword guard would pass while the documented claim became
// false. Any new field on either message fails this and sends the author to
// re-read the claim, which is the intended cost: these two messages are
// small, stable, and the whole of what a caller may ask for.
func TestCreateDelegationRPC_CarriesNoClassificationCapField(t *testing.T) {
	for _, tc := range []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeOf(CreateDelegationRequest{}),
			[]string{"Subject", "AgentId", "RequestedScope", "ParentDelegationId", "Purpose", "TtlSeconds"}},
		{reflect.TypeOf(RequestedScope{}),
			[]string{"MaxActionTier", "Tools"}},
	} {
		t.Run(tc.typ.Name(), func(t *testing.T) {
			var got []string
			for i := range tc.typ.NumField() {
				// Exported only: protoc's own state/sizeCache/unknownFields
				// are not part of the caller's surface and would make this
				// guard fail on a protoc upgrade for no reason.
				if f := tc.typ.Field(i); f.IsExported() {
					got = append(got, f.Name)
				}
			}

			// A floor, the same one TestResourceLabelRule_RuleCopiesEvery
			// MatcherField needed added after the fact: reflection returning
			// nothing must not read as "nothing cap-shaped found".
			if len(got) < 2 {
				t.Fatalf("%s has %d exported fields, want at least 2 — either the message was gutted or "+
					"this guard is about to verify nothing", tc.typ.Name(), len(got))
			}

			if !slices.Equal(got, tc.want) {
				t.Errorf("%s exported fields = %v, want %v.\n"+
					"docs/pep.md's section \"Nothing in the admin plane can change a cap\" tells operators "+
					"this RPC carries no field for a classification cap, and warns that revoking a "+
					"delegation therefore returns a session with NO cap rather than a different one. If a "+
					"field here can now carry one, that warning is false and it is the sentence that will "+
					"talk an operator out of the correct remedy. Update docs/pep.md in this commit, then "+
					"update this list.", tc.typ.Name(), got, tc.want)
			}
		})
	}
}

// TestCreateDelegation_RootIsCreatedWithNoClassificationCap is the fact the
// re-issue warning rests on most directly: session-start issues a ROOT, and a
// root is written with an empty cap map — which CheckCap treats as "no cap
// configured" and allows unconditionally, not as a cap of zero.
//
// The parent-id assertion is not decoration. It makes "this is a root" true
// by check rather than by assumption about a shared fixture; if the fixture
// ever gains a parent, this test would otherwise silently start proving the
// inheritance path that already has its own test, and the root claim would go
// unguarded while still reporting success.
func TestCreateDelegation_RootIsCreatedWithNoClassificationCap(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	if req.GetParentDelegationId() != "" {
		t.Fatalf("fixture parent_delegation_id = %q, want empty — this guard is about the ROOT path, and "+
			"a fixture with a parent would prove the inheritance path instead",
			req.GetParentDelegationId())
	}
	srv := newDelegationServer(fs, permissiveGrantSet())

	if _, err := srv.CreateDelegation(context.Background(), req); err != nil {
		t.Fatalf("CreateDelegation() error = %v, want a response", err)
	}
	if len(fs.created) != 1 {
		t.Fatalf("delegation rows created = %d, want 1", len(fs.created))
	}

	if caps := fs.created[0].ClassificationCaps; len(caps) != 0 {
		t.Errorf("root delegation ClassificationCaps = %v, want empty.\n"+
			"docs/pep.md's section \"Nothing in the admin plane can change a cap\" tells operators that "+
			"revoking and re-issuing returns a session with classification enforcement OFF on every "+
			"hierarchy, because session-start issues a root and a root is created with no cap. If a root "+
			"now carries one, that warning is wrong in the dangerous direction — it talks an operator out "+
			"of a remedy that would in fact work. Update docs/pep.md in this commit.", caps)
	}
}
