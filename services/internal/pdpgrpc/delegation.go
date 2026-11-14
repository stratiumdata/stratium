package pdpgrpc

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
)

// eventTypeDelegationCreated is the audit_chain event_type recorded for
// every delegation CreateDelegation persists. Distinct from eventTypeDecision
// (server.go): a Decide call is audited whatever its outcome, allow or deny,
// but CreateDelegation only reaches its audit step once every rejection has
// already passed (see CreateDelegation's own doc comment) — so every entry
// carrying this event type is, by construction, a successful grant.
const eventTypeDelegationCreated = "delegation_created"

// noDenial is the DeniedAtDepth sentinel for an audit entry that recorded no
// denial — every CreateDelegation audit entry, since audit only runs on the
// success path. Same -1 sentinel authz.Result and Decide's own audit entries
// already use for the same fact (see server.go's appendAudit and
// audit_chain.denied_at_depth's comment in migrations/000003).
const noDenial int16 = -1

// CreateDelegation mints a new delegation: a root grant from a principal, or
// (with parent_delegation_id set) a child narrowing an existing one.
//
// Order: validate the request, including the two rejections below -> read
// the tenant's revocation epoch (loadEpochOrDeny; server.go's own doc
// comment covers why every RPC in this package reads it first, ahead of
// every other store call) -> load the target agent -> load the parent chain
// if any -> probe the principal's own policy grants and clamp the request
// to them (internal/authz.Clamp) -> reject if every requested tool was
// clamped away -> build the delegation -> persist (permset.ScopeNarrows runs
// inside store.CreateDelegation for a child) -> audit -> respond. A failed
// audit write fails the call and no delegation id is ever returned — spec
// D3's sibling rule for creation, the same discipline Decide applies to an
// unrecorded ALLOW (see server.go's Decide doc comment): the row may exist,
// but nothing that reaches a caller says so, which is what "a delegation
// created without a record did not happen" means here.
//
// Two rejections are the reason this method exists rather than a thin
// pass-through to Clamp. Everywhere else in this system an empty tool list
// means UNRESTRICTED (models.Agent.HasTool, models.Delegation.HasTool,
// deliberately) — which collides with Clamp, which can produce an empty
// list in two different directions:
//
//   - An empty requested tool list (InvalidArgument): requesting no tools
//     would mean requesting unrestricted access, exactly what this gate
//     exists to prevent, and it is structurally unprobeable — there is no
//     policy question "may this principal hold every tool that exists."
//   - A request whose tools are all removed by the clamp (PermissionDenied),
//     not granted with an empty list: "you asked for three tools and hold
//     none of them" is a refusal, not a grant of nothing. Returning an empty
//     Tools would produce a delegation meaning the opposite of what the
//     clamp just decided, and a caller copying it into an
//     ApprovedTools-shaped field without also reading Removed would silently
//     grant everything.
//
// This is the same empty-means-unrestricted asymmetry that produced the
// ScopeNarrows omission hole in Phase 0+1 (a child shedding its parent's
// classification ceiling by omitting a map entry rather than widening it).
// Handling it here, at the RPC boundary, keeps the convention intact
// everywhere else rather than special-casing the model types themselves.
func (s *Server) CreateDelegation(ctx context.Context, req *CreateDelegationRequest) (*CreateDelegationResponse, error) {
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	agentID, err := parseNonNilUUID(req.GetAgentId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "agent_id: %s", err)
	}
	var parentID *uuid.UUID
	if raw := req.GetParentDelegationId(); raw != "" {
		id, err := parseNonNilUUID(raw)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "parent_delegation_id: %s", err)
		}
		parentID = &id
	}
	tier, err := models.ParseActionTier(int(req.GetRequestedScope().GetMaxActionTier()))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "requested_scope.max_action_tier: %s", err)
	}
	tools := req.GetRequestedScope().GetTools()
	if len(tools) == 0 {
		return nil, status.Error(codes.InvalidArgument,
			"requested_scope.tools must not be empty: an empty list means unrestricted access "+
				"everywhere else in this system, which this gate cannot grant")
	}
	if req.GetTtlSeconds() <= 0 {
		return nil, status.Error(codes.InvalidArgument, "ttl_seconds must be positive")
	}

	epoch, err := s.loadEpochOrDeny(ctx)
	if err != nil {
		return nil, err
	}

	agent, err := s.store.LoadAgent(ctx, agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "agent %s: %s", agentID, err)
		}
		return nil, status.Errorf(codes.Internal, "load agent: %s", err)
	}

	// parent is the last hop of the parent chain — the delegation being
	// narrowed — or nil for a root. Loaded before probing/clamping so a
	// missing parent fails fast (NotFound) before paying for a policy-engine
	// walk, and so its ChainAgentIDs/ClassificationCaps/ResourceConstraints
	// and RootDelegationID/Depth are on hand once the clamp succeeds.
	var parent *models.Delegation
	if parentID != nil {
		chain, err := s.store.LoadChain(ctx, *parentID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return nil, status.Errorf(codes.NotFound, "parent delegation %s: %s", *parentID, err)
			}
			return nil, status.Errorf(codes.Internal, "load parent chain: %s", err)
		}
		parent = chain[len(chain)-1]
	}

	// s.policy.PrepareAll compiles this tenant's full, multi-language policy
	// set once, so Clamp's tier walk and per-tool probes (each a call to
	// policy.Probe) all evaluate against the same compiled set instead of
	// recompiling per probe — the same per-request recompilation spec defect
	// D5 already ruled out for Decide's own principal-policy path (see
	// policy.PolicyEngine's own doc comment: "Prepare is that compile-once
	// step"). Any non-nil err here is treated as blocking, even though
	// policy.Multi.PrepareAll can also return a non-nil err alongside a
	// still-usable set (a partial per-language prepare failure — see its own
	// doc comment): folding that into PermissionDenied instead would
	// misreport "we could not fully ask" as "you may not hold this" to
	// anything watching gRPC status codes, so it stays Internal here exactly
	// as a total load failure does.
	set, err := s.policy.PrepareAll(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "prepare policy set: %s", err)
	}
	principal := authz.Principal{Subject: req.GetSubject()}
	granted, err := authz.Clamp(ctx, authz.RequestedScope{MaxActionTier: tier, Tools: tools},
		func(tool string, t models.ActionTier) (bool, error) {
			return policy.Probe(ctx, set, policy.GrantProbe{Principal: principal, Tool: tool, Tier: t})
		})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "clamp: %s", err)
	}

	// Rejection 2 (see doc comment above): every requested tool was clamped
	// away. len(tools) > 0 is already guaranteed by the validation above, so
	// an empty granted.Tools here can only mean "nothing survived," never
	// "nothing was asked for."
	if len(granted.Tools) == 0 {
		return nil, status.Error(codes.PermissionDenied,
			"none of the requested tools are held by this principal")
	}

	now := time.Now()
	newID := uuid.New()
	d := &models.Delegation{
		ID:            newID,
		UserID:        req.GetSubject(),
		AgentID:       agentID,
		ApprovedTools: granted.Tools,
		MaxActionTier: granted.MaxActionTier,
		// Copied from the agent row, which is the only place an operator can
		// set a ceiling (PUT /v1/agents/{id}/classification-caps). A root has
		// no parent to clamp against, so this is where the ceiling enters the
		// chain; children below copy their parent and can only narrow.
		ClassificationCaps: copyStringMap(agent.ClassificationCaps),
		// Copied from the agent row, the only place an operator can set a
		// scope (PUT /v1/agents/{id}/resource-constraints). A root has no
		// parent to clamp against, so this is where the scope enters the
		// chain; children below copy their parent and can only narrow.
		// Exactly the path ClassificationCaps above takes.
		ResourceConstraints: copyStringMap(agent.ResourceConstraints),
		Purpose:             req.GetPurpose(),
		ExpiresAt:           now.Add(time.Duration(req.GetTtlSeconds()) * time.Second),
		ParentDelegationID:  parentID,
		ChainAgentIDs:       []uuid.UUID{agentID},
	}
	// rootID/depth are this delegation's own structural position, used only
	// for the audit entry below — store.CreateDelegation computes and writes
	// its own copy from the freshly (re)loaded parent inside its transaction
	// and never reads d.RootDelegationID/d.Depth, so those are deliberately
	// left unset here (see store/delegation.go's doc comment).
	rootID, depth := newID, 0
	if parent != nil {
		// Classification/resource constraints are inherited unchanged, never
		// renegotiated here: G6 clamps the tier ceiling and tool set only —
		// resource and classification stay with the runtime principal leg
		// (see internal/authz.Clamp's doc comment). An identical child value
		// always narrows (permset.ScopeNarrows treats equal as valid), so
		// copying the parent's maps unchanged is always accepted, never a
		// widening.
		d.ClassificationCaps = copyStringMap(parent.ClassificationCaps)
		d.ResourceConstraints = copyStringMap(parent.ResourceConstraints)
		d.ChainAgentIDs = append(append([]uuid.UUID{}, parent.ChainAgentIDs...), agentID)
		rootID, depth = parent.RootDelegationID, parent.Depth+1
	}

	if err := s.store.CreateDelegation(ctx, d); err != nil {
		switch {
		case errors.Is(err, store.ErrScopeWidens):
			return nil, status.Errorf(codes.PermissionDenied, "create delegation: %s", err)
		case errors.Is(err, store.ErrNotFound):
			return nil, status.Errorf(codes.NotFound, "create delegation: %s", err)
		default:
			return nil, status.Errorf(codes.Internal, "create delegation: %s", err)
		}
	}

	if err := s.appendDelegationAudit(ctx, d, req.GetSubject(), tier, now, rootID, depth); err != nil {
		return nil, err
	}

	// A delegation with no way to use it is not useful — the caller already
	// has a round trip here, so the token comes back with the id rather than
	// requiring a second call. Minted last, after persist and audit both
	// succeeded: the delegation is a fact of record before this method ever
	// asks the signer for anything, matching D3's "a delegation created
	// without a record did not happen" — a signing failure here means the
	// row exists and is audited but this call still fails closed, the same
	// shape as a failed audit write above (no delegation id ever escapes
	// without what it is paired with). requestedExpiry == delegationExpiresAt
	// == d.ExpiresAt: a freshly created delegation's token has no
	// independently requested lifetime, so mintToken's clamp is structurally
	// a no-op here — see IssueToken (token.go) for the path where it is not.
	// jkt is empty: CreateDelegation mints a bearer token, unchanged by Phase
	// 15. Binding is asked for at IssueToken, where a caller that has just
	// generated a keypair presents the public half (spec §4.7.2 K6) — this
	// call has no JWK to bind to and CreateDelegationRequest deliberately
	// does not carry one, since the caller creating a delegation is not
	// necessarily the party that will later hold and use its token.
	tok, _, _, err := s.mintToken(d.ID, s.cfg.TenantID, "", now, d.ExpiresAt, d.ExpiresAt)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign token: %s", err)
	}

	return &CreateDelegationResponse{
		DelegationId: d.ID.String(),
		GrantedScope: toProtoGrantedScope(granted),
		Token:        tok,
		Epoch:        epoch,
	}, nil
}

// appendDelegationAudit records d's creation. Unlike appendAudit (server.go,
// Decide's audit entry, written whatever the decision's outcome), this only
// ever runs on CreateDelegation's success path: every rejection it can
// produce returns before this is called, so Decision is unconditionally
// "ALLOW" and DeniedLeg/DeniedAtDepth unconditionally carry no denial.
//
// DeclaredTier/DerivedTier are repurposed from their Decide meaning (claimed
// vs. server-derived tier of one action) to the closest fit available on the
// shared audit.Entry shape: DeclaredTier is the tier that was requested,
// DerivedTier is the tier actually granted after clamping — the same
// claim-vs-reality shape, one step removed.
//
// PolicySource/PolicyID are left empty: no single verdict decided this
// compound outcome the way one PolicyVerdict decides Decide's principal leg
// — Clamp folds one probe per tier step and per requested tool, each
// independently. Attributing the result to any one of them would misattribute
// it to a policy that, alone, did not decide it. Empty carries the same "no
// single verdict decided this" meaning Decide's own audit entries already
// give that pair (server.go's appendAudit doc comment; DecideResponse's
// decided_source/decided_policy_id).
func (s *Server) appendDelegationAudit(
	ctx context.Context,
	d *models.Delegation,
	actor string,
	requestedTier models.ActionTier,
	now time.Time,
	rootID uuid.UUID,
	depth int,
) error {
	entry := audit.Entry{
		TenantID:         s.cfg.TenantID,
		OccurredAt:       now,
		EventType:        eventTypeDelegationCreated,
		Actor:            actor,
		AgentID:          &d.AgentID,
		DelegationID:     &d.ID,
		RootDelegationID: &rootID,
		ChainDepth:       int16(depth),           //nolint:gosec // G115: 0 for a root or parent.Depth+1, the same bound store.maxChainWalk already places on any chain walk
		DeclaredTier:     int16(requestedTier),   //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		DerivedTier:      int16(d.MaxActionTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		Decision:         "ALLOW",
		DeniedAtDepth:    noDenial,
		Reason:           d.Purpose,
	}

	if err := s.store.AppendAudit(ctx, entry); err != nil {
		if errors.Is(err, store.ErrConcurrentAppend) {
			return status.Errorf(codes.Aborted, "audit append: %s", err)
		}
		return status.Errorf(codes.Internal, "audit append: %s", err)
	}
	return nil
}

// copyStringMap returns a new map with the same entries as m (nil-safe: a
// nil m returns a non-nil empty map). A child delegation's
// ClassificationCaps/ResourceConstraints are inherited from its parent, and
// coding-style immutability means the child gets its own map rather than
// aliasing the parent's — see CreateDelegation's construction of d above.
func copyStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// toProtoGrantedScope converts a clamp result to the wire shape. Reason
// uses authz.ClampReason's own String() rather than a second switch on the
// same two cases, matching ScopeRemoval.reason's doc comment ("denied" or
// "probe error").
func toProtoGrantedScope(g authz.GrantedScope) *GrantedScope {
	removed := make([]*ScopeRemoval, 0, len(g.Removed))
	for _, r := range g.Removed {
		removed = append(removed, &ScopeRemoval{
			Dimension: r.Dimension,
			Value:     r.Value,
			Reason:    r.Reason.String(),
			Detail:    r.Detail,
		})
	}
	return &GrantedScope{
		MaxActionTier: int32(g.MaxActionTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		Tools:         g.Tools,
		Removed:       removed,
	}
}
