// Package pdpgrpc is the gRPC transport for the PDP: it adapts wire requests
// into the pure decision in internal/authz and wire responses back out.
//
// Server trusts the request for exactly what proto/pdp/v1/pdp.proto's
// DecideRequest carries and nothing more. In particular the tenant comes
// from cfg (startup configuration) and the principal decision comes from
// evaluating policy here — neither is ever read off the request. See the
// proto's doc comment for why: the predecessor's client-supplied tenant
// header was a critical authentication bypass, and a caller-supplied
// principal verdict would be the same defect aimed at authorization.
package pdpgrpc

import (
	"context"
	"crypto/sha256"
	"errors"
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

// Store is what Decide needs from the tenant-scoped repository. *store.Store
// satisfies it; tests substitute a fake. Defined here, where it is consumed,
// rather than in package store, which has no reason to know about its gRPC
// caller.
type Store interface {
	LoadAgent(ctx context.Context, id uuid.UUID) (authz.AgentInfo, error)
	LoadChain(ctx context.Context, actingDelegationID uuid.UUID) ([]*models.Delegation, error)
	AppendAudit(ctx context.Context, e audit.Entry) error
}

// eventTypeDecision is the audit_chain event_type recorded for every Decide
// call. Not a documented convention anywhere else in the schema, but it is
// the value pkg/audit, internal/store's, and internal/authz's own tests all
// already use for a decision entry — matched here rather than invented anew.
const eventTypeDecision = "decision"

// auditDeclaredTierAbsent is stored in an audit entry's DeclaredTier when the
// request did not declare one. audit_chain.declared_tier is a plain SMALLINT
// with no CHECK constraint pinning it to the valid ActionTier range (0-4:
// see migrations/000003_audit_chain.up.sql), so -1 can never collide with a
// real declared tier — unlike 0, which is REASONING, a real, declarable
// value. Same absent-vs-zero reasoning as DecideRequest.declared_tier.
const auditDeclaredTierAbsent int16 = -1

// errZeroUUID rejects the zero UUID even when it parses cleanly:
// "00000000-0000-0000-0000-000000000000" is a well-formed string but never a
// legitimate agent or delegation identifier, and proceeding with one would
// mean querying the store for a record that cannot exist.
var errZeroUUID = errors.New("must not be the zero UUID")

// Server implements PDPServiceServer.
type Server struct {
	UnimplementedPDPServiceServer

	store  Store
	policy policy.PrincipalPolicy
	cfg    config.Config
}

// NewServer wires a Server. cfg supplies the tenant and the maximum
// delegation depth; both are startup configuration, never per-request.
func NewServer(store Store, policy policy.PrincipalPolicy, cfg config.Config) *Server {
	return &Server{store: store, policy: policy, cfg: cfg}
}

// Decide turns req into a decision.
//
// Order: parse and validate the request -> load the acting agent -> load the
// delegation chain -> evaluate (tenant from cfg, principal decision from
// policy, clock from time.Now — the one boundary where the ambient clock is
// allowed, so internal/authz itself stays pure) -> append the audit entry ->
// respond. A failed audit append returns an error and no response: spec D3
// says a failed audit write denies the action, and the only way that holds
// for an ALLOW is for this method to never hand one back once the append has
// failed.
func (s *Server) Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error) {
	delegationID, err := parseNonNilUUID(req.GetDelegationId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "delegation_id: %s", err)
	}
	agentID, err := parseNonNilUUID(req.GetAgentId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "agent_id: %s", err)
	}
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	var declaredTier *models.ActionTier
	if req.DeclaredTier != nil {
		tier, err := models.ParseActionTier(int(*req.DeclaredTier))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "declared_tier: %s", err)
		}
		declaredTier = &tier
	}

	agent, err := s.store.LoadAgent(ctx, agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "agent %s: %s", agentID, err)
		}
		return nil, status.Errorf(codes.Internal, "load agent: %s", err)
	}

	chain, err := s.store.LoadChain(ctx, delegationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "delegation %s: %s", delegationID, err)
		}
		return nil, status.Errorf(codes.Internal, "load chain: %s", err)
	}

	now := time.Now()
	principal := authz.Principal{Subject: req.GetSubject()}
	resource := req.GetResource()
	action := authz.Action{
		Tool:         req.GetTool(),
		Verb:         req.GetVerb(),
		RawInput:     req.GetRawInput(),
		DeclaredTier: declaredTier,
	}
	tiers := authz.TierTable{} // tenant tier overrides load from the DB starting Phase 2; none exist yet.

	// Derived ahead of authz.Decide so the policy engine can see it (spec Y3):
	// DeriveTier is pure, and Decide (below) derives it again, independently,
	// from these same inputs — that second derivation stays authoritative for
	// the actual decision, so this one cannot itself widen anything.
	//
	// On error, this does NOT return codes.Internal directly: Decide's own
	// re-derivation (same tiers, same action) would hit this identical error
	// and deny-and-audit via authz.DeriveTierDenial — bailing out here first,
	// before principal verdicts are even evaluated, would bypass the audit
	// trail on exactly the same error Decide always audits. Building that
	// same Result here, through the same shared function, keeps both call
	// sites deny-and-audit rather than two paths that could report the
	// identical failure differently.
	derivedTier, err := authz.DeriveTier(tiers, action)
	if err != nil {
		result := authz.DeriveTierDenial(err)
		if auditErr := s.appendAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), result, now); auditErr != nil {
			return nil, auditErr
		}
		return toResponse(result), nil
	}

	// acting is the delegation the agent is presenting — the last hop.
	// LoadChain guarantees chain is non-empty on a nil error (see
	// appendAudit below, which makes the same assumption).
	acting := chain[len(chain)-1]

	// The policy provider returns every verdict it consulted for the
	// principal leg; authz.Decide folds them with deny-overrides via
	// authz.FoldVerdicts. It now sees the agent and delegation dimensions
	// too, so a tenant can condition on them, but it still only decides the
	// principal leg — the agent and delegation legs below are independent
	// AND terms, so nothing returned here can widen what they allow.
	principalVerdicts := s.policy.Evaluate(ctx, policy.EvaluationInput{
		Principal:   principal,
		Action:      action,
		DerivedTier: derivedTier,
		Resource:    resource,
		// Environment: no wire source yet — DecideRequest carries none.
		Agent: agent,
		Delegation: policy.DelegationContext{
			Depth:              acting.Depth,
			MaxActionTier:      acting.MaxActionTier,
			ClassificationCaps: acting.ClassificationCaps,
			Purpose:            acting.Purpose,
		},
	})
	result := authz.Decide(authz.Request{
		TenantID:          s.cfg.TenantID, // config only. Never req — see package doc.
		Principal:         principal,
		Agent:             agent,
		Chain:             chain,
		Action:            action,
		Resource:          resource,
		Now:               now,
		PrincipalVerdicts: principalVerdicts,
	}, authz.Config{
		Tiers:    tiers,
		Trust:    authz.DefaultTrustTable(),
		MaxDepth: s.cfg.MaxDepth,
	})

	if err := s.appendAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), result, now); err != nil {
		return nil, err
	}

	return toResponse(result), nil
}

// appendAudit builds the audit entry for one decision and appends it.
// chain must be non-empty (LoadChain guarantees this on a nil error).
//
// PolicySource/PolicyID are populated from result.Deciding, guarded against
// nil exactly as toResponse guards it: left at their zero value ("") for the
// default-deny-with-no-verdict case, which audit.Entry's own doc comment
// already documents as the meaning of "empty" there.
func (s *Server) appendAudit(
	ctx context.Context,
	agentID, delegationID uuid.UUID,
	chain []*models.Delegation,
	action authz.Action,
	actor string,
	result authz.Result,
	now time.Time,
) error {
	acting := chain[len(chain)-1]
	root := chain[0]

	declaredTier := auditDeclaredTierAbsent
	if action.DeclaredTier != nil {
		declaredTier = int16(*action.DeclaredTier) //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier before it ever reaches here
	}

	// Raw tool input is never stored, only its digest — see pkg/audit's
	// package doc.
	digest := sha256.Sum256([]byte(action.RawInput))

	entry := audit.Entry{
		TenantID:         s.cfg.TenantID,
		OccurredAt:       now,
		EventType:        eventTypeDecision,
		Actor:            actor,
		AgentID:          &agentID,
		DelegationID:     &delegationID,
		RootDelegationID: &root.ID,
		ChainDepth:       int16(acting.Depth), //nolint:gosec // G115: store.maxChainWalk bounds any chain walk to 64 hops, far under int16's range
		ToolName:         action.Tool,
		Action:           action.Verb,
		DeclaredTier:     declaredTier,
		DerivedTier:      int16(result.DerivedTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		Decision:         result.Effect.String(),
		DeniedLeg:        result.DeniedLeg,
		DeniedAtDepth:    int16(result.DeniedAtDepth), //nolint:gosec // G115: -1 sentinel or a chain depth bounded well under int16's range (see ChainDepth above)
		Reason:           result.Reason,
		InputDigest:      digest,
	}
	if d := result.Deciding; d != nil {
		entry.PolicySource = d.Source
		entry.PolicyID = d.PolicyID
	}

	if err := s.store.AppendAudit(ctx, entry); err != nil {
		if errors.Is(err, store.ErrConcurrentAppend) {
			return status.Errorf(codes.Aborted, "audit append: %s", err)
		}
		return status.Errorf(codes.Internal, "audit append: %s", err)
	}
	return nil
}

// parseNonNilUUID parses s as a UUID and rejects the zero value.
func parseNonNilUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, err
	}
	if id == uuid.Nil {
		return uuid.Nil, errZeroUUID
	}
	return id, nil
}

// toResponse converts a decision into the wire response. Every field is
// populated explicitly, including the three per-leg pairs — leaving any of
// them at its zero value would silently read back as EFFECT_DENY with no
// reason, indistinguishable from a leg that was actually evaluated and
// denied for no stated reason.
//
// DecidedSource/DecidedPolicyId are the exception: they are left unset
// (nil), not zeroed, when result.Deciding is nil. That case is real — a
// default-deny with no verdict at all, from a nil/empty PrincipalVerdicts —
// and collapsing it into empty strings would make it indistinguishable from
// a verdict that did decide the outcome and whose Source/PolicyID happen to
// be empty. Both fields are proto3 optional for exactly that reason, the
// same presence-vs-zero-value pattern DecideRequest.declared_tier uses.
func toResponse(result authz.Result) *DecideResponse {
	resp := &DecideResponse{
		Effect:           toProtoEffect(result.Effect),
		DerivedTier:      int32(result.DerivedTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		PrincipalEffect:  toProtoEffect(result.Principal.Effect),
		PrincipalReason:  result.Principal.Reason,
		AgentEffect:      toProtoEffect(result.Agent.Effect),
		AgentReason:      result.Agent.Reason,
		DelegationEffect: toProtoEffect(result.Delegation.Effect),
		DelegationReason: result.Delegation.Reason,
		DeniedLeg:        result.DeniedLeg,
		DeniedAtDepth:    int32(result.DeniedAtDepth), //nolint:gosec // G115: -1 sentinel or a chain depth bounded well under int32's range
		Reason:           result.Reason,
	}

	if d := result.Deciding; d != nil {
		source, policyID := d.Source, d.PolicyID
		resp.DecidedSource = &source
		resp.DecidedPolicyId = &policyID
	}

	return resp
}

// toProtoEffect maps authz.Effect onto the wire enum explicitly rather than
// by numeric cast: the two are independently defined types that happen to
// share an ordering today, and a cast would keep compiling silently if that
// ever stopped being true.
func toProtoEffect(e authz.Effect) Effect {
	switch e {
	case authz.EffectAllow:
		return Effect_EFFECT_ALLOW
	case authz.EffectEscalate:
		return Effect_EFFECT_ESCALATE
	default:
		return Effect_EFFECT_DENY
	}
}
