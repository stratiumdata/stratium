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
	"fmt"
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

	// CreateDelegation persists a new delegation, used by CreateDelegation
	// (delegation.go). *store.Store's own doc comment covers ScopeNarrows
	// enforcement and why root_delegation_id/depth are computed server-side
	// rather than trusted from the caller's struct.
	CreateDelegation(ctx context.Context, d *models.Delegation) error

	// CreateApproval and LoadApproval back escalation.go's resolveEscalation
	// — the only two operations the PDP ever performs against approvals
	// (E7: it creates pending records and reads them, never grants one).
	// models.Approval, not a pdpgrpc-local type: see that type's own doc
	// comment for why Task 3 moved it out of package store once this
	// interface needed to name it.
	CreateApproval(ctx context.Context, a *models.Approval) error
	LoadApproval(ctx context.Context, id uuid.UUID) (*models.Approval, error)

	// LoadToolCatalog loads the tenant's per-tool tool_catalog rows (spec
	// §4.4.2 T1/T2), consulted both for the catalog step of DeriveTier's
	// resolution order and for the resource/command extraction Decide
	// performs before deriving a tier. Called fresh on every Decide, the
	// same no-caching-layer choice LoadAgent and LoadChain already make for
	// their own per-tenant data — kept consistent rather than special-cased
	// for this one lookup.
	LoadToolCatalog(ctx context.Context) ([]models.ToolCatalogEntry, error)
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

	store Store

	// policy decides the principal leg for Decide (one action, one
	// evaluation, via Evaluate) and also backs CreateDelegation's grant
	// probes (delegation.go), which need a policy.CompiledPolicySet to
	// probe several times over for one grant request rather than a single
	// per-action verdict — policy.Multi's PrepareAll is what supplies that,
	// so both RPCs are served from this one field. Earlier this was a
	// policy.PrincipalPolicy plus a raw PolicySource/PolicyEngine pair
	// CreateDelegation prepared itself, because policy.Configured (the
	// single-engine predecessor) had no way to hand back a compiled set
	// through the PrincipalPolicy interface it returned. policy.Multi
	// exposes PrepareAll directly, so that pair — and the single-language
	// assumption it carried — is gone rather than fixed twice.
	policy policy.Multi

	cfg config.Config
}

// NewServer wires a Server. cfg supplies the tenant and the maximum
// delegation depth; both are startup configuration, never per-request.
func NewServer(store Store, principalPolicy policy.Multi, cfg config.Config) *Server {
	return &Server{
		store:  store,
		policy: principalPolicy,
		cfg:    cfg,
	}
}

// Decide turns req into a decision.
//
// Order: parse and validate the request -> load the acting agent -> load the
// delegation chain -> evaluate (tenant from cfg, principal decision from
// policy, clock from time.Now — the one boundary where the ambient clock is
// allowed, so internal/authz itself stays pure) -> resolve an escalation, if
// any (escalation.go: create a pending approval, or verify one offered on a
// retry — the one place approval verification happens, since it needs the
// store and internal/authz must not) -> append the audit entry -> respond. A
// failed audit append returns an error and no response: spec D3 says a
// failed audit write denies the action, and the only way that holds for an
// ALLOW is for this method to never hand one back once the append has
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
	// approvalID is present only on a retry after a prior call returned
	// EFFECT_ESCALATE (DecideRequest.approval_id's own doc comment).
	// Malformed shape is rejected here, alongside every other caller-
	// supplied UUID, because it is a request-shape defect (InvalidArgument,
	// no store call, no decision) — not a verification failure, which fails
	// closed to a named, audited DENY instead (resolveEscalation, below).
	var approvalID *uuid.UUID
	if req.ApprovalId != nil {
		id, err := parseNonNilUUID(req.GetApprovalId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "approval_id: %s", err)
		}
		approvalID = &id
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
	// Verb and NormalizedInput start unset, deliberately: DecideRequest no
	// longer carries either (spec §4.4.2 T3 retired both from the wire
	// alongside the PEP's per-tool tables that used to compute them). Both
	// are populated below, per tool, only when the tenant's own catalog
	// names this one — authz.ApplyExtraction — never from a caller's claim.
	action := authz.Action{
		Tool:         req.GetTool(),
		RawInput:     req.GetRawInput(),
		DeclaredTier: declaredTier,
	}
	resource := req.GetResource()

	// The tenant's own tool_catalog rows (spec §4.4.2 T1/T2), loaded fresh
	// for this decision. A load failure fails closed rather than proceeding
	// as though the tenant had none: a row that exists but could not be read
	// might be the one row that would have raised this tool's tier, and
	// silently falling back to DefaultCatalog() in that case would be
	// exactly the "skipped row" the phase brief rules out. Routed through
	// denyAndAudit — the same deny-and-audit shape a DeriveTier failure uses
	// below — rather than a bare codes.Internal, so this failure is audited
	// identically to any other pre-decision denial instead of only ever
	// surfacing as an RPC error with no row in the audit chain.
	catalogEntries, err := s.store.LoadToolCatalog(ctx)
	if err != nil {
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now,
			fmt.Errorf("load tool catalog: %w", err))
	}

	// Extraction happens before tiers is even built, and touches only
	// action.Verb, action.NormalizedInput, and resource — never
	// action.RawInput (see authz.ApplyExtraction's own doc comment).
	// DeriveTier below re-scans RawInput for destructive-or-external
	// evidence unconditionally (tier.go's destructiveEvidence), so the order
	// extraction runs in relative to that scan cannot matter: nothing on
	// this path can narrow what the evidence check sees.
	extracted := authz.ExtractFromCatalog(catalogEntries, action)
	action, resource = authz.ApplyExtraction(extracted, action, resource)

	// The catalog step of §4.4's resolution order (override, catalog,
	// built-in): the tenant's own rows override DefaultCatalog() per tool,
	// and a tenant with none yet resolves through an unchanged
	// DefaultCatalog() — see BuildTierCatalog's own doc comment for why that
	// is the regression guard that makes shipping this table safe.
	tiers := authz.TierTable{Catalog: authz.BuildTierCatalog(catalogEntries, authz.DefaultCatalog())}

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
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now, err)
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
		Agent:       agent,
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

	// Escalation only ever reaches here through the compound decision every
	// other outcome does too — authz.Decide has already run all three legs
	// fresh, on this exact call, and its own deny-check loop runs before its
	// escalate-check loop (compound.go), so a leg that denies (a revoked
	// delegation, a policy that now forbids) has already won by the time
	// Effect could read EFFECT_ESCALATE. An approval is therefore never
	// consulted for a request the three legs would have denied anyway —
	// see resolveEscalation's own doc comment (escalation.go) for why that
	// holds by construction rather than by a check repeated here, and why
	// this is also what keeps a decision above max_action_tier from ever
	// creating an approval row: that case denies before it ever escalates.
	var newApprovalID string
	if result.Effect == authz.EffectEscalate {
		result, newApprovalID, err = s.resolveEscalation(
			ctx, approvalID, req.GetSubject(), agentID, delegationID, chain, action, result, now)
		if err != nil {
			return nil, err
		}
	}

	if err := s.appendAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), result, now); err != nil {
		return nil, err
	}

	// ApprovalId is not part of authz.Result — it is a wire-only fact
	// (which row, if any, this call just created), not a decision fact — so
	// it is attached here rather than threaded through toResponse. It is
	// only ever non-empty on the fresh-escalation branch above: a verified
	// retry converts result.Effect to ALLOW or DENY, never leaves it
	// ESCALATE, so newApprovalID stays "" on every other path, matching
	// approval_id's own doc comment in the proto (populated only when
	// effect is EFFECT_ESCALATE).
	resp := toResponse(result)
	resp.ApprovalId = newApprovalID
	return resp, nil
}

// appendAudit builds the audit entry for one decision and appends it.
// chain must be non-empty (LoadChain guarantees this on a nil error).
//
// PolicySource/PolicyID are populated from result.Deciding, guarded against
// nil exactly as toResponse guards it: left at their zero value ("") for the
// default-deny-with-no-verdict case, which audit.Entry's own doc comment
// already documents as the meaning of "empty" there.
//
// UnevaluatedPolicyIDs is copied unconditionally, not guarded by
// result.Deciding: it is authz.Decide's own aggregate across every verdict
// it saw (internal/authz/compound.go), independent of which single verdict
// Deciding names — that independence is the entire point (see
// authz.Result.UnevaluatedPolicyIDs' own doc comment), so gating it on
// Deciding here would reintroduce exactly the loses-the-fold defect the
// aggregate exists to avoid.
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
		TenantID:             s.cfg.TenantID,
		OccurredAt:           now,
		EventType:            eventTypeDecision,
		Actor:                actor,
		AgentID:              &agentID,
		DelegationID:         &delegationID,
		RootDelegationID:     &root.ID,
		ChainDepth:           int16(acting.Depth), //nolint:gosec // G115: store.maxChainWalk bounds any chain walk to 64 hops, far under int16's range
		ToolName:             action.Tool,
		Action:               action.Verb,
		DeclaredTier:         declaredTier,
		DerivedTier:          int16(result.DerivedTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		Decision:             result.Effect.String(),
		DeniedLeg:            result.DeniedLeg,
		DeniedAtDepth:        int16(result.DeniedAtDepth), //nolint:gosec // G115: -1 sentinel or a chain depth bounded well under int16's range (see ChainDepth above)
		Reason:               result.Reason,
		UnevaluatedPolicyIDs: result.UnevaluatedPolicyIDs,
		InputDigest:          digest,
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

// denyAndAudit builds the DeriveTierDenial-shaped Result for err, appends
// the audit entry, and returns the wire response. Two failures on Decide's
// pre-decision path — a tool catalog that could not be loaded, and a
// DeriveTier failure — resolve through this one function rather than each
// inlining its own copy of "build the denial, audit it, respond," so they
// are audited identically and cannot independently drift the way two
// hand-written copies of the same three lines eventually would.
func (s *Server) denyAndAudit(
	ctx context.Context,
	agentID, delegationID uuid.UUID,
	chain []*models.Delegation,
	action authz.Action,
	subject string,
	now time.Time,
	err error,
) (*DecideResponse, error) {
	result := authz.DeriveTierDenial(err)
	if auditErr := s.appendAudit(ctx, agentID, delegationID, chain, action, subject, result, now); auditErr != nil {
		return nil, auditErr
	}
	return toResponse(result), nil
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
