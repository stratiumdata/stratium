package pdpgrpc

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/pkg/models"
)

// resolveEscalation is where an EFFECT_ESCALATE result becomes either a
// freshly created pending approval or the outcome of verifying one offered
// on a retry. It is a method on Server, not a function in internal/authz,
// because verifying an approval means loading a row from the store —
// internal/authz stays pure (no database handle, no network, no ambient
// clock; see that package's own doc comment), so this is the one place that
// boundary is allowed to be crossed. The pure part of verification —
// whether an already-loaded row satisfies the retry's conditions — still
// lives in internal/authz's neighbor pkg/models, as Approval.Verify.
//
// By the time this is called, result.Effect is already EffectEscalate,
// which authz.Decide only returns after its own deny-check loop has found
// nothing to deny (compound.go): every leg has already run fresh, on this
// exact request, against the current chain and current policy. An approval
// is layered ON TOP of that fresh evaluation, never instead of it — a
// delegation revoked between the original escalation and this retry denies
// before resolveEscalation is ever reached, because result.Effect would
// already be EffectDeny by then, not EffectEscalate.
//
// Returns the (possibly rewritten) result, the id of a newly created
// approval (empty unless one was just created — see Decide's own comment on
// why that is attached to the response outside this function), and an error
// only for a store failure that leaves the decision impossible to record —
// never for a verification failure, which comes back as an ordinary DENY
// result instead (the phase plan's fail-closed rule: "a missing approval
// denies," "an approval that cannot be loaded... denies" — an RPC error
// would let a caller's retry loop treat a denial as transient and hammer
// it, where a DENY response is the final, auditable word).
func (s *Server) resolveEscalation(
	ctx context.Context,
	approvalID *uuid.UUID,
	subject string,
	agentID, delegationID uuid.UUID,
	chain []*models.Delegation,
	action authz.Action,
	result authz.Result,
	now time.Time,
) (authz.Result, string, error) {
	// ValidateChain (inside the authz.Decide call the caller already made)
	// has proven chain[0] is a genuine, well-formed root before result could
	// ever read EffectEscalate — see this function's own doc comment.
	root := chain[0]

	if approvalID == nil {
		// No approval offered: this action has hit the escalation band for
		// the first time. The approver is fixed to the chain's ROOT
		// principal, never the immediate delegator — at depth > 0 the
		// immediate delegator is an agent, not a person, and routing
		// approval to an agent would let a chain approve itself (C21).
		a := &models.Approval{
			ID:               uuid.New(),
			AgentID:          agentID,
			DelegationID:     delegationID,
			RootDelegationID: root.ID,
			Subject:          subject,
			RootPrincipal:    root.UserID,
			ToolName:         action.RecordedTool(),
			Action:           action.Verb,
			DerivedTier:      result.DerivedTier,
			InputDigest:      sha256.Sum256([]byte(action.RawInput)),
			ExpiresAt:        now.Add(s.cfg.ApprovalTTL),
		}
		if err := s.store.CreateApproval(ctx, a); err != nil {
			// Matches appendAudit's own treatment of a failed durable write
			// (server.go): a pending approval that failed to persist is a
			// fact that did not happen, the same as an audit entry that
			// failed to append — this returns an error and no response
			// rather than a bare ESCALATE a PEP could poll forever with no
			// row behind it to ever resolve.
			return authz.Result{}, "", status.Errorf(codes.Internal, "create approval: %s", err)
		}
		return result, a.ID.String(), nil
	}

	// A retry: verify every one of the five conditions. Any failure — the
	// row does not exist, cannot be decoded, or does not satisfy one of the
	// four checks Approval.Verify makes — denies and names which one, per
	// the phase plan's fail-closed rule. Tenant membership (condition 1)
	// needs no check here at all: LoadApproval is RLS-scoped like every
	// store method, so a row for another tenant is already indistinguishable
	// from no row — the same guarantee LoadAgent and LoadChain give
	// (store.go's package doc). Adding a WHERE tenant_id here would be the
	// second, divergent tenant boundary that doc explicitly rules out.
	approval, err := s.store.LoadApproval(ctx, *approvalID)
	if err != nil {
		return denyForApproval(result, fmt.Sprintf("approval %s: %s", *approvalID, err)), "", nil
	}

	digest := sha256.Sum256([]byte(action.RawInput))
	if reason := approval.Verify(root.UserID, agentID, delegationID, action.RecordedTool(), action.Verb,
		result.DerivedTier, digest, now); reason != "" {
		return denyForApproval(result, reason), "", nil
	}

	result.Effect = authz.EffectAllow
	result.Reason = fmt.Sprintf("escalation approved by %s (approval %s)", root.UserID, approval.ID)
	return result, "", nil
}

// denyForApproval turns result — an EffectEscalate decision — into a denial
// naming reason, attributed to the delegation leg: the same structural
// bucket DeriveTierDenial (internal/authz/compound.go) already uses for a
// denial that is not any single FoldVerdicts/AgentLeg/DelegationLeg output.
// Approval verification is exactly that kind of denial — a fourth,
// structural condition layered on the compound decision, never a fourth leg
// of it (FoldVerdicts keeps its two-input, one-output shape unchanged; see
// its own doc comment).
//
// "delegation" is also the only one of the three leg names available here
// that audit_chain's own CHECK constraint on denied_leg accepts alongside a
// genuinely structural reason (migrations/000003_audit_chain: only ”,
// 'principal', 'agent', or 'delegation' are legal). Inventing a fourth name
// would fail that constraint on every audit write this path produces,
// turning what should be a clean, named DENY into an opaque Internal error
// instead — exactly the failure mode this function exists to avoid.
func denyForApproval(result authz.Result, reason string) authz.Result {
	result.Effect = authz.EffectDeny
	result.DeniedLeg = "delegation"
	result.DeniedAtDepth = -1
	result.Reason = reason
	result.Delegation = authz.LegResult{Effect: authz.EffectDeny, Reason: reason}
	return result
}
