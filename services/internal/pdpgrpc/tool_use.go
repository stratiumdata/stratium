// tool_use.go implements ReportToolUse: a PEP's after-the-fact report that a
// tool call ran, checked against the decisions this PDP recorded.
//
// Decide only ever hears about a tool call when the PEP asks. If the asking
// stops -- a hook entry narrowed, a hook the harness gave up on -- the PDP
// sees nothing at all. A report arrives by a different route (Claude Code's
// PostToolUse hook rather than PreToolUse), so a tool call that ran without
// an ALLOW is visible here even though Decide never saw it.
//
// This is detection, not enforcement: the tool call has already run, and
// nothing here changes a decision. It also cannot see a session in which
// neither hook runs.
package pdpgrpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/audit"
)

// unmatchedToolUseReason is the audit row's reason. Fixed text: the row's
// tool_name and input_digest already say which call.
const unmatchedToolUseReason = "tool call ran with no ALLOW decision for this delegation, tool and input"

// ReportToolUse looks for the ALLOW decision that should have preceded a
// tool call. Found: nothing is written. Not found: one audit entry and one
// error-level log line.
//
// The token is verified but no proof of possession is asked for, unlike
// Decide: this call grants nothing. The holder of a token can therefore
// report tool calls that never happened, which can only add entries about
// its own delegation, never remove or satisfy one.
//
// A failed token is an Unauthenticated error and is not audited: Decide
// audits a bad token because it is a refused attempt to act, and there is no
// attempted action here.
func (s *Server) ReportToolUse(ctx context.Context, req *ReportToolUseRequest) (*ReportToolUseResponse, error) {
	if req.GetTool() == "" {
		return nil, status.Error(codes.InvalidArgument, "tool is required")
	}
	delegationID, _, err := s.authenticateToken(req.GetToken())
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "token: %s", err)
	}

	// Loaded for the audit row's agent, principal and chain position, and so
	// that another tenant's delegation is NotFound through RLS like every
	// other lookup. A revoked or expired delegation still loads: a tool call
	// that ran under one is exactly what this RPC is for.
	chain, err := s.store.LoadChain(ctx, delegationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "delegation %s: %s", delegationID, err)
		}
		return nil, status.Errorf(codes.Internal, "load chain: %s", err)
	}

	// The same digest appendAudit stores for a decision, over the same bytes.
	digest := sha256.Sum256([]byte(req.GetRawInput()))
	matched, err := s.store.HasAllowDecision(ctx, delegationID, req.GetTool(), digest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "look up decision: %s", err)
	}
	if matched {
		return &ReportToolUseResponse{Matched: true}, nil
	}

	acting, root := chain[len(chain)-1], chain[0]
	entry := audit.Entry{
		TenantID:         s.cfg.TenantID,
		OccurredAt:       time.Now(),
		EventType:        store.EventTypeUnmatchedToolUse,
		Actor:            root.UserID,
		AgentID:          &acting.AgentID,
		DelegationID:     &delegationID,
		RootDelegationID: &root.ID,
		ChainDepth:       int16(acting.Depth), //nolint:gosec // G115: store.maxChainWalk bounds a chain to 64 hops
		ToolName:         req.GetTool(),
		DeclaredTier:     auditDeclaredTierAbsent,
		// audit_chain.decision admits only ALLOW, DENY and ESCALATE. DENY is
		// the true one of the three: the PDP did not allow this call. The
		// event_type is what tells this row apart from a Decide denial.
		Decision:      authz.EffectDeny.String(),
		DeniedAtDepth: noDenial,
		Reason:        unmatchedToolUseReason,
		InputDigest:   digest,
	}
	if err := s.store.AppendAudit(ctx, entry); err != nil {
		if errors.Is(err, store.ErrConcurrentAppend) {
			return nil, status.Errorf(codes.Aborted, "audit append: %s", err)
		}
		return nil, status.Errorf(codes.Internal, "audit append: %s", err)
	}
	// Error level, per this package's convention for "an operator should
	// look": there is no metrics or notification surface to raise it on.
	slog.Error("tool call ran without an ALLOW decision",
		"delegation_id", delegationID.String(),
		"agent_id", acting.AgentID.String(),
		"tool", req.GetTool())
	return &ReportToolUseResponse{Matched: false}, nil
}
