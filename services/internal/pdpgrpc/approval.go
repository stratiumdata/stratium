package pdpgrpc

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/stratiumdata/stratium/internal/store"
)

// GetApproval reports one approval's current status and expiry, for a PEP
// polling after an ESCALATE response (cmd/stratium-pep's escalation.go).
//
// The caller presents a token for the delegation the approval was requested
// under, and is told about no other delegation's approvals.
//
// Read-only by construction: this method calls s.store.LoadApproval and
// nothing else. The only store method that can write to the approvals table
// is CreateApproval, called exclusively from resolveEscalation's
// fresh-escalation branch (escalation.go) — GetApproval never calls it, so
// there is no code path here that could extend, refresh, or otherwise touch
// the row, whatever a future edit might be tempted to add "while it's
// already loaded." Under E7 the PDP's serving role holds no UPDATE grant on
// approvals at all (migrations/000012_approvals' own GRANT comment), so an
// attempt would fail at the database regardless — but the guarantee this
// method actually gives is the Go-level one: nothing here tries.
func (s *Server) GetApproval(ctx context.Context, req *GetApprovalRequest) (*GetApprovalResponse, error) {
	id, err := parseNonNilUUID(req.GetApprovalId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "approval_id: %s", err)
	}

	if err := overLong(bounded{"token", req.GetToken(), s.cfg.Limits.CredentialBytes}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	// Before any store call, so a caller with no token costs no database work.
	delegationID, err := s.tokenDelegation(req.GetToken())
	if err != nil {
		return nil, err
	}

	a, err := s.store.LoadApproval(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, approvalNotFound(id)
		}
		return nil, status.Errorf(codes.Internal, "load approval: %s", err)
	}
	// An approval is reported only to a holder of its own delegation's token.
	// Anyone else gets the answer an unknown id gets.
	if a.DelegationID != delegationID {
		return nil, approvalNotFound(id)
	}

	return &GetApprovalResponse{
		Status:    a.Status,
		ExpiresAt: timestamppb.New(a.ExpiresAt),
	}, nil
}

// approvalNotFound is the one answer for an approval the caller may not see,
// whether it does not exist or belongs to another delegation.
func approvalNotFound(id uuid.UUID) error {
	return status.Errorf(codes.NotFound, "approval %s: not found", id)
}

// tokenDelegation returns the delegation a token was issued for. Signature
// only, like IssueToken's prior token (priorTokenBinding): a PEP may wait for
// a person longer than its token lasts, and GetApproval reports a status, it
// allows nothing.
func (s *Server) tokenDelegation(tokenString string) (uuid.UUID, error) {
	if tokenString == "" {
		return uuid.Nil, status.Error(codes.Unauthenticated,
			"token is required: present the token the escalated call was made with")
	}
	claims, err := s.signer.VerifySignature(tokenString)
	if err != nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "token does not verify")
	}
	sub, _ := claims[subjectClaim].(string)
	id, err := parseNonNilUUID(sub)
	if err != nil {
		return uuid.Nil, status.Error(codes.Unauthenticated, "token does not verify")
	}
	return id, nil
}
