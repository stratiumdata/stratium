package pdpgrpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"stratium/internal/store"
)

// GetApproval reports one approval's current status and expiry, for a PEP
// polling after an ESCALATE response (cmd/stratium-pep's escalation.go).
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

	a, err := s.store.LoadApproval(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "approval %s: %s", id, err)
		}
		return nil, status.Errorf(codes.Internal, "load approval: %s", err)
	}

	return &GetApprovalResponse{
		Status:    a.Status,
		ExpiresAt: timestamppb.New(a.ExpiresAt),
	}, nil
}
