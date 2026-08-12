package pdpgrpc

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"stratium/internal/store"
	"stratium/pkg/models"
)

// approvalFixture returns a fake store loaded with one approval row, and the
// approval itself, so tests can assert the response traces back to specific,
// distinguishable field values rather than merely "some approval".
func approvalFixture() (*fakeStore, *models.Approval) {
	expires := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	a := &models.Approval{
		ID:        uuid.New(),
		TenantID:  testTenant,
		Status:    "pending",
		ExpiresAt: expires,
	}
	return &fakeStore{loadApproval: a}, a
}

func TestGetApproval_ReturnsStatusAndExpiry(t *testing.T) {
	fs, a := approvalFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig())

	resp, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String()})
	if err != nil {
		t.Fatalf("GetApproval() error = %v, want nil", err)
	}
	if resp.GetStatus() != a.Status {
		t.Errorf("Status = %q, want %q", resp.GetStatus(), a.Status)
	}
	if !resp.GetExpiresAt().AsTime().Equal(a.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", resp.GetExpiresAt().AsTime(), a.ExpiresAt)
	}
}

// A different status value round-trips too -- proves the field is actually
// read from the loaded row, not a hardcoded "pending" that
// TestGetApproval_ReturnsStatusAndExpiry's own fixture status could not by
// itself distinguish from a bug that always reported the same value.
func TestGetApproval_ReflectsApprovedStatus(t *testing.T) {
	fs, a := approvalFixture()
	a.Status = "approved"
	srv := NewServer(fs, escalationPolicy(), testConfig())

	resp, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String()})
	if err != nil {
		t.Fatalf("GetApproval() error = %v, want nil", err)
	}
	if resp.GetStatus() != "approved" {
		t.Errorf("Status = %q, want %q", resp.GetStatus(), "approved")
	}
}

func TestGetApproval_UnknownID_NotFound(t *testing.T) {
	fs, _ := approvalFixture()
	unknown := uuid.New()
	fs.loadApprovalErr = fmt.Errorf("%w: approval %s", store.ErrNotFound, unknown)
	srv := NewServer(fs, escalationPolicy(), testConfig())

	resp, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: unknown.String()})
	if resp != nil {
		t.Fatalf("GetApproval() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.NotFound)
}

// A generic store failure (a corrupt row, a connection blip) -- not
// ErrNotFound -- is Internal, not NotFound: GetApproval is a plain read, with
// none of resolveEscalation's fail-closed-to-DENY obligation (that rule
// exists because a verification failure must be indistinguishable from "no,
// denied" to a retrying caller; a poller asking "what is the status" has no
// decision to protect by masking an infrastructure error as a clean answer).
func TestGetApproval_StoreErrorNotNotFound_Internal(t *testing.T) {
	fs, _ := approvalFixture()
	fs.loadApprovalErr = errors.New("connection reset")
	srv := NewServer(fs, escalationPolicy(), testConfig())

	resp, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: uuid.NewString()})
	if resp != nil {
		t.Fatalf("GetApproval() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.Internal)
}

// Malformed input is rejected before any store call -- the same
// InvalidArgument-before-lookup discipline TestDecide_InvalidInput_
// InvalidArgument (server_test.go) already requires of every caller-supplied
// UUID in this package.
func TestGetApproval_InvalidApprovalID_InvalidArgument(t *testing.T) {
	cases := map[string]string{
		"not a UUID": "not-a-uuid",
		"zero UUID":  uuid.Nil.String(),
		"empty":      "",
	}
	for name, id := range cases {
		t.Run(name, func(t *testing.T) {
			fs, _ := approvalFixture()
			srv := NewServer(fs, escalationPolicy(), testConfig())

			resp, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: id})
			if resp != nil {
				t.Fatalf("GetApproval() response = %+v, want nil", resp)
			}
			wantCode(t, err, codes.InvalidArgument)
			if fs.calls != 0 {
				t.Errorf("store was called %d times, want 0 -- invalid input must not proceed to a lookup", fs.calls)
			}
		})
	}
}

// The mutation-testing anchor for "make GetApproval mutate the row": the
// fakeStore's call counter increments on EVERY method, not just LoadApproval
// (see its own doc comment in server_test.go), so a single successful call
// leaving fs.calls at exactly 1 proves LoadApproval was the ONLY store
// interaction -- no CreateApproval, no anything else, however incidental --
// which is the Go-level half of E7's read-only guarantee this method's own
// doc comment describes. len(fs.createdApprovals) == 0 restates the same
// fact for the one write path that does exist on this fake, by name.
func TestGetApproval_OnlyLoadsNeverWrites(t *testing.T) {
	fs, a := approvalFixture()
	srv := NewServer(fs, escalationPolicy(), testConfig())

	if _, err := srv.GetApproval(context.Background(), &GetApprovalRequest{ApprovalId: a.ID.String()}); err != nil {
		t.Fatalf("GetApproval() error = %v, want nil", err)
	}

	if fs.calls != 1 {
		t.Errorf("store calls = %d, want exactly 1 (LoadApproval only) -- GetApproval must not write anything", fs.calls)
	}
	if len(fs.createdApprovals) != 0 {
		t.Errorf("approvals created = %d, want 0: GetApproval must never create or otherwise write a row",
			len(fs.createdApprovals))
	}
}
