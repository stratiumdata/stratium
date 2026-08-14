// approvals.go implements the two /v1/approvals/{id}/... write routes
// routeTable (server.go) registers: approve and deny -- E7's entire admin-
// plane surface, and the security-critical half of this task (spec §4.10.1,
// N7/N8). There is deliberately no list or get route: discovering a pending
// approval's id is Task 6's UI concern (it "is a client of the API Tasks
// 3-5 proved" per the phase plan), out of this task's own stated scope --
// "the approve action itself." Tests that need a known id create one
// directly against internal/store, the same way every other integration
// proof in this codebase seeds fixtures it does not itself expose a read
// route for.
package main

import (
	"net/http"
	"time"
)

func approveApproval(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	decideApproval(s, w, r, op, true)
}

func denyApproval(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	decideApproval(s, w, r, op, false)
}

// decideApproval is shared by approveApproval/denyApproval: both are the
// identical write with a different outcome, and splitting the identity
// check or the store call between two near-duplicate handler bodies would
// be exactly the place a future edit could fix N7 in one copy and forget
// the other.
//
// op.ApproverIdentity == "" is refused here, before ever reaching
// internal/store, with 401 -- an identity problem (who is this), the same
// bucket authorize's own Subject/Role checks use, not 403 (this identity is
// known and not permitted here): N8's own claim resolution
// (role.go's resolveApproverIdentity) already failed to establish who this
// operator even is for approval purposes, so there is nothing yet to
// compare against root_principal. This is a convenience short-circuit, not
// the actual enforcement: internal/store.DecideApproval's own comparison
// against the loaded approval's root_principal is what N7 depends on (an
// empty string can never equal a non-empty root_principal either way), so
// removing this check would not reopen N7 -- see approval_test.go's mutation
// coverage for both layers.
//
// The RoleAdmin floor routeTable already applies before this function is
// ever called is what makes N7's own wording literally true here: "a role is
// necessary" (RoleAdmin gates the route) "and never sufficient" (this
// function, and the store-layer check beneath it, still run regardless of
// role). There is no override and no path that skips either check --
// C22's own designed behavior ("an escalation whose approver is unavailable
// times out and denies") depends on that remaining true.
func decideApproval(s *Server, w http.ResponseWriter, r *http.Request, op Operator, approve bool) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if op.ApproverIdentity == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	decided, err := s.store.DecideApproval(r.Context(), id, approve, op.ApproverIdentity, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, decided)
}
