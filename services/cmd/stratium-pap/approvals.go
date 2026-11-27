// approvals.go implements the /v1/approvals routes routeTable (server.go)
// registers: Task 4's two write actions -- approve and deny, E7's entire
// admin-plane write surface and the security-critical half of that task
// (spec §4.10.1, N7/N8) -- and Task 6's list.
//
// Task 4 deliberately shipped no read route, and its own comment here said
// why: "discovering a pending approval's id is Task 6's UI concern." That is
// this task, and listApprovals below is the whole of it. The write actions'
// RoleAdmin floor is untouched by adding a RoleViewer read beside them; a
// viewer can now find an approval and still cannot decide it, which is
// precisely the shape N14 asks the UI to reflect rather than enforce.
package main

import (
	"net/http"
	"time"
)

// listApprovals returns every approval the tenant has, whatever its status
// -- see internal/store.listApprovalsQuery's own doc comment for why all
// statuses and not only 'pending'. Gated at RoleViewer, matching every other
// list route in routeTable, and unaudited, matching every other GET handler
// in this package (N4 is about writes).
func listApprovals(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	before, limit, ok := parsePage(w, r)
	if !ok {
		return
	}
	approvals, next, err := s.store.ListApprovals(r.Context(), before, limit)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	linkNext(w, r, next)
	writeJSON(w, http.StatusOK, approvals)
}

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
