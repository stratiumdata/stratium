// delegations.go implements the /v1/delegations routes routeTable
// (server.go) registers: Task 4's revoke action -- V4's entire admin-plane
// write surface -- and Task 6's list, which is the "discovering which
// delegation to revoke is Task 6's UI concern" that task's own comment here
// deferred. Revoke stays at RoleAdmin; the list is RoleViewer.
package main

import (
	"net/http"
	"time"
)

// listDelegations returns every delegation the tenant has, revoked and
// expired ones included -- see internal/store.listDelegationsQuery's own doc
// comment. Gated at RoleViewer and unaudited, matching every other list route
// and GET handler in this package.
func listDelegations(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	delegations, err := s.store.ListDelegations(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, delegations)
}

// revokeDelegation sets revoked and revoked_at on the id delegation.
// Role-gated at RoleAdmin (routeTable) with no further identity check --
// unlike decideApproval, revocation reduces authority, and spec N7's own
// contrast (§4.10.1) is explicit that taking authority away needs only a
// role: "the worst outcome of a wrongly-scoped revocation is that something
// stops working, which fails closed." internal/store.RevokeDelegation is
// the entire write; DelegationLeg (internal/authz/delegation.go) already
// checks Revoked at every hop of any chain it is later handed, on every
// decision, so cascade denial for this delegation's descendants needs no
// code here or anywhere else -- see that store method's own doc comment.
func revokeDelegation(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	revoked, err := s.store.RevokeDelegation(r.Context(), id, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, revoked)
}
