// delegations.go implements the one /v1/delegations/{id}/revoke route
// routeTable (server.go) registers -- V4's entire admin-plane surface.
// There is no list or get route: as with approvals.go, discovering which
// delegation to revoke is Task 6's UI concern, out of this task's own
// stated scope ("setting revoked and revoked_at").
package main

import (
	"net/http"
	"time"
)

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
