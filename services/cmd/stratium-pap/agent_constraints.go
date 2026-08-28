// agent_constraints.go implements the three /v1/agents/{id}/resource-constraints
// routes routeTable (server.go) registers -- the same thin decode/call/respond
// shape agent_caps.go uses. All validation lives in internal/store's
// validateResourceConstraints, not duplicated here.
package main

import (
	"net/http"
	"time"
)

// constraintsRequest is wrapped rather than a bare map so the route can gain a
// field without ambiguity, matching capsRequest.
type constraintsRequest struct {
	ResourceConstraints map[string]string `json:"resource_constraints"`
}

func getAgentConstraints(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	view, err := s.store.GetAgentResourceConstraints(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func putAgentConstraints(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req constraintsRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	view, err := s.store.SetAgentResourceConstraints(
		r.Context(), id, req.ResourceConstraints, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// deleteAgentConstraints turns scope enforcement OFF for delegations issued
// from now on. A separate verb from PUT so that cannot happen by omitting a
// field from a request body -- the same reasoning deleteAgentCaps documents.
func deleteAgentConstraints(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.ClearAgentResourceConstraints(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
