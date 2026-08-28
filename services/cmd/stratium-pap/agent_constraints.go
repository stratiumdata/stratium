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
	// req.ResourceConstraints is nil both when the field is entirely absent
	// and when it is present but JSON null -- encoding/json leaves a map nil
	// in both cases, distinct from an explicit "resource_constraints": {},
	// which decodes to a non-nil, zero-length map (the same nil-vs-present-
	// empty distinction ErrAllowedToolsRequired enforces, internal/store/
	// agent.go). Refusing only the nil case, not len==0, is what keeps an
	// operator's deliberate "no constraints" {} accepted while catching the
	// silent-wipe case this guards against: PUT {} or a body with a typo'd
	// key would otherwise decode to nil, sail through
	// validateResourceConstraints (zero iterations, nothing to reject), and
	// clear the agent's scope -- indistinguishable, on the wire, from an
	// operator who meant to do that. DELETE is the one place that means it.
	if req.ResourceConstraints == nil {
		http.Error(w, "resource_constraints is required (use DELETE to clear the scope, "+
			`or "resource_constraints": {} to set it to unrestricted explicitly)`,
			http.StatusBadRequest)
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
// from now on. A separate verb from PUT, and putAgentConstraints' own nil
// check above is what keeps that a deliberate, distinct action rather than
// something an operator could trigger by omitting a field from a PUT body --
// the same reasoning deleteAgentCaps documents.
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
