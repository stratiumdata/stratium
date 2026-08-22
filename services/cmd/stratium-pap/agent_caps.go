// agent_caps.go implements the three /v1/agents/{id}/classification-caps
// routes routeTable (server.go) registers -- the same thin decode/call/
// respond shape agents.go uses: all validation (unknown hierarchy, no
// catch-all rule, case ambiguity) already lives in internal/store's
// SetAgentClassificationCaps/ClearAgentClassificationCaps/
// GetAgentClassificationCaps, not duplicated here.
package main

import (
	"net/http"
	"time"
)

// capsRequest is wrapped rather than a bare map so the route can gain a field
// without ambiguity.
type capsRequest struct {
	ClassificationCaps map[string]string `json:"classification_caps"`
}

func getAgentCaps(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	view, err := s.store.GetAgentClassificationCaps(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func putAgentCaps(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req capsRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	allowUncovered := r.URL.Query().Get("allow_uncovered") == "true"
	view, err := s.store.SetAgentClassificationCaps(
		r.Context(), id, req.ClassificationCaps, allowUncovered, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// deleteAgentCaps turns classification enforcement OFF for delegations issued
// from now on. It is a separate verb from PUT so that cannot happen by omitting
// a field from a request body.
func deleteAgentCaps(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.ClearAgentClassificationCaps(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
