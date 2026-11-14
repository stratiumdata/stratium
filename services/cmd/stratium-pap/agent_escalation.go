// agent_escalation.go implements the three /v1/agents/{id}/escalation routes
// routeTable (server.go) registers, in the same decode/call/respond shape as
// agent_constraints.go. Validation lives in internal/store.
package main

import (
	"net/http"

	"github.com/stratiumdata/stratium/pkg/models"
)

// escalationRequest carries a pointer so an absent key and an explicit null
// both decode to nil and can be refused, rather than reading as tier 0.
type escalationRequest struct {
	EscalateAt *int `json:"escalate_at"`
}

func getAgentEscalation(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	view, err := s.store.GetAgentEscalation(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func putAgentEscalation(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var req escalationRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// A missing or null escalate_at must not become tier 0 (escalate on
	// every action) or "no threshold" (unattended). Removing a threshold is
	// DELETE, a separate verb, as for caps and scope.
	if req.EscalateAt == nil {
		http.Error(w, "escalate_at is required (use DELETE to remove the threshold)", http.StatusBadRequest)
		return
	}
	tier, err := models.ParseActionTier(*req.EscalateAt)
	if err != nil {
		http.Error(w, "escalate_at: "+err.Error(), http.StatusBadRequest)
		return
	}
	view, err := s.store.SetAgentEscalation(r.Context(), id, tier, op.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func deleteAgentEscalation(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.ClearAgentEscalation(r.Context(), id, op.Subject); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
