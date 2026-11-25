// agents.go implements the five /v1/agents routes routeTable (server.go)
// registers -- the same thin decode/call/respond shape policies.go uses,
// for the same reason: validation lives once, in
// internal/store/agent.go's validateAgentFields, not duplicated here.
package main

import (
	"net/http"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
)

func listAgents(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	agents, err := s.store.ListAgents(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, agents)
}

func getAgent(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	a, err := s.store.GetAgent(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// createAgent decodes directly into models.Agent -- see createPolicy's own
// doc comment (policies.go) for why accepting the full, store-persisted
// type costs nothing here: CreateAgent ignores whatever the body sets
// ID/TenantID/CreatedAt/UpdatedAt to and sets them authoritatively itself.
//
// AllowedTools is the one field worth calling out: a request that omits it
// (or sends it as JSON null) decodes to a nil slice, and internal/store's
// own validateAgentFields refuses that with ErrAllowedToolsRequired rather
// than defaulting it to unrestricted -- see that error's own doc comment.
// An operator who genuinely wants an unrestricted agent must send
// "allowed_tools": [] explicitly.
func createAgent(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	var a models.Agent
	if err := decodeJSON(r, &a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := s.store.CreateAgent(r.Context(), a, op.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// updateAgent is a PUT-shaped full replace, matching updatePolicy.
func updateAgent(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var a models.Agent
	if err := decodeJSON(r, &a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updated, err := s.store.UpdateAgent(r.Context(), id, a, op.Subject, op.Role.meets(RoleAdmin))
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// deleteAgent responds 204 No Content on success. A delete blocked by a
// foreign key (a delegation or approval still naming this agent --
// migrations/000001_baseline.up.sql and migrations/000012_approvals.up.sql
// both make agent_id ON DELETE RESTRICT) surfaces through writeStoreError's
// default case as a 500: the schema is doing exactly what it is supposed to
// (refusing to orphan history), but nothing in internal/store.DeleteAgent
// distinguishes that SQLSTATE from any other database error today, so
// neither does this handler. An operator sees "internal error," not "this
// agent still has delegations" -- a rough edge, not a silent failure (the
// delete IS refused, the row IS NOT deleted), noted rather than hidden.
func deleteAgent(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteAgent(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
