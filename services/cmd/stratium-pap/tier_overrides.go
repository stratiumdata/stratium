// tier_overrides.go implements the five /v1/tier-overrides routes
// routeTable (server.go) registers -- the same thin decode/call/respond
// shape policies.go and agents.go use. The raise-only rule (spec §4.4,
// Property 3 of Task 3) is enforced once, in
// internal/store/tier_override.go's CreateTierOverride/UpdateTierOverride
// via authz.ValidateOverride, never here: a handler that tried to
// pre-check it would either duplicate that logic or trust a client-supplied
// "builtin_tier" value, and TierOverride.BuiltinTier's own doc comment
// (pkg/models) is explicit about why the latter is exactly the hole this
// whole property exists to close.
package main

import (
	"net/http"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
)

func listTierOverrides(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	overrides, err := s.store.ListTierOverrides(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, overrides)
}

func getTierOverride(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	t, err := s.store.GetTierOverride(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// createTierOverride decodes directly into models.TierOverride -- see
// createPolicy's own doc comment (policies.go) for why accepting the full,
// store-persisted type costs nothing here. Only ToolOrVerb and ActionTier
// are meaningful in the request body: CreateTierOverride computes
// BuiltinTier itself (never trusting a client-supplied value) and sets
// ID/TenantID/CreatedAt/CreatedBy authoritatively, exactly as createAgent's
// own doc comment describes for the identical pattern.
func createTierOverride(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	var t models.TierOverride
	if err := decodeJSON(r, &t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := s.store.CreateTierOverride(r.Context(), t, op.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// updateTierOverride is a PUT-shaped full replace of ToolOrVerb and
// ActionTier, matching updatePolicy/updateAgent. now is captured once, here
// at the request boundary, and passed through to UpdateTierOverride for its
// audit entry's OccurredAt -- see that method's own doc comment on why it
// alone, among this file's Update handlers, needs an injected clock
// (tier_overrides has no updated_at column for it to read back instead).
func updateTierOverride(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var t models.TierOverride
	if err := decodeJSON(r, &t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updated, err := s.store.UpdateTierOverride(r.Context(), id, t, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// deleteTierOverride responds 204 No Content on success. No raise-only
// check applies to a delete -- see DeleteTierOverride's own doc comment
// (internal/store/tier_override.go) for why removing an override can never
// be a lowering.
func deleteTierOverride(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteTierOverride(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
