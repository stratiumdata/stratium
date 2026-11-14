// resource_labels.go implements the five /v1/resource-label-rules routes
// routeTable (server.go) registers -- the same thin decode/call/respond shape
// policies.go, agents.go, tier_overrides.go and catalog.go use.
//
// Nothing here decides whether a rule is valid. "Is this level a level of this
// hierarchy?" is answered once, by internal/store's own
// validateResourceLabelRule against pkg/classification.Levels, and both the
// create and the update path call THAT function -- see
// UpdateResourceLabelRule's own doc comment for why a second copy of the rule
// (here, or anywhere) is the precise defect a schema CHECK was rejected for.
// A handler-side pre-check would be that copy: it would either drift from
// Levels or restate it, and its only reward would be turning a 400 into a
// slightly earlier 400.
//
// Nothing here pre-checks a delete either. Removing a rule can turn allows
// into denials beneath its prefix (R2/R7), and DeleteResourceLabelRule's own
// doc comment records at length what is done about that instead of a
// confirmation gate -- the short version being that the blast radius is
// computed and audited at the moment of the delete, and that the operator's
// pre-flight view is the list route directly above.
package main

import (
	"net/http"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
)

func listResourceLabelRules(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	rules, err := s.store.ListResourceLabelRules(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func getResourceLabelRule(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	rule, err := s.store.GetResourceLabelRule(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rule)
}

// createResourceLabelRule decodes directly into models.ResourceLabelRule --
// see createPolicy's own doc comment (policies.go) for why accepting the full,
// store-persisted type costs nothing here. Only Prefix, Hierarchy and Level are
// meaningful in the request body; ID and TenantID are set authoritatively by
// the store.
//
// A body omitting "prefix" entirely decodes to the empty string and is
// ACCEPTED, unlike every other create in this package, where an empty required
// field is refused. That is R7's catch-all -- a rule matching every id, and the
// answer an operator needs when enabling a cap denies everything unmatched --
// and a reflexive required-field guard here would delete the capability
// outright. internal/store's validateResourceLabelRule makes the same
// exception, in the same words, and is the reason this handler needs no
// opinion of its own.
func createResourceLabelRule(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	var rule models.ResourceLabelRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := s.store.CreateResourceLabelRule(r.Context(), rule, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// updateResourceLabelRule is a PUT-shaped full replace of prefix, hierarchy and
// level, matching updatePolicy/updateAgent/updateTierOverride. now is captured
// once, here at the request boundary, and passed through for the audit entry's
// OccurredAt -- this table has no updated_at column to read back instead, the
// same reason updateTierOverride injects one.
func updateResourceLabelRule(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var rule models.ResourceLabelRule
	if err := decodeJSON(r, &rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updated, err := s.store.UpdateResourceLabelRule(r.Context(), id, rule, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// deleteResourceLabelRule responds 204 No Content on success, matching every
// other delete route here. The consequence of the delete is not in the
// response -- it is in the audit entry the same transaction wrote; see
// DeleteResourceLabelRule (internal/store/resource_label.go).
func deleteResourceLabelRule(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeleteResourceLabelRule(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
