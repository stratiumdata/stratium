// policies.go implements the five /v1/policies routes routeTable (server.go)
// registers: list, create, get, update, delete. Every handler is thin by
// design -- decode the request, call the matching internal/store method,
// map the result to a response -- because request-shape validation
// (required fields) and domain validation (a policy's own engine Validate,
// the effect enum) both already live in internal/store/policy.go's
// CreatePolicy/UpdatePolicy, the single chokepoint every caller of them
// routes through. See that file's own doc comment for why validation
// belongs there and not duplicated here.
package main

import (
	"net/http"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
)

func listPolicies(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	policies, err := s.store.ListPolicies(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, policies)
}

func getPolicy(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	p, err := s.store.GetPolicy(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// createPolicy decodes the request body directly into a models.Policy --
// the same type this file's GET handlers return, and the type
// internal/store persists -- rather than a separate request DTO: N1/N4 give
// CreatePolicy sole authority over ID, TenantID, Version, CreatedAt, and
// UpdatedAt regardless of what the body sets them to (see that method's own
// doc comment), so accepting the full type costs nothing extra here and
// saves a second, parallel struct this package would otherwise have to keep
// in sync with models.Policy by hand.
func createPolicy(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	var p models.Policy
	if err := decodeJSON(r, &p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := s.store.CreatePolicy(r.Context(), s.registry, p, op.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// updatePolicy is a PUT-shaped full replace: the body must carry every
// field CreatePolicy accepts, matching UpdatePolicy's own doc comment
// (internal/store/policy.go) on why there is no separate partial-patch
// path.
func updatePolicy(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var p models.Policy
	if err := decodeJSON(r, &p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updated, err := s.store.UpdatePolicy(r.Context(), s.registry, id, p, op.Subject)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

// deletePolicy responds 204 No Content on success: DELETE's caller already
// knows the id it asked to delete, so there is nothing left worth a
// response body, matching REST convention.
func deletePolicy(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if err := s.store.DeletePolicy(r.Context(), id, op.Subject, time.Now()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
