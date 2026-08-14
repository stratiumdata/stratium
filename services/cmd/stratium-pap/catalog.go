// catalog.go implements the four /v1/tool-catalog routes routeTable
// (server.go) registers: list, create, get, update -- no delete, since
// migrations/000016_stratium_pap_role deliberately withholds that grant (see
// routeTable's own comment on why). Same thin decode/call/respond shape
// policies.go/agents.go/tier_overrides.go use: request-shape and domain
// validation (tool_name required; a fixed action_tier, a command_field, or
// both) both live once, in internal/store/catalog.go's
// validateToolCatalogFields and the database CHECK it mirrors, not
// duplicated here.
package main

import (
	"net/http"
	"time"

	"stratium/pkg/models"
)

func listToolCatalog(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	entries, err := s.store.ListToolCatalogEntries(r.Context())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}

func getToolCatalogEntry(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	e, err := s.store.GetToolCatalogEntry(r.Context(), id)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, e)
}

// createToolCatalogEntry decodes directly into models.ToolCatalogEntry --
// see createPolicy's own doc comment (policies.go) for why accepting the
// full, store-persisted type costs nothing here. All three of this table's
// row states are expressible through the identical request shape: a fixed
// action_tier with command_field left null; a null action_tier with
// command_field set (Bash's own shape -- "extract that field and classify it
// with the command classifier"); or both set together. Nothing in this
// handler favors one shape over another -- CreateToolCatalogEntry's own
// validation (internal/store/catalog.go) is what actually enforces "at
// least one of the two," not this file, so getting the NULL-tier-plus-
// command_field shape wrong here would mean this handler silently narrowed
// what the store layer already allows, not that the store layer was itself
// incomplete.
func createToolCatalogEntry(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	var e models.ToolCatalogEntry
	if err := decodeJSON(r, &e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	created, err := s.store.CreateToolCatalogEntry(r.Context(), e, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, created)
}

// updateToolCatalogEntry is a PUT-shaped full replace, matching
// updatePolicy/updateAgent: the caller supplies every field
// createToolCatalogEntry accepts, so an update can freely move a row between
// this table's three valid shapes (e.g. correcting a fixed-tier row into a
// NULL-tier, command_field row) without a separate partial-patch path to
// keep in sync with the CHECK constraint's own "at least one" rule.
func updateToolCatalogEntry(s *Server, w http.ResponseWriter, r *http.Request, op Operator) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	var e models.ToolCatalogEntry
	if err := decodeJSON(r, &e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	updated, err := s.store.UpdateToolCatalogEntry(r.Context(), id, e, op.Subject, time.Now())
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}
