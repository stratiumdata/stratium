// audit.go implements GET /v1/audit: the read path for the hash-chained
// audit log.
//
// Until this route existed, audit_chain was write-only from the API's point
// of view. Every write path appended to it -- decisions, delegation
// creation, every CRUD event, and since the containment work a `containment`
// row whenever an agent's grant widens -- and nothing served any of it back.
// The record was tamper-evident and unreachable, so the only way to read a
// verdict about your own tenant was to open Postgres. The containment
// design's own risk section said so in as many words: a verdict with no
// reader is an incomplete implementation.
//
// WHAT THIS DOES NOT DO: verify the chain. pkg/audit.Verify requires its
// first entry to link to the zero hash, so it can only run on a CONTIGUOUS
// range starting at a tenant's very first row -- and a filtered read is by
// construction not contiguous. Rather than ship a verification that silently
// means something weaker than it sounds, the response carries prev_hash and
// entry_hash on every row and leaves verification to a caller who has read a
// contiguous range. See docs/architecture.md §14.
//
// RoleViewer, matching every other list route here. Worth knowing what that
// exposes: reason strings name the resource identities a call resolved to,
// which is more than GET /v1/delegations reveals. It is not secret material
// -- raw tool inputs are never stored, only input_digest (§14 again) -- but
// an operator deciding who gets viewer should know that reading the audit
// log is part of it.
package main

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/store"
)

// maxAuditLimitHint is used only in the 400 message. The real clamp lives in
// internal/store, where it also binds callers that are not this handler; a
// second literal here would be a second place to get it wrong, so this one
// never participates in a comparison.
const maxAuditLimitHint = 500

func listAudit(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	q := r.URL.Query()
	filter := store.AuditFilter{EventType: q.Get("event_type")}

	// Parse at the boundary rather than handing the database a string it
	// will reject: a 400 naming the parameter is an answer, and the 500 a
	// failed uuid cast would produce is not.
	if raw := q.Get("agent_id"); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			http.Error(w, "invalid agent_id: not a UUID", http.StatusBadRequest)
			return
		}
		filter.AgentID = &id
	}

	if raw := q.Get("before_seq"); raw != "" {
		seq, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || seq < 0 {
			http.Error(w, "invalid before_seq: want a non-negative integer", http.StatusBadRequest)
			return
		}
		filter.BeforeSeq = seq
	}

	// An out-of-range limit is clamped by the store rather than refused --
	// a caller asking for more than the maximum wants as much as it can
	// have, and failing that request would be pedantry. A limit that is not
	// a number at all is a different thing: that is a typo, and silently
	// substituting the default would hide it.
	if raw := q.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil || limit < 1 {
			http.Error(w, "invalid limit: want a positive integer (values above "+
				strconv.Itoa(maxAuditLimitHint)+" are clamped)", http.StatusBadRequest)
			return
		}
		filter.Limit = limit
	}

	page, err := s.store.ListAudit(r.Context(), filter)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
