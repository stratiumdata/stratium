// principals.go implements GET /v1/principals/{id}/effective: the union of
// every live root delegation a principal holds.
//
// It answers the horizontal question the delegation leg does not. That leg
// enforces child <= parent at every hop, exhaustively; nothing compares
// SIBLINGS. Two live root delegations -- one reaching /secret, one reaching
// EXTERNAL_COMMS -- are individually in bounds and jointly an exfiltration
// path, and until this route existed that union could not even be seen.
//
// It REPORTS and does not enforce. There is no principal ceiling to check
// the union against; adding one is a follow-up whose whole implementation is
// one permset.Contains call against the value this route already returns.
package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
)

type effectiveResponse struct {
	PrincipalID string      `json:"principal_id"`
	Union       permset.Set `json:"union"`

	// DelegationsCounted disambiguates the empty grant. An empty Tools list
	// means UNRESTRICTED everywhere else in this system, so a zero-value
	// Set and a genuinely unrestricted one are the same JSON; the count is
	// what tells them apart.
	DelegationsCounted int `json:"delegations_counted"`

	// Imprecision names every dimension Union had to widen beyond an exact
	// join. Returned rather than logged because a report that silently lost
	// precision is worse than no report.
	Imprecision []string `json:"imprecision"`
}

// effectiveFor is the pure core, separated from the handler so the filters
// are testable without a database.
func effectiveFor(all []models.Delegation, principalID string, now time.Time) effectiveResponse {
	var sets []permset.Set
	for i := range all {
		d := &all[i]
		if d.UserID != principalID || !d.IsRoot() || !d.IsActive(now) {
			continue
		}
		sets = append(sets, permset.FromDelegation(d))
	}
	union, imprecision := permset.Union(sets...)
	if imprecision == nil {
		imprecision = []string{}
	}
	return effectiveResponse{
		PrincipalID:        principalID,
		Union:              union,
		DelegationsCounted: len(sets),
		Imprecision:        imprecision,
	}
}

// maxSessionsCounted is the most live sessions one answer reads.
const maxSessionsCounted = 1000

func getPrincipalEffective(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	// Not pathID: a principal id is the OIDC subject string, not a uuid.
	principalID := r.PathValue("id")
	if principalID == "" {
		http.Error(w, "principal id is required", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC()
	live, more, err := s.store.ListActiveRootDelegations(r.Context(), principalID, now, maxSessionsCounted)
	if err != nil {
		writeStoreError(w, err)
		return
	}
	resp := effectiveFor(live, principalID, now)
	if more {
		// Said, not hidden: the union is of the newest sessions only, so it
		// may understate what this principal has delegated.
		resp.Imprecision = append(resp.Imprecision, fmt.Sprintf(
			"this principal has more than %d live sessions; only the newest %d are counted",
			maxSessionsCounted, maxSessionsCounted))
	}
	writeJSON(w, http.StatusOK, resp)
}
