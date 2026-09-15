// containment.go implements POST /v1/containment: does this candidate
// permission set allow anything the baseline does not?
//
// It is the universal query this system did not have. Every other question
// the PAP can ask is a POINT query -- POST /v1/policies/test evaluates one
// sample input, policy.Probe asks about one tier and tool with no resource --
// and neither answers "what did this change widen?"
//
// POST, not GET, because the sets go in the body: they are structured values,
// not identifiers. It writes nothing, which is why it is RoleViewer.
package main

import (
	"net/http"

	"stratium/pkg/permset"
)

type containmentRequest struct {
	Baseline  permset.Set `json:"baseline"`
	Candidate permset.Set `json:"candidate"`
}

type containmentResponse struct {
	Contained bool `json:"contained"`

	// Reason is the counterexample in the only form this engine produces: the
	// first dimension on which the candidate exceeds the baseline, named the
	// same way an operator would see it in a refused delegation.
	Reason string `json:"reason"`
}

func containmentOf(baseline, candidate permset.Set) containmentResponse {
	reason := permset.Contains(baseline, candidate)
	return containmentResponse{Contained: reason == "", Reason: reason}
}

func checkContainment(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	var req containmentRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, http.StatusOK, containmentOf(req.Baseline, req.Candidate))
}
