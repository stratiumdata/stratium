// containment.go implements POST /v1/containment: does this candidate
// permission set allow anything the baseline does not?
//
// It is the universal query this system did not have. Every other question
// the PAP can ask is a POINT query -- POST /v1/policies/test evaluates one
// sample input, policy.Probe asks about one tier and tool with no resource --
// and neither answers "what did this change widen?"
//
// POST, not GET, because the sets go in the body: they are structured values,
// not identifiers. It writes nothing -- but it is RoleEditor anyway, not
// RoleViewer: this codebase gates every POST route at RoleEditor regardless
// of whether the handler persists anything, and POST /v1/policies/test --
// the point-query counterpart to this universal one -- is gated the same
// way for the same reason. A Viewer can read every dimension this endpoint
// compares through the plain GET routes; what RoleEditor buys is the
// structural property that a Viewer can never reach a POST route at all.
package main

import (
	"net/http"

	"stratium/pkg/models"
	"stratium/pkg/permset"
)

// The two questions this endpoint can answer. They are NOT
// interchangeable, and they disagree on exactly one case -- a key the
// candidate introduces and the baseline lacks:
//
//	delegation  may a CHILD hold this?   permset.Contains
//	grant       did this get WIDER?      permset.GrantWidens
//
// Introducing a classification cap or a resource constraint is refused as a
// delegation (a child may not invent a dimension its parent never had -- a
// deliberate shape rule, spec section 4.3.1) and NARROWS as a grant (an
// absent cap or constraint means unrestricted). Both answers are correct for
// their own question.
const (
	questionDelegation = "delegation"
	questionGrant      = "grant"
)

type containmentRequest struct {
	// Question selects which comparison to run. Empty means "delegation",
	// so every caller that predates this field keeps its existing answer.
	Question string `json:"question"`

	Baseline  permset.Set `json:"baseline"`
	Candidate permset.Set `json:"candidate"`
}

type containmentResponse struct {
	// Question echoes which comparison actually ran, so a logged or stored
	// response says what it answered rather than leaving a reader to infer
	// it from a request they may no longer have.
	Question string `json:"question"`

	Contained bool `json:"contained"`

	// Reason is the counterexample in the only form this engine produces: the
	// first dimension on which the candidate exceeds the baseline, named the
	// same way an operator would see it in a refused delegation.
	Reason string `json:"reason"`
}

// answerContainment runs the named comparison. The caller has already
// validated question, so an unrecognised one here is a programming error
// rather than a caller's, and defaulting would be the specific mistake this
// endpoint must not make: the two answers differ, so guessing which was
// meant is worse than refusing.
func answerContainment(question string, baseline, candidate permset.Set) containmentResponse {
	var reason string
	if question == questionGrant {
		reason = permset.GrantWidens(baseline, candidate)
	} else {
		question = questionDelegation
		reason = permset.Contains(baseline, candidate)
	}
	return containmentResponse{Question: question, Contained: reason == "", Reason: reason}
}

// validateSetTiers range-checks a decoded Set's ActionTier fields, following
// the same convention test_input.go's DeclaredTier check does: decodeJSON
// puts an untrusted int straight into MaxTier and EscalateAt, which compiles
// because ActionTier's underlying type is int, but ParseActionTier's own doc
// comment warns that casting alone admits a value outside the lattice.
// Empty string means valid, matching permset.Contains's own convention.
func validateSetTiers(label string, set permset.Set) string {
	if _, err := models.ParseActionTier(int(set.MaxTier)); err != nil {
		return label + ".max_action_tier: " + err.Error()
	}
	if set.EscalateAt != nil {
		if _, err := models.ParseActionTier(int(*set.EscalateAt)); err != nil {
			return label + ".escalate_at: " + err.Error()
		}
	}
	return ""
}

func checkContainment(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	var req containmentRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if msg := validateSetTiers("baseline", req.Baseline); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	if msg := validateSetTiers("candidate", req.Candidate); msg != "" {
		http.Error(w, msg, http.StatusBadRequest)
		return
	}
	// Refuse an unrecognised question rather than falling back. The two
	// comparisons disagree, so a silent default would answer a question the
	// caller did not ask and label it as the one they did.
	switch req.Question {
	case "", questionDelegation, questionGrant:
	default:
		http.Error(w, "invalid question: "+req.Question+`; want "`+
			questionDelegation+`" (may a child hold this?) or "`+
			questionGrant+`" (did this get wider?)`, http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, answerContainment(req.Question, req.Baseline, req.Candidate))
}
