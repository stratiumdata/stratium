// validate.go implements POST /v1/policies/validate (spec §4.10.2), the
// simpler of Task 5's two authoring endpoints: run a candidate's text through
// its own language's engine.Validate and report exactly what the engine
// says, without ever opening a store transaction. All four engines implement
// Validate, and Phase 4a made every one of them strict enough to reject text
// that is syntactically well-formed but semantically dead (a typo'd Rego
// package, a JSON "in": [], an XACML document naming an out-of-vocabulary
// tier, a Cedar `in []` scope) -- see internal/store/policy.go's
// validatePolicyText, the identical choke point CreatePolicy/UpdatePolicy use
// for the same engines, reused here rather than reimplemented.
//
// validateCandidate (below) is also test_input.go's own first step: a
// candidate that cannot even parse has nothing to evaluate, so both authoring
// endpoints refuse on it the same way, through the same function, before
// either does anything else.
package main

import (
	"context"
	"fmt"
	"net/http"

	"stratium/internal/policy"
	"stratium/internal/store"
)

// candidatePolicyID marks a StoredPolicy built from request text rather than
// a database row. A real policies.id is always a UUID (uuid_generate_v4(),
// migrations/000001_baseline); this literal can never collide with one, so a
// response verdict attributed to it (PolicyVerdict.PolicyID, surfaced by
// test_input.go) can never be mistaken for an existing, persisted policy.
const candidatePolicyID = "candidate"

// validatePolicyRequest carries only what a syntax check needs -- no name, no
// effect, no enabled flag: those are CreatePolicy/UpdatePolicy concerns
// (internal/store/policy.go), not this endpoint's. Reusing models.Policy here
// the way createPolicy (policies.go) does for a real write would invite a
// caller to believe those fields mean something on a request that never
// persists anything.
type validatePolicyRequest struct {
	Language string `json:"language"`
	Text     string `json:"policy_content"`
}

// validatePolicyResponse is deliberately the one-field shape a passing check
// produces. On failure this endpoint never reaches writeJSON at all -- see
// validatePolicy below -- so there is no "valid: false" case for this type to
// represent.
type validatePolicyResponse struct {
	Valid bool `json:"valid"`
}

// validateCandidate looks up language in s.registry and runs text through
// that engine's own Validate -- the identical two-step validatePolicyText
// (internal/store/policy.go) performs for CreatePolicy/UpdatePolicy, called
// here directly instead of through that function because this package has no
// access to it (unexported, a different package) and, more importantly,
// because that function's own job is different: it also wraps the result in
// store.ErrPolicyInvalid for writeStoreError's status-mapping switch
// (respond.go), and this task's own brief is explicit that an authoring
// endpoint reports "the engine's own error text" -- unwrapped, exactly as the
// engine produced it, since that text already names the offending construct
// and was written to be actionable on its own. Adding a wrapping sentinel
// here would only dilute it.
//
// store.ErrUnknownLanguage is reused for the one case that is not an engine
// opinion at all -- a language no engine in the registry implements -- so
// this wording stays identical to what a CreatePolicy caller sees for the
// same mistake, rather than a second, independently phrased message to keep
// in sync with it.
//
// On success, returns a policy.StoredPolicy ready to feed an engine's own
// Prepare (test_input.go's job): "anything Validate accepts, Prepare
// accepts too" is each engine's own documented guarantee (see e.g.
// cedar.Engine.Validate's doc comment), so a candidate that reaches this
// return is safe to compile.
func (s *Server) validateCandidate(ctx context.Context, language, text string) (policy.StoredPolicy, error) {
	engine, ok := s.registry[language]
	if !ok {
		return policy.StoredPolicy{}, fmt.Errorf("%w: %q", store.ErrUnknownLanguage, language)
	}
	if err := engine.Validate(ctx, text); err != nil {
		return policy.StoredPolicy{}, err
	}
	return policy.StoredPolicy{ID: candidatePolicyID, Name: "candidate", Language: language, Text: text}, nil
}

// validatePolicy handles POST /v1/policies/validate. No internal/store method
// is ever called on this path -- validateCandidate reaches only s.registry,
// never s.store -- so there is no beginTenantTx for a database write to hide
// behind; validate_test.go's zero-sqlmock-expectation proof (matching this
// package's established "nothing reached the database" idiom -- see e.g.
// policies_test.go's TestCreatePolicy_InvalidPolicyRefused_NothingPersisted)
// catches a call to s.store added here with its error handled the normal
// way this file's own style (and errcheck) expects. See that test's own
// doc comment for the one narrower shape mutation testing found this proof
// does not close.
func validatePolicy(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	var req validatePolicyRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := s.validateCandidate(r.Context(), req.Language, req.Text); err != nil {
		// Fail closed (this task's own binding constraint): an unparseable
		// candidate refuses with a clear 400 and the engine's own reason,
		// never a 200 dressed up as an opinion.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	writeJSON(w, http.StatusOK, validatePolicyResponse{Valid: true})
}
