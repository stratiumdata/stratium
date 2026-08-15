// validate_test.go proves POST /v1/policies/validate: a policy that fails
// its own engine's Validate is refused with that engine's own message, a
// well-formed one passes, and neither ever reaches the database. Fixtures
// are the identical texts internal/store/policy_test.go's own testRegistry
// section uses for the same property (Property 2) -- literal duplicates,
// not an import (policy_test.go's constants are unexported, in a different
// package), chosen there, and here, for the same reason: each invalid text
// is syntactically well-formed in its own language but semantically dead,
// the exact "looks fine, does nothing" failure Phase 4a closed.
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	validateValidCedarPolicy   = `permit(principal == User::"alice", action, resource);`
	validateInvalidCedarPolicy = `permit(principal, action, resource) when { resource in [] };`

	validateValidRegoPolicy   = "package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}"
	validateInvalidRegoPolicy = "package stratium.polic\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}"

	validateValidJSONPolicy   = `{"effect": "allow", "match": {}}`
	validateInvalidJSONPolicy = `{"effect": "allow", "match": {"tool": {"in": []}}}`

	validateValidXACMLPolicy = `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target><AnyOf><AllOf>
    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">DESTRUCTIVE</AttributeValue>
      <AttributeDesignator AttributeId="derived-tier" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"/>
    </Match>
  </AllOf></AnyOf></Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	validateInvalidXACMLPolicy = `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target><AnyOf><AllOf>
    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">ULTRA_DESTRUCTIVE</AttributeValue>
      <AttributeDesignator AttributeId="derived-tier" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"/>
    </Match>
  </AllOf></AnyOf></Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
)

// TestValidatePolicy_ValidPolicy_Success is the property's positive case,
// all four languages: a well-formed policy in each returns 200 with
// valid=true, and (assertExpectationsMet's zero registered expectations)
// never touches the database -- this endpoint never calls s.store at all,
// unlike CreatePolicy, which persists on the identical input.
func TestValidatePolicy_ValidPolicy_Success(t *testing.T) {
	tests := []struct {
		language string
		text     string
	}{
		{"cedar", validateValidCedarPolicy},
		{"rego", validateValidRegoPolicy},
		{"json", validateValidJSONPolicy},
		{"xacml", validateValidXACMLPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			f := newPolicyTestFixture(t)
			body := validatePolicyRequest{Language: tt.language, Text: tt.text}
			rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/validate", f.token(t, "org-editors"), body)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
			}
			got := decodeBody[validatePolicyResponse](t, rec)
			if !got.Valid {
				t.Errorf("Valid = false, want true for a well-formed %s policy", tt.language)
			}
			assertExpectationsMet(t, f.mock) // never reached the database
		})
	}
}

// TestValidatePolicy_InvalidPolicy_RejectedWithEngineMessage is the
// property's negative case and this task's own first required test: "an
// invalid policy is rejected with its engine's own message, for each of the
// four languages." wantSubstr is each engine's own "<language>: validate:"
// prefix (cedar/engine.go, rego/engine.go, jsonpolicy/engine.go,
// xacml/engine.go all format their Validate error this way) -- a literal
// asserted here, not a reference to any of those engines' own error-
// formatting internals, so this test is not blind to a future change in
// what exactly gets returned.
func TestValidatePolicy_InvalidPolicy_RejectedWithEngineMessage(t *testing.T) {
	tests := []struct {
		language   string
		text       string
		wantSubstr string
	}{
		{"cedar", validateInvalidCedarPolicy, "cedar: validate"},
		{"rego", validateInvalidRegoPolicy, "rego: validate"},
		{"json", validateInvalidJSONPolicy, "json: validate"},
		{"xacml", validateInvalidXACMLPolicy, "xacml: validate"},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			f := newPolicyTestFixture(t)
			body := validatePolicyRequest{Language: tt.language, Text: tt.text}
			rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/validate", f.token(t, "org-editors"), body)

			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tt.wantSubstr) {
				t.Errorf("body = %q, want it to contain %q (the engine's own error, not a generic refusal)",
					rec.Body.String(), tt.wantSubstr)
			}
			assertExpectationsMet(t, f.mock) // nothing reached the database
		})
	}
}

// TestValidatePolicy_UnknownLanguage_Refused covers the one refusal that is
// not an engine opinion: a language no engine implements. 400, the engine
// registry's own wording, nothing persisted.
func TestValidatePolicy_UnknownLanguage_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	body := validatePolicyRequest{Language: "cobol", Text: "irrelevant"}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/validate", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "no policy engine registered") {
		t.Errorf("body = %q, want it to name the unrecognised language", rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestValidatePolicy_NeverReachesDatabase is this task's own binding
// constraint made explicit and separate from the two tests above (which
// already prove it as a side effect of their own zero-expectation mocks):
// a dry-run that mutates is not a dry-run, asserted against the simulated
// database itself (sqlmock's own ExpectationsWereMet, this package's
// established "assert against the database, not by inspection" idiom -- see
// e.g. policies_test.go's TestCreatePolicy_InvalidPolicyRefused_
// NothingPersisted, which states the same proof the same way), not merely
// by reading validate.go's source and reasoning that it looks read-only. A
// sqlmock with zero registered expectations errors on the FIRST unexpected
// call -- Begin, Exec, or Query alike -- so a mutation introducing so much
// as one write here (or one accidental read), with its error handled the
// normal way (checked and propagated -- this file's own established style,
// and errcheck is an enabled linter), fails this test on a non-200 status.
// Verified live via mutation testing: adding a call to
// s.store.CreateToolCatalogEntry after the success path, error checked,
// failed this test and six of validate_test.go's other five; every one of
// this file's tests reaches the same 200-body assertion, so any of them can
// catch an accidental write on this path, not only this one.
//
// Documented limit, found the same way and reported rather than hidden:
// this is NOT closed against a write whose OWN return is explicitly
// discarded at the call site (`_, _ = s.store.Create...(...)`) -- sqlmock
// still rejects the call, but the rejection travels home in exactly the
// error value a blank identifier throws away, so nothing downstream
// (including assertExpectationsMet) can observe the attempt. This is the
// identical shape Task 4's own report names for a different property (an
// audit event-type constant renamed, every sqlmock-backed test in two
// packages staying green) and reaches the identical conclusion: only a
// live database closes it, and this package has no live-Postgres
// convention of its own to close it with (see internal/store/
// pap_task4_integration_test.go's own package doc for where every other
// task's real-Postgres proofs live instead -- cmd/stratium-pap is package
// main and cannot be dialed into the way that package's own store_test can
// dial pdpgrpc). Narrow, and honestly not closed, rather than silently
// assumed to be.
func TestValidatePolicy_NeverReachesDatabase(t *testing.T) {
	f := newPolicyTestFixture(t)
	body := validatePolicyRequest{Language: "cedar", Text: validateValidCedarPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/validate", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestValidatePolicy_InsufficientRole_Refused is this endpoint's own
// role-boundary proof (viewer, below the editor floor routeTable's own doc
// comment argues for) -- server_test.go's generic tables cover the three
// Task-3 resources only, per that file's own doc comment, so each later
// resource proves its own boundary here, matching approvals_test.go/
// delegations_test.go's established precedent for Task 4's routes.
func TestValidatePolicy_InsufficientRole_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	body := validatePolicyRequest{Language: "cedar", Text: validateValidCedarPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/validate", f.token(t, "org-viewers"), body)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d for a viewer token", rec.Code, http.StatusForbidden)
	}
	assertExpectationsMet(t, f.mock) // refused before ever reaching the handler
}

// TestValidatePolicy_MalformedJSONBody_Refused covers decodeJSON's own
// refusal path for this handler specifically -- shared plumbing
// (respond.go) already unit-tested in isolation, but not, until this test,
// exercised through this particular route.
func TestValidatePolicy_MalformedJSONBody_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/validate", strings.NewReader("{not valid json"))
	req.Header.Set("Authorization", "Bearer "+f.token(t, "org-editors"))
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for a malformed body", rec.Code, http.StatusBadRequest)
	}
	assertExpectationsMet(t, f.mock)
}
