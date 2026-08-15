// test_input_test.go proves POST /v1/policies/test against N9 (isolated vs.
// folded), N10 (the not-evaluated marker), N11 (derive vs. declare, and the
// evidence rule), and this task's own "neither endpoint writes" binding
// constraint. Fixtures reuse validate_test.go's own valid/invalid policy
// texts rather than a second set of near-duplicate literals.
package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/pkg/models"
)

// toolCatalogLoadColumns and policyLoadColumns are the two production
// queries this endpoint's read path issues, in the exact column order their
// own scan functions expect: loadToolCatalogQuery (internal/store/
// catalog.go, LoadToolCatalog) and loadAllPoliciesQuery (internal/store/
// policy.go, LoadAllPolicies) -- distinct from this file's sibling
// policyListColumns (server_test.go) and listToolCatalogEntriesQuery, both
// of which back a different, admin-facing seven/eleven-column read this
// endpoint never calls.
func toolCatalogLoadColumns() []string {
	return []string{"tool_name", "action_tier", "verb", "resource_field", "command_field"}
}

func policyLoadColumns() []string {
	return []string{"id", "name", "language", "policy_content", "priority", "version"}
}

// expectToolCatalogLoad and expectPolicyLoad register the ordered
// begin/set_config/query/commit sequence store.LoadToolCatalog and store.
// LoadAllPolicies each issue -- crud_helpers_test.go's expectWriteAndAudit
// sibling for a read rather than a write, one per production query this
// endpoint's handler calls.
func expectToolCatalogLoad(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM tool_catalog").WillReturnRows(rows)
	mock.ExpectCommit()
}

func expectPolicyLoad(mock sqlmock.Sqlmock, rows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery("FROM policies").WillReturnRows(rows)
	mock.ExpectCommit()
}

// TestTestPolicyAgainstSampleInput_ValidCandidate_Success is the basic
// success shape: an unconditional Cedar permit, no existing tenant
// policies, both evaluations allow, exactly two reads happen (tool_catalog
// for tier derivation, policies for the folded comparison) and nothing
// else.
func TestTestPolicyAgainstSampleInput_ValidCandidate_Success(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	// Unconditional, not validateValidCedarPolicy: that fixture matches only
	// principal == User::"alice" (validate_test.go's own fixture, chosen
	// there to exercise a real engine, not to match an empty sample
	// Principal), and this test's own point is the response shape on
	// success, not conditional matching.
	body := policyTestRequest{Language: "cedar", Text: `permit(principal, action, resource);`}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[policyTestResponse](t, rec)
	if got.Isolated.Effect != "ALLOW" {
		t.Errorf("Isolated.Effect = %q, want ALLOW", got.Isolated.Effect)
	}
	if got.WithExistingPolicies.Effect != "ALLOW" {
		t.Errorf("WithExistingPolicies.Effect = %q, want ALLOW", got.WithExistingPolicies.Effect)
	}
	assertExpectationsMet(t, f.mock)
}

// TestTestPolicyAgainstSampleInput_CandidateAttributedByItsOwnSyntheticID is
// this endpoint's own proof that a not-yet-persisted candidate can never be
// confused with a real, stored policy: the isolated evaluation's deciding
// verdict is the candidate (nothing else is in play), and PolicyID must
// read the literal "candidate" -- asserted here as a hardcoded string, not
// a reference to the candidatePolicyID symbol test_input.go itself defines,
// so a mutation to that constant's VALUE (rather than its use) is something
// this specific assertion can actually catch, unlike a test that compared
// against the same symbol on both sides.
func TestTestPolicyAgainstSampleInput_CandidateAttributedByItsOwnSyntheticID(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	// Unconditional -- see ValidCandidate_Success's own comment on why not
	// validateValidCedarPolicy: this test needs the candidate to actually
	// decide the isolated evaluation, not to test conditional matching.
	body := policyTestRequest{Language: "cedar", Text: `permit(principal, action, resource);`}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	got := decodeBody[policyTestResponse](t, rec)
	if got.Isolated.Source != "cedar" {
		t.Errorf("Isolated.Source = %q, want %q", got.Isolated.Source, "cedar")
	}
	if got.Isolated.PolicyID != "candidate" {
		t.Errorf(`Isolated.PolicyID = %q, want "candidate" (a literal that can never collide with a real policies.id UUID)`, got.Isolated.PolicyID)
	}
}

// TestTestPolicyAgainstSampleInput_InvalidCandidate_Refused is this
// endpoint's own instance of "fail closed: an unparseable candidate ...
// refuses with a clear status" -- reusing validate_test.go's own invalid
// Rego fixture, since the property (an engine's own Validate rejects it) is
// identical to validate.go's, just reached through a different route. Zero
// sqlmock expectations: an unparseable candidate must refuse BEFORE
// LoadToolCatalog or LoadAllPolicies are ever called, not fold into a
// misleading deny verdict two steps later.
func TestTestPolicyAgainstSampleInput_InvalidCandidate_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	body := policyTestRequest{Language: "rego", Text: validateInvalidRegoPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // never reached the database
}

// TestTestPolicyAgainstSampleInput_OutOfRangeDeclaredTier_Refused proves the
// same range check pdpgrpc/server.go applies to DecideRequest.declared_tier
// applies here too: an override outside models.ActionTier's 0-4 lattice is
// refused with 400 before any store call, not silently clamped or trusted.
func TestTestPolicyAgainstSampleInput_OutOfRangeDeclaredTier_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	bogus := models.ActionTier(99)
	body := policyTestRequest{Language: "cedar", Text: validateValidCedarPolicy, DeclaredTier: &bogus}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock) // never reached the database
}

// TestTestPolicyAgainstSampleInput_IsolatedAndFoldedDifferWhenExistingPolicyForbids
// is N9's own required test, verbatim: "the isolated and folded results
// differ where deny-overrides makes them differ ... needs a test that would
// fail if only one evaluation were run." The candidate permits everything;
// an existing tenant policy forbids everything. Isolated sees only the
// candidate (ALLOW); folded sees both, and deny-overrides makes the
// existing forbid win (DENY) regardless of what the candidate itself says.
//
// This single test is what independently catches BOTH of the required
// mutations "return only the isolated result" (would leave
// WithExistingPolicies == ALLOW, failing the second assertion) and "return
// only the folded one" (would leave Isolated == DENY, failing the first) --
// two distinct assertions, each sensitive to a different one of the two
// mutations, not one assertion vaguely covering both.
func TestTestPolicyAgainstSampleInput_IsolatedAndFoldedDifferWhenExistingPolicyForbids(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()).
		AddRow(uuid.New().String(), "existing-forbid-everything", "cedar", `forbid(principal, action, resource);`, int64(0), int64(1)))

	body := policyTestRequest{Language: "cedar", Text: `permit(principal, action, resource);`}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[policyTestResponse](t, rec)

	if got.Isolated.Effect != "ALLOW" {
		t.Errorf("Isolated.Effect = %q, want ALLOW (the candidate alone permits everything -- an existing "+
			"policy must not be consulted for this half of the answer)", got.Isolated.Effect)
	}
	if got.WithExistingPolicies.Effect != "DENY" {
		t.Errorf("WithExistingPolicies.Effect = %q, want DENY (an existing forbid anywhere in the tenant "+
			"wins deny-overrides, which is exactly why the candidate cannot be trusted in isolation)",
			got.WithExistingPolicies.Effect)
	}
	assertExpectationsMet(t, f.mock)
}

// TestTestPolicyAgainstSampleInput_ResponseStatesAgentAndDelegationLegsNotEvaluated
// is N10's own required test: the response states, in its own payload, that
// only the principal leg ran. The required mutation "drop the not-evaluated
// marker from the response" is caught here -- whether by omitting
// legs_evaluated entirely (got.LegsEvaluated would decode to its Go zero
// value, which happens to already read Agent=false/Delegation=false, so
// Principal's own assertion is what actually catches an outright drop) or
// by hardcoding Agent/Delegation to true (caught directly).
func TestTestPolicyAgainstSampleInput_ResponseStatesAgentAndDelegationLegsNotEvaluated(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	body := policyTestRequest{Language: "cedar", Text: validateValidCedarPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)
	got := decodeBody[policyTestResponse](t, rec)

	if !got.LegsEvaluated.Principal {
		t.Error("LegsEvaluated.Principal = false, want true -- this is the one leg a policy endpoint always runs")
	}
	if got.LegsEvaluated.Agent {
		t.Error("LegsEvaluated.Agent = true, want false -- the agent leg is structural and policy-independent; " +
			"this endpoint never calls authz.AgentLeg")
	}
	if got.LegsEvaluated.Delegation {
		t.Error("LegsEvaluated.Delegation = true, want false -- the delegation leg is structural and " +
			"policy-independent; this endpoint never calls authz.DelegationLeg")
	}
}

// TestTestPolicyAgainstSampleInput_DerivedTierMatchesDecisionPath is N11's
// own required test: "a derived tier matches what the decision path would
// derive for the same input." The expected tier is computed here by calling
// the exact same exported internal/authz functions pdpgrpc.Server.Decide
// calls, in the same order, independently of this endpoint's own
// implementation -- so this test fails if deriveOrDeclareTier (test_input.go)
// diverges from that sequence in any way (wrong order, a skipped step, an
// extra one), not merely if it returns some plausible-looking number.
//
// The fixture is Bash with a raw shell command containing "rm -rf /" and no
// catalog entry -- the exact evidence-rule scenario tier.go's own doc
// comment names, chosen so the expected tier (DESTRUCTIVE) is unambiguous
// and could not be produced by an unrelated bug that happened to derive the
// same tier by accident (e.g. always returning ActionTierReasoning would
// not coincidentally equal DESTRUCTIVE).
func TestTestPolicyAgainstSampleInput_DerivedTierMatchesDecisionPath(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	const rawInput = `{"command":"rm -rf /"}`
	body := policyTestRequest{
		Language: "cedar", Text: validateValidCedarPolicy,
		Action: testInputAction{Tool: "Bash", RawInput: rawInput},
	}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[policyTestResponse](t, rec)

	// Independently reproduce pdpgrpc.Server.Decide's own tier-derivation
	// steps (server.go lines ~356-395) against the identical (empty)
	// catalog and action -- not a call into deriveOrDeclareTier itself,
	// which would make this test unable to catch a bug IN that function.
	var noCatalog []models.ToolCatalogEntry
	action := authz.Action{Tool: "Bash", RawInput: rawInput}
	extracted := authz.ExtractFromCatalog(noCatalog, action)
	wantAction, _ := authz.ApplyExtraction(extracted, action, map[string]string{})
	tiers := authz.TierTable{Catalog: authz.BuildTierCatalog(noCatalog, authz.DefaultCatalog())}
	wantTier, err := authz.DeriveTier(tiers, wantAction)
	if err != nil {
		t.Fatalf("test setup: authz.DeriveTier() error = %v", err)
	}
	if wantTier != models.ActionTierDestructive {
		t.Fatalf("test setup: independently-derived tier = %s, want DESTRUCTIVE (fixture no longer exercises the evidence rule)", wantTier)
	}

	if got.Tier.Value != wantTier {
		t.Errorf("Tier.Value = %s, want %s (must match what pdpgrpc.Server.Decide would derive for the identical input)",
			got.Tier.Value, wantTier)
	}
	if got.Tier.Source != "derived" {
		t.Errorf(`Tier.Source = %q, want "derived" for the default (no override) path`, got.Tier.Source)
	}
}

// TestTestPolicyAgainstSampleInput_ExplicitTierOverride_Labelled is N11's
// other required half: an explicit override is honored AND labelled as
// such. The action below (a plain file read) would derive READ_ONLY on its
// own -- chosen so a mutant that silently ignored the override and derived
// anyway would produce a visibly wrong Tier.Value (READ_ONLY, not
// DESTRUCTIVE), not merely a wrong label on an otherwise-correct number.
// tierSourceDeclaredOverride's own string is asserted here as a literal,
// not the symbol, for the same structural-blindness reason
// CandidateAttributedByItsOwnSyntheticID gives.
func TestTestPolicyAgainstSampleInput_ExplicitTierOverride_Labelled(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	override := models.ActionTierDestructive
	body := policyTestRequest{
		Language: "cedar", Text: validateValidCedarPolicy,
		Action:       testInputAction{Tool: "Read", RawInput: `{"path":"/tmp/notes.txt"}`},
		DeclaredTier: &override,
	}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[policyTestResponse](t, rec)

	if got.Tier.Value != models.ActionTierDestructive {
		t.Errorf("Tier.Value = %s, want DESTRUCTIVE (the declared override), not whatever Read on a plain path would derive", got.Tier.Value)
	}
	if got.Tier.Source != "declared_override" {
		t.Errorf(`Tier.Source = %q, want "declared_override" -- a declared tier must never be labelled the same as a derived one`, got.Tier.Source)
	}
}

// TestTestPolicyAgainstSampleInput_EvidenceRuleNotLoweredByCatalogEntry is
// this task's own required mutation-5 target, given a dedicated test rather
// than left to accidental coverage: a tenant tool_catalog row fixes Bash at
// READ_ONLY (a tenant CAN write this today; nothing stops a mistaken or
// dishonest catalog entry), and the sample action's raw input is an
// unambiguous "rm -rf /" -- destructive evidence that authz.DeriveTier's
// own destructiveEvidence check must raise above whatever the catalog
// claims (tier.go's own doc comment: "an override or catalog entry higher
// than the evidence stands... evidence only ever raises"). A derivation
// that consulted the catalog and stopped there -- the exact shape of the
// required mutation -- would report READ_ONLY instead.
func TestTestPolicyAgainstSampleInput_EvidenceRuleNotLoweredByCatalogEntry(t *testing.T) {
	f := newPolicyTestFixture(t)
	readOnly := int64(models.ActionTierReadOnly)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()).
		AddRow("Bash", readOnly, "execute", nil, nil))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	body := policyTestRequest{
		Language: "cedar", Text: validateValidCedarPolicy,
		Action: testInputAction{Tool: "Bash", RawInput: `{"command":"rm -rf /"}`},
	}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[policyTestResponse](t, rec)

	if got.Tier.Value != models.ActionTierDestructive {
		t.Errorf("Tier.Value = %s, want DESTRUCTIVE -- a tenant catalog entry claiming Bash is READ_ONLY must "+
			"never mask raw destructive evidence (spec §4.4.1)", got.Tier.Value)
	}
}

// TestTestPolicyAgainstSampleInput_NeverWritesToDatabase is this task's own
// binding constraint, asserted directly: exactly the two reads this
// endpoint's own design calls for (tool_catalog for tier derivation,
// policies for the folded comparison) are registered, and
// assertExpectationsMet -- this package's established "assert against the
// database, not by inspection" idiom -- confirms nothing else was
// attempted. Verified live (mutation testing, not merely asserted): an
// extra write call added to the handler and its error checked/propagated
// the normal way this codebase's own style requires (errcheck is an
// enabled linter) is caught here -- sqlmock rejects the unregistered call,
// the handler surfaces it, and seven of this file's nine tests fail on a
// non-200 status.
//
// Documented limit, found the same way and reported rather than hidden:
// this proof is NOT closed against a write whose OWN error is explicitly
// discarded (`_, _ = s.store.Create...(...)`) at the call site -- sqlmock
// still rejects the unexpected call, but the rejection's error return is
// exactly what a `_, _ =` assignment throws away, so nothing downstream of
// it (this test included) can observe that the attempt was ever made. This
// is the identical shape Task 4's own report names: "a security property
// enforced at one level... survives exactly until someone" stops checking
// the return value that would have carried it, and that task's own finding
// was that only a live database closes it (an actual, unwanted INSERT
// either exists afterward or it does not, independent of whether the
// mutated code bothered to look at its own write's result) -- this
// package has no live-Postgres convention of its own to close it with
// (every task's real-Postgres proofs live in internal/store; cmd/
// stratium-pap is package main and cannot be imported into an external
// test package the way internal/store's own store_test can dial in).
func TestTestPolicyAgainstSampleInput_NeverWritesToDatabase(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	expectPolicyLoad(f.mock, sqlmock.NewRows(policyLoadColumns()))

	body := policyTestRequest{Language: "cedar", Text: validateValidCedarPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestTestPolicyAgainstSampleInput_InsufficientRole_Refused mirrors
// TestValidatePolicy_InsufficientRole_Refused for this endpoint -- see that
// test's own doc comment for why each authoring route proves its own
// role boundary rather than relying only on server_test.go's generic tables.
func TestTestPolicyAgainstSampleInput_InsufficientRole_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	body := policyTestRequest{Language: "cedar", Text: validateValidCedarPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-viewers"), body)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d for a viewer token", rec.Code, http.StatusForbidden)
	}
	assertExpectationsMet(t, f.mock)
}

// TestTestPolicyAgainstSampleInput_MalformedJSONBody_Refused is this
// endpoint's own instance of TestValidatePolicy_MalformedJSONBody_Refused
// (validate_test.go) -- see that test's own doc comment.
func TestTestPolicyAgainstSampleInput_MalformedJSONBody_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/policies/test", strings.NewReader("{not valid json"))
	req.Header.Set("Authorization", "Bearer "+f.token(t, "org-editors"))
	rec := httptest.NewRecorder()
	f.server.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d for a malformed body", rec.Code, http.StatusBadRequest)
	}
	assertExpectationsMet(t, f.mock)
}

// TestTestPolicyAgainstSampleInput_ToolCatalogLoadFails_Refused is this
// endpoint's own "fail closed... an unreadable catalog... refuses with a
// clear status" proof: LoadToolCatalog's own query erroring must not fall
// back to DefaultCatalog() as though the tenant simply had no rows (the
// identical line pdpgrpc/server.go's own LoadToolCatalog failure handling
// draws, and deriveOrDeclareTier's own doc comment states directly) -- it
// is this endpoint's own infrastructure failing, refused with 500 before
// either evaluation ever runs, never a 200 built on a guess.
func TestTestPolicyAgainstSampleInput_ToolCatalogLoadFails_Refused(t *testing.T) {
	f := newPolicyTestFixture(t)
	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM tool_catalog").WillReturnError(errors.New("connection reset by peer"))
	f.mock.ExpectRollback()

	body := policyTestRequest{Language: "cedar", Text: validateValidCedarPolicy}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusInternalServerError, rec.Body.String())
	}
	assertExpectationsMet(t, f.mock)
}

// TestTestPolicyAgainstSampleInput_ExistingPoliciesLoadFails_FoldedDeniesIsolatedStillAnswers
// is this task's own second fail-closed proof, and a sharper one than the
// tool_catalog case above: a failure loading the tenant's EXISTING policies
// only affects the FOLDED half of N9's answer -- candidateAppendingSource's
// own LoadAllPolicies call -- never the isolated half, which is backed by
// singlePolicySource and never touches the store at all. The whole request
// still succeeds (200): policy.Multi's own PrepareAll/Evaluate already fold
// a load failure into a single deny verdict (Source "none") rather than
// propagating a bare error (see Multi.Evaluate's own doc comment), so this
// endpoint inherits that fail-closed behavior for free, on the folded half
// only, exactly matching what "alongside the tenant's existing policies"
// should do when the tenant's existing policies cannot even be read: deny,
// not silently ALLOW, and not a 500 that would also hide the isolated
// half's own, still-valid answer.
func TestTestPolicyAgainstSampleInput_ExistingPoliciesLoadFails_FoldedDeniesIsolatedStillAnswers(t *testing.T) {
	f := newPolicyTestFixture(t)
	expectToolCatalogLoad(f.mock, sqlmock.NewRows(toolCatalogLoadColumns()))
	f.mock.ExpectBegin()
	f.mock.ExpectExec("set_config").WillReturnResult(sqlmock.NewResult(0, 0))
	f.mock.ExpectQuery("FROM policies").WillReturnError(errors.New("connection reset by peer"))
	f.mock.ExpectRollback()

	body := policyTestRequest{Language: "cedar", Text: `permit(principal, action, resource);`}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/policies/test", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
	got := decodeBody[policyTestResponse](t, rec)
	if got.Isolated.Effect != "ALLOW" {
		t.Errorf("Isolated.Effect = %q, want ALLOW -- a failure loading the TENANT's existing policies must not "+
			"affect the isolated half, which never reads them", got.Isolated.Effect)
	}
	if got.WithExistingPolicies.Effect != "DENY" {
		t.Errorf("WithExistingPolicies.Effect = %q, want DENY -- an unreadable set of existing policies must "+
			"fail closed, not silently allow", got.WithExistingPolicies.Effect)
	}
	assertExpectationsMet(t, f.mock)
}
