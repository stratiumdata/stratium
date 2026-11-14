package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/policy/cedar"
	"github.com/stratiumdata/stratium/internal/policy/jsonpolicy"
	"github.com/stratiumdata/stratium/internal/policy/rego"
	"github.com/stratiumdata/stratium/internal/policy/xacml"
	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
)

func policyColumns() []string {
	return []string{"id", "name", "language", "policy_content", "priority", "version"}
}

// addPolicyRow appends p as one loadAllPoliciesQuery result row, in that
// query's column order.
func addPolicyRow(rows *sqlmock.Rows, p policy.StoredPolicy) *sqlmock.Rows {
	return rows.AddRow(p.ID, p.Name, p.Language, p.Text, p.Priority, p.Version)
}

// testPolicy returns a StoredPolicy with every queried field set to a
// distinguishable value. Priority is non-zero on purpose: it is the field
// 000009_policy_priority added a column for, and a zero here would let a
// dropped scan target pass every round-trip assertion below, which is exactly
// how the value went unnoticed as structurally-always-zero for two phases.
// Version differs from Priority so transposing the two adjacent scan targets
// fails rather than silently swapping equal numbers — the two are directly
// adjacent in loadAllPoliciesQuery's column order since Phase 4a Task 4
// dropped the effect column that used to sit between them.
func testPolicy(id, name string) policy.StoredPolicy {
	return policy.StoredPolicy{
		ID:       id,
		Name:     name,
		Language: "cedar",
		Text:     "permit(principal, action, resource);",
		Priority: 7,
		Version:  1,
	}
}

// --- LoadAllPolicies ---

// loadAllPoliciesQuery's own text is asserted directly, independent of the
// mock-plumbing tests below: sqlmock never executes real SQL, so the only
// way a unit test can pin "disabled rows are excluded," "ordered by id," and
// "regardless of language" as properties of the query itself — rather than
// merely "whatever text the mock was told to expect" — is to inspect that
// text. Also pins the same no-WHERE-tenant_id discipline the package doc
// requires of every query. The "regardless of language" property is
// asserted here as the query having no language predicate at all, and
// separately, below, as a behavioral test that rows from several different
// languages all come back in one call.
func TestLoadAllPoliciesQuery_FiltersEnabledOrdersByIDAndIgnoresLanguage(t *testing.T) {
	if !strings.Contains(loadAllPoliciesQuery, "enabled = true") {
		t.Errorf("loadAllPoliciesQuery = %q, want it to filter on enabled = true", loadAllPoliciesQuery)
	}
	if !strings.Contains(loadAllPoliciesQuery, "ORDER BY id") {
		t.Errorf("loadAllPoliciesQuery = %q, want ORDER BY id", loadAllPoliciesQuery)
	}
	if strings.Contains(loadAllPoliciesQuery, "tenant_id") {
		t.Errorf("loadAllPoliciesQuery = %q, must not reference tenant_id — RLS is the only tenant boundary", loadAllPoliciesQuery)
	}
	// "language" alone would also match the selected column name, so the
	// filter form itself is what's checked for absence.
	if strings.Contains(loadAllPoliciesQuery, "language =") {
		t.Errorf("loadAllPoliciesQuery = %q, must not filter on language — it loads every language a tenant has authored in one call", loadAllPoliciesQuery)
	}
}

// Rows spanning three different languages all come back in one call — the
// behavioral proof that this is a single query with no language filter at
// all, not one call repeated per language.
func TestStore_LoadAllPolicies_ReturnsEveryLanguage(t *testing.T) {
	s, mock := newMockStore(t)
	cedarPolicy := testPolicy("11111111-1111-1111-1111-111111111111", "cedar-one")
	regoPolicy := testPolicy("22222222-2222-2222-2222-222222222222", "rego-one")
	regoPolicy.Language = "rego"
	jsonPolicy := testPolicy("33333333-3333-3333-3333-333333333333", "json-one")
	jsonPolicy.Language = "json"
	want := []policy.StoredPolicy{cedarPolicy, regoPolicy, jsonPolicy}

	mock.ExpectBegin()
	expectSetTenant(mock)
	rows := sqlmock.NewRows(policyColumns())
	for _, p := range want {
		addPolicyRow(rows, p)
	}
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(rows)
	mock.ExpectCommit()

	got, err := s.LoadAllPolicies(context.Background())
	if err != nil {
		t.Fatalf("LoadAllPolicies() error = %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("LoadAllPolicies() returned %d policies, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("policy[%d] = %+v, want %+v", i, got[i], want[i])
		}
		// Redundant with the struct comparison above, and kept deliberately:
		// it fails loudly if testPolicy's Priority is ever reset to zero,
		// which would make the comparison above pass while proving nothing
		// about the column 000009 added. Priority spent two phases
		// structurally-always-zero specifically because no test caught a
		// fixture regression shaped exactly like that.
		if got[i].Priority == 0 {
			t.Errorf("policy[%d].Priority = 0, want the stored value round-tripped", i)
		}
	}

	assertExpectationsMet(t, mock)
}

// A tenant with no policies in any language is an ordinary, empty result,
// not an error: the caller gets a non-nil, zero-length slice so it can
// prepare an empty policy set without a nil check, and a nil error so
// nothing downstream mistakes "no policies" for "something broke."
func TestStore_LoadAllPolicies_EmptyResultReturnsEmptyNonNilSlice(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(sqlmock.NewRows(policyColumns()))
	mock.ExpectCommit()

	got, err := s.LoadAllPolicies(context.Background())
	if err != nil {
		t.Fatalf("LoadAllPolicies() error = %v, want nil — no policies is not an error", err)
	}
	if got == nil {
		t.Fatal("LoadAllPolicies() returned a nil slice, want a non-nil empty slice")
	}
	if len(got) != 0 {
		t.Fatalf("LoadAllPolicies() returned %d policies, want 0", len(got))
	}

	assertExpectationsMet(t, mock)
}

func TestStore_LoadAllPolicies_QueryErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	dbErr := errors.New("connection reset")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnError(dbErr)
	mock.ExpectRollback()

	got, err := s.LoadAllPolicies(context.Background())
	if err == nil {
		t.Fatal("LoadAllPolicies() error = nil, want error")
	}
	if got != nil {
		t.Errorf("LoadAllPolicies() = %v, want nil on query failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A row that cannot scan into StoredPolicy's types — here, a version column
// that isn't a valid int64 — must fail loudly and roll back, not silently
// truncate or zero the field.
func TestStore_LoadAllPolicies_RowScanErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)

	rows := sqlmock.NewRows(policyColumns()).
		AddRow("id-1", "bad-version", "cedar", "permit(principal, action, resource);", 7, "not-a-version")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadAllPolicies(context.Background())
	if err == nil {
		t.Fatal("LoadAllPolicies() error = nil, want scan error")
	}
	if got != nil {
		t.Errorf("LoadAllPolicies() = %v, want nil on scan failure", got)
	}

	assertExpectationsMet(t, mock)
}

// A failure partway through iteration (connection dropped after some rows
// already arrived) must discard whatever was collected so far and return an
// error, never a silently truncated policy set — half a tenant's policies
// enforced as if it were the whole set is worse than an outright failure.
func TestStore_LoadAllPolicies_RowsIterationErrorPropagates(t *testing.T) {
	s, mock := newMockStore(t)
	iterErr := errors.New("connection dropped mid-stream")

	rows := sqlmock.NewRows(policyColumns())
	addPolicyRow(rows, testPolicy("id-1", "first"))
	addPolicyRow(rows, testPolicy("id-2", "second"))
	addPolicyRow(rows, testPolicy("id-3", "third")).RowError(2, iterErr)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAllPoliciesQuery)).WillReturnRows(rows)
	mock.ExpectRollback()

	got, err := s.LoadAllPolicies(context.Background())
	if !errors.Is(err, iterErr) {
		t.Fatalf("LoadAllPolicies() error = %v, want it to wrap %v", err, iterErr)
	}
	if got != nil {
		t.Errorf("LoadAllPolicies() = %v, want nil when row iteration fails partway through", got)
	}

	assertExpectationsMet(t, mock)
}

// --- PAP CRUD (Task 3) ---

// testRegistry wires all four real engines -- the same set
// cmd/stratium-pap/registry.go's newPolicyRegistry builds for the actual
// binary -- so validatePolicyText's own tests run against the genuine
// Validate implementations, never a stub that could accept something the
// real engines would reject.
func testRegistry() policy.Registry {
	return policy.Registry{
		"cedar": cedar.New(),
		"json":  jsonpolicy.New(),
		"rego":  rego.New(),
		"xacml": xacml.New(),
	}
}

// Fixtures below are chosen, not invented: each valid text is copied from
// (or is the identical shape of) that engine's own bench_test.go fixture,
// already proven to compile; each invalid text is the exact scenario the
// task brief names by name -- a Rego module with a typo'd package, a JSON
// "in": [], an XACML document naming an out-of-vocabulary tier -- plus a
// Cedar case (`in []` on an empty set, jsonpolicy's own "in": [] defect one
// language over) since the brief's own three examples do not cover all
// four engines this property must hold for.
const (
	validCedarPolicy   = `permit(principal == User::"alice", action, resource);`
	invalidCedarPolicy = `permit(principal, action, resource) when { resource in [] };`

	validRegoPolicy   = "package stratium.policy\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}"
	invalidRegoPolicy = "package stratium.polic\n\nallow if {\n\tinput.principal.subject == \"alice\"\n}"

	validJSONPolicy   = `{"effect": "allow", "match": {}}`
	invalidJSONPolicy = `{"effect": "allow", "match": {"tool": {"in": []}}}`

	validXACMLPolicy = `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target><AnyOf><AllOf>
    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">DESTRUCTIVE</AttributeValue>
      <AttributeDesignator AttributeId="derived-tier" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"/>
    </Match>
  </AllOf></AnyOf></Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
	invalidXACMLPolicy = `<Policy PolicyId="p1" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target><AnyOf><AllOf>
    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
      <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">ULTRA_DESTRUCTIVE</AttributeValue>
      <AttributeDesignator AttributeId="derived-tier" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"/>
    </Match>
  </AllOf></AnyOf></Target>
  <Rule RuleId="r1" Effect="Permit"/>
</Policy>`
)

func policyRowColumns() []string {
	return []string{"id", "tenant_id", "name", "description", "language",
		"policy_content", "effect", "version", "enabled", "created_at", "updated_at"}
}

// --- CreatePolicy ---

// TestStore_CreatePolicy_ValidPolicyPersistsForEveryLanguage is Property 2's
// positive case, run against all four real engines: a well-formed policy in
// each language passes Validate and is inserted, with the audit chain
// written in the same transaction (mutation target: "persist without
// auditing" -- absent that write below, ExpectCommit would be the next
// registered expectation and sqlmock would fail this test the moment the
// real code asked for something else instead).
//
// effect is per-language, not a single "allow" reused for all four, since
// Issue 1's validateEffectAgreement now checks it: cedar/json must equal
// what their own fixture text actually declares (validCedarPolicy is a
// permit(...) statement; validJSONPolicy's own "effect" key is "allow"),
// and rego/xacml -- not single-valued, see that function's own doc comment
// -- must be multiValuedLanguageEffect regardless of what their fixture
// text's rules happen to look like. TestStore_CreatePolicy_EffectAgreement*
// below are this property's own dedicated, per-behavior tests; this table
// only needs each case to be INTERNALLY consistent so the create itself
// still succeeds.
func TestStore_CreatePolicy_ValidPolicyPersistsForEveryLanguage(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		language string
		text     string
		effect   string
	}{
		{"cedar", validCedarPolicy, "allow"},
		{"rego", validRegoPolicy, multiValuedLanguageEffect},
		{"json", validJSONPolicy, "allow"},
		{"xacml", validXACMLPolicy, multiValuedLanguageEffect},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			s, mock := newMockStore(t)
			id := uuid.New()
			now := time.Now().UTC().Truncate(time.Second)

			mock.ExpectBegin()
			expectSetTenant(mock)
			mock.ExpectQuery(regexp.QuoteMeta(insertPolicyQuery)).
				WithArgs(testTenant, "a-policy", "", tt.language, tt.text, tt.effect, true).
				WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
					AddRow(id.String(), now, now))
			expectAdvisoryLock(mock)
			mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
			mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()

			p := models.Policy{Name: "a-policy", Language: tt.language, Text: tt.text, Effect: tt.effect, Enabled: true}
			got, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
			if err != nil {
				t.Fatalf("CreatePolicy() error = %v, want nil for a well-formed %s policy", err, tt.language)
			}
			if got.ID != id {
				t.Errorf("ID = %s, want %s (the RETURNING value)", got.ID, id)
			}
			if got.TenantID != testTenant {
				t.Errorf("TenantID = %q, want %q (caller-supplied TenantID must be ignored)", got.TenantID, testTenant)
			}
			if got.Version != 1 {
				t.Errorf("Version = %d, want 1 for a freshly created policy", got.Version)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// --- Issue 1: policies.effect must agree with policy text (Phase 14 Task 3) ---

// TestStore_CreatePolicy_EffectAgreement_MismatchRefused is the direct proof
// for the required mutation "skip the effect-agreement check": for the two
// languages where a stored policy's effect is single-valued and derivable
// from its own text (see validateEffectAgreement's own doc comment), a
// declared effect that contradicts the text is refused with
// ErrEffectMismatch, and nothing is persisted (the mock below registers
// zero expectations, so any reach into beginTenantTx fails the test).
func TestStore_CreatePolicy_EffectAgreement_MismatchRefused(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		language string
		text     string
		effect   string
	}{
		// permit(...) declares "allow"; the request claims "deny".
		{"cedar", validCedarPolicy, "deny"},
		// The JSON text's own "effect" key is "allow"; the request claims "deny".
		{"json", validJSONPolicy, "deny"},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			s, mock := newMockStore(t) // no expectations registered at all

			p := models.Policy{Name: "contradicts-its-own-text", Language: tt.language, Text: tt.text, Effect: tt.effect, Enabled: true}
			_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
			if !errors.Is(err, ErrEffectMismatch) {
				t.Errorf("CreatePolicy() error = %v, want errors.Is(_, ErrEffectMismatch)", err)
			}

			assertExpectationsMet(t, mock) // nothing reached the database
		})
	}
}

// TestStore_CreatePolicy_EffectAgreement_AgreesAccepted is the mismatch
// test's positive counterpart, named for the same property from the other
// side: a declared effect that DOES agree with what cedar/json's own text
// says is accepted and persisted, proven by letting the mock's write
// expectation actually be consumed (a stricter proof than merely checking
// err == nil, which a mutant returning nil without ever calling
// beginTenantTx would also satisfy).
func TestStore_CreatePolicy_EffectAgreement_AgreesAccepted(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		language string
		text     string
		effect   string
	}{
		{"cedar", validCedarPolicy, "allow"},
		{"json", validJSONPolicy, "allow"},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			s, mock := newMockStore(t)
			now := time.Now().UTC().Truncate(time.Second)

			mock.ExpectBegin()
			expectSetTenant(mock)
			mock.ExpectQuery(regexp.QuoteMeta(insertPolicyQuery)).
				WithArgs(testTenant, "agrees-with-its-own-text", "", tt.language, tt.text, tt.effect, true).
				WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
					AddRow(uuid.New().String(), now, now))
			expectAdvisoryLock(mock)
			mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
			mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()

			p := models.Policy{Name: "agrees-with-its-own-text", Language: tt.language, Text: tt.text, Effect: tt.effect, Enabled: true}
			if _, err := s.CreatePolicy(context.Background(), registry, p, "operator-1"); err != nil {
				t.Fatalf("CreatePolicy() error = %v, want nil when effect agrees with text", err)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// TestStore_CreatePolicy_NotSingleValued_NonSentinelEffectRefused pins the
// decision this task made for rego/xacml (see validateEffectAgreement's own
// doc comment for the justification): a stored policy in either language
// can itself produce both an allow and a deny outcome depending on the
// request, so the column cannot be a claim about that policy at all, and
// this package refuses any operator-supplied value other than the fixed
// sentinel rather than accepting one it cannot check.
func TestStore_CreatePolicy_NotSingleValued_NonSentinelEffectRefused(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		language string
		text     string
	}{
		{"rego", validRegoPolicy},
		{"xacml", validXACMLPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			s, mock := newMockStore(t) // no expectations registered at all

			p := models.Policy{Name: "claims-a-single-effect", Language: tt.language, Text: tt.text, Effect: "allow", Enabled: true}
			_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
			if !errors.Is(err, ErrEffectNotDeclarable) {
				t.Errorf("CreatePolicy() error = %v, want errors.Is(_, ErrEffectNotDeclarable)", err)
			}

			assertExpectationsMet(t, mock) // nothing reached the database
		})
	}
}

// TestStore_CreatePolicy_NotSingleValued_SentinelAccepted is
// NonSentinelEffectRefused's positive counterpart: the ONE value this
// package accepts for rego/xacml -- multiValuedLanguageEffect -- is
// accepted and persisted, proven the same stricter way (a consumed write
// expectation, not merely err == nil).
func TestStore_CreatePolicy_NotSingleValued_SentinelAccepted(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		language string
		text     string
	}{
		{"rego", validRegoPolicy},
		{"xacml", validXACMLPolicy},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			s, mock := newMockStore(t)
			now := time.Now().UTC().Truncate(time.Second)

			mock.ExpectBegin()
			expectSetTenant(mock)
			mock.ExpectQuery(regexp.QuoteMeta(insertPolicyQuery)).
				WithArgs(testTenant, "uses-the-sentinel", "", tt.language, tt.text, multiValuedLanguageEffect, true).
				WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
					AddRow(uuid.New().String(), now, now))
			expectAdvisoryLock(mock)
			mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
			mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
			mock.ExpectCommit()

			p := models.Policy{Name: "uses-the-sentinel", Language: tt.language, Text: tt.text, Effect: multiValuedLanguageEffect, Enabled: true}
			if _, err := s.CreatePolicy(context.Background(), registry, p, "operator-1"); err != nil {
				t.Fatalf("CreatePolicy() error = %v, want nil for the sentinel effect", err)
			}

			assertExpectationsMet(t, mock)
		})
	}
}

// TestStore_CreatePolicy_InvalidPolicyTextRefusedBeforePersisting is
// Property 2's negative case and the direct proof for the required mutation
// "skip Validate": each fixture is syntactically well-formed in its own
// language but semantically dead, so a mutant that removed the
// validatePolicyText call would sail past it straight into beginTenantTx --
// which would immediately fail against this test's deliberately EMPTY mock
// (zero expectations registered) with a distinctive "was not expected"
// error, never containing the engine's own "<language>: validate:" prefix
// this test asserts on. That is what makes this assertion catch the
// mutation rather than merely detect "some error happened."
func TestStore_CreatePolicy_InvalidPolicyTextRefusedBeforePersisting(t *testing.T) {
	registry := testRegistry()
	tests := []struct {
		language   string
		text       string
		wantSubstr string
	}{
		{"cedar", invalidCedarPolicy, "cedar: validate"},
		{"rego", invalidRegoPolicy, "rego: validate"},
		{"json", invalidJSONPolicy, "json: validate"},
		{"xacml", invalidXACMLPolicy, "xacml: validate"},
	}
	for _, tt := range tests {
		t.Run(tt.language, func(t *testing.T) {
			s, mock := newMockStore(t) // no expectations registered at all

			p := models.Policy{Name: "dead-on-arrival", Language: tt.language, Text: tt.text, Effect: "allow"}
			_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
			if err == nil {
				t.Fatal("CreatePolicy() error = nil, want a validation error for a semantically dead policy")
			}
			if !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("CreatePolicy() error = %q, want it to contain %q (proving the real engine rejected it, "+
					"not a database call that should never have happened)", err.Error(), tt.wantSubstr)
			}

			// Nothing was persisted: not one query or exec reached the
			// (empty) mock. If it had, the assertion above would already
			// have failed on the mismatched error text.
			assertExpectationsMet(t, mock)
		})
	}
}

func TestStore_CreatePolicy_EmptyNameRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()

	p := models.Policy{Name: "", Language: "cedar", Text: validCedarPolicy, Effect: "allow"}
	_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("CreatePolicy() error = %v, want ErrInvalidRequest", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreatePolicy_InvalidEffectRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()

	p := models.Policy{Name: "p1", Language: "cedar", Text: validCedarPolicy, Effect: "maybe"}
	_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
	if !errors.Is(err, ErrInvalidEffect) {
		t.Errorf("CreatePolicy() error = %v, want ErrInvalidEffect", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreatePolicy_UnknownLanguageRefusedBeforePersisting(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()

	p := models.Policy{Name: "p1", Language: "cobol", Text: "PROGRAM-ID. ALLOW.", Effect: "allow"}
	_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
	if !errors.Is(err, ErrUnknownLanguage) {
		t.Errorf("CreatePolicy() error = %v, want ErrUnknownLanguage", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreatePolicy_DuplicateNameIsAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertPolicyQuery)).
		WillReturnError(&pq.Error{Code: sqlStateUniqueViolation, Message: `duplicate key value violates unique constraint "policies_tenant_id_name_key"`})
	mock.ExpectRollback()

	p := models.Policy{Name: "dup", Language: "cedar", Text: validCedarPolicy, Effect: "allow"}
	_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("CreatePolicy() error = %v, want ErrAlreadyExists", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreatePolicy_AuditFailureRollsBackWrite is N4's own proof and
// the direct target of the required mutation "audit outside the write's
// transaction": the policy INSERT succeeds, but the audit append's own
// advisory-lock step (the first statement appendAuditTx issues) fails.
// Because both run against the same tx, that failure must abort the
// transaction as a whole -- ExpectRollback is the next (and only remaining)
// registered expectation, never ExpectCommit, so a mutant that moved the
// audit call to AFTER tx.Commit() (or to a second, separate transaction via
// AppendAudit instead of appendAuditTx) would either commit the policy row
// before ever reaching this failure, or open a second, unexpected
// transaction against this same single-transaction mock -- either way,
// sqlmock's ordered matching fails this test.
func TestStore_CreatePolicy_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()
	lockErr := errors.New("connection reset mid-audit")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertPolicyQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New().String(), time.Now(), time.Now()))
	mock.ExpectExec(regexp.QuoteMeta(advisoryLockQuery)).WillReturnError(lockErr)
	mock.ExpectRollback()

	p := models.Policy{Name: "p1", Language: "cedar", Text: validCedarPolicy, Effect: "allow", Enabled: true}
	_, err := s.CreatePolicy(context.Background(), registry, p, "operator-1")
	if err == nil {
		t.Fatal("CreatePolicy() error = nil, want the audit failure to propagate")
	}

	// The row the INSERT produced must not survive: this mock never
	// registered a Commit expectation, so if the real code tried to call
	// one, assertExpectationsMet below would report it as unmet-vs-extra
	// rather than silently passing. A separate, live-Postgres version of
	// this exact property (a genuinely rolled-back row, not just an
	// un-called Commit) is TestIntegration_PAPCRUD_AuditFailureRollsBack
	// WriteEndToEnd (pap_crud_integration_test.go).
	assertExpectationsMet(t, mock)
}

// --- GetPolicy ---

func TestStore_GetPolicy_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getPolicyQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(policyRowColumns()).
			AddRow(id.String(), testTenant, "p1", "a description", "cedar", validCedarPolicy, "allow", int64(3), true, now, now))
	mock.ExpectCommit()

	got, err := s.GetPolicy(context.Background(), id)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got.Name != "p1" || got.Description != "a description" || got.Version != 3 {
		t.Errorf("GetPolicy() = %+v, want Name=p1 Description=%q Version=3", got, "a description")
	}
}

// A NULL description (a row predating any PAP write, or one that never set
// it) must decode to "", not error and not panic.
func TestStore_GetPolicy_NullDescriptionDecodesAsEmptyString(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getPolicyQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(policyRowColumns()).
			AddRow(id.String(), testTenant, "p1", nil, "cedar", validCedarPolicy, "allow", int64(1), true, now, now))
	mock.ExpectCommit()

	got, err := s.GetPolicy(context.Background(), id)
	if err != nil {
		t.Fatalf("GetPolicy() error = %v", err)
	}
	if got.Description != "" {
		t.Errorf("Description = %q, want empty string for a NULL column", got.Description)
	}
}

func TestStore_GetPolicy_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getPolicyQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	_, err := s.GetPolicy(context.Background(), id)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("GetPolicy() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- ListPolicies ---

// TestStore_ListPolicies_IncludesDisabled is what distinguishes this method
// from LoadAllPolicies above: an admin screen must be able to see (and
// re-enable) a disabled policy, so this list is never filtered by enabled.
func TestStore_ListPolicies_IncludesDisabled(t *testing.T) {
	s, mock := newMockStore(t)
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listPoliciesQuery)).
		WillReturnRows(sqlmock.NewRows(policyRowColumns()).
			AddRow(uuid.New().String(), testTenant, "enabled-one", "", "cedar", validCedarPolicy, "allow", int64(1), true, now, now).
			AddRow(uuid.New().String(), testTenant, "disabled-one", "", "rego", validRegoPolicy, "deny", int64(2), false, now, now))
	mock.ExpectCommit()

	got, err := s.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListPolicies() returned %d policies, want 2", len(got))
	}
	if got[1].Enabled {
		t.Errorf("ListPolicies()[1].Enabled = true, want false -- the disabled row must still be returned")
	}

	assertExpectationsMet(t, mock)
}

func TestStore_ListPolicies_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listPoliciesQuery)).WillReturnRows(sqlmock.NewRows(policyRowColumns()))
	mock.ExpectCommit()

	got, err := s.ListPolicies(context.Background())
	if err != nil {
		t.Fatalf("ListPolicies() error = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("ListPolicies() = %v, want a non-nil empty slice", got)
	}

	assertExpectationsMet(t, mock)
}

// --- UpdatePolicy ---

func TestStore_UpdatePolicy_Success(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updatePolicyQuery)).
		WithArgs("renamed", "new description", "rego", validRegoPolicy, "deny", false, id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"version", "created_at", "updated_at"}).
			AddRow(int64(2), now, now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	p := models.Policy{Name: "renamed", Description: "new description", Language: "rego", Text: validRegoPolicy, Effect: "deny", Enabled: false}
	got, err := s.UpdatePolicy(context.Background(), registry, id, p, "operator-2")
	if err != nil {
		t.Fatalf("UpdatePolicy() error = %v", err)
	}
	if got.Version != 2 {
		t.Errorf("Version = %d, want 2 (RETURNING value after version = version + 1)", got.Version)
	}
	if got.ID != id {
		t.Errorf("ID = %s, want %s", got.ID, id)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_UpdatePolicy_RevalidatesText proves re-validation is not
// skipped on the update path -- a second, independent anchor for the "skip
// Validate" mutation, at the sibling method CreatePolicy's own test
// already covers.
func TestStore_UpdatePolicy_RevalidatesText(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()

	p := models.Policy{Name: "p1", Language: "json", Text: invalidJSONPolicy, Effect: "allow"}
	_, err := s.UpdatePolicy(context.Background(), registry, uuid.New(), p, "operator-1")
	if err == nil {
		t.Fatal("UpdatePolicy() error = nil, want a validation error")
	}
	if !strings.Contains(err.Error(), "json: validate") {
		t.Errorf("UpdatePolicy() error = %q, want it to contain %q", err.Error(), "json: validate")
	}

	assertExpectationsMet(t, mock)
}

// TestStore_UpdatePolicy_RevalidatesEffectAgreement is
// RevalidatesText's own sibling for Issue 1: re-checking policies.effect
// against the text is not skipped on the update path either -- a second,
// independent anchor for the "skip the effect-agreement check" mutation, at
// CreatePolicy's own TestStore_CreatePolicy_EffectAgreement_MismatchRefused.
func TestStore_UpdatePolicy_RevalidatesEffectAgreement(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()

	// permit(...) declares "allow"; the request claims "deny".
	p := models.Policy{Name: "p1", Language: "cedar", Text: validCedarPolicy, Effect: "deny"}
	_, err := s.UpdatePolicy(context.Background(), registry, uuid.New(), p, "operator-1")
	if !errors.Is(err, ErrEffectMismatch) {
		t.Errorf("UpdatePolicy() error = %v, want errors.Is(_, ErrEffectMismatch)", err)
	}

	assertExpectationsMet(t, mock) // nothing reached the database
}

func TestStore_UpdatePolicy_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	registry := testRegistry()
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(updatePolicyQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	p := models.Policy{Name: "p1", Language: "cedar", Text: validCedarPolicy, Effect: "allow"}
	_, err := s.UpdatePolicy(context.Background(), registry, id, p, "operator-1")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdatePolicy() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- DeletePolicy ---

// TestStore_DeletePolicy_Success asserts the FULL audit insert argument
// list, via the same insertArgsFor helper audit_test.go's own AppendAudit
// tests use — not a hand-typed 22-value list of this test's own, which
// would only prove "the args I re-derived by hand from insertAuditQuery's
// column order happen to match," a weaker and more error-prone claim. Both
// the RETURNING-supplied name (captured for Reason) and DeletePolicy's own
// EventType/PolicyID/Actor/OccurredAt mapping are pinned by constructing
// the exact audit.Entry DeletePolicy should build and letting audit.Link/
// insertArgsFor (production code this package already trusts, per
// audit_test.go) derive what the INSERT must look like from it.
func TestStore_DeletePolicy_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	wantEntry := audit.Entry{
		TenantID:      testTenant,
		OccurredAt:    now,
		EventType:     eventTypePolicyDeleted,
		Actor:         "operator-3",
		PolicyID:      id.String(),
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        "doomed-policy",
	}
	wantLinked := audit.Link(nil, wantEntry)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deletePolicyQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("doomed-policy"))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.DeletePolicy(context.Background(), id, "operator-3", now); err != nil {
		t.Fatalf("DeletePolicy() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_DeletePolicy_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deletePolicyQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if err := s.DeletePolicy(context.Background(), id, "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeletePolicy() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}
