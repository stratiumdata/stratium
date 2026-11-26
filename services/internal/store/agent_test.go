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

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
)

func agentRowColumns() []string {
	return []string{"id", "tenant_id", "name", "provider", "model_id",
		"trust_tier", "enabled", "suspended", "allowed_tools", "classification_caps", "resource_constraints", "created_at", "updated_at", "escalate_at"}
}

// validAgent returns a models.Agent that passes validateAgentFields --
// every test below starts from a copy of this and breaks exactly one
// field, the same "one broken field per test" discipline oidc_test.go's
// validClaims establishes for this package's sibling cmd/stratium-pap
// tests.
func validAgent() models.Agent {
	return models.Agent{
		Name:         "billing-bot",
		Provider:     "anthropic",
		ModelID:      "claude-opus",
		TrustTier:    models.TrustTierCertified,
		Enabled:      true,
		Suspended:    false,
		AllowedTools: []string{"Read", "Bash"},
	}
}

// --- CreateAgent ---

func TestStore_CreateAgent_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertAgentQuery)).
		WithArgs(testTenant, "billing-bot", "anthropic", "claude-opus", int64(models.TrustTierCertified),
			true, false, []byte(`["Read","Bash"]`), []byte(`{}`), []byte(`{}`)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := s.CreateAgent(context.Background(), validAgent(), "operator-1", true)
	if err != nil {
		t.Fatalf("CreateAgent() error = %v", err)
	}
	if got.ID != id {
		t.Errorf("ID = %s, want %s (the RETURNING value)", got.ID, id)
	}
	if got.TenantID != testTenant {
		t.Errorf("TenantID = %q, want %q", got.TenantID, testTenant)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateAgent_RequiredFieldsRefusedBeforePersisting covers every
// field validateAgentFields checks, table-driven so each is its own
// sub-property with its own empty (zero-expectation) mock: a bug that
// removed just ONE of these checks fails only that field's own subtest,
// never masked by a sibling passing.
func TestStore_CreateAgent_RequiredFieldsRefusedBeforePersisting(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*models.Agent)
		wantErr error
	}{
		{"empty name", func(a *models.Agent) { a.Name = "" }, ErrInvalidRequest},
		{"empty provider", func(a *models.Agent) { a.Provider = "" }, ErrInvalidRequest},
		{"trust_tier below range", func(a *models.Agent) { a.TrustTier = -1 }, ErrInvalidRequest},
		{"trust_tier above range", func(a *models.Agent) { a.TrustTier = 4 }, ErrInvalidRequest},
		{"nil allowed_tools", func(a *models.Agent) { a.AllowedTools = nil }, ErrAllowedToolsRequired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, mock := newMockStore(t)
			a := validAgent()
			tt.mutate(&a)

			_, err := s.CreateAgent(context.Background(), a, "operator-1", true)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("CreateAgent() error = %v, want %v", err, tt.wantErr)
			}
			assertExpectationsMet(t, mock) // zero expectations: nothing may reach the database
		})
	}
}

// TestStore_CreateAgent_EmptyAllowedToolsIsAccepted is
// ErrAllowedToolsRequired's own negative control: an explicit, non-nil
// EMPTY slice ("allowed_tools": [] on the wire) is the operator's
// deliberate "unrestricted" declaration and must be accepted, distinct
// from the nil case the sibling subtest above refuses. Without this test,
// a mutant that refused ANY empty-length slice (nil or not) would still
// pass every other test in this file.
func TestStore_CreateAgent_EmptyAllowedToolsIsAccepted(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertAgentQuery)).
		WithArgs(testTenant, "billing-bot", "anthropic", "claude-opus", int64(models.TrustTierCertified),
			true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	a := validAgent()
	a.AllowedTools = []string{} // explicit, non-nil, empty -- "every tool"
	if _, err := s.CreateAgent(context.Background(), a, "operator-1", true); err != nil {
		t.Fatalf("CreateAgent() error = %v, want nil for an explicit empty allowed_tools", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_CreateAgent_DuplicateNameIsAlreadyExists(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertAgentQuery)).
		WillReturnError(&pq.Error{Code: sqlStateUniqueViolation, Message: `duplicate key value violates unique constraint "agents_tenant_id_name_key"`})
	mock.ExpectRollback()

	_, err := s.CreateAgent(context.Background(), validAgent(), "operator-1", true)
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("CreateAgent() error = %v, want ErrAlreadyExists", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_CreateAgent_AuditFailureRollsBackWrite is agent.go's own
// instance of N4's atomicity proof -- see policy_test.go's
// TestStore_CreatePolicy_AuditFailureRollsBackWrite for the full reasoning;
// the shape is identical because both call the same appendAuditTx.
func TestStore_CreateAgent_AuditFailureRollsBackWrite(t *testing.T) {
	s, mock := newMockStore(t)
	tailErr := errors.New("connection reset reading the chain tail")

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertAgentQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).
			AddRow(uuid.New().String(), time.Now(), time.Now()))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(tailErr)
	mock.ExpectRollback()

	if _, err := s.CreateAgent(context.Background(), validAgent(), "operator-1", true); err == nil {
		t.Fatal("CreateAgent() error = nil, want the audit tail-read failure to propagate")
	}

	assertExpectationsMet(t, mock)
}

// --- ClassificationCaps ---

// TestCreateAgent_IgnoresCallerSuppliedClassificationCaps replaces the old
// TestCreateAgent_RoundTripsClassificationCaps: that test asserted a caller-
// supplied cap round-tripped through Create, which is exactly the contract
// the controller ruling reverses. classification_caps is now written ONLY by
// SetAgentClassificationCaps/ClearAgentClassificationCaps (agent_caps.go);
// Create always inserts {} and the insertAgentQuery arg list below pins that
// -- it names the literal []byte(`{}`), never the request's "nato":"CONFIDENTIAL".
func TestCreateAgent_IgnoresCallerSuppliedClassificationCaps(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertAgentQuery)).
		WithArgs(testTenant, "capped", "anthropic", "", int64(models.TrustTierCertified),
			true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := s.CreateAgent(context.Background(), models.Agent{
		Name: "capped", Provider: "anthropic", TrustTier: models.TrustTierCertified,
		Enabled: true, AllowedTools: []string{},
		// A caller trying to set a cap at creation time. It must be ignored.
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
	}, "operator@example.com", true)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if len(got.ClassificationCaps) != 0 {
		t.Errorf("caps = %v, want {} -- Create must ignore a caller-supplied cap", got.ClassificationCaps)
	}

	assertExpectationsMet(t, mock)
}

// A nil map must persist as {} and not as SQL NULL: the column is NOT NULL, and
// {} is the documented "no cap" value.
func TestCreateAgent_NilCapsPersistsAsEmptyObject(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(insertAgentQuery)).
		WithArgs(testTenant, "uncapped", "anthropic", "", int64(models.TrustTierCertified),
			true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`)).
		WillReturnRows(sqlmock.NewRows([]string{"id", "created_at", "updated_at"}).AddRow(id.String(), now, now))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	got, err := s.CreateAgent(context.Background(), models.Agent{
		Name: "uncapped", Provider: "anthropic", TrustTier: models.TrustTierCertified,
		Enabled: true, AllowedTools: []string{}, ClassificationCaps: nil,
	}, "operator@example.com", true)
	if err != nil {
		t.Fatalf("CreateAgent: %v", err)
	}
	if got.ClassificationCaps == nil || len(got.ClassificationCaps) != 0 {
		t.Errorf("caps = %v, want an empty non-nil map", got.ClassificationCaps)
	}

	assertExpectationsMet(t, mock)
}

// --- GetAgent ---

func TestStore_GetAgent_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getAgentQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(agentRowColumns()).
			AddRow(id.String(), testTenant, "billing-bot", "anthropic", "claude-opus",
				int64(models.TrustTierCertified), true, false, []byte(`["Read","Bash"]`), []byte(`{"nato":"SECRET"}`),
				[]byte(`{"id_prefix":"/workspace/"}`), now, now, nil))
	mock.ExpectCommit()

	got, err := s.GetAgent(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if got.Name != "billing-bot" || len(got.AllowedTools) != 2 {
		t.Errorf("GetAgent() = %+v, want Name=billing-bot with 2 allowed tools", got)
	}
	if got.ClassificationCaps["nato"] != "SECRET" {
		t.Errorf("ClassificationCaps = %v, want nato=SECRET", got.ClassificationCaps)
	}
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("ResourceConstraints = %v, want id_prefix=/workspace/", got.ResourceConstraints)
	}
}

// A NULL model_id (a row predating any PAP write) must decode to "", not
// error.
func TestStore_GetAgent_NullModelIDDecodesAsEmptyString(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getAgentQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(agentRowColumns()).
			AddRow(id.String(), testTenant, "billing-bot", "anthropic", nil,
				int64(models.TrustTierCertified), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`), now, now, nil))
	mock.ExpectCommit()

	got, err := s.GetAgent(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAgent() error = %v", err)
	}
	if got.ModelID != "" {
		t.Errorf("ModelID = %q, want empty string for a NULL column", got.ModelID)
	}
}

// A corrupt allowed_tools column must fail loudly, never decode into an
// empty (meaning unrestricted) slice -- the same discipline LoadAgent's own
// TestStore_LoadAgent_DecodeFailure (store_test.go) already requires of the
// PDP's own read path, now proven for this table's second reader too.
func TestStore_GetAgent_CorruptAllowedToolsFailsLoudly(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getAgentQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows(agentRowColumns()).
			AddRow(id.String(), testTenant, "billing-bot", "anthropic", "claude-opus",
				int64(models.TrustTierCertified), true, false, []byte(`not-json`), []byte(`{}`), []byte(`{}`), now, now, nil))
	mock.ExpectRollback()

	got, err := s.GetAgent(context.Background(), id)
	if err == nil {
		t.Fatal("GetAgent() error = nil, want a decode error")
	}
	if len(got.AllowedTools) != 0 {
		t.Errorf("AllowedTools = %v, want empty/zero value on decode failure", got.AllowedTools)
	}
}

func TestStore_GetAgent_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(getAgentQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := s.GetAgent(context.Background(), id); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetAgent() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- ListAgents ---

// TestStore_ListAgents_IncludesSuspended is what distinguishes this method
// from LoadAgent's own by-id read: an admin screen must be able to see (and
// un-suspend) a suspended agent, so this list filters nothing.
func TestStore_ListAgents_IncludesSuspended(t *testing.T) {
	s, mock := newMockStore(t)
	now := time.Now()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listAgentsQuery)).
		WillReturnRows(sqlmock.NewRows(agentRowColumns()).
			AddRow(uuid.New().String(), testTenant, "active-bot", "anthropic", "", int64(1), true, false, []byte(`[]`), []byte(`{}`), []byte(`{}`), now, now, nil).
			AddRow(uuid.New().String(), testTenant, "suspended-bot", "anthropic", "", int64(1), true, true, []byte(`[]`), []byte(`{}`), []byte(`{}`), now, now, nil))
	mock.ExpectCommit()

	got, err := s.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListAgents() returned %d agents, want 2", len(got))
	}
	if !got[1].Suspended {
		t.Errorf("ListAgents()[1].Suspended = false, want true -- the suspended row must still be returned")
	}

	assertExpectationsMet(t, mock)
}

func TestStore_ListAgents_EmptyIsNotAnError(t *testing.T) {
	s, mock := newMockStore(t)

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(listAgentsQuery)).WillReturnRows(sqlmock.NewRows(agentRowColumns()))
	mock.ExpectCommit()

	got, err := s.ListAgents(context.Background())
	if err != nil {
		t.Fatalf("ListAgents() error = %v, want nil", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("ListAgents() = %v, want a non-nil empty slice", got)
	}

	assertExpectationsMet(t, mock)
}

// --- UpdateAgent ---

// expectAgentToolsBeforeRead registers UpdateAgent's locking read of the
// allowlist it is about to replace -- the first statement in that
// transaction since Task 7, which needs a baseline captured inside the
// transaction to judge the write against (containment_audit.go).
// beforeJSON is the column's stored bytes.
//
// Every caller below passes the SAME tool list the update then writes, so
// the write moves no permission dimension at all, no containment entry
// follows, and these sequences keep their single audit row. A test that
// wants the widening is TestStore_UpdateAgent_AuditsAToolWidening.
func expectAgentToolsBeforeRead(mock sqlmock.Sqlmock, beforeJSON string) {
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentToolsForUpdateQuery)).
		WillReturnRows(sqlmock.NewRows([]string{"allowed_tools"}).AddRow([]byte(beforeJSON)))
}

func TestStore_UpdateAgent_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAgentToolsBeforeRead(mock, `["Bash"]`)
	mock.ExpectQuery(regexp.QuoteMeta(updateAgentQuery)).
		WithArgs("renamed-bot", "anthropic", "claude-opus", int64(models.TrustTierPlatformTrusted),
			false, true, []byte(`["Bash"]`), id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"created_at", "updated_at", "classification_caps", "resource_constraints", "escalate_at"}).
			AddRow(now, now, []byte(`{"nato":"SECRET"}`), []byte(`{"id_prefix":"/workspace/"}`), nil))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	a := models.Agent{
		Name: "renamed-bot", Provider: "anthropic", ModelID: "claude-opus",
		TrustTier: models.TrustTierPlatformTrusted, Enabled: false, Suspended: true,
		AllowedTools: []string{"Bash"},
	}
	got, err := s.UpdateAgent(context.Background(), id, a, "operator-2", true)
	if err != nil {
		t.Fatalf("UpdateAgent() error = %v", err)
	}
	if got.ID != id {
		t.Errorf("ID = %s, want %s", got.ID, id)
	}
	if !got.Suspended {
		t.Errorf("Suspended = false, want true (round-tripped from the update)")
	}
	if got.ClassificationCaps["nato"] != "SECRET" {
		t.Errorf("ClassificationCaps = %v, want the row's stored nato=SECRET (read back via RETURNING, not echoed from the request, which set none)", got.ClassificationCaps)
	}
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("ResourceConstraints = %v, want the row's stored id_prefix=/workspace/ (read back via RETURNING, not echoed from the request, which set none)", got.ResourceConstraints)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_UpdateAgent_PreservesExistingCapsRegardlessOfRequestBody proves
// the CRITICAL fix directly: a request body that sets ClassificationCaps (or
// ResourceConstraints) does not reach the database at all --
// updateAgentQuery's arg list has no slot for either (see that query's own
// doc comment) -- and the row's existing values come back unchanged. Before
// this fix, PUT /v1/agents/{id} (RoleEditor) could set an unknown hierarchy,
// zero every cap to {}, or set one with no catch-all rule, all bypassing
// SetAgentClassificationCaps' validation and its RoleAdmin gate;
// resource_constraints is exposed to the identical hole by the same route and
// is proven here too.
func TestStore_UpdateAgent_PreservesExistingCapsRegardlessOfRequestBody(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	mock.ExpectBegin()
	expectSetTenant(mock)
	expectAgentToolsBeforeRead(mock, `["Bash"]`)
	mock.ExpectQuery(regexp.QuoteMeta(updateAgentQuery)).
		WithArgs("renamed-bot", "anthropic", "claude-opus", int64(models.TrustTierPlatformTrusted),
			false, true, []byte(`["Bash"]`), id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"created_at", "updated_at", "classification_caps", "resource_constraints", "escalate_at"}).
			AddRow(now, now, []byte(`{"nato":"SECRET"}`), []byte(`{"id_prefix":"/workspace/"}`), int64(4)))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	a := models.Agent{
		Name: "renamed-bot", Provider: "anthropic", ModelID: "claude-opus",
		TrustTier: models.TrustTierPlatformTrusted, Enabled: false, Suspended: true,
		AllowedTools: []string{"Bash"},
		// An attacker (or a stale-form editor) trying to smuggle a caps, a
		// resource-constraints, and an escalation change through the
		// whole-object PUT. All three must be ignored. A nil EscalateAt would
		// remove the threshold and let the agent act unattended.
		ClassificationCaps:  map[string]string{"nato": "UNCLASSIFIED"},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/"},
		EscalateAt:          nil,
	}
	got, err := s.UpdateAgent(context.Background(), id, a, "operator-2", true)
	if err != nil {
		t.Fatalf("UpdateAgent() error = %v", err)
	}
	if got.ClassificationCaps["nato"] != "SECRET" {
		t.Errorf("ClassificationCaps = %v, want the row's real nato=SECRET, not the request body's UNCLASSIFIED", got.ClassificationCaps)
	}
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("ResourceConstraints = %v, want the row's real id_prefix=/workspace/, not the request body's /", got.ResourceConstraints)
	}
	if got.EscalateAt == nil || *got.EscalateAt != models.ActionTierDestructive {
		t.Errorf("EscalateAt = %v, want the row's real DESTRUCTIVE, not the request body's nil", got.EscalateAt)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_UpdateAgent_RevalidatesFields(t *testing.T) {
	s, mock := newMockStore(t)

	a := validAgent()
	a.AllowedTools = nil // the same nil-refused rule Create enforces
	if _, err := s.UpdateAgent(context.Background(), uuid.New(), a, "operator-1", true); !errors.Is(err, ErrAllowedToolsRequired) {
		t.Errorf("UpdateAgent() error = %v, want ErrAllowedToolsRequired", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_UpdateAgent_NotFound pins that an id matching no row is
// ErrNotFound, not a silent no-op.
//
// The refusal now comes from the LOAD rather than the UPDATE (Task 7: the
// allowlist this update replaces is read first, under FOR UPDATE, so the
// containment verdict has a baseline). Same sentinel, same rollback, one
// statement earlier -- and the UPDATE's own sql.ErrNoRows branch stays where
// it is.
func TestStore_UpdateAgent_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(loadAgentToolsForUpdateQuery)).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if _, err := s.UpdateAgent(context.Background(), id, validAgent(), "operator-1", true); !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateAgent() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// --- DeleteAgent ---

// TestStore_DeleteAgent_Success pins the full audit argument list via
// insertArgsFor, the same discipline TestStore_DeletePolicy_Success
// (policy_test.go) applies -- see that test's own doc comment for why.
func TestStore_DeleteAgent_Success(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)

	wantEntry := audit.Entry{
		TenantID:      testTenant,
		OccurredAt:    now,
		EventType:     eventTypeAgentDeleted,
		Actor:         "operator-3",
		AgentID:       &id,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        "doomed-bot",
	}
	wantLinked := audit.Link(nil, wantEntry)
	wantHash := wantLinked.Hash()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteAgentQuery)).
		WithArgs(id.String()).
		WillReturnRows(sqlmock.NewRows([]string{"name"}).AddRow("doomed-bot"))
	expectAdvisoryLock(mock)
	mock.ExpectQuery(regexp.QuoteMeta(auditTailQuery)).WillReturnError(sql.ErrNoRows)
	mock.ExpectExec(regexp.QuoteMeta(insertAuditQuery)).
		WithArgs(insertArgsFor(wantLinked, wantHash)...).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := s.DeleteAgent(context.Background(), id, "operator-3", now); err != nil {
		t.Fatalf("DeleteAgent() error = %v", err)
	}

	assertExpectationsMet(t, mock)
}

func TestStore_DeleteAgent_NotFound(t *testing.T) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteAgentQuery)).
		WithArgs(id.String()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	if err := s.DeleteAgent(context.Background(), id, "operator-1", time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteAgent() error = %v, want ErrNotFound", err)
	}

	assertExpectationsMet(t, mock)
}

// TestStore_DeleteAgent_ForeignKeyViolationIsConflict is Issue 2's direct
// proof for the required mutation "map the FK violation back to 500": a
// Postgres foreign_key_violation from the DELETE (a delegation or approval
// still naming this agent, per agents.id's ON DELETE RESTRICT) must be
// mapped to ErrConflict, not left as an unrecognized error that
// cmd/stratium-pap/respond.go's writeStoreError would fall through to its
// default 500 case.
func TestStore_DeleteAgent_ForeignKeyViolationIsConflict(t *testing.T) {
	// PostgreSQL 17 and earlier raise the first code, 18 and later the second.
	for _, code := range []pq.ErrorCode{sqlStateForeignKeyViolation, sqlStateRestrictViolation} {
		t.Run(string(code), func(t *testing.T) { deleteAgentRefusedIsConflict(t, code) })
	}
}

func deleteAgentRefusedIsConflict(t *testing.T, code pq.ErrorCode) {
	s, mock := newMockStore(t)
	id := uuid.New()

	mock.ExpectBegin()
	expectSetTenant(mock)
	mock.ExpectQuery(regexp.QuoteMeta(deleteAgentQuery)).
		WithArgs(id.String()).
		WillReturnError(&pq.Error{
			Code:    code,
			Message: `update or delete on table "agents" violates foreign key constraint "delegations_agent_id_fkey" on table "delegations"`,
			Detail:  `Key (id)=(deadbeef-0000-0000-0000-000000000000) is still referenced from table "delegations".`,
		})
	mock.ExpectRollback()

	err := s.DeleteAgent(context.Background(), id, "operator-1", time.Now())
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("DeleteAgent() error = %v, want errors.Is(_, ErrConflict)", err)
	}
	// The required mutation this test also catches, from the OTHER
	// direction: a fix that maps the violation to ErrConflict but does so by
	// echoing the raw Postgres error text (e.g. wrapping err.Error() instead
	// of building a fixed message) would leak schema/constraint detail no
	// operator needs — this message is built from id and a fixed string,
	// never from the underlying pq.Error's own Message/Detail.
	if strings.Contains(err.Error(), "delegations_agent_id_fkey") || strings.Contains(err.Error(), "still referenced from table") {
		t.Errorf("DeleteAgent() error = %q, must not echo the underlying Postgres constraint/detail text", err.Error())
	}

	assertExpectationsMet(t, mock)
}
