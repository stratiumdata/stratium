package postgres

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"stratium/pkg/models"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func setupPolicyRepoTest(t *testing.T) (*PolicyRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := NewPolicyRepository(sqlxDB)

	cleanup := func() {
		db.Close()
	}

	return repo, mock, cleanup
}

func TestNewPolicyRepository(t *testing.T) {
	db, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	assert.NotNil(t, db)
	assert.NotNil(t, mock)
}

func TestPolicyRepository_Create(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()
	now := time.Now()

	policy := &models.Policy{
		ID:            policyID,
		Name:          "test-policy",
		Description:   "Test policy description",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"test": "content"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      100,
		Enabled:       true,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     sql.NullString{String: "admin", Valid: true},
		UpdatedBy:     sql.NullString{String: "admin", Valid: true},
	}

	mock.ExpectExec("INSERT INTO policies").
		WithArgs(
			policy.ID,
			policy.Name,
			policy.Description,
			policy.Language,
			policy.PolicyContent,
			policy.Effect,
			policy.Priority,
			policy.Enabled,
			policy.CreatedAt,
			policy.UpdatedAt,
			policy.CreatedBy,
			policy.UpdatedBy,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Create(ctx, policy)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyRepository_Create_Error(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policy := &models.Policy{
		ID:   uuid.New(),
		Name: "test-policy",
	}

	mock.ExpectExec("INSERT INTO policies").
		WillReturnError(sql.ErrConnDone)

	err := repo.Create(ctx, policy)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to create policy")
}

func TestPolicyRepository_GetByID(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "language", "policy_content",
		"effect", "priority", "enabled", "created_at", "updated_at",
		"created_by", "updated_by",
	}).AddRow(
		policyID, "test-policy", "description", models.PolicyLanguageJSON,
		`{"test": "content"}`, models.PolicyEffectAllow, 100, true,
		now, now, "admin", "admin",
	)

	mock.ExpectQuery("SELECT (.+) FROM policies WHERE id").
		WithArgs(policyID).
		WillReturnRows(rows)

	policy, err := repo.GetByID(ctx, policyID)
	assert.NoError(t, err)
	assert.NotNil(t, policy)
	assert.Equal(t, policyID, policy.ID)
	assert.Equal(t, "test-policy", policy.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyRepository_GetByID_NotFound(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()

	mock.ExpectQuery("SELECT (.+) FROM policies WHERE id").
		WithArgs(policyID).
		WillReturnError(sql.ErrNoRows)

	policy, err := repo.GetByID(ctx, policyID)
	assert.Error(t, err)
	assert.Equal(t, models.ErrPolicyNotFound, err)
	assert.Nil(t, policy)
}

func TestPolicyRepository_GetByName(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "language", "policy_content",
		"effect", "priority", "enabled", "created_at", "updated_at",
		"created_by", "updated_by",
	}).AddRow(
		policyID, "test-policy", "description", models.PolicyLanguageJSON,
		`{"test": "content"}`, models.PolicyEffectAllow, 100, true,
		now, now, "admin", "admin",
	)

	mock.ExpectQuery("SELECT (.+) FROM policies WHERE name").
		WithArgs("test-policy").
		WillReturnRows(rows)

	policy, err := repo.GetByName(ctx, "test-policy")
	assert.NoError(t, err)
	assert.NotNil(t, policy)
	assert.Equal(t, "test-policy", policy.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyRepository_List(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name    string
		request *models.ListPoliciesRequest
		setup   func(mock sqlmock.Sqlmock)
	}{
		{
			name:    "List all policies",
			request: &models.ListPoliciesRequest{},
			setup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "language", "policy_content",
					"effect", "priority", "enabled", "created_at", "updated_at",
					"created_by", "updated_by",
				}).
					AddRow(uuid.New(), "policy1", "desc1", models.PolicyLanguageJSON, "{}", models.PolicyEffectAllow, 100, true, now, now, "admin", "admin").
					AddRow(uuid.New(), "policy2", "desc2", models.PolicyLanguageOPA, "package test", models.PolicyEffectDeny, 90, true, now, now, "admin", "admin")

				mock.ExpectQuery("SELECT (.+) FROM policies WHERE 1=1 ORDER BY").
					WillReturnRows(rows)
			},
		},
		{
			name: "List with language filter",
			request: &models.ListPoliciesRequest{
				Language: &[]models.PolicyLanguage{models.PolicyLanguageJSON}[0],
			},
			setup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "language", "policy_content",
					"effect", "priority", "enabled", "created_at", "updated_at",
					"created_by", "updated_by",
				}).
					AddRow(uuid.New(), "policy1", "desc1", models.PolicyLanguageJSON, "{}", models.PolicyEffectAllow, 100, true, now, now, "admin", "admin")

				mock.ExpectQuery("SELECT (.+) FROM policies WHERE 1=1 AND language").
					WithArgs(models.PolicyLanguageJSON).
					WillReturnRows(rows)
			},
		},
		{
			name: "List with enabled filter",
			request: &models.ListPoliciesRequest{
				Enabled: &[]bool{true}[0],
			},
			setup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "language", "policy_content",
					"effect", "priority", "enabled", "created_at", "updated_at",
					"created_by", "updated_by",
				}).
					AddRow(uuid.New(), "policy1", "desc1", models.PolicyLanguageJSON, "{}", models.PolicyEffectAllow, 100, true, now, now, "admin", "admin")

				mock.ExpectQuery("SELECT (.+) FROM policies WHERE 1=1 AND enabled").
					WithArgs(true).
					WillReturnRows(rows)
			},
		},
		{
			name: "List with pagination",
			request: &models.ListPoliciesRequest{
				Limit:  10,
				Offset: 20,
			},
			setup: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "language", "policy_content",
					"effect", "priority", "enabled", "created_at", "updated_at",
					"created_by", "updated_by",
				})

				mock.ExpectQuery("SELECT (.+) FROM policies WHERE 1=1 ORDER BY (.+) LIMIT (.+) OFFSET").
					WithArgs(10, 20).
					WillReturnRows(rows)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, mock, cleanup := setupPolicyRepoTest(t)
			defer cleanup()

			tt.setup(mock)
			policies, err := repo.List(ctx, tt.request)
			assert.NoError(t, err)
			assert.NotNil(t, policies)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestPolicyRepository_Update(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()
	now := time.Now()

	policy := &models.Policy{
		ID:            policyID,
		Name:          "updated-policy",
		Description:   "Updated description",
		Language:      models.PolicyLanguageJSON,
		PolicyContent: `{"updated": "content"}`,
		Effect:        models.PolicyEffectAllow,
		Priority:      200,
		Enabled:       false,
		UpdatedAt:     now,
		UpdatedBy:     sql.NullString{String: "admin", Valid: true},
	}

	mock.ExpectExec("UPDATE policies").
		WithArgs(
			policy.Name,
			policy.Description,
			policy.Language,
			policy.PolicyContent,
			policy.Effect,
			policy.Priority,
			policy.Enabled,
			policy.UpdatedAt,
			policy.UpdatedBy,
			policy.ID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.Update(ctx, policy)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyRepository_Update_NotFound(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policy := &models.Policy{
		ID:   uuid.New(),
		Name: "non-existent",
	}

	mock.ExpectExec("UPDATE policies").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.Update(ctx, policy)
	assert.Error(t, err)
	assert.Equal(t, models.ErrPolicyNotFound, err)
}

func TestPolicyRepository_Delete(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()

	mock.ExpectExec("DELETE FROM policies WHERE id").
		WithArgs(policyID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.Delete(ctx, policyID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyRepository_Delete_NotFound(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	policyID := uuid.New()

	mock.ExpectExec("DELETE FROM policies WHERE id").
		WithArgs(policyID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.Delete(ctx, policyID)
	assert.Error(t, err)
	assert.Equal(t, models.ErrPolicyNotFound, err)
}

func TestPolicyRepository_ListEnabled(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "language", "policy_content",
		"effect", "priority", "enabled", "created_at", "updated_at",
		"created_by", "updated_by",
	}).
		AddRow(uuid.New(), "policy1", "desc1", models.PolicyLanguageJSON, "{}", models.PolicyEffectAllow, 100, true, now, now, "admin", "admin").
		AddRow(uuid.New(), "policy2", "desc2", models.PolicyLanguageOPA, "package test", models.PolicyEffectAllow, 90, true, now, now, "admin", "admin")

	mock.ExpectQuery("SELECT (.+) FROM policies WHERE enabled = true ORDER BY").
		WillReturnRows(rows)

	policies, err := repo.ListEnabled(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, policies)
	assert.Len(t, policies, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestPolicyRepository_Count(t *testing.T) {
	repo, mock, cleanup := setupPolicyRepoTest(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name          string
		request       *models.ListPoliciesRequest
		expectedCount int
		setup         func()
	}{
		{
			name:          "Count all policies",
			request:       &models.ListPoliciesRequest{},
			expectedCount: 5,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(5)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policies WHERE 1=1").
					WillReturnRows(rows)
			},
		},
		{
			name: "Count with language filter",
			request: &models.ListPoliciesRequest{
				Language: &[]models.PolicyLanguage{models.PolicyLanguageJSON}[0],
			},
			expectedCount: 3,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(3)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policies WHERE 1=1 AND language").
					WithArgs(models.PolicyLanguageJSON).
					WillReturnRows(rows)
			},
		},
		{
			name: "Count with enabled filter",
			request: &models.ListPoliciesRequest{
				Enabled: &[]bool{true}[0],
			},
			expectedCount: 4,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(4)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM policies WHERE 1=1 AND enabled").
					WithArgs(true).
					WillReturnRows(rows)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			count, err := repo.Count(ctx, tt.request)
			assert.NoError(t, err)
			assert.Equal(t, tt.expectedCount, count)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}