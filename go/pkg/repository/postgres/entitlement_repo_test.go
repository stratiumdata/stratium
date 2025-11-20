package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"stratium/pkg/models"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/assert"
)

func setupEntitlementRepoTest(t *testing.T) (*EntitlementRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := NewEntitlementRepository(sqlxDB)

	cleanup := func() {
		db.Close()
	}

	return repo, mock, cleanup
}

func TestNewEntitlementRepository(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	assert.NotNil(t, repo)
	assert.NotNil(t, mock)
}

func TestEntitlementRepository_Create(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	subjectAttrs := map[string]interface{}{"role": "admin"}
	resourceAttrs := map[string]interface{}{"type": "document"}
	actions := []string{"read", "write"}
	conditions := map[string]interface{}{"time": "business_hours"}

	entitlement := &models.Entitlement{
		ID:                 entitlementID,
		Name:               "test-entitlement",
		Description:        "Test entitlement",
		SubjectAttributes:  subjectAttrs,
		ResourceAttributes: resourceAttrs,
		Actions:            actions,
		Conditions:         conditions,
		Enabled:            true,
		CreatedAt:          now,
		UpdatedAt:          now,
		CreatedBy:          sql.NullString{String: "admin", Valid: true},
		UpdatedBy:          sql.NullString{String: "admin", Valid: true},
		ExpiresAt:          &expiresAt,
	}

	subjectAttrsJSON, _ := json.Marshal(subjectAttrs)
	resourceAttrsJSON, _ := json.Marshal(resourceAttrs)
	actionsJSON, _ := json.Marshal(actions)
	conditionsJSON, _ := json.Marshal(conditions)

	mock.ExpectExec("INSERT INTO entitlements").
		WithArgs(
			entitlement.ID,
			entitlement.Name,
			entitlement.Description,
			subjectAttrsJSON,
			resourceAttrsJSON,
			actionsJSON,
			conditionsJSON,
			entitlement.Enabled,
			entitlement.CreatedAt,
			entitlement.UpdatedAt,
			entitlement.CreatedBy,
			entitlement.UpdatedBy,
			entitlement.ExpiresAt,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Create(ctx, entitlement)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_Create_MarshalErrors(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name          string
		entitlement   *models.Entitlement
		expectedError string
	}{
		{
			name: "Invalid subject attributes",
			entitlement: &models.Entitlement{
				ID:                uuid.New(),
				SubjectAttributes: map[string]interface{}{"invalid": make(chan int)},
			},
			expectedError: "failed to marshal subject attributes",
		},
		{
			name: "Invalid resource attributes",
			entitlement: &models.Entitlement{
				ID:                 uuid.New(),
				SubjectAttributes:  map[string]interface{}{},
				ResourceAttributes: map[string]interface{}{"invalid": make(chan int)},
			},
			expectedError: "failed to marshal resource attributes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := repo.Create(ctx, tt.entitlement)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_GetByID(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()
	now := time.Now()

	subjectAttrs := map[string]interface{}{"role": "admin"}
	resourceAttrs := map[string]interface{}{"type": "document"}
	actions := []string{"read"}
	conditions := map[string]interface{}{}

	subjectAttrsJSON, _ := json.Marshal(subjectAttrs)
	resourceAttrsJSON, _ := json.Marshal(resourceAttrs)
	actionsJSON, _ := json.Marshal(actions)
	conditionsJSON, _ := json.Marshal(conditions)

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "subject_attributes", "resource_attributes",
		"actions", "conditions", "enabled", "created_at", "updated_at",
		"created_by", "updated_by", "expires_at",
	}).AddRow(
		entitlementID, "test-entitlement", "Test description", subjectAttrsJSON, resourceAttrsJSON,
		actionsJSON, conditionsJSON, true, now, now,
		"admin", "admin", nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE id").
		WithArgs(entitlementID).
		WillReturnRows(rows)

	entitlement, err := repo.GetByID(ctx, entitlementID)
	assert.NoError(t, err)
	assert.NotNil(t, entitlement)
	assert.Equal(t, entitlementID, entitlement.ID)
	assert.Equal(t, "test-entitlement", entitlement.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_GetByID_NotFound(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()

	mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE id").
		WithArgs(entitlementID).
		WillReturnError(sql.ErrNoRows)

	entitlement, err := repo.GetByID(ctx, entitlementID)
	assert.Error(t, err)
	assert.Equal(t, models.ErrEntitlementNotFound, err)
	assert.Nil(t, entitlement)
}

func TestEntitlementRepository_GetByName(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()
	now := time.Now()

	subjectAttrsJSON, _ := json.Marshal(map[string]interface{}{})
	resourceAttrsJSON, _ := json.Marshal(map[string]interface{}{})
	actionsJSON, _ := json.Marshal([]string{})
	conditionsJSON, _ := json.Marshal(map[string]interface{}{})

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "subject_attributes", "resource_attributes",
		"actions", "conditions", "enabled", "created_at", "updated_at",
		"created_by", "updated_by", "expires_at",
	}).AddRow(
		entitlementID, "test-entitlement", "Test description", subjectAttrsJSON, resourceAttrsJSON,
		actionsJSON, conditionsJSON, true, now, now,
		"admin", "admin", nil,
	)

	mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE name").
		WithArgs("test-entitlement").
		WillReturnRows(rows)

	entitlement, err := repo.GetByName(ctx, "test-entitlement")
	assert.NoError(t, err)
	assert.NotNil(t, entitlement)
	assert.Equal(t, "test-entitlement", entitlement.Name)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_GetByName_NotFound(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()

	mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE name").
		WithArgs("non-existent").
		WillReturnError(sql.ErrNoRows)

	entitlement, err := repo.GetByName(ctx, "non-existent")
	assert.Error(t, err)
	assert.Equal(t, models.ErrEntitlementNotFound, err)
	assert.Nil(t, entitlement)
}

func TestEntitlementRepository_List(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name    string
		request *models.ListEntitlementsRequest
		setup   func()
	}{
		{
			name:    "List all entitlements",
			request: &models.ListEntitlementsRequest{},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "subject_attributes", "resource_attributes",
					"actions", "conditions", "enabled", "created_at", "updated_at",
					"created_by", "updated_by", "expires_at",
				}).
					AddRow(uuid.New(), "ent1", "desc1", []byte("{}"), []byte("{}"), []byte("[]"), []byte("{}"), true, now, now, "admin", "admin", nil).
					AddRow(uuid.New(), "ent2", "desc2", []byte("{}"), []byte("{}"), []byte("[]"), []byte("{}"), true, now, now, "admin", "admin", nil)

				mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE 1=1 ORDER BY").
					WillReturnRows(rows)
			},
		},
		{
			name: "List with enabled filter",
			request: &models.ListEntitlementsRequest{
				Enabled: &[]bool{true}[0],
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "subject_attributes", "resource_attributes",
					"actions", "conditions", "enabled", "created_at", "updated_at",
					"created_by", "updated_by", "expires_at",
				}).
					AddRow(uuid.New(), "ent1", "desc1", []byte("{}"), []byte("{}"), []byte("[]"), []byte("{}"), true, now, now, "admin", "admin", nil)

				mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE 1=1 AND enabled").
					WithArgs(true).
					WillReturnRows(rows)
			},
		},
		{
			name: "List with action filter",
			request: &models.ListEntitlementsRequest{
				Action: "read",
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "subject_attributes", "resource_attributes",
					"actions", "conditions", "enabled", "created_at", "updated_at",
					"created_by", "updated_by", "expires_at",
				})

				actionJSON, _ := json.Marshal([]string{"read"})
				mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE 1=1 AND actions").
					WithArgs(actionJSON).
					WillReturnRows(rows)
			},
		},
		{
			name: "List with pagination",
			request: &models.ListEntitlementsRequest{
				Limit:  10,
				Offset: 5,
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "name", "description", "subject_attributes", "resource_attributes",
					"actions", "conditions", "enabled", "created_at", "updated_at",
					"created_by", "updated_by", "expires_at",
				})

				mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE 1=1 ORDER BY (.+) LIMIT (.+) OFFSET").
					WithArgs(10, 5).
					WillReturnRows(rows)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			entitlements, err := repo.List(ctx, tt.request)
			assert.NoError(t, err)
			assert.NotNil(t, entitlements)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestEntitlementRepository_Update(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()
	now := time.Now()

	subjectAttrs := map[string]interface{}{"role": "user"}
	resourceAttrs := map[string]interface{}{"type": "file"}
	actions := []string{"read"}
	conditions := map[string]interface{}{}

	entitlement := &models.Entitlement{
		ID:                 entitlementID,
		Name:               "updated-entitlement",
		Description:        "Updated description",
		SubjectAttributes:  subjectAttrs,
		ResourceAttributes: resourceAttrs,
		Actions:            actions,
		Conditions:         conditions,
		Enabled:            false,
		UpdatedAt:          now,
		UpdatedBy:          sql.NullString{String: "admin", Valid: true},
		ExpiresAt:          nil,
	}

	subjectAttrsJSON, _ := json.Marshal(subjectAttrs)
	resourceAttrsJSON, _ := json.Marshal(resourceAttrs)
	actionsJSON, _ := json.Marshal(actions)
	conditionsJSON, _ := json.Marshal(conditions)

	mock.ExpectExec("UPDATE entitlements").
		WithArgs(
			entitlement.Name,
			entitlement.Description,
			subjectAttrsJSON,
			resourceAttrsJSON,
			actionsJSON,
			conditionsJSON,
			entitlement.Enabled,
			entitlement.UpdatedAt,
			entitlement.UpdatedBy,
			entitlement.ExpiresAt,
			entitlement.ID,
		).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.Update(ctx, entitlement)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_Update_NotFound(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlement := &models.Entitlement{
		ID:                 uuid.New(),
		Name:               "non-existent",
		SubjectAttributes:  map[string]interface{}{},
		ResourceAttributes: map[string]interface{}{},
		Actions:            []string{},
		Conditions:         map[string]interface{}{},
	}

	mock.ExpectExec("UPDATE entitlements").
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.Update(ctx, entitlement)
	assert.Error(t, err)
	assert.Equal(t, models.ErrEntitlementNotFound, err)
}

func TestEntitlementRepository_Delete(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()

	mock.ExpectExec("DELETE FROM entitlements WHERE id").
		WithArgs(entitlementID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.Delete(ctx, entitlementID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_Delete_NotFound(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entitlementID := uuid.New()

	mock.ExpectExec("DELETE FROM entitlements WHERE id").
		WithArgs(entitlementID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.Delete(ctx, entitlementID)
	assert.Error(t, err)
	assert.Equal(t, models.ErrEntitlementNotFound, err)
}

func TestEntitlementRepository_FindMatching(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	t.Run("FindMatching without action", func(t *testing.T) {
		subjectAttrs := map[string]interface{}{"role": "admin", "department": "engineering"}
		subjectAttrsJSON, _ := json.Marshal(subjectAttrs)

		rows := sqlmock.NewRows([]string{
			"id", "name", "description", "subject_attributes", "resource_attributes",
			"actions", "conditions", "enabled", "created_at", "updated_at",
			"created_by", "updated_by", "expires_at",
		}).
			AddRow(uuid.New(), "ent1", "desc1", []byte("{}"), []byte("{}"), []byte("[]"), []byte("{}"), true, now, now, "admin", "admin", nil)

		mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE enabled = true AND (.+) AND subject_attributes").
			WithArgs(subjectAttrsJSON).
			WillReturnRows(rows)

		req := &models.EntitlementMatchRequest{
			SubjectAttributes: subjectAttrs,
		}

		entitlements, err := repo.FindMatching(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, entitlements)
		assert.NoError(t, mock.ExpectationsWereMet())
	})

	t.Run("FindMatching with action", func(t *testing.T) {
		subjectAttrs := map[string]interface{}{"role": "admin"}
		subjectAttrsJSON, _ := json.Marshal(subjectAttrs)
		actionJSON, _ := json.Marshal([]string{"read"})

		rows := sqlmock.NewRows([]string{
			"id", "name", "description", "subject_attributes", "resource_attributes",
			"actions", "conditions", "enabled", "created_at", "updated_at",
			"created_by", "updated_by", "expires_at",
		})

		mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE enabled = true AND (.+) AND subject_attributes (.+) AND actions").
			WithArgs(subjectAttrsJSON, actionJSON).
			WillReturnRows(rows)

		req := &models.EntitlementMatchRequest{
			SubjectAttributes: subjectAttrs,
			Action:            "read",
		}

		entitlements, err := repo.FindMatching(ctx, req)
		assert.NoError(t, err)
		assert.NotNil(t, entitlements)
		assert.NoError(t, mock.ExpectationsWereMet())
	})
}

func TestEntitlementRepository_ListActive(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "name", "description", "subject_attributes", "resource_attributes",
		"actions", "conditions", "enabled", "created_at", "updated_at",
		"created_by", "updated_by", "expires_at",
	}).
		AddRow(uuid.New(), "ent1", "desc1", []byte("{}"), []byte("{}"), []byte("[]"), []byte("{}"), true, now, now, "admin", "admin", nil).
		AddRow(uuid.New(), "ent2", "desc2", []byte("{}"), []byte("{}"), []byte("[]"), []byte("{}"), true, now, now, "admin", "admin", nil)

	mock.ExpectQuery("SELECT (.+) FROM entitlements WHERE enabled = true AND (.+) ORDER BY").
		WillReturnRows(rows)

	entitlements, err := repo.ListActive(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, entitlements)
	assert.Len(t, entitlements, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestEntitlementRepository_Count(t *testing.T) {
	repo, mock, cleanup := setupEntitlementRepoTest(t)
	defer cleanup()

	ctx := context.Background()

	tests := []struct {
		name          string
		request       *models.ListEntitlementsRequest
		expectedCount int
		setup         func()
	}{
		{
			name:          "Count all entitlements",
			request:       &models.ListEntitlementsRequest{},
			expectedCount: 10,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(10)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM entitlements WHERE 1=1").
					WillReturnRows(rows)
			},
		},
		{
			name: "Count with enabled filter",
			request: &models.ListEntitlementsRequest{
				Enabled: &[]bool{true}[0],
			},
			expectedCount: 8,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(8)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM entitlements WHERE 1=1 AND enabled").
					WithArgs(true).
					WillReturnRows(rows)
			},
		},
		{
			name: "Count with action filter",
			request: &models.ListEntitlementsRequest{
				Action: "read",
			},
			expectedCount: 5,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(5)
				actionJSON, _ := json.Marshal([]string{"read"})
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM entitlements WHERE 1=1 AND actions").
					WithArgs(actionJSON).
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

func TestEntitlementRow_toModel(t *testing.T) {
	now := time.Now()

	t.Run("Valid conversion", func(t *testing.T) {
		subjectAttrs := map[string]interface{}{"role": "admin"}
		resourceAttrs := map[string]interface{}{"type": "document"}
		actions := []string{"read", "write"}
		conditions := map[string]interface{}{"time": "business_hours"}

		subjectAttrsJSON, _ := json.Marshal(subjectAttrs)
		resourceAttrsJSON, _ := json.Marshal(resourceAttrs)
		actionsJSON, _ := json.Marshal(actions)
		conditionsJSON, _ := json.Marshal(conditions)

		row := &entitlementRow{
			ID:                 uuid.New(),
			Name:               "test-entitlement",
			Description:        "Test description",
			SubjectAttributes:  subjectAttrsJSON,
			ResourceAttributes: resourceAttrsJSON,
			Actions:            actionsJSON,
			Conditions:         conditionsJSON,
			Enabled:            true,
			CreatedAt:          sql.NullTime{Time: now, Valid: true},
			UpdatedAt:          sql.NullTime{Time: now, Valid: true},
			CreatedBy:          sql.NullString{String: "admin", Valid: true},
			UpdatedBy:          sql.NullString{String: "admin", Valid: true},
			ExpiresAt:          sql.NullTime{Time: now.Add(24 * time.Hour), Valid: true},
		}

		entitlement, err := row.toModel()
		assert.NoError(t, err)
		assert.NotNil(t, entitlement)
		assert.Equal(t, row.ID, entitlement.ID)
		assert.Equal(t, "test-entitlement", entitlement.Name)
		assert.Equal(t, subjectAttrs, entitlement.SubjectAttributes)
		assert.Equal(t, actions, entitlement.Actions)
		assert.NotNil(t, entitlement.ExpiresAt)
	})

	t.Run("Valid conversion with empty JSON", func(t *testing.T) {
		row := &entitlementRow{
			ID:                 uuid.New(),
			Name:               "test",
			Description:        "Test",
			SubjectAttributes:  []byte("{}"),
			ResourceAttributes: []byte("{}"),
			Actions:            []byte("[]"),
			Conditions:         []byte("{}"),
			Enabled:            true,
			CreatedAt:          sql.NullTime{Time: now, Valid: true},
			UpdatedAt:          sql.NullTime{Time: now, Valid: true},
			ExpiresAt:          sql.NullTime{Valid: false},
		}

		entitlement, err := row.toModel()
		assert.NoError(t, err)
		assert.NotNil(t, entitlement)
		assert.NotNil(t, entitlement.SubjectAttributes)
		assert.NotNil(t, entitlement.ResourceAttributes)
		assert.NotNil(t, entitlement.Actions)
		assert.NotNil(t, entitlement.Conditions)
		assert.Nil(t, entitlement.ExpiresAt)
	})

	t.Run("Invalid subject attributes JSON", func(t *testing.T) {
		row := &entitlementRow{
			ID:                uuid.New(),
			SubjectAttributes: []byte("{invalid json}"),
			CreatedAt:         sql.NullTime{Time: now, Valid: true},
			UpdatedAt:         sql.NullTime{Time: now, Valid: true},
		}

		entitlement, err := row.toModel()
		assert.Error(t, err)
		assert.Nil(t, entitlement)
		assert.Contains(t, err.Error(), "failed to unmarshal subject attributes")
	})

	t.Run("Invalid resource attributes JSON", func(t *testing.T) {
		row := &entitlementRow{
			ID:                 uuid.New(),
			SubjectAttributes:  []byte("{}"),
			ResourceAttributes: []byte("{invalid json}"),
			CreatedAt:          sql.NullTime{Time: now, Valid: true},
			UpdatedAt:          sql.NullTime{Time: now, Valid: true},
		}

		entitlement, err := row.toModel()
		assert.Error(t, err)
		assert.Nil(t, entitlement)
		assert.Contains(t, err.Error(), "failed to unmarshal resource attributes")
	})

	t.Run("Invalid actions JSON", func(t *testing.T) {
		row := &entitlementRow{
			ID:                 uuid.New(),
			SubjectAttributes:  []byte("{}"),
			ResourceAttributes: []byte("{}"),
			Actions:            []byte("{invalid json}"),
			CreatedAt:          sql.NullTime{Time: now, Valid: true},
			UpdatedAt:          sql.NullTime{Time: now, Valid: true},
		}

		entitlement, err := row.toModel()
		assert.Error(t, err)
		assert.Nil(t, entitlement)
		assert.Contains(t, err.Error(), "failed to unmarshal actions")
	})

	t.Run("Invalid conditions JSON", func(t *testing.T) {
		row := &entitlementRow{
			ID:                 uuid.New(),
			SubjectAttributes:  []byte("{}"),
			ResourceAttributes: []byte("{}"),
			Actions:            []byte("[]"),
			Conditions:         []byte("{invalid json}"),
			CreatedAt:          sql.NullTime{Time: now, Valid: true},
			UpdatedAt:          sql.NullTime{Time: now, Valid: true},
		}

		entitlement, err := row.toModel()
		assert.Error(t, err)
		assert.Nil(t, entitlement)
		assert.Contains(t, err.Error(), "failed to unmarshal conditions")
	})
}

func TestEntitlementRowsToModels(t *testing.T) {
	now := time.Now()

	t.Run("Convert multiple rows", func(t *testing.T) {
		rows := []entitlementRow{
			{
				ID:                 uuid.New(),
				Name:               "ent1",
				SubjectAttributes:  []byte("{}"),
				ResourceAttributes: []byte("{}"),
				Actions:            []byte("[]"),
				Conditions:         []byte("{}"),
				CreatedAt:          sql.NullTime{Time: now, Valid: true},
				UpdatedAt:          sql.NullTime{Time: now, Valid: true},
			},
			{
				ID:                 uuid.New(),
				Name:               "ent2",
				SubjectAttributes:  []byte("{}"),
				ResourceAttributes: []byte("{}"),
				Actions:            []byte("[]"),
				Conditions:         []byte("{}"),
				CreatedAt:          sql.NullTime{Time: now, Valid: true},
				UpdatedAt:          sql.NullTime{Time: now, Valid: true},
			},
		}

		entitlements, err := entitlementRowsToModels(rows)
		assert.NoError(t, err)
		assert.Len(t, entitlements, 2)
		assert.Equal(t, "ent1", entitlements[0].Name)
		assert.Equal(t, "ent2", entitlements[1].Name)
	})

	t.Run("Error in conversion", func(t *testing.T) {
		rows := []entitlementRow{
			{
				ID:                uuid.New(),
				SubjectAttributes: []byte("{invalid}"),
				CreatedAt:         sql.NullTime{Time: now, Valid: true},
				UpdatedAt:         sql.NullTime{Time: now, Valid: true},
			},
		}

		entitlements, err := entitlementRowsToModels(rows)
		assert.Error(t, err)
		assert.Nil(t, entitlements)
	})
}

func TestNullTimeToTimePtr(t *testing.T) {
	t.Run("Valid NullTime", func(t *testing.T) {
		now := time.Now()
		nt := &sql.NullTime{Time: now, Valid: true}
		result := nullTimeToTimePtr(nt)
		assert.NotNil(t, result)
		assert.Equal(t, now, *result)
	})

	t.Run("Invalid NullTime", func(t *testing.T) {
		nt := &sql.NullTime{Valid: false}
		result := nullTimeToTimePtr(nt)
		assert.Nil(t, result)
	})

	t.Run("Nil NullTime", func(t *testing.T) {
		result := nullTimeToTimePtr(nil)
		assert.Nil(t, result)
	})
}