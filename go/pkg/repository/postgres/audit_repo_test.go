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

func setupAuditRepoTest(t *testing.T) (*AuditRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}

	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := NewAuditRepository(sqlxDB)

	cleanup := func() {
		db.Close()
	}

	return repo, mock, cleanup
}

func TestNewAuditRepository(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	assert.NotNil(t, repo)
	assert.NotNil(t, mock)
}

func TestAuditRepository_Create(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	auditID := uuid.New()
	entityID := uuid.New()
	now := time.Now()

	changes := map[string]interface{}{
		"field1": "old_value",
		"field2": "new_value",
	}
	result := map[string]interface{}{
		"status": "success",
	}

	auditLog := &models.AuditLog{
		ID:         auditID,
		EntityType: models.EntityTypePolicy,
		EntityID:   &entityID,
		Action:     models.AuditActionCreate,
		Actor:      "admin@example.com",
		Changes:    changes,
		Result:     result,
		Timestamp:  now,
		IPAddress:  "192.168.1.100",
		UserAgent:  "Mozilla/5.0",
	}

	changesJSON, _ := json.Marshal(changes)
	resultJSON, _ := json.Marshal(result)

	mock.ExpectExec("INSERT INTO audit_logs").
		WithArgs(
			auditLog.ID,
			auditLog.EntityType,
			auditLog.EntityID,
			auditLog.Action,
			auditLog.Actor,
			changesJSON,
			resultJSON,
			auditLog.Timestamp,
			auditLog.IPAddress,
			auditLog.UserAgent,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.Create(ctx, auditLog)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditRepository_Create_MarshalError(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()

	// Create invalid changes that can't be marshaled (channels can't be marshaled)
	invalidChanges := map[string]interface{}{
		"invalid": make(chan int),
	}

	auditLog := &models.AuditLog{
		ID:      uuid.New(),
		Changes: invalidChanges,
		Result:  map[string]interface{}{},
	}

	err := repo.Create(ctx, auditLog)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal changes")
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditRepository_GetByID(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	auditID := uuid.New()
	entityID := uuid.New()
	now := time.Now()

	changes := map[string]interface{}{"field": "value"}
	result := map[string]interface{}{"status": "success"}
	changesJSON, _ := json.Marshal(changes)
	resultJSON, _ := json.Marshal(result)

	rows := sqlmock.NewRows([]string{
		"id", "entity_type", "entity_id", "action", "actor",
		"changes", "result", "timestamp", "ip_address", "user_agent",
	}).AddRow(
		auditID, models.EntityTypePolicy, entityID, models.AuditActionCreate,
		"admin@example.com", changesJSON, resultJSON, now, "192.168.1.1", "Mozilla/5.0",
	)

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE id").
		WithArgs(auditID).
		WillReturnRows(rows)

	auditLog, err := repo.GetByID(ctx, auditID)
	assert.NoError(t, err)
	assert.NotNil(t, auditLog)
	assert.Equal(t, auditID, auditLog.ID)
	assert.Equal(t, "admin@example.com", auditLog.Actor)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditRepository_GetByID_NotFound(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	auditID := uuid.New()

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE id").
		WithArgs(auditID).
		WillReturnError(sql.ErrNoRows)

	auditLog, err := repo.GetByID(ctx, auditID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audit log not found")
	assert.Nil(t, auditLog)
}

func TestAuditRepository_List(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name    string
		request *models.ListAuditLogsRequest
		setup   func()
	}{
		{
			name:    "List all audit logs",
			request: &models.ListAuditLogsRequest{},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "entity_type", "entity_id", "action", "actor",
					"changes", "result", "timestamp", "ip_address", "user_agent",
				}).
					AddRow(uuid.New(), models.EntityTypePolicy, uuid.New(), models.AuditActionCreate, "admin", []byte("{}"), []byte("{}"), now, "127.0.0.1", "Mozilla").
					AddRow(uuid.New(), models.EntityTypeEntitlement, uuid.New(), models.AuditActionUpdate, "user", []byte("{}"), []byte("{}"), now, "127.0.0.1", "Mozilla")

				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE 1=1 ORDER BY").
					WillReturnRows(rows)
			},
		},
		{
			name: "List with entity type filter",
			request: &models.ListAuditLogsRequest{
				EntityType: &[]models.EntityType{models.EntityTypePolicy}[0],
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "entity_type", "entity_id", "action", "actor",
					"changes", "result", "timestamp", "ip_address", "user_agent",
				}).
					AddRow(uuid.New(), models.EntityTypePolicy, uuid.New(), models.AuditActionCreate, "admin", []byte("{}"), []byte("{}"), now, "127.0.0.1", "Mozilla")

				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE 1=1 AND entity_type").
					WithArgs(models.EntityTypePolicy).
					WillReturnRows(rows)
			},
		},
		{
			name: "List with actor filter",
			request: &models.ListAuditLogsRequest{
				Actor: "admin@example.com",
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "entity_type", "entity_id", "action", "actor",
					"changes", "result", "timestamp", "ip_address", "user_agent",
				})

				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE 1=1 AND actor").
					WithArgs("admin@example.com").
					WillReturnRows(rows)
			},
		},
		{
			name: "List with date range",
			request: &models.ListAuditLogsRequest{
				StartDate: &now,
				EndDate:   &now,
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "entity_type", "entity_id", "action", "actor",
					"changes", "result", "timestamp", "ip_address", "user_agent",
				})

				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE 1=1 AND timestamp >= (.+) AND timestamp <=").
					WithArgs(now, now).
					WillReturnRows(rows)
			},
		},
		{
			name: "List with pagination",
			request: &models.ListAuditLogsRequest{
				Limit:  10,
				Offset: 5,
			},
			setup: func() {
				rows := sqlmock.NewRows([]string{
					"id", "entity_type", "entity_id", "action", "actor",
					"changes", "result", "timestamp", "ip_address", "user_agent",
				})

				mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE 1=1 ORDER BY (.+) LIMIT (.+) OFFSET").
					WithArgs(10, 5).
					WillReturnRows(rows)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			auditLogs, err := repo.List(ctx, tt.request)
			assert.NoError(t, err)
			assert.NotNil(t, auditLogs)
			assert.NoError(t, mock.ExpectationsWereMet())
		})
	}
}

func TestAuditRepository_ListByEntity(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	entityID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "entity_type", "entity_id", "action", "actor",
		"changes", "result", "timestamp", "ip_address", "user_agent",
	}).
		AddRow(uuid.New(), models.EntityTypePolicy, entityID, models.AuditActionCreate, "admin", []byte("{}"), []byte("{}"), now, "127.0.0.1", "Mozilla").
		AddRow(uuid.New(), models.EntityTypePolicy, entityID, models.AuditActionUpdate, "admin", []byte("{}"), []byte("{}"), now, "127.0.0.1", "Mozilla")

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE entity_type = (.+) AND entity_id").
		WithArgs(models.EntityTypePolicy, entityID).
		WillReturnRows(rows)

	auditLogs, err := repo.ListByEntity(ctx, models.EntityTypePolicy, entityID)
	assert.NoError(t, err)
	assert.NotNil(t, auditLogs)
	assert.Len(t, auditLogs, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditRepository_ListByActor(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "entity_type", "entity_id", "action", "actor",
		"changes", "result", "timestamp", "ip_address", "user_agent",
	}).
		AddRow(uuid.New(), models.EntityTypePolicy, uuid.New(), models.AuditActionCreate, "admin@example.com", []byte("{}"), []byte("{}"), now, "127.0.0.1", "Mozilla")

	mock.ExpectQuery("SELECT (.+) FROM audit_logs WHERE actor").
		WithArgs("admin@example.com", 10, 0).
		WillReturnRows(rows)

	auditLogs, err := repo.ListByActor(ctx, "admin@example.com", 10, 0)
	assert.NoError(t, err)
	assert.NotNil(t, auditLogs)
	assert.Len(t, auditLogs, 1)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestAuditRepository_Count(t *testing.T) {
	repo, mock, cleanup := setupAuditRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	tests := []struct {
		name          string
		request       *models.ListAuditLogsRequest
		expectedCount int
		setup         func()
	}{
		{
			name:          "Count all audit logs",
			request:       &models.ListAuditLogsRequest{},
			expectedCount: 42,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(42)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs WHERE 1=1").
					WillReturnRows(rows)
			},
		},
		{
			name: "Count with entity type filter",
			request: &models.ListAuditLogsRequest{
				EntityType: &[]models.EntityType{models.EntityTypePolicy}[0],
			},
			expectedCount: 15,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(15)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs WHERE 1=1 AND entity_type").
					WithArgs(models.EntityTypePolicy).
					WillReturnRows(rows)
			},
		},
		{
			name: "Count with date range",
			request: &models.ListAuditLogsRequest{
				StartDate: &now,
				EndDate:   &now,
			},
			expectedCount: 8,
			setup: func() {
				rows := sqlmock.NewRows([]string{"count"}).AddRow(8)
				mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM audit_logs WHERE 1=1 AND timestamp >= (.+) AND timestamp <=").
					WithArgs(now, now).
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

func TestAuditLogRow_toModel(t *testing.T) {
	now := time.Now()
	entityID := uuid.New()

	t.Run("Valid conversion", func(t *testing.T) {
		changes := map[string]interface{}{"field": "value"}
		result := map[string]interface{}{"status": "success"}
		changesJSON, _ := json.Marshal(changes)
		resultJSON, _ := json.Marshal(result)

		row := &auditLogRow{
			ID:         uuid.New(),
			EntityType: models.EntityTypePolicy,
			EntityID:   &entityID,
			Action:     models.AuditActionCreate,
			Actor:      "admin",
			Changes:    changesJSON,
			Result:     resultJSON,
			Timestamp:  sql.NullTime{Time: now, Valid: true},
			IPAddress:  "127.0.0.1",
			UserAgent:  "Mozilla",
		}

		auditLog, err := row.toModel()
		assert.NoError(t, err)
		assert.NotNil(t, auditLog)
		assert.Equal(t, row.ID, auditLog.ID)
		assert.Equal(t, "admin", auditLog.Actor)
	})

	t.Run("Invalid changes JSON", func(t *testing.T) {
		row := &auditLogRow{
			ID:        uuid.New(),
			Changes:   []byte("{invalid json}"),
			Result:    []byte("{}"),
			Timestamp: sql.NullTime{Time: now, Valid: true},
		}

		auditLog, err := row.toModel()
		assert.Error(t, err)
		assert.Nil(t, auditLog)
		assert.Contains(t, err.Error(), "failed to unmarshal changes")
	})

	t.Run("Invalid result JSON", func(t *testing.T) {
		row := &auditLogRow{
			ID:        uuid.New(),
			Changes:   []byte("{}"),
			Result:    []byte("{invalid json}"),
			Timestamp: sql.NullTime{Time: now, Valid: true},
		}

		auditLog, err := row.toModel()
		assert.Error(t, err)
		assert.Nil(t, auditLog)
		assert.Contains(t, err.Error(), "failed to unmarshal result")
	})
}