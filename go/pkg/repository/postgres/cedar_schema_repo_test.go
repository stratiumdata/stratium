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

func setupCedarSchemaRepoTest(t *testing.T) (*CedarSchemaRepository, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	sqlxDB := sqlx.NewDb(db, "sqlmock")
	repo := NewCedarSchemaRepository(sqlxDB)
	return repo, mock, func() { db.Close() }
}

func TestCedarSchemaRepository_Create(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()
	schema := &models.CedarSchema{
		ID:            uuid.New(),
		Namespace:     "Acme",
		Name:          "main",
		Description:   "Main schema",
		SchemaContent: `{"entityTypes": {}}`,
		SchemaFormat:  "json",
		Version:       "1.0",
		IsActive:      true,
		CreatedAt:     now,
		UpdatedAt:     now,
		CreatedBy:     "admin",
		UpdatedBy:     "admin",
	}

	mock.ExpectExec("INSERT INTO cedar_schemas").
		WithArgs(
			schema.ID, schema.Namespace, schema.Name, schema.Description,
			schema.SchemaContent, schema.SchemaFormat, schema.Version,
			schema.IsActive, schema.CreatedAt, schema.UpdatedAt,
			schema.CreatedBy, schema.UpdatedBy,
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err := repo.CreateSchema(ctx, schema)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarSchemaRepository_GetByID(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	schemaID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "namespace", "name", "description", "schema_content", "schema_format",
		"version", "is_active", "created_at", "updated_at", "created_by", "updated_by",
	}).AddRow(
		schemaID, "Acme", "main", "Main schema", `{"entityTypes": {}}`, "json",
		"1.0", true, now, now, "admin", "admin",
	)

	mock.ExpectQuery("SELECT .+ FROM cedar_schemas WHERE id = \\$1").
		WithArgs(schemaID).
		WillReturnRows(rows)

	schema, err := repo.GetSchemaByID(ctx, schemaID)
	assert.NoError(t, err)
	assert.Equal(t, schemaID, schema.ID)
	assert.Equal(t, "Acme", schema.Namespace)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarSchemaRepository_GetByID_NotFound(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	schemaID := uuid.New()

	mock.ExpectQuery("SELECT .+ FROM cedar_schemas WHERE id = \\$1").
		WithArgs(schemaID).
		WillReturnError(sql.ErrNoRows)

	_, err := repo.GetSchemaByID(ctx, schemaID)
	assert.ErrorIs(t, err, models.ErrCedarSchemaNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarSchemaRepository_Delete(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	schemaID := uuid.New()

	mock.ExpectExec("DELETE FROM cedar_schemas WHERE id = \\$1").
		WithArgs(schemaID).
		WillReturnResult(sqlmock.NewResult(0, 1))

	err := repo.DeleteSchema(ctx, schemaID)
	assert.NoError(t, err)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarSchemaRepository_Delete_NotFound(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	schemaID := uuid.New()

	mock.ExpectExec("DELETE FROM cedar_schemas WHERE id = \\$1").
		WithArgs(schemaID).
		WillReturnResult(sqlmock.NewResult(0, 0))

	err := repo.DeleteSchema(ctx, schemaID)
	assert.ErrorIs(t, err, models.ErrCedarSchemaNotFound)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarSchemaRepository_ListSchemas(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "namespace", "name", "description", "schema_content", "schema_format",
		"version", "is_active", "created_at", "updated_at", "created_by", "updated_by",
	}).AddRow(
		uuid.New(), "Acme", "main", "Main", `{}`, "json", "1.0", true, now, now, "admin", "admin",
	).AddRow(
		uuid.New(), "Acme", "secondary", "Secondary", `{}`, "json", "1.0", false, now, now, "admin", "admin",
	)

	mock.ExpectQuery("SELECT .+ FROM cedar_schemas WHERE namespace = \\$1").
		WithArgs("Acme").
		WillReturnRows(rows)

	schemas, err := repo.ListSchemas(ctx, "Acme")
	assert.NoError(t, err)
	assert.Len(t, schemas, 2)
	assert.NoError(t, mock.ExpectationsWereMet())
}

func TestCedarSchemaRepository_GetActiveSchema(t *testing.T) {
	repo, mock, cleanup := setupCedarSchemaRepoTest(t)
	defer cleanup()

	ctx := context.Background()
	schemaID := uuid.New()
	now := time.Now()

	rows := sqlmock.NewRows([]string{
		"id", "namespace", "name", "description", "schema_content", "schema_format",
		"version", "is_active", "created_at", "updated_at", "created_by", "updated_by",
	}).AddRow(
		schemaID, "Acme", "main", "Main", `{}`, "json", "1.0", true, now, now, "admin", "admin",
	)

	mock.ExpectQuery("SELECT .+ FROM cedar_schemas WHERE namespace = \\$1 AND is_active = true").
		WithArgs("Acme").
		WillReturnRows(rows)

	schema, err := repo.GetActiveSchema(ctx, "Acme")
	assert.NoError(t, err)
	assert.Equal(t, schemaID, schema.ID)
	assert.True(t, schema.IsActive)
	assert.NoError(t, mock.ExpectationsWereMet())
}
