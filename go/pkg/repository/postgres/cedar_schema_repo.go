package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"stratium/pkg/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// CedarSchemaRepository implements cedar.SchemaStore for PostgreSQL.
type CedarSchemaRepository struct {
	db sqlx.ExtContext
}

// NewCedarSchemaRepository creates a new PostgreSQL Cedar schema repository.
func NewCedarSchemaRepository(db sqlx.ExtContext) *CedarSchemaRepository {
	return &CedarSchemaRepository{db: db}
}

// CreateSchema persists a new Cedar schema.
func (r *CedarSchemaRepository) CreateSchema(ctx context.Context, schema *models.CedarSchema) error {
	query := `
		INSERT INTO cedar_schemas (id, namespace, name, description, schema_content, schema_format, version, is_active, created_at, updated_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.db.ExecContext(ctx, query,
		schema.ID,
		schema.Namespace,
		schema.Name,
		schema.Description,
		schema.SchemaContent,
		schema.SchemaFormat,
		schema.Version,
		schema.IsActive,
		schema.CreatedAt,
		schema.UpdatedAt,
		schema.CreatedBy,
		schema.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create cedar schema: %w", err)
	}
	return nil
}

// GetSchemaByID retrieves a Cedar schema by ID.
func (r *CedarSchemaRepository) GetSchemaByID(ctx context.Context, id uuid.UUID) (*models.CedarSchema, error) {
	query := `SELECT id, namespace, name, description, schema_content, schema_format, version, is_active, created_at, updated_at, created_by, updated_by FROM cedar_schemas WHERE id = $1`
	var schema models.CedarSchema
	err := sqlx.GetContext(ctx, r.db, &schema, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.ErrCedarSchemaNotFound
		}
		return nil, fmt.Errorf("failed to get cedar schema: %w", err)
	}
	return &schema, nil
}

// ListSchemas lists Cedar schemas, optionally filtered by namespace.
func (r *CedarSchemaRepository) ListSchemas(ctx context.Context, namespace string) ([]*models.CedarSchema, error) {
	var schemas []*models.CedarSchema
	var err error

	if namespace != "" {
		query := `SELECT id, namespace, name, description, schema_content, schema_format, version, is_active, created_at, updated_at, created_by, updated_by FROM cedar_schemas WHERE namespace = $1 ORDER BY created_at DESC`
		err = sqlx.SelectContext(ctx, r.db, &schemas, query, namespace)
	} else {
		query := `SELECT id, namespace, name, description, schema_content, schema_format, version, is_active, created_at, updated_at, created_by, updated_by FROM cedar_schemas ORDER BY created_at DESC`
		err = sqlx.SelectContext(ctx, r.db, &schemas, query)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list cedar schemas: %w", err)
	}
	return schemas, nil
}

// UpdateSchema updates an existing Cedar schema.
func (r *CedarSchemaRepository) UpdateSchema(ctx context.Context, schema *models.CedarSchema) error {
	schema.UpdatedAt = time.Now()
	query := `
		UPDATE cedar_schemas
		SET name = $2, description = $3, schema_content = $4, schema_format = $5, version = $6, is_active = $7, updated_at = $8, updated_by = $9
		WHERE id = $1
	`
	result, err := r.db.ExecContext(ctx, query,
		schema.ID,
		schema.Name,
		schema.Description,
		schema.SchemaContent,
		schema.SchemaFormat,
		schema.Version,
		schema.IsActive,
		schema.UpdatedAt,
		schema.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to update cedar schema: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrCedarSchemaNotFound
	}
	return nil
}

// DeleteSchema deletes a Cedar schema by ID.
func (r *CedarSchemaRepository) DeleteSchema(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM cedar_schemas WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete cedar schema: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrCedarSchemaNotFound
	}
	return nil
}

// GetActiveSchema returns the active schema for a namespace.
func (r *CedarSchemaRepository) GetActiveSchema(ctx context.Context, namespace string) (*models.CedarSchema, error) {
	query := `SELECT id, namespace, name, description, schema_content, schema_format, version, is_active, created_at, updated_at, created_by, updated_by FROM cedar_schemas WHERE namespace = $1 AND is_active = true ORDER BY updated_at DESC LIMIT 1`
	var schema models.CedarSchema
	err := sqlx.GetContext(ctx, r.db, &schema, query, namespace)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.ErrCedarSchemaNotFound
		}
		return nil, fmt.Errorf("failed to get active cedar schema: %w", err)
	}
	return &schema, nil
}
