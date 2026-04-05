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

// CedarTemplateRepository implements cedar.TemplateStore for PostgreSQL.
type CedarTemplateRepository struct {
	db sqlx.ExtContext
}

// NewCedarTemplateRepository creates a new PostgreSQL Cedar template repository.
func NewCedarTemplateRepository(db sqlx.ExtContext) *CedarTemplateRepository {
	return &CedarTemplateRepository{db: db}
}

// CreateTemplate persists a new Cedar policy template.
func (r *CedarTemplateRepository) CreateTemplate(ctx context.Context, template *models.CedarTemplate) error {
	query := `
		INSERT INTO cedar_templates (id, name, description, template_content, schema_id, namespace, created_at, updated_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err := r.db.ExecContext(ctx, query,
		template.ID,
		template.Name,
		template.Description,
		template.TemplateContent,
		template.SchemaID,
		template.Namespace,
		template.CreatedAt,
		template.UpdatedAt,
		template.CreatedBy,
		template.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create cedar template: %w", err)
	}
	return nil
}

// GetTemplateByID retrieves a Cedar template by ID.
func (r *CedarTemplateRepository) GetTemplateByID(ctx context.Context, id uuid.UUID) (*models.CedarTemplate, error) {
	query := `SELECT id, name, description, template_content, schema_id, namespace, created_at, updated_at, created_by, updated_by FROM cedar_templates WHERE id = $1`
	var template models.CedarTemplate
	err := sqlx.GetContext(ctx, r.db, &template, query, id)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, models.ErrCedarTemplateNotFound
		}
		return nil, fmt.Errorf("failed to get cedar template: %w", err)
	}
	return &template, nil
}

// ListTemplates lists Cedar templates, optionally filtered by namespace.
func (r *CedarTemplateRepository) ListTemplates(ctx context.Context, namespace string) ([]*models.CedarTemplate, error) {
	var templates []*models.CedarTemplate
	var err error

	if namespace != "" {
		query := `SELECT id, name, description, template_content, schema_id, namespace, created_at, updated_at, created_by, updated_by FROM cedar_templates WHERE namespace = $1 ORDER BY created_at DESC`
		err = sqlx.SelectContext(ctx, r.db, &templates, query, namespace)
	} else {
		query := `SELECT id, name, description, template_content, schema_id, namespace, created_at, updated_at, created_by, updated_by FROM cedar_templates ORDER BY created_at DESC`
		err = sqlx.SelectContext(ctx, r.db, &templates, query)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to list cedar templates: %w", err)
	}
	return templates, nil
}

// UpdateTemplate updates an existing Cedar template.
func (r *CedarTemplateRepository) UpdateTemplate(ctx context.Context, template *models.CedarTemplate) error {
	template.UpdatedAt = time.Now()
	query := `
		UPDATE cedar_templates
		SET name = $2, description = $3, template_content = $4, schema_id = $5, namespace = $6, updated_at = $7, updated_by = $8
		WHERE id = $1
	`
	result, err := r.db.ExecContext(ctx, query,
		template.ID,
		template.Name,
		template.Description,
		template.TemplateContent,
		template.SchemaID,
		template.Namespace,
		template.UpdatedAt,
		template.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to update cedar template: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrCedarTemplateNotFound
	}
	return nil
}

// DeleteTemplate deletes a Cedar template by ID.
func (r *CedarTemplateRepository) DeleteTemplate(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM cedar_templates WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete cedar template: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrCedarTemplateNotFound
	}
	return nil
}

// CreateLinkedPolicy persists a template-linked policy record.
func (r *CedarTemplateRepository) CreateLinkedPolicy(ctx context.Context, link *models.CedarLinkedPolicy) error {
	query := `
		INSERT INTO cedar_linked_policies (id, template_id, policy_id, principal_entity, resource_entity, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := r.db.ExecContext(ctx, query,
		link.ID,
		link.TemplateID,
		link.PolicyID,
		link.PrincipalEntity,
		link.ResourceEntity,
		link.CreatedAt,
		link.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create linked policy: %w", err)
	}
	return nil
}

// ListLinkedPolicies lists all linked policies for a template.
func (r *CedarTemplateRepository) ListLinkedPolicies(ctx context.Context, templateID uuid.UUID) ([]*models.CedarLinkedPolicy, error) {
	query := `SELECT id, template_id, policy_id, principal_entity, resource_entity, created_at, created_by FROM cedar_linked_policies WHERE template_id = $1 ORDER BY created_at DESC`
	var links []*models.CedarLinkedPolicy
	err := sqlx.SelectContext(ctx, r.db, &links, query, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to list linked policies: %w", err)
	}
	return links, nil
}
