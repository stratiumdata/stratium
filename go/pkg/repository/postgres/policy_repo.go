package postgres

import (
	"context"
	"database/sql"
	"fmt"

	"stratium/pkg/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// PolicyRepository implements repository.PolicyRepository for PostgreSQL
type PolicyRepository struct {
	db sqlx.ExtContext
}

// NewPolicyRepository creates a new PostgreSQL policy repository
func NewPolicyRepository(db sqlx.ExtContext) *PolicyRepository {
	return &PolicyRepository{db: db}
}

// Create creates a new policy
func (r *PolicyRepository) Create(ctx context.Context, policy *models.Policy) error {
	query := `
		INSERT INTO policies (id, name, description, language, policy_content, effect, priority, enabled, created_at, updated_at, created_by, updated_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`
	_, err := r.db.ExecContext(ctx, query,
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
	)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}
	return nil
}

// GetByID retrieves a policy by ID
func (r *PolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Policy, error) {
	var policy models.Policy
	query := `
		SELECT id, name, description, language, policy_content, effect, priority, enabled, created_at, updated_at, created_by, updated_by
		FROM policies
		WHERE id = $1
	`
	err := sqlx.GetContext(ctx, r.db, &policy, query, id)
	if err == sql.ErrNoRows {
		return nil, models.ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	return &policy, nil
}

// GetByName retrieves a policy by name
func (r *PolicyRepository) GetByName(ctx context.Context, name string) (*models.Policy, error) {
	var policy models.Policy
	query := `
		SELECT id, name, description, language, policy_content, effect, priority, enabled, created_at, updated_at, created_by, updated_by
		FROM policies
		WHERE name = $1
	`
	err := sqlx.GetContext(ctx, r.db, &policy, query, name)
	if err == sql.ErrNoRows {
		return nil, models.ErrPolicyNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get policy: %w", err)
	}
	return &policy, nil
}

// List retrieves policies with optional filtering
func (r *PolicyRepository) List(ctx context.Context, req *models.ListPoliciesRequest) ([]*models.Policy, error) {
	policies := make([]*models.Policy, 0)

	query := `
		SELECT id, name, description, language, policy_content, effect, priority, enabled, created_at, updated_at, created_by, updated_by
		FROM policies
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	// Build WHERE clause
	if req.Language != nil {
		query += fmt.Sprintf(" AND language = $%d", argCount)
		args = append(args, *req.Language)
		argCount++
	}
	if req.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argCount)
		args = append(args, *req.Enabled)
		argCount++
	}
	if req.Effect != nil {
		query += fmt.Sprintf(" AND effect = $%d", argCount)
		args = append(args, *req.Effect)
		argCount++
	}

	// Add ordering
	query += " ORDER BY priority DESC, created_at DESC"

	// Add pagination
	if req.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argCount)
		args = append(args, req.Limit)
		argCount++
	}
	if req.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argCount)
		args = append(args, req.Offset)
	}

	err := sqlx.SelectContext(ctx, r.db, &policies, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list policies: %w", err)
	}

	return policies, nil
}

// Update updates an existing policy
func (r *PolicyRepository) Update(ctx context.Context, policy *models.Policy) error {
	query := `
		UPDATE policies
		SET name = $1, description = $2, language = $3, policy_content = $4, effect = $5, priority = $6, enabled = $7, updated_at = $8, updated_by = $9
		WHERE id = $10
	`
	result, err := r.db.ExecContext(ctx, query,
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
	)
	if err != nil {
		return fmt.Errorf("failed to update policy: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrPolicyNotFound
	}

	return nil
}

// Delete deletes a policy by ID
func (r *PolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM policies WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete policy: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrPolicyNotFound
	}

	return nil
}

// ListEnabled retrieves all enabled policies ordered by priority
func (r *PolicyRepository) ListEnabled(ctx context.Context) ([]*models.Policy, error) {
	var policies []*models.Policy
	query := `
		SELECT id, name, description, language, policy_content, effect, priority, enabled, created_at, updated_at, created_by, updated_by
		FROM policies
		WHERE enabled = true
		ORDER BY priority DESC, created_at DESC
	`
	err := sqlx.SelectContext(ctx, r.db, &policies, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list enabled policies: %w", err)
	}
	return policies, nil
}

// Count returns the total count of policies matching the criteria
func (r *PolicyRepository) Count(ctx context.Context, req *models.ListPoliciesRequest) (int, error) {
	query := "SELECT COUNT(*) FROM policies WHERE 1=1"
	args := []interface{}{}
	argCount := 1

	if req.Language != nil {
		query += fmt.Sprintf(" AND language = $%d", argCount)
		args = append(args, *req.Language)
		argCount++
	}
	if req.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argCount)
		args = append(args, *req.Enabled)
		argCount++
	}
	if req.Effect != nil {
		query += fmt.Sprintf(" AND effect = $%d", argCount)
		args = append(args, *req.Effect)
	}

	var count int
	err := sqlx.GetContext(ctx, r.db, &count, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to count policies: %w", err)
	}

	return count, nil
}