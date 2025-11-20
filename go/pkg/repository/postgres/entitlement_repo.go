package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"stratium/pkg/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// EntitlementRepository implements repository.EntitlementRepository for PostgreSQL
type EntitlementRepository struct {
	db sqlx.ExtContext
}

// NewEntitlementRepository creates a new PostgreSQL entitlement repository
func NewEntitlementRepository(db sqlx.ExtContext) *EntitlementRepository {
	return &EntitlementRepository{db: db}
}

// Create creates a new entitlement
func (r *EntitlementRepository) Create(ctx context.Context, entitlement *models.Entitlement) error {
	subjectAttrs, err := json.Marshal(entitlement.SubjectAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal subject attributes: %w", err)
	}

	resourceAttrs, err := json.Marshal(entitlement.ResourceAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal resource attributes: %w", err)
	}

	actions, err := json.Marshal(entitlement.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	conditions, err := json.Marshal(entitlement.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	query := `
		INSERT INTO entitlements (id, name, description, subject_attributes, resource_attributes, actions, conditions, enabled, created_at, updated_at, created_by, updated_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`
	_, err = r.db.ExecContext(ctx, query,
		entitlement.ID,
		entitlement.Name,
		entitlement.Description,
		subjectAttrs,
		resourceAttrs,
		actions,
		conditions,
		entitlement.Enabled,
		entitlement.CreatedAt,
		entitlement.UpdatedAt,
		entitlement.CreatedBy,
		entitlement.UpdatedBy,
		entitlement.ExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create entitlement: %w", err)
	}
	return nil
}

// GetByID retrieves an entitlement by ID
func (r *EntitlementRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Entitlement, error) {
	query := `
		SELECT id, name, description, subject_attributes, resource_attributes, actions, conditions, enabled, created_at, updated_at, created_by, updated_by, expires_at
		FROM entitlements
		WHERE id = $1
	`
	var entitlement entitlementRow
	err := sqlx.GetContext(ctx, r.db, &entitlement, query, id)
	if err == sql.ErrNoRows {
		return nil, models.ErrEntitlementNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get entitlement: %w", err)
	}
	return entitlement.toModel()
}

// GetByName retrieves an entitlement by name
func (r *EntitlementRepository) GetByName(ctx context.Context, name string) (*models.Entitlement, error) {
	query := `
		SELECT id, name, description, subject_attributes, resource_attributes, actions, conditions, enabled, created_at, updated_at, created_by, updated_by, expires_at
		FROM entitlements
		WHERE name = $1
	`
	var entitlement entitlementRow
	err := sqlx.GetContext(ctx, r.db, &entitlement, query, name)
	if err == sql.ErrNoRows {
		return nil, models.ErrEntitlementNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get entitlement: %w", err)
	}
	return entitlement.toModel()
}

// List retrieves entitlements with optional filtering
func (r *EntitlementRepository) List(ctx context.Context, req *models.ListEntitlementsRequest) ([]*models.Entitlement, error) {
	query := `
		SELECT id, name, description, subject_attributes, resource_attributes, actions, conditions, enabled, created_at, updated_at, created_by, updated_by, expires_at
		FROM entitlements
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	// Build WHERE clause
	if req.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argCount)
		args = append(args, *req.Enabled)
		argCount++
	}

	if req.Action != "" {
		query += fmt.Sprintf(" AND actions @> $%d", argCount)
		actionJSON, _ := json.Marshal([]string{req.Action})
		args = append(args, actionJSON)
		argCount++
	}

	// Add ordering
	query += " ORDER BY created_at DESC"

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

	var entitlements []entitlementRow
	err := sqlx.SelectContext(ctx, r.db, &entitlements, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list entitlements: %w", err)
	}

	return entitlementRowsToModels(entitlements)
}

// Update updates an existing entitlement
func (r *EntitlementRepository) Update(ctx context.Context, entitlement *models.Entitlement) error {
	subjectAttrs, err := json.Marshal(entitlement.SubjectAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal subject attributes: %w", err)
	}

	resourceAttrs, err := json.Marshal(entitlement.ResourceAttributes)
	if err != nil {
		return fmt.Errorf("failed to marshal resource attributes: %w", err)
	}

	actions, err := json.Marshal(entitlement.Actions)
	if err != nil {
		return fmt.Errorf("failed to marshal actions: %w", err)
	}

	conditions, err := json.Marshal(entitlement.Conditions)
	if err != nil {
		return fmt.Errorf("failed to marshal conditions: %w", err)
	}

	query := `
		UPDATE entitlements
		SET name = $1, description = $2, subject_attributes = $3, resource_attributes = $4, actions = $5, conditions = $6, enabled = $7, updated_at = $8, updated_by = $9, expires_at = $10
		WHERE id = $11
	`
	result, err := r.db.ExecContext(ctx, query,
		entitlement.Name,
		entitlement.Description,
		subjectAttrs,
		resourceAttrs,
		actions,
		conditions,
		entitlement.Enabled,
		entitlement.UpdatedAt,
		entitlement.UpdatedBy,
		entitlement.ExpiresAt,
		entitlement.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update entitlement: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrEntitlementNotFound
	}

	return nil
}

// Delete deletes an entitlement by ID
func (r *EntitlementRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM entitlements WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete entitlement: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return models.ErrEntitlementNotFound
	}

	return nil
}

// FindMatching finds entitlements matching the given criteria
func (r *EntitlementRepository) FindMatching(ctx context.Context, req *models.EntitlementMatchRequest) ([]*models.Entitlement, error) {
	subjectAttrs, err := json.Marshal(req.SubjectAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject attributes: %w", err)
	}

	// Build query with optional action filter
	// Note: subject_attributes <@ $1 means "entitlement's subject_attributes is contained by user's attributes"
	// This allows partial matching - the entitlement only needs to specify a subset of the user's attributes
	query := `
		SELECT id, name, description, subject_attributes, resource_attributes, actions, conditions, enabled, created_at, updated_at, created_by, updated_by, expires_at
		FROM entitlements
		WHERE enabled = true
		AND (expires_at IS NULL OR expires_at > NOW())
		AND subject_attributes <@ $1
	`
	args := []interface{}{subjectAttrs}

	// Add action filter if specified
	if req.Action != "" {
		actionJSON, err := json.Marshal([]string{req.Action})
		if err != nil {
			return nil, fmt.Errorf("failed to marshal action: %w", err)
		}
		query += " AND actions @> $2"
		args = append(args, actionJSON)
	}

	query += " ORDER BY created_at DESC"

	var entitlements []entitlementRow
	err = sqlx.SelectContext(ctx, r.db, &entitlements, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to find matching entitlements: %w", err)
	}

	return entitlementRowsToModels(entitlements)
}

// ListActive retrieves all active (enabled and not expired) entitlements
func (r *EntitlementRepository) ListActive(ctx context.Context) ([]*models.Entitlement, error) {
	query := `
		SELECT id, name, description, subject_attributes, resource_attributes, actions, conditions, enabled, created_at, updated_at, created_by, updated_by, expires_at
		FROM entitlements
		WHERE enabled = true
		AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY created_at DESC
	`

	var entitlements []entitlementRow
	err := sqlx.SelectContext(ctx, r.db, &entitlements, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list active entitlements: %w", err)
	}

	return entitlementRowsToModels(entitlements)
}

// Count returns the total count of entitlements matching the criteria
func (r *EntitlementRepository) Count(ctx context.Context, req *models.ListEntitlementsRequest) (int, error) {
	query := "SELECT COUNT(*) FROM entitlements WHERE 1=1"
	args := []interface{}{}
	argCount := 1

	if req.Enabled != nil {
		query += fmt.Sprintf(" AND enabled = $%d", argCount)
		args = append(args, *req.Enabled)
		argCount++
	}

	if req.Action != "" {
		query += fmt.Sprintf(" AND actions @> $%d", argCount)
		actionJSON, _ := json.Marshal([]string{req.Action})
		args = append(args, actionJSON)
	}

	var count int
	err := sqlx.GetContext(ctx, r.db, &count, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to count entitlements: %w", err)
	}

	return count, nil
}

// entitlementRow is a helper struct for scanning JSONB columns
type entitlementRow struct {
	ID                 uuid.UUID      `db:"id"`
	Name               string         `db:"name"`
	Description        string         `db:"description"`
	SubjectAttributes  []byte         `db:"subject_attributes"`
	ResourceAttributes []byte         `db:"resource_attributes"`
	Actions            []byte         `db:"actions"`
	Conditions         []byte         `db:"conditions"`
	Enabled            bool           `db:"enabled"`
	CreatedAt          sql.NullTime   `db:"created_at"`
	UpdatedAt          sql.NullTime   `db:"updated_at"`
	CreatedBy          sql.NullString `db:"created_by"`
	UpdatedBy          sql.NullString `db:"updated_by"`
	ExpiresAt          sql.NullTime   `db:"expires_at"`
}

func (r *entitlementRow) toModel() (*models.Entitlement, error) {
	var subjectAttrs map[string]interface{}
	if len(r.SubjectAttributes) > 0 {
		if err := json.Unmarshal(r.SubjectAttributes, &subjectAttrs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal subject attributes: %w", err)
		}
	}
	if subjectAttrs == nil {
		subjectAttrs = make(map[string]interface{})
	}

	var resourceAttrs map[string]interface{}
	if len(r.ResourceAttributes) > 0 {
		if err := json.Unmarshal(r.ResourceAttributes, &resourceAttrs); err != nil {
			return nil, fmt.Errorf("failed to unmarshal resource attributes: %w", err)
		}
	}
	if resourceAttrs == nil {
		resourceAttrs = make(map[string]interface{})
	}

	var actions []string
	if len(r.Actions) > 0 {
		if err := json.Unmarshal(r.Actions, &actions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal actions: %w", err)
		}
	}
	if actions == nil {
		actions = []string{}
	}

	var conditions map[string]interface{}
	if len(r.Conditions) > 0 {
		if err := json.Unmarshal(r.Conditions, &conditions); err != nil {
			return nil, fmt.Errorf("failed to unmarshal conditions: %w", err)
		}
	}
	if conditions == nil {
		conditions = make(map[string]interface{})
	}

	var expiresAt *sql.NullTime
	if r.ExpiresAt.Valid {
		expiresAt = &r.ExpiresAt
	}

	return &models.Entitlement{
		ID:                 r.ID,
		Name:               r.Name,
		Description:        r.Description,
		SubjectAttributes:  subjectAttrs,
		ResourceAttributes: resourceAttrs,
		Actions:            actions,
		Conditions:         conditions,
		Enabled:            r.Enabled,
		CreatedAt:          r.CreatedAt.Time,
		UpdatedAt:          r.UpdatedAt.Time,
		CreatedBy:          r.CreatedBy,
		UpdatedBy:          r.UpdatedBy,
		ExpiresAt:          nullTimeToTimePtr(expiresAt),
	}, nil
}

func entitlementRowsToModels(rows []entitlementRow) ([]*models.Entitlement, error) {
	entitlements := make([]*models.Entitlement, 0, len(rows))
	for _, row := range rows {
		entitlement, err := row.toModel()
		if err != nil {
			return nil, err
		}
		entitlements = append(entitlements, entitlement)
	}
	return entitlements, nil
}

func nullTimeToTimePtr(nt *sql.NullTime) *time.Time {
	if nt == nil || !nt.Valid {
		return nil
	}
	t := nt.Time
	return &t
}