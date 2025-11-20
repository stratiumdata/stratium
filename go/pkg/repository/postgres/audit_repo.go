package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"stratium/pkg/models"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// AuditRepository implements repository.AuditRepository for PostgreSQL
type AuditRepository struct {
	db sqlx.ExtContext
}

// NewAuditRepository creates a new PostgreSQL audit repository
func NewAuditRepository(db sqlx.ExtContext) *AuditRepository {
	return &AuditRepository{db: db}
}

// Create creates a new audit log entry
func (r *AuditRepository) Create(ctx context.Context, auditLog *models.AuditLog) error {
	changes, err := json.Marshal(auditLog.Changes)
	if err != nil {
		return fmt.Errorf("failed to marshal changes: %w", err)
	}

	result, err := json.Marshal(auditLog.Result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	query := `
		INSERT INTO audit_logs (id, entity_type, entity_id, action, actor, changes, result, timestamp, ip_address, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`
	_, err = r.db.ExecContext(ctx, query,
		auditLog.ID,
		auditLog.EntityType,
		auditLog.EntityID,
		auditLog.Action,
		auditLog.Actor,
		changes,
		result,
		auditLog.Timestamp,
		auditLog.IPAddress,
		auditLog.UserAgent,
	)
	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}
	return nil
}

// GetByID retrieves an audit log entry by ID
func (r *AuditRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.AuditLog, error) {
	query := `
		SELECT id, entity_type, entity_id, action, actor, changes, result, timestamp, ip_address, user_agent
		FROM audit_logs
		WHERE id = $1
	`
	var auditLog auditLogRow
	err := sqlx.GetContext(ctx, r.db, &auditLog, query, id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("audit log not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get audit log: %w", err)
	}
	return auditLog.toModel()
}

// List retrieves audit logs with optional filtering
func (r *AuditRepository) List(ctx context.Context, req *models.ListAuditLogsRequest) ([]*models.AuditLog, error) {
	query := `
		SELECT id, entity_type, entity_id, action, actor, changes, result, timestamp, ip_address, user_agent
		FROM audit_logs
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 1

	// Build WHERE clause
	if req.EntityType != nil {
		query += fmt.Sprintf(" AND entity_type = $%d", argCount)
		args = append(args, *req.EntityType)
		argCount++
	}
	if req.EntityID != nil {
		query += fmt.Sprintf(" AND entity_id = $%d", argCount)
		args = append(args, *req.EntityID)
		argCount++
	}
	if req.Action != nil {
		query += fmt.Sprintf(" AND action = $%d", argCount)
		args = append(args, *req.Action)
		argCount++
	}
	if req.Actor != "" {
		query += fmt.Sprintf(" AND actor = $%d", argCount)
		args = append(args, req.Actor)
		argCount++
	}
	if req.StartDate != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argCount)
		args = append(args, *req.StartDate)
		argCount++
	}
	if req.EndDate != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argCount)
		args = append(args, *req.EndDate)
		argCount++
	}

	// Add ordering
	query += " ORDER BY timestamp DESC"

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

	var auditLogs []auditLogRow
	err := sqlx.SelectContext(ctx, r.db, &auditLogs, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}

	return auditLogRowsToModels(auditLogs)
}

// ListByEntity retrieves audit logs for a specific entity
func (r *AuditRepository) ListByEntity(ctx context.Context, entityType models.EntityType, entityID uuid.UUID) ([]*models.AuditLog, error) {
	query := `
		SELECT id, entity_type, entity_id, action, actor, changes, result, timestamp, ip_address, user_agent
		FROM audit_logs
		WHERE entity_type = $1 AND entity_id = $2
		ORDER BY timestamp DESC
	`

	var auditLogs []auditLogRow
	err := sqlx.SelectContext(ctx, r.db, &auditLogs, query, entityType, entityID)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs by entity: %w", err)
	}

	return auditLogRowsToModels(auditLogs)
}

// ListByActor retrieves audit logs for a specific actor
func (r *AuditRepository) ListByActor(ctx context.Context, actor string, limit, offset int) ([]*models.AuditLog, error) {
	query := `
		SELECT id, entity_type, entity_id, action, actor, changes, result, timestamp, ip_address, user_agent
		FROM audit_logs
		WHERE actor = $1
		ORDER BY timestamp DESC
		LIMIT $2 OFFSET $3
	`

	var auditLogs []auditLogRow
	err := sqlx.SelectContext(ctx, r.db, &auditLogs, query, actor, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list audit logs by actor: %w", err)
	}

	return auditLogRowsToModels(auditLogs)
}

// Count returns the total count of audit logs matching the criteria
func (r *AuditRepository) Count(ctx context.Context, req *models.ListAuditLogsRequest) (int, error) {
	query := "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
	args := []interface{}{}
	argCount := 1

	if req.EntityType != nil {
		query += fmt.Sprintf(" AND entity_type = $%d", argCount)
		args = append(args, *req.EntityType)
		argCount++
	}
	if req.EntityID != nil {
		query += fmt.Sprintf(" AND entity_id = $%d", argCount)
		args = append(args, *req.EntityID)
		argCount++
	}
	if req.Action != nil {
		query += fmt.Sprintf(" AND action = $%d", argCount)
		args = append(args, *req.Action)
		argCount++
	}
	if req.Actor != "" {
		query += fmt.Sprintf(" AND actor = $%d", argCount)
		args = append(args, req.Actor)
		argCount++
	}
	if req.StartDate != nil {
		query += fmt.Sprintf(" AND timestamp >= $%d", argCount)
		args = append(args, *req.StartDate)
		argCount++
	}
	if req.EndDate != nil {
		query += fmt.Sprintf(" AND timestamp <= $%d", argCount)
		args = append(args, *req.EndDate)
	}

	var count int
	err := sqlx.GetContext(ctx, r.db, &count, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit logs: %w", err)
	}

	return count, nil
}

// auditLogRow is a helper struct for scanning JSONB columns
type auditLogRow struct {
	ID         uuid.UUID           `db:"id"`
	EntityType models.EntityType   `db:"entity_type"`
	EntityID   *uuid.UUID          `db:"entity_id"`
	Action     models.AuditAction  `db:"action"`
	Actor      string              `db:"actor"`
	Changes    []byte              `db:"changes"`
	Result     []byte              `db:"result"`
	Timestamp  sql.NullTime        `db:"timestamp"`
	IPAddress  string              `db:"ip_address"`
	UserAgent  string              `db:"user_agent"`
}

func (r *auditLogRow) toModel() (*models.AuditLog, error) {
	var changes map[string]interface{}
	if len(r.Changes) > 0 {
		if err := json.Unmarshal(r.Changes, &changes); err != nil {
			return nil, fmt.Errorf("failed to unmarshal changes: %w", err)
		}
	}

	var result map[string]interface{}
	if len(r.Result) > 0 {
		if err := json.Unmarshal(r.Result, &result); err != nil {
			return nil, fmt.Errorf("failed to unmarshal result: %w", err)
		}
	}

	return &models.AuditLog{
		ID:         r.ID,
		EntityType: r.EntityType,
		EntityID:   r.EntityID,
		Action:     r.Action,
		Actor:      r.Actor,
		Changes:    changes,
		Result:     result,
		Timestamp:  r.Timestamp.Time,
		IPAddress:  r.IPAddress,
		UserAgent:  r.UserAgent,
	}, nil
}

func auditLogRowsToModels(rows []auditLogRow) ([]*models.AuditLog, error) {
	auditLogs := make([]*models.AuditLog, 0, len(rows))
	for _, row := range rows {
		auditLog, err := row.toModel()
		if err != nil {
			return nil, err
		}
		auditLogs = append(auditLogs, auditLog)
	}
	return auditLogs, nil
}
