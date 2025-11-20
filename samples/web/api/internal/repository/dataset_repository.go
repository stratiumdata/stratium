package repository

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/stratium/samples/micro-research-api/internal/models"
)

// DatasetRepository handles database operations for datasets
type DatasetRepository struct {
	db *sqlx.DB
}

// NewDatasetRepository creates a new dataset repository
func NewDatasetRepository(db *sqlx.DB) *DatasetRepository {
	return &DatasetRepository{db: db}
}

// Create creates a new dataset
func (r *DatasetRepository) Create(ctx context.Context, dataset *models.Dataset) error {
	query := `
		INSERT INTO datasets (id, title, description, owner_id, data_url, department, tags, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	_, err := r.db.ExecContext(ctx, query,
		dataset.ID,
		dataset.Title,
		dataset.Description,
		dataset.OwnerID,
		dataset.DataURL,
		dataset.Department,
		pq.Array(dataset.Tags),
		dataset.CreatedAt,
		dataset.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("failed to create dataset: %w", err)
	}
	return nil
}

// GetByID retrieves a dataset by ID
func (r *DatasetRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DatasetWithOwner, error) {
	var dataset models.DatasetWithOwner
	query := `
		SELECT
			d.*,
			u.name as owner_name,
			u.email as owner_email
		FROM datasets d
		JOIN users u ON d.owner_id = u.id
		WHERE d.id = $1
	`
	err := r.db.GetContext(ctx, &dataset, query, id)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("dataset not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get dataset: %w", err)
	}
	return &dataset, nil
}

// List retrieves datasets with pagination
func (r *DatasetRepository) List(ctx context.Context, limit, offset int) ([]models.DatasetWithOwner, int, error) {
	var datasets []models.DatasetWithOwner

	// Get total count
	var total int
	countQuery := `SELECT COUNT(*) FROM datasets`
	err := r.db.GetContext(ctx, &total, countQuery)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count datasets: %w", err)
	}

	// Get paginated results
	query := `
		SELECT
			d.*,
			u.name as owner_name,
			u.email as owner_email
		FROM datasets d
		JOIN users u ON d.owner_id = u.id
		ORDER BY d.created_at DESC
		LIMIT $1 OFFSET $2
	`
	err = r.db.SelectContext(ctx, &datasets, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list datasets: %w", err)
	}

	return datasets, total, nil
}

// Search searches datasets with filters
func (r *DatasetRepository) Search(ctx context.Context, req models.SearchDatasetsRequest) ([]models.DatasetWithOwner, int, error) {
	var datasets []models.DatasetWithOwner

	// Build WHERE clause dynamically
	where := []string{"1=1"}
	args := []interface{}{}
	argCount := 1

	// Text search on title and description
	if req.Query != "" {
		where = append(where, fmt.Sprintf("(d.title ILIKE $%d OR d.description ILIKE $%d)", argCount, argCount))
		args = append(args, "%"+req.Query+"%")
		argCount++
	}

	// Filter by department
	if req.Department != "" {
		where = append(where, fmt.Sprintf("d.department = $%d", argCount))
		args = append(args, req.Department)
		argCount++
	}

	// Filter by owner
	if req.OwnerID != "" {
		ownerUUID, err := uuid.Parse(req.OwnerID)
		if err == nil {
			where = append(where, fmt.Sprintf("d.owner_id = $%d", argCount))
			args = append(args, ownerUUID)
			argCount++
		}
	}

	// Filter by tags (array overlap)
	if len(req.Tags) > 0 {
		where = append(where, fmt.Sprintf("d.tags && $%d", argCount))
		args = append(args, pq.Array(req.Tags))
		argCount++
	}

	whereClause := strings.Join(where, " AND ")

	// Get total count with filters
	var total int
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM datasets d WHERE %s`, whereClause)
	err := r.db.GetContext(ctx, &total, countQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count datasets: %w", err)
	}

	// Set defaults for pagination
	if req.Limit <= 0 {
		req.Limit = 20
	}
	if req.Offset < 0 {
		req.Offset = 0
	}

	// Get results with pagination
	query := fmt.Sprintf(`
		SELECT
			d.*,
			u.name as owner_name,
			u.email as owner_email
		FROM datasets d
		JOIN users u ON d.owner_id = u.id
		WHERE %s
		ORDER BY d.created_at DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argCount, argCount+1)

	args = append(args, req.Limit, req.Offset)

	err = r.db.SelectContext(ctx, &datasets, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to search datasets: %w", err)
	}

	return datasets, total, nil
}

// Update updates a dataset
func (r *DatasetRepository) Update(ctx context.Context, dataset *models.Dataset) error {
	query := `
		UPDATE datasets
		SET title = $1, description = $2, data_url = $3, department = $4, tags = $5, updated_at = NOW()
		WHERE id = $6
	`
	result, err := r.db.ExecContext(ctx, query,
		dataset.Title,
		dataset.Description,
		dataset.DataURL,
		dataset.Department,
		pq.Array(dataset.Tags),
		dataset.ID,
	)
	if err != nil {
		return fmt.Errorf("failed to update dataset: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("dataset not found")
	}

	return nil
}

// Delete deletes a dataset
func (r *DatasetRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM datasets WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete dataset: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("dataset not found")
	}

	return nil
}