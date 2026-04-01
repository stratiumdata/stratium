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

// AgentRepository implements repository.AgentRepository for PostgreSQL
type AgentRepository struct {
	db sqlx.ExtContext
}

// NewAgentRepository creates a new PostgreSQL agent repository
func NewAgentRepository(db sqlx.ExtContext) *AgentRepository {
	return &AgentRepository{db: db}
}

// Create registers a new agent
func (r *AgentRepository) Create(ctx context.Context, agent *models.Agent) error {
	toolsJSON, err := json.Marshal(agent.AllowedTools)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_tools: %w", err)
	}
	actionsJSON, err := json.Marshal(agent.AllowedActions)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_actions: %w", err)
	}
	metadataJSON, err := json.Marshal(agent.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		INSERT INTO agents (id, name, description, provider, model_id, trust_tier,
			allowed_tools, allowed_actions, tenant_id, cert_status, client_id,
			client_secret, metadata, enabled, created_at, updated_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
	`
	_, err = r.db.ExecContext(ctx, query,
		agent.ID, agent.Name, agent.Description, agent.Provider,
		agent.ModelIdentifier, agent.TrustTier, toolsJSON, actionsJSON,
		agent.TenantID, agent.CertStatus, agent.ClientID, agent.ClientSecret,
		metadataJSON, agent.Enabled, agent.CreatedAt, agent.UpdatedAt, agent.CreatedBy,
	)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}
	return nil
}

// agentRow is the database row representation of an agent
type agentRow struct {
	ID              uuid.UUID `db:"id"`
	Name            string    `db:"name"`
	Description     string    `db:"description"`
	Provider        string    `db:"provider"`
	ModelIdentifier string    `db:"model_id"`
	TrustTier       int       `db:"trust_tier"`
	AllowedTools    []byte    `db:"allowed_tools"`
	AllowedActions  []byte    `db:"allowed_actions"`
	TenantID        string    `db:"tenant_id"`
	CertStatus      string    `db:"cert_status"`
	ClientID        string    `db:"client_id"`
	ClientSecret    []byte    `db:"client_secret"`
	Metadata        []byte    `db:"metadata"`
	Enabled         bool      `db:"enabled"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
	CreatedBy       string    `db:"created_by"`
}

func (row *agentRow) toAgent() (*models.Agent, error) {
	agent := &models.Agent{
		ID:              row.ID,
		Name:            row.Name,
		Description:     row.Description,
		Provider:        row.Provider,
		ModelIdentifier: row.ModelIdentifier,
		TrustTier:       models.AgentTrustTier(row.TrustTier),
		TenantID:        row.TenantID,
		CertStatus:      models.AgentCertStatus(row.CertStatus),
		ClientID:        row.ClientID,
		ClientSecret:    row.ClientSecret,
		Enabled:         row.Enabled,
		CreatedAt:       row.CreatedAt,
		UpdatedAt:       row.UpdatedAt,
		CreatedBy:       row.CreatedBy,
	}

	if err := json.Unmarshal(row.AllowedTools, &agent.AllowedTools); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allowed_tools: %w", err)
	}
	if err := json.Unmarshal(row.AllowedActions, &agent.AllowedActions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal allowed_actions: %w", err)
	}
	if len(row.Metadata) > 0 {
		if err := json.Unmarshal(row.Metadata, &agent.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	return agent, nil
}

const agentColumns = `id, name, description, provider, model_id, trust_tier,
	allowed_tools, allowed_actions, tenant_id, cert_status, client_id,
	client_secret, metadata, enabled, created_at, updated_at, created_by`

// GetByID retrieves an agent by ID
func (r *AgentRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Agent, error) {
	var row agentRow
	query := fmt.Sprintf("SELECT %s FROM agents WHERE id = $1", agentColumns)
	err := sqlx.GetContext(ctx, r.db, &row, query, id)
	if err == sql.ErrNoRows {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get agent: %w", err)
	}
	return row.toAgent()
}

// GetByClientID retrieves an agent by client ID
func (r *AgentRepository) GetByClientID(ctx context.Context, clientID string) (*models.Agent, error) {
	var row agentRow
	query := fmt.Sprintf("SELECT %s FROM agents WHERE client_id = $1", agentColumns)
	err := sqlx.GetContext(ctx, r.db, &row, query, clientID)
	if err == sql.ErrNoRows {
		return nil, models.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get agent by client_id: %w", err)
	}
	return row.toAgent()
}

// List retrieves agents with optional filtering
func (r *AgentRepository) List(ctx context.Context, req *models.ListAgentsRequest) ([]*models.Agent, error) {
	query := fmt.Sprintf("SELECT %s FROM agents WHERE 1=1", agentColumns)
	args := []interface{}{}
	argIdx := 1

	if req.TenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, req.TenantID)
		argIdx++
	}
	if req.TrustTier != nil {
		query += fmt.Sprintf(" AND trust_tier = $%d", argIdx)
		args = append(args, *req.TrustTier)
		argIdx++
	}
	if req.EnabledOnly {
		query += " AND enabled = true"
	}

	query += " ORDER BY created_at DESC"

	if req.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", argIdx)
		args = append(args, req.Limit)
		argIdx++
	}
	if req.Offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, req.Offset)
	}

	var rows []agentRow
	err := sqlx.SelectContext(ctx, r.db, &rows, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list agents: %w", err)
	}

	agents := make([]*models.Agent, 0, len(rows))
	for _, row := range rows {
		agent, err := row.toAgent()
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, nil
}

// Update updates an existing agent
func (r *AgentRepository) Update(ctx context.Context, agent *models.Agent) error {
	toolsJSON, err := json.Marshal(agent.AllowedTools)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_tools: %w", err)
	}
	actionsJSON, err := json.Marshal(agent.AllowedActions)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed_actions: %w", err)
	}
	metadataJSON, err := json.Marshal(agent.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	query := `
		UPDATE agents SET
			name = $2, description = $3, trust_tier = $4,
			allowed_tools = $5, allowed_actions = $6, cert_status = $7,
			metadata = $8, enabled = $9, updated_at = $10
		WHERE id = $1
	`
	result, err := r.db.ExecContext(ctx, query,
		agent.ID, agent.Name, agent.Description, agent.TrustTier,
		toolsJSON, actionsJSON, agent.CertStatus,
		metadataJSON, agent.Enabled, time.Now(),
	)
	if err != nil {
		return fmt.Errorf("failed to update agent: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return models.ErrNotFound
	}
	return nil
}

// Delete deletes an agent by ID
func (r *AgentRepository) Delete(ctx context.Context, id uuid.UUID) error {
	result, err := r.db.ExecContext(ctx, "DELETE FROM agents WHERE id = $1", id)
	if err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return models.ErrNotFound
	}
	return nil
}

// Count returns the total count of agents matching the criteria
func (r *AgentRepository) Count(ctx context.Context, req *models.ListAgentsRequest) (int, error) {
	query := "SELECT COUNT(*) FROM agents WHERE 1=1"
	args := []interface{}{}
	argIdx := 1

	if req.TenantID != "" {
		query += fmt.Sprintf(" AND tenant_id = $%d", argIdx)
		args = append(args, req.TenantID)
		argIdx++
	}
	if req.TrustTier != nil {
		query += fmt.Sprintf(" AND trust_tier = $%d", argIdx)
		args = append(args, *req.TrustTier)
		argIdx++
	}
	if req.EnabledOnly {
		query += " AND enabled = true"
	}

	var count int
	err := sqlx.GetContext(ctx, r.db, &count, query, args...)
	if err != nil {
		return 0, fmt.Errorf("failed to count agents: %w", err)
	}
	return count, nil
}
