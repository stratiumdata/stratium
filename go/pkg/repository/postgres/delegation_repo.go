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

// DelegationRepository implements repository.DelegationRepository for PostgreSQL
type DelegationRepository struct {
	db sqlx.ExtContext
}

// NewDelegationRepository creates a new PostgreSQL delegation repository
func NewDelegationRepository(db sqlx.ExtContext) *DelegationRepository {
	return &DelegationRepository{db: db}
}

// delegationRow is the database row representation of a delegation
type delegationRow struct {
	ID                  uuid.UUID  `db:"id"`
	UserID              string     `db:"user_id"`
	AgentID             uuid.UUID  `db:"agent_id"`
	TenantID            string     `db:"tenant_id"`
	ConversationID      string     `db:"conversation_id"`
	ApprovedTools       []byte     `db:"approved_tools"`
	ApprovedActions     []byte     `db:"approved_actions"`
	MaxActionTier       int        `db:"max_action_tier"`
	ClassificationCaps  []byte     `db:"classification_caps"`
	ResourceConstraints []byte     `db:"resource_constraints"`
	Purpose             string     `db:"purpose"`
	ExpiresAt           time.Time  `db:"expires_at"`
	CreatedAt           time.Time  `db:"created_at"`
	Revoked             bool       `db:"revoked"`
	RevokedAt           *time.Time `db:"revoked_at"`
	ParentDelegationID  *uuid.UUID `db:"parent_delegation_id"`
	RootDelegationID    uuid.UUID  `db:"root_delegation_id"`
	Depth               int        `db:"depth"`
	ChainAgentIDs       []byte     `db:"chain_agent_ids"`
}

func (row *delegationRow) toDelegation() (*models.Delegation, error) {
	d := &models.Delegation{
		ID:                 row.ID,
		UserID:             row.UserID,
		AgentID:            row.AgentID,
		TenantID:           row.TenantID,
		ConversationID:     row.ConversationID,
		MaxActionTier:      models.ActionTier(row.MaxActionTier),
		Purpose:            row.Purpose,
		ExpiresAt:          row.ExpiresAt,
		CreatedAt:          row.CreatedAt,
		Revoked:            row.Revoked,
		RevokedAt:          row.RevokedAt,
		ParentDelegationID: row.ParentDelegationID,
		RootDelegationID:   row.RootDelegationID,
		Depth:              row.Depth,
	}

	if err := json.Unmarshal(row.ApprovedTools, &d.ApprovedTools); err != nil {
		return nil, fmt.Errorf("failed to unmarshal approved_tools: %w", err)
	}
	if err := json.Unmarshal(row.ApprovedActions, &d.ApprovedActions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal approved_actions: %w", err)
	}
	if err := json.Unmarshal(row.ClassificationCaps, &d.ClassificationCaps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal classification_caps: %w", err)
	}
	if err := json.Unmarshal(row.ResourceConstraints, &d.ResourceConstraints); err != nil {
		return nil, fmt.Errorf("failed to unmarshal resource_constraints: %w", err)
	}
	if err := json.Unmarshal(row.ChainAgentIDs, &d.ChainAgentIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal chain_agent_ids: %w", err)
	}

	return d, nil
}

const delegationColumns = `id, user_id, agent_id, tenant_id, conversation_id,
	approved_tools, approved_actions, max_action_tier, classification_caps,
	resource_constraints, purpose, expires_at, created_at, revoked, revoked_at,
	parent_delegation_id, root_delegation_id, depth, chain_agent_ids`

// Create creates a new delegation record
func (r *DelegationRepository) Create(ctx context.Context, delegation *models.Delegation) error {
	toolsJSON, err := json.Marshal(delegation.ApprovedTools)
	if err != nil {
		return fmt.Errorf("failed to marshal approved_tools: %w", err)
	}
	actionsJSON, err := json.Marshal(delegation.ApprovedActions)
	if err != nil {
		return fmt.Errorf("failed to marshal approved_actions: %w", err)
	}
	capsJSON, err := json.Marshal(delegation.ClassificationCaps)
	if err != nil {
		return fmt.Errorf("failed to marshal classification_caps: %w", err)
	}
	constraintsJSON, err := json.Marshal(delegation.ResourceConstraints)
	if err != nil {
		return fmt.Errorf("failed to marshal resource_constraints: %w", err)
	}
	chainJSON, err := json.Marshal(delegation.ChainAgentIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal chain_agent_ids: %w", err)
	}

	query := `
		INSERT INTO delegations (id, user_id, agent_id, tenant_id, conversation_id,
			approved_tools, approved_actions, max_action_tier, classification_caps,
			resource_constraints, purpose, expires_at, created_at, revoked,
			parent_delegation_id, root_delegation_id, depth, chain_agent_ids)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`
	_, err = r.db.ExecContext(ctx, query,
		delegation.ID, delegation.UserID, delegation.AgentID,
		delegation.TenantID, delegation.ConversationID,
		toolsJSON, actionsJSON, delegation.MaxActionTier,
		capsJSON, constraintsJSON, delegation.Purpose,
		delegation.ExpiresAt, delegation.CreatedAt, delegation.Revoked,
		delegation.ParentDelegationID, delegation.RootDelegationID,
		delegation.Depth, chainJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to create delegation: %w", err)
	}
	return nil
}

// GetByID retrieves a delegation by ID
func (r *DelegationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.Delegation, error) {
	var row delegationRow
	query := fmt.Sprintf("SELECT %s FROM delegations WHERE id = $1", delegationColumns)
	err := sqlx.GetContext(ctx, r.db, &row, query, id)
	if err == sql.ErrNoRows {
		return nil, models.ErrDelegationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get delegation: %w", err)
	}
	return row.toDelegation()
}

// GetChain retrieves the full delegation chain from root to the given delegation
func (r *DelegationRepository) GetChain(ctx context.Context, delegationID uuid.UUID) ([]*models.Delegation, error) {
	// First get the delegation to find its root
	delegation, err := r.GetByID(ctx, delegationID)
	if err != nil {
		return nil, err
	}

	// Get all delegations in the chain by root_delegation_id, ordered by depth
	query := fmt.Sprintf(`SELECT %s FROM delegations
		WHERE root_delegation_id = $1 AND depth <= $2
		ORDER BY depth ASC`, delegationColumns)

	var rows []delegationRow
	err = sqlx.SelectContext(ctx, r.db, &rows, query, delegation.RootDelegationID, delegation.Depth)
	if err != nil {
		return nil, fmt.Errorf("failed to get delegation chain: %w", err)
	}

	chain := make([]*models.Delegation, 0, len(rows))
	for _, row := range rows {
		d, err := row.toDelegation()
		if err != nil {
			return nil, err
		}
		chain = append(chain, d)
	}
	return chain, nil
}

// GetChildren retrieves all direct child delegations
func (r *DelegationRepository) GetChildren(ctx context.Context, parentID uuid.UUID) ([]*models.Delegation, error) {
	query := fmt.Sprintf("SELECT %s FROM delegations WHERE parent_delegation_id = $1", delegationColumns)

	var rows []delegationRow
	err := sqlx.SelectContext(ctx, r.db, &rows, query, parentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get children: %w", err)
	}

	children := make([]*models.Delegation, 0, len(rows))
	for _, row := range rows {
		d, err := row.toDelegation()
		if err != nil {
			return nil, err
		}
		children = append(children, d)
	}
	return children, nil
}

// GetDescendants retrieves all descendants for cascade revocation
func (r *DelegationRepository) GetDescendants(ctx context.Context, rootDelegationID uuid.UUID, minDepth int) ([]*models.Delegation, error) {
	query := fmt.Sprintf(`SELECT %s FROM delegations
		WHERE root_delegation_id = $1 AND depth >= $2 AND revoked = false
		ORDER BY depth ASC`, delegationColumns)

	var rows []delegationRow
	err := sqlx.SelectContext(ctx, r.db, &rows, query, rootDelegationID, minDepth)
	if err != nil {
		return nil, fmt.Errorf("failed to get descendants: %w", err)
	}

	descendants := make([]*models.Delegation, 0, len(rows))
	for _, row := range rows {
		d, err := row.toDelegation()
		if err != nil {
			return nil, err
		}
		descendants = append(descendants, d)
	}
	return descendants, nil
}

// Revoke revokes a delegation and cascades to all children.
// Returns the count of revoked delegations and their IDs.
func (r *DelegationRepository) Revoke(ctx context.Context, id uuid.UUID, reason string) (int, []uuid.UUID, error) {
	delegation, err := r.GetByID(ctx, id)
	if err != nil {
		return 0, nil, err
	}

	now := time.Now()

	// Revoke the target delegation
	_, err = r.db.ExecContext(ctx,
		"UPDATE delegations SET revoked = true, revoked_at = $2 WHERE id = $1",
		id, now)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to revoke delegation: %w", err)
	}

	revokedIDs := []uuid.UUID{id}

	// Cascade: revoke all descendants
	result, err := r.db.ExecContext(ctx, `
		UPDATE delegations SET revoked = true, revoked_at = $3
		WHERE root_delegation_id = $1 AND depth > $2 AND revoked = false`,
		delegation.RootDelegationID, delegation.Depth, now)
	if err != nil {
		return 1, revokedIDs, fmt.Errorf("failed to cascade revoke: %w", err)
	}

	cascaded, _ := result.RowsAffected()

	// Fetch the cascade-revoked IDs for the response
	if cascaded > 0 {
		var ids []uuid.UUID
		err = sqlx.SelectContext(ctx, r.db, &ids, `
			SELECT id FROM delegations
			WHERE root_delegation_id = $1 AND depth > $2 AND revoked = true AND revoked_at = $3`,
			delegation.RootDelegationID, delegation.Depth, now)
		if err == nil {
			revokedIDs = append(revokedIDs, ids...)
		}
	}

	return int(cascaded) + 1, revokedIDs, nil
}

// ListActive retrieves all active delegations for a user+agent pair
func (r *DelegationRepository) ListActive(ctx context.Context, userID string, agentID uuid.UUID) ([]*models.Delegation, error) {
	query := fmt.Sprintf(`SELECT %s FROM delegations
		WHERE user_id = $1 AND agent_id = $2 AND revoked = false AND expires_at > $3
		ORDER BY created_at DESC`, delegationColumns)

	var rows []delegationRow
	err := sqlx.SelectContext(ctx, r.db, &rows, query, userID, agentID, time.Now())
	if err != nil {
		return nil, fmt.Errorf("failed to list active delegations: %w", err)
	}

	delegations := make([]*models.Delegation, 0, len(rows))
	for _, row := range rows {
		d, err := row.toDelegation()
		if err != nil {
			return nil, err
		}
		delegations = append(delegations, d)
	}
	return delegations, nil
}

// RevokeByAgent revokes all active delegations for an agent
func (r *DelegationRepository) RevokeByAgent(ctx context.Context, agentID uuid.UUID) (int, error) {
	now := time.Now()
	result, err := r.db.ExecContext(ctx, `
		UPDATE delegations SET revoked = true, revoked_at = $2
		WHERE agent_id = $1 AND revoked = false`,
		agentID, now)
	if err != nil {
		return 0, fmt.Errorf("failed to revoke delegations by agent: %w", err)
	}
	count, _ := result.RowsAffected()
	return int(count), nil
}

// CleanExpired removes expired delegations (maintenance)
func (r *DelegationRepository) CleanExpired(ctx context.Context) (int, error) {
	result, err := r.db.ExecContext(ctx,
		"DELETE FROM delegations WHERE expires_at < $1 AND revoked = true",
		time.Now().Add(-24*time.Hour))
	if err != nil {
		return 0, fmt.Errorf("failed to clean expired delegations: %w", err)
	}
	count, _ := result.RowsAffected()
	return int(count), nil
}
