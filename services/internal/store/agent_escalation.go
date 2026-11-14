// agent_escalation.go writes the one agent column the escalation routes own,
// escalate_at, with the same shape agent_constraints.go gives
// resource_constraints: one transaction, the row locked before it is read,
// an audit entry attributed to the operator, and a containment verdict when
// the write widens the agent's grant.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
)

const (
	eventTypeAgentEscalationSet     = "agent_escalation_set"
	eventTypeAgentEscalationCleared = "agent_escalation_cleared"
)

// loadAgentEscalationForUpdateQuery locks the row before reading the value
// this write replaces, for the reason loadAgentConstraintsForUpdateQuery
// gives: the containment verdict is only meaningful against the value this
// transaction's own UPDATE then overwrites.
const loadAgentEscalationForUpdateQuery = `SELECT escalate_at FROM agents WHERE id = $1 FOR UPDATE`

// updateAgentEscalationQuery leaves updated_at to Postgres, returned as the
// audit entry's OccurredAt, as updateAgentConstraintsQuery does.
const updateAgentEscalationQuery = `UPDATE agents SET escalate_at = $2, updated_at = NOW() WHERE id = $1 RETURNING updated_at`

// decodeEscalateAt turns a nullable column into the model's pointer,
// refusing a value outside the tier range rather than trusting the CHECK
// constraint alone: a threshold that decoded to the wrong tier would move
// where a human is asked.
func decodeEscalateAt(v sql.NullInt16) (*models.ActionTier, error) {
	if !v.Valid {
		return nil, nil
	}
	tier, err := models.ParseActionTier(int(v.Int16))
	if err != nil {
		return nil, err
	}
	return &tier, nil
}

// escalationGrant is the permission set an agent's threshold contributes to
// a containment comparison. MaxTier is the HIGHEST tier on purpose: an agent
// has no ceiling of its own (the delegation's ceiling is chosen at issuance),
// so every tier must count as reachable. Left at its zero value, REASONING,
// Contains would treat any threshold as unreachable and a removed threshold
// would not be reported as the widening it is.
func escalationGrant(t *models.ActionTier) permset.Set {
	return permset.Set{MaxTier: models.ActionTierDestructive, EscalateAt: t}
}

// SetAgentEscalation sets the agent's threshold and returns the advisory
// view. A threshold applies to delegations issued from now on, never to
// live ones.
func (s *Store) SetAgentEscalation(
	ctx context.Context, id uuid.UUID, tier models.ActionTier, actor string,
) (models.AgentEscalationView, error) {
	if _, err := models.ParseActionTier(int(tier)); err != nil {
		return models.AgentEscalationView{}, fmt.Errorf("%w: escalate_at: %s", ErrInvalidRequest, err)
	}
	if err := s.writeAgentEscalation(ctx, id, &tier, actor); err != nil {
		return models.AgentEscalationView{}, err
	}
	return s.agentEscalationView(ctx, id, &tier)
}

// ClearAgentEscalation removes the threshold, so delegations issued from now
// on escalate only if their caller asks for it. A distinct verb, like
// ClearAgentResourceConstraints, so it cannot happen as a side effect.
func (s *Store) ClearAgentEscalation(ctx context.Context, id uuid.UUID, actor string) error {
	return s.writeAgentEscalation(ctx, id, nil, actor)
}

// GetAgentEscalation returns the same view the writes return, unchanged.
func (s *Store) GetAgentEscalation(ctx context.Context, id uuid.UUID) (models.AgentEscalationView, error) {
	agent, err := s.GetAgent(ctx, id)
	if err != nil {
		return models.AgentEscalationView{}, err
	}
	return s.agentEscalationView(ctx, id, agent.EscalateAt)
}

func (s *Store) writeAgentEscalation(ctx context.Context, id uuid.UUID, tier *models.ActionTier, actor string) error {
	eventType, reason, value := eventTypeAgentEscalationCleared, "escalate_at cleared", sql.NullInt16{}
	if tier != nil {
		eventType = eventTypeAgentEscalationSet
		reason = "escalate_at " + tier.String()
		value = sql.NullInt16{Int16: int16(*tier), Valid: true} //nolint:gosec // G115: ParseActionTier bounds it to 0-4
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var beforeRaw sql.NullInt16
	if err := tx.QueryRowContext(ctx, loadAgentEscalationForUpdateQuery, id.String()).Scan(&beforeRaw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: load agent %s escalate_at: %w", id, err)
	}
	before, err := decodeEscalateAt(beforeRaw)
	if err != nil {
		return fmt.Errorf("store: agent %s escalate_at decode: %w", id, err)
	}

	var updatedAt time.Time
	if err := tx.QueryRowContext(ctx, updateAgentEscalationQuery, id.String(), value).Scan(&updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: update agent %s escalate_at: %w", id, err)
	}

	if err := s.appendAuditTx(ctx, tx, audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    updatedAt,
		EventType:     eventType,
		Actor:         actor,
		AgentID:       &id,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        reason,
	}); err != nil {
		return err
	}

	if err := s.recordWideningTx(ctx, tx, id, actor, updatedAt,
		escalationGrant(before), escalationGrant(tier)); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

func (s *Store) agentEscalationView(
	ctx context.Context, id uuid.UUID, tier *models.ActionTier,
) (models.AgentEscalationView, error) {
	liveDelegations, err := s.countLiveDelegations(ctx, id)
	if err != nil {
		return models.AgentEscalationView{}, err
	}
	return models.AgentEscalationView{
		AgentID:         id,
		EscalateAt:      tier,
		LiveDelegations: liveDelegations,
		Applies:         "at next issuance",
	}, nil
}
