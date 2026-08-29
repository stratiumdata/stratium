// agent_constraints.go is the write path for an agent's resource_constraints,
// the scope copied onto every root delegation at issuance. It mirrors
// agent_caps.go method for method; read that file first.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// eventTypeAgentConstraintsSet and eventTypeAgentConstraintsCleared are
// audit_chain.event_type values for this file's two write operations -- the
// same one-constant-pair-per-file discipline agent_caps.go's own
// eventTypeAgentCapsSet/eventTypeAgentCapsCleared comment explains.
const (
	eventTypeAgentConstraintsSet     = "agent_resource_constraints_set"
	eventTypeAgentConstraintsCleared = "agent_resource_constraints_cleared"
)

// ErrInvalidResourceConstraint wraps ErrInvalidRequest so the PAP maps it to
// 400 through writeStoreError without a special case.
var ErrInvalidResourceConstraint = fmt.Errorf("%w: invalid resource constraint", ErrInvalidRequest)

// validateResourceConstraints enforces the two rules that let the decision
// path compare with a bare strings.HasPrefix (internal/authz.satisfiesIDPrefix):
// a prefix is non-empty and ends with "/".
//
// The trailing slash is not cosmetic. Without it "/workspace" admits
// "/workspace-evil/secrets.txt", and the same trap reappears in ScopeNarrows,
// where parent "/workspace" would accept child "/workspace-evil/" as a
// narrowing. Enforcing it once here closes both.
//
// A prefix containing ".." is refused for the same reason an id containing one
// is: it cannot be compared without resolving it, and nothing here may assume
// the value is a filesystem path.
func validateResourceConstraints(constraints map[string]string) error {
	for key, value := range constraints {
		if key == "" {
			return fmt.Errorf("%w: a constraint key must not be empty", ErrInvalidResourceConstraint)
		}
		if key != models.ResourceIDPrefixKey {
			// Opaque caller-defined attribute with exact-match semantics.
			// Nothing to validate: any string is a legitimate value.
			continue
		}
		if value == "" {
			return fmt.Errorf("%w: %s must not be empty; use DELETE to remove the scope",
				ErrInvalidResourceConstraint, models.ResourceIDPrefixKey)
		}
		if strings.Contains(value, "..") {
			return fmt.Errorf("%w: %s %q must not contain %q",
				ErrInvalidResourceConstraint, models.ResourceIDPrefixKey, value, "..")
		}
		if !strings.HasSuffix(value, "/") {
			return fmt.Errorf("%w: %s %q must end with %q (did you mean %q?) — without it the "+
				"prefix also matches siblings such as %q",
				ErrInvalidResourceConstraint, models.ResourceIDPrefixKey, value, "/",
				value+"/", value+"-other/secrets")
		}
	}
	return nil
}

// renderConstraints is the audit entry's Reason for a resource-constraints
// write: a compact, deterministic (sorted) rendering, the same shape and
// motivation as renderCaps (agent_caps.go) -- so two writes of the identical
// constraints produce byte-identical audit text and an operator reading the
// chain does not need to parse JSON to see what changed. {}
// (ClearAgentResourceConstraints, or an explicitly empty Set) renders as the
// literal empty-braces form rather than an empty string.
func renderConstraints(constraints map[string]string) string {
	if len(constraints) == 0 {
		return "resource_constraints={}"
	}
	keys := make([]string, 0, len(constraints))
	for k := range constraints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(constraints))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, constraints[k]))
	}
	return "resource_constraints={" + strings.Join(parts, ", ") + "}"
}

// SetAgentResourceConstraints replaces the agent's resource_constraints and
// returns the view callers need to understand what they just did. Unlike
// SetAgentClassificationCaps, an empty map is accepted: there is no
// allow_uncovered analogue here (that parameter exists for catch-all label
// rules and has no meaning for resource constraints), and an empty scope is
// simply "unrestricted," a legitimate value to set explicitly, not only via
// DELETE. Every ambiguity in the value itself is still refused by
// validateResourceConstraints before anything is written.
//
// now is not forwarded to the write (see updateAgentConstraintsQuery's own
// doc comment) -- kept as a parameter only so this and
// ClearAgentResourceConstraints present the same shape to their HTTP-routes
// caller.
func (s *Store) SetAgentResourceConstraints(
	ctx context.Context, id uuid.UUID, constraints map[string]string, actor string, now time.Time,
) (models.AgentConstraintsView, error) {
	if err := validateResourceConstraints(constraints); err != nil {
		return models.AgentConstraintsView{}, err
	}
	if err := s.writeAgentConstraints(ctx, id, constraints, actor); err != nil {
		return models.AgentConstraintsView{}, err
	}
	return s.agentConstraintsView(ctx, id, constraints)
}

// ClearAgentResourceConstraints sets the map back to {}, which removes every
// resource-identity restriction from delegations issued from now on. Kept as
// a distinct verb for the same reason ClearAgentClassificationCaps is: an
// explicit act, not a side effect of some other write.
func (s *Store) ClearAgentResourceConstraints(ctx context.Context, id uuid.UUID, actor string, now time.Time) error {
	return s.writeAgentConstraints(ctx, id, map[string]string{}, actor)
}

// updateAgentConstraintsQuery leaves updated_at to Postgres (NOW()),
// returned via RETURNING -- the identical reasoning updateAgentCapsQuery's
// own doc comment gives: the row's own persisted clock is authoritative, and
// that RETURNING value becomes the audit entry's OccurredAt below, so there
// is exactly one clock in play for this column, not two.
const updateAgentConstraintsQuery = `UPDATE agents SET resource_constraints = $2, updated_at = NOW() WHERE id = $1 RETURNING updated_at`

// writeAgentConstraints is SetAgentResourceConstraints and
// ClearAgentResourceConstraints's shared write path: replace
// resource_constraints and audit the change in the SAME transaction (N4),
// inside one beginTenantTx -- the identical shape writeAgentCaps
// (agent_caps.go) uses for classification_caps.
//
// The audit event type is derived from constraints itself, len(constraints)
// == 0 means eventTypeAgentConstraintsCleared, regardless of which exported
// method got here -- the same derivation-not-parameter discipline
// writeAgentCaps follows, so a future caller cannot pass the wrong constant.
func (s *Store) writeAgentConstraints(ctx context.Context, id uuid.UUID, constraints map[string]string, actor string) error {
	eventType := eventTypeAgentConstraintsSet
	if len(constraints) == 0 {
		eventType = eventTypeAgentConstraintsCleared
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	constraintsJSON, err := json.Marshal(constraints)
	if err != nil {
		return fmt.Errorf("store: marshal resource_constraints: %w", err)
	}

	var updatedAt time.Time
	row := tx.QueryRowContext(ctx, updateAgentConstraintsQuery, id.String(), constraintsJSON)
	if err := row.Scan(&updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: update agent %s resource constraints: %w", id, err)
	}

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    updatedAt,
		EventType:     eventType,
		Actor:         actor,
		AgentID:       &id,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        renderConstraints(constraints),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// GetAgentResourceConstraints returns the same advisory view
// SetAgentResourceConstraints returns, without changing anything -- for an
// operator who wants to see the consequences (UnsatisfiableTools,
// LiveDelegations) of the agent's CURRENT scope before deciding whether to
// act, not only after.
func (s *Store) GetAgentResourceConstraints(ctx context.Context, id uuid.UUID) (models.AgentConstraintsView, error) {
	agent, err := s.GetAgent(ctx, id)
	if err != nil {
		return models.AgentConstraintsView{}, err
	}
	return s.agentConstraintsView(ctx, id, agent.ResourceConstraints)
}

// agentConstraintsView assembles the advisory response every
// resource-constraints write (and read) returns. It loads the agent fresh
// (for AllowedTools -- unsatisfiableTools needs the CURRENT allowlist, not
// whatever the caller of SetAgentResourceConstraints happened to have in
// hand), the tool catalog, and the live-delegation count -- the same shape
// agentCapsView (agent_caps.go) builds, and it reuses that file's
// unsatisfiableTools and countLiveDelegations unchanged rather than
// recomputing either: a second copy of either is exactly the drift this
// design warns against.
func (s *Store) agentConstraintsView(
	ctx context.Context, id uuid.UUID, constraints map[string]string,
) (models.AgentConstraintsView, error) {
	agent, err := s.GetAgent(ctx, id)
	if err != nil {
		return models.AgentConstraintsView{}, err
	}
	catalog, err := s.ListToolCatalogEntries(ctx)
	if err != nil {
		return models.AgentConstraintsView{}, err
	}
	liveDelegations, err := s.countLiveDelegations(ctx, id)
	if err != nil {
		return models.AgentConstraintsView{}, err
	}

	return models.AgentConstraintsView{
		AgentID:             id,
		ResourceConstraints: constraints,
		UnsatisfiableTools:  unsatisfiableTools(agent.AllowedTools, catalog),
		LiveDelegations:     liveDelegations,
		Applies:             "at next issuance",
	}, nil
}
