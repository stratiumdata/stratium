package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// Package doc for this file: the PAP's CRUD surface over the agents table
// (migrations/000001_baseline). Distinct from LoadAgent (store.go), the
// PDP's own decision-path read: that method returns the reduced
// authz.AgentInfo a decision needs (id, trust_tier, enabled, suspended,
// allowed_tools, no name/provider/model_id) and is left untouched here —
// this file adds a second, full-fidelity family (models.Agent) for the
// admin plane, the same LoadAgent/GetAgent split policy.go keeps between
// LoadAllPolicies and this file's own GetPolicy/ListPolicies.

// eventTypeAgentCreated, eventTypeAgentUpdated, and eventTypeAgentDeleted are
// audit_chain.event_type values for this table's three write operations
// (N4) — see policy.go's own comment on the identical three-constant shape
// for why one per operation, not one shared value.
const (
	eventTypeAgentCreated = "agent_created"
	eventTypeAgentUpdated = "agent_updated"
	eventTypeAgentDeleted = "agent_deleted"
)

// ErrAllowedToolsRequired indicates a Create/Update call left AllowedTools
// nil. Unlike every other field on models.Agent, nil here is not "the
// operator left this blank" — migrations/000001_baseline.up.sql's own
// comment on the allowed_tools column states the rule this error enforces:
// "an empty/absent list means UNRESTRICTED... A writer must say
// 'unrestricted' explicitly with '[]'::jsonb, not get it for free by
// leaving the column out." A nil Go slice and a present-but-empty one are
// distinguishable (encoding/json leaves an omitted or JSON-null field nil;
// an explicit "allowed_tools": [] decodes to a non-nil, zero-length slice),
// so this check can require the explicit form without also rejecting a
// caller who genuinely wants unrestricted access — they just have to say so.
var ErrAllowedToolsRequired = errors.New("store: allowed_tools is required (use [] to explicitly grant every tool)")

// insertAgentQuery omits id from its column list -- see insertPolicyQuery's
// own doc comment (policy.go) for why: nothing here needs the id before
// this statement returns, so the schema's own DEFAULT uuid_generate_v4()
// generates it, read back via RETURNING.
const insertAgentQuery = `INSERT INTO agents (tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools) ` +
	`VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at, updated_at`

const getAgentQuery = `SELECT id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools, created_at, updated_at ` +
	`FROM agents WHERE id = $1`

// listAgentsQuery orders by name, the PAP admin screen's natural order — see
// policy.go's listPoliciesQuery for the identical reasoning against
// LoadAllPolicies/LoadAgent's own ORDER BY id.
const listAgentsQuery = `SELECT id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools, created_at, updated_at ` +
	`FROM agents ORDER BY name`

// updateAgentQuery leaves updated_at to Postgres (NOW()), returned via
// RETURNING — the same reasoning updatePolicyQuery documents: the row's own
// clock is authoritative, and reusing it for the audit entry's OccurredAt
// needs no separate, potentially skewed time.Now() call.
const updateAgentQuery = `UPDATE agents SET name = $1, provider = $2, model_id = $3, trust_tier = $4, ` +
	`enabled = $5, suspended = $6, allowed_tools = $7, updated_at = NOW() ` +
	`WHERE id = $8 RETURNING created_at, updated_at`

const deleteAgentQuery = `DELETE FROM agents WHERE id = $1 RETURNING name`

// scanFullAgent scans one row (Get) or the current row of a *sql.Rows
// (List) into a models.Agent, sharing decode logic via rowScanner
// (store.go). model_id is nullable in the schema; unlike LoadAgent's own
// allowed_tools decode (store.go), a corrupt allowed_tools column here still
// fails loudly for the identical reason: a decode error must never silently
// become the empty (meaning unrestricted) slice.
func scanFullAgent(row rowScanner) (models.Agent, error) {
	var a models.Agent
	var trustTier int64
	var modelID sql.NullString
	var allowedTools []byte
	err := row.Scan(&a.ID, &a.TenantID, &a.Name, &a.Provider, &modelID, &trustTier,
		&a.Enabled, &a.Suspended, &allowedTools, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return models.Agent{}, err
	}
	a.TrustTier = models.AgentTrustTier(trustTier)
	if modelID.Valid {
		a.ModelID = modelID.String
	}
	if err := json.Unmarshal(allowedTools, &a.AllowedTools); err != nil {
		return models.Agent{}, fmt.Errorf("agent %s allowed_tools decode: %w", a.ID, err)
	}
	return a, nil
}

// validateAgentFields checks what the schema's own CHECK constraints
// already enforce (trust_tier BETWEEN 0 AND 3) plus AllowedTools'
// no-silent-default rule (ErrAllowedToolsRequired) — the Go-side mirror
// discipline validateEffect (policy.go) already follows, refusing with a
// clear message before a bad value ever reaches Postgres as an opaque
// constraint violation.
func validateAgentFields(a models.Agent) error {
	if a.Name == "" {
		return fmt.Errorf("%w: agent name is required", ErrInvalidRequest)
	}
	if a.Provider == "" {
		return fmt.Errorf("%w: agent provider is required", ErrInvalidRequest)
	}
	if int(a.TrustTier) < int(models.TrustTierUnverified) || int(a.TrustTier) > int(models.TrustTierPlatformTrusted) {
		return fmt.Errorf("%w: agent trust_tier %d out of range 0-3", ErrInvalidRequest, a.TrustTier)
	}
	if a.AllowedTools == nil {
		return ErrAllowedToolsRequired
	}
	return nil
}

// CreateAgent inserts a and audits its creation inside one transaction
// (N4). a.ID, a.TenantID, a.CreatedAt, and a.UpdatedAt are ignored on input
// and set authoritatively here, matching CreatePolicy's identical treatment
// of its own caller-supplied identity/timestamp fields.
func (s *Store) CreateAgent(ctx context.Context, a models.Agent, actor string) (models.Agent, error) {
	if err := validateAgentFields(a); err != nil {
		return models.Agent{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Agent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	a.TenantID = s.tenantID

	allowedTools, err := json.Marshal(a.AllowedTools)
	if err != nil {
		return models.Agent{}, fmt.Errorf("store: marshal allowed_tools: %w", err)
	}

	row := tx.QueryRowContext(ctx, insertAgentQuery,
		s.tenantID, a.Name, a.Provider, a.ModelID, int64(a.TrustTier),
		a.Enabled, a.Suspended, allowedTools)
	if err := row.Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return models.Agent{}, fmt.Errorf("%w: agent named %q", ErrAlreadyExists, a.Name)
		}
		return models.Agent{}, fmt.Errorf("store: insert agent %q: %w", a.Name, err)
	}

	// AgentID is the one audit.Entry field that fits an agent-row write
	// literally, not by repurposing: it already exists to identify "which
	// agent," which is exactly what this entry needs to record.
	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    a.CreatedAt,
		EventType:     eventTypeAgentCreated,
		Actor:         actor,
		AgentID:       &a.ID,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        a.Name,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.Agent{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.Agent{}, fmt.Errorf("store: commit: %w", err)
	}
	return a, nil
}

// GetAgent loads one agents row by id, in full — every column, unlike
// LoadAgent's decision-shaped authz.AgentInfo. ErrNotFound covers both "no
// such row" and "another tenant's row," indistinguishably, per the package
// doc.
func (s *Store) GetAgent(ctx context.Context, id uuid.UUID) (models.Agent, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Agent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	a, err := scanFullAgent(tx.QueryRowContext(ctx, getAgentQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Agent{}, fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return models.Agent{}, fmt.Errorf("store: get agent %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return models.Agent{}, fmt.Errorf("store: commit: %w", err)
	}
	return a, nil
}

// ListAgents loads every agent the tenant has, enabled or not, suspended or
// not — an admin screen needs to show a suspended agent to un-suspend it.
// A tenant with none is an ordinary, empty result.
func (s *Store) ListAgents(ctx context.Context) ([]models.Agent, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listAgentsQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list agents: %w", err)
	}
	defer func() { _ = rows.Close() }()

	agents := make([]models.Agent, 0)
	for rows.Next() {
		a, err := scanFullAgent(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan agent row: %w", err)
		}
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate agent rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return agents, nil
}

// UpdateAgent replaces every mutable column of the id row and audits the
// change, inside one transaction — a PUT-shaped full replace, matching
// UpdatePolicy. id names the row; a.ID, a.TenantID, a.CreatedAt, and
// a.UpdatedAt are ignored on input. ErrNotFound if no row with id exists for
// this tenant.
func (s *Store) UpdateAgent(ctx context.Context, id uuid.UUID, a models.Agent, actor string) (models.Agent, error) {
	if err := validateAgentFields(a); err != nil {
		return models.Agent{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Agent{}, err
	}
	defer func() { _ = tx.Rollback() }()

	allowedTools, err := json.Marshal(a.AllowedTools)
	if err != nil {
		return models.Agent{}, fmt.Errorf("store: marshal allowed_tools: %w", err)
	}

	row := tx.QueryRowContext(ctx, updateAgentQuery,
		a.Name, a.Provider, a.ModelID, int64(a.TrustTier), a.Enabled, a.Suspended, allowedTools, id.String())
	if err := row.Scan(&a.CreatedAt, &a.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Agent{}, fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		if isUniqueViolation(err) {
			return models.Agent{}, fmt.Errorf("%w: agent named %q", ErrAlreadyExists, a.Name)
		}
		return models.Agent{}, fmt.Errorf("store: update agent %s: %w", id, err)
	}
	a.ID = id
	a.TenantID = s.tenantID

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    a.UpdatedAt,
		EventType:     eventTypeAgentUpdated,
		Actor:         actor,
		AgentID:       &a.ID,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        a.Name,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.Agent{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.Agent{}, fmt.Errorf("store: commit: %w", err)
	}
	return a, nil
}

// DeleteAgent deletes the id row and audits the deletion inside one
// transaction. now is a parameter for the same reason DeletePolicy's is:
// a DELETE leaves no row behind whose own timestamp the audit entry could
// reuse via RETURNING.
//
// migrations/000001_baseline.up.sql's delegations.agent_id and
// migrations/000012_approvals.up.sql's approvals.agent_id are both
// ON DELETE RESTRICT, so this DELETE itself fails closed (a Postgres
// foreign_key_violation, surfaced as an ordinary error here, never silently
// ignored) if any delegation or approval still names this agent — this
// method does not need its own check for that, the schema already refuses
// it.
func (s *Store) DeleteAgent(ctx context.Context, id uuid.UUID, actor string, now time.Time) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var name string
	if err := tx.QueryRowContext(ctx, deleteAgentQuery, id.String()).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: delete agent %s: %w", id, err)
	}

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeAgentDeleted,
		Actor:         actor,
		AgentID:       &id,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        name,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
