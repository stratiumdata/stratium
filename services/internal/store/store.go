// Package store is Stratium's tenant-scoped repository. Row-level security is
// the tenant boundary: every migration enables and FORCEs RLS with a policy
// of tenant_id = current_tenant(), where current_tenant() reads
// current_setting('app.tenant_id', true) — see
// migrations/000002_rls.up.sql.
//
// Every method here opens a transaction, sets app.tenant_id for it first,
// and only then queries. The Go code never adds a WHERE tenant_id clause: a
// second, divergent implementation of the tenant boundary is worse than none,
// because if the two ever disagree the WHERE clause silently wins while RLS
// looks like it is still protecting you. An unset app.tenant_id makes RLS
// return zero rows, which is the correct fail-closed default.
//
// The tenant is fixed at New and is never a per-call argument: it comes from
// startup configuration (config.Config.TenantID). The predecessor took an
// equivalent value from a client-supplied header, and that was a critical
// authentication bypass.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/pkg/models"
)

// ErrNotFound indicates the requested row does not exist for this tenant.
// Row-level security makes "belongs to another tenant" and "does not exist"
// indistinguishable by design, so both surface identically here.
var ErrNotFound = errors.New("not found")

// maxChainWalk bounds LoadChain's upward walk through parent_delegation_id.
// A cycle introduced by a bad write must produce an error, not hang the PDP.
const maxChainWalk = 64

// setTenantQuery sets app.tenant_id for the current transaction only.
//
// Postgres's SET/SET LOCAL grammar does not accept a bind parameter in the
// value position ("SET LOCAL app.tenant_id = $1" is a syntax error) — the
// value there must be a literal. set_config() is the parameterized
// equivalent: its third argument, is_local = true, makes it transaction
// scoped exactly like SET LOCAL (per the Postgres docs), and unlike a
// literal it cannot be broken by a tenant ID containing a quote character.
// is_local must stay true — *sql.DB pools connections, and a session-scoped
// SET would leak one tenant's setting onto a later transaction that reuses
// the same physical connection for a different tenant.
const setTenantQuery = `SELECT set_config('app.tenant_id', $1, true)`

const loadAgentQuery = `SELECT id, trust_tier, enabled, suspended, allowed_tools FROM agents WHERE id = $1`

// escalate_at is appended at the end, after chain_agent_ids, rather than
// grouped next to max_action_tier: every positional Scan in scanDelegation
// and every sqlmock fixture in this package's tests lines args up by
// position, and appending is the one place to add a column that cannot
// shift any of those positions for the fourteen columns that already exist.
const loadDelegationQuery = `SELECT id, tenant_id, user_id, agent_id, approved_tools, max_action_tier, ` +
	`classification_caps, resource_constraints, purpose, expires_at, ` +
	`created_at, revoked, revoked_at, parent_delegation_id, ` +
	`root_delegation_id, depth, chain_agent_ids, escalate_at FROM delegations WHERE id = $1`

// Store is a tenant-scoped repository. The tenant is fixed at construction;
// see the package doc.
type Store struct {
	db       *sql.DB
	tenantID string
}

// New returns a Store scoped to tenantID for the lifetime of db. tenantID is
// startup configuration, never a request field.
func New(db *sql.DB, tenantID string) *Store {
	return &Store{db: db, tenantID: tenantID}
}

// beginTenantTx opens a transaction and sets app.tenant_id on it before
// returning, so every statement the caller runs afterward is bounded by row-
// level security. The caller must Commit on success; deferring Rollback
// immediately after a successful Commit is a documented no-op in
// database/sql (Tx tracks its own done state), so "defer tx.Rollback()"
// followed by an explicit Commit is sufficient to guarantee the transaction
// is always closed, on every path including errors.
func (s *Store) beginTenantTx(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: begin transaction: %w", err)
	}
	if _, err := tx.ExecContext(ctx, setTenantQuery, s.tenantID); err != nil {
		_ = tx.Rollback()
		return nil, fmt.Errorf("store: set tenant: %w", err)
	}
	return tx, nil
}

// LoadAgent loads the acting agent's registry record, reduced to what a
// decision needs. RLS scopes the row to the tenant fixed at New; a row for
// another tenant, or no row at all, is ErrNotFound either way.
func (s *Store) LoadAgent(ctx context.Context, id uuid.UUID) (authz.AgentInfo, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return authz.AgentInfo{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var info authz.AgentInfo
	var trustTier int64
	var allowedTools []byte
	err = tx.QueryRowContext(ctx, loadAgentQuery, id.String()).
		Scan(&info.ID, &trustTier, &info.Enabled, &info.Suspended, &allowedTools)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return authz.AgentInfo{}, fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return authz.AgentInfo{}, fmt.Errorf("store: load agent %s: %w", id, err)
	}
	info.TrustTier = models.AgentTrustTier(trustTier)

	// Decode explicitly and fail loudly: database/sql cannot scan JSONB into
	// []string, and a decode error left unchecked would leave AllowedTools at
	// its zero value, nil — which HasTool reads as unrestricted. A corrupt
	// row must never become an unrestricted grant.
	if err := json.Unmarshal(allowedTools, &info.AllowedTools); err != nil {
		return authz.AgentInfo{}, fmt.Errorf("store: agent %s allowed_tools decode: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return authz.AgentInfo{}, fmt.Errorf("store: commit: %w", err)
	}
	return info, nil
}

// LoadChain loads the delegation chain ending at actingDelegationID — the
// last hop, the delegation actually presented — and returns it root-first,
// the order authz.ValidateChain requires.
//
// It walks parent_delegation_id upward one row at a time, collecting as it
// goes, then reverses once at the end. The walk is bounded at maxChainWalk
// hops: a cycle introduced by a bad write must error, not hang the PDP, and
// the bound is enforced rather than silently truncating the chain.
func (s *Store) LoadChain(ctx context.Context, actingDelegationID uuid.UUID) ([]*models.Delegation, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	// Collected leaf-first (the acting delegation first, root last) since
	// that's the direction the walk travels; reversed once below.
	chain := make([]*models.Delegation, 0, 8)
	id := actingDelegationID
	for i := 0; ; i++ {
		if i == maxChainWalk {
			return nil, fmt.Errorf("store: delegation chain from %s exceeds %d hops without reaching a root (possible cycle)",
				actingDelegationID, maxChainWalk)
		}

		d, err := scanDelegation(tx.QueryRowContext(ctx, loadDelegationQuery, id.String()))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, fmt.Errorf("%w: delegation %s", ErrNotFound, id)
			}
			return nil, fmt.Errorf("store: load delegation %s: %w", id, err)
		}
		chain = append(chain, d)

		if d.ParentDelegationID == nil {
			break
		}
		id = *d.ParentDelegationID
	}

	for l, r := 0, len(chain)-1; l < r; l, r = l+1, r-1 {
		chain[l], chain[r] = chain[r], chain[l]
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return chain, nil
}

// scanDelegation scans one delegations row, decoding its JSONB columns
// explicitly (database/sql cannot scan JSONB into []string,
// map[string]string, or []uuid.UUID) and converting its nullable purpose
// column via sql.NullString, since Delegation.Purpose is a plain string, not
// a pointer. A decode error is returned rather than left as a Delegation
// with an empty (meaning unrestricted) tool list or cap map — the same
// fail-loudly requirement as LoadAgent's allowed_tools.
//
// parent_delegation_id and revoked_at need no such wrapper: Delegation
// already models them as pointers (*uuid.UUID, *time.Time), and
// database/sql's generic Scan handles a NULL column that way natively —
// unlike a plain string field, which errors on Scanning a NULL.
//
// escalate_at scans through sql.NullInt64, like maxActionTier's own local
// below, rather than straight into *models.ActionTier: EscalateAt is a
// pointer, but its pointee is a validated enum, not a bare int, so a NULL
// must decode to nil (never escalate) while a non-NULL value must still run
// through ParseActionTier — the same validation maxActionTier gets — before
// it is trusted as an ActionTier at all.
func scanDelegation(row *sql.Row) (*models.Delegation, error) {
	var d models.Delegation
	var maxActionTier int64
	var escalateAt sql.NullInt64
	var purpose sql.NullString
	var approvedTools, classificationCaps, resourceConstraints, chainAgentIDs []byte

	err := row.Scan(
		&d.ID, &d.TenantID, &d.UserID, &d.AgentID,
		&approvedTools, &maxActionTier, &classificationCaps, &resourceConstraints,
		&purpose, &d.ExpiresAt, &d.CreatedAt, &d.Revoked, &d.RevokedAt,
		&d.ParentDelegationID, &d.RootDelegationID, &d.Depth, &chainAgentIDs, &escalateAt,
	)
	if err != nil {
		return nil, err // includes sql.ErrNoRows; callers distinguish with errors.Is
	}

	tier, err := models.ParseActionTier(int(maxActionTier))
	if err != nil {
		return nil, fmt.Errorf("store: delegation %s max_action_tier: %w", d.ID, err)
	}
	d.MaxActionTier = tier

	if escalateAt.Valid {
		escalate, err := models.ParseActionTier(int(escalateAt.Int64))
		if err != nil {
			return nil, fmt.Errorf("store: delegation %s escalate_at: %w", d.ID, err)
		}
		d.EscalateAt = &escalate
	}

	if purpose.Valid {
		d.Purpose = purpose.String
	}

	if err := json.Unmarshal(approvedTools, &d.ApprovedTools); err != nil {
		return nil, fmt.Errorf("store: delegation %s approved_tools decode: %w", d.ID, err)
	}
	if err := json.Unmarshal(classificationCaps, &d.ClassificationCaps); err != nil {
		return nil, fmt.Errorf("store: delegation %s classification_caps decode: %w", d.ID, err)
	}
	if err := json.Unmarshal(resourceConstraints, &d.ResourceConstraints); err != nil {
		return nil, fmt.Errorf("store: delegation %s resource_constraints decode: %w", d.ID, err)
	}
	if err := json.Unmarshal(chainAgentIDs, &d.ChainAgentIDs); err != nil {
		return nil, fmt.Errorf("store: delegation %s chain_agent_ids decode: %w", d.ID, err)
	}

	return &d, nil
}
