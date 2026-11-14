package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
)

// Package doc for this file: the PAP's CRUD surface over the tier_overrides
// table (migrations/000001_baseline) — spec §4.4's raise-only tenant
// correction to a tool or verb's built-in action-tier classification — plus,
// as of Phase 14 Task 7, the PDP's own decision-path read of that table
// (LoadTierOverrides, below).
//
// Those two families are named distinctly for the same reason
// LoadAllPolicies/ListPolicies (policy.go) and LoadToolCatalog/
// ListToolCatalogEntries (catalog.go) are: they read different shapes for
// different purposes. LoadTierOverrides selects two columns and returns the
// map internal/authz.TierTable.Overrides is keyed by; the List/Get family
// selects all seven and returns models.TierOverride, id and created_by
// included. A decision has no use for who authored a row — and this phase's
// own logging rule forbids naming that operator — so the decision path does
// not read the column at all rather than reading it and remembering not to
// use it.

// eventTypeTierOverrideCreated, eventTypeTierOverrideUpdated, and
// eventTypeTierOverrideDeleted are audit_chain.event_type values for this
// table's three write operations (N4) — see policy.go's own comment on the
// identical three-constant shape.
const (
	eventTypeTierOverrideCreated = "tier_override_created"
	eventTypeTierOverrideUpdated = "tier_override_updated"
	eventTypeTierOverrideDeleted = "tier_override_deleted"
)

// insertTierOverrideQuery omits id from its column list -- see
// insertPolicyQuery's own doc comment (policy.go) for why: nothing here
// needs the id before this statement returns, so the schema's own DEFAULT
// uuid_generate_v4() generates it, read back via RETURNING.
const insertTierOverrideQuery = `INSERT INTO tier_overrides (tenant_id, tool_or_verb, action_tier, builtin_tier, created_by) ` +
	`VALUES ($1,$2,$3,$4,$5) RETURNING id, created_at`

const getTierOverrideQuery = `SELECT id, tenant_id, tool_or_verb, action_tier, builtin_tier, created_at, created_by ` +
	`FROM tier_overrides WHERE id = $1`

// listTierOverridesQuery orders by tool_or_verb, matching
// internal/store/catalog.go's own loadToolCatalogQuery ORDER BY tool_name
// for a similarly name-keyed config table, and for the same reason:
// (tenant_id, tool_or_verb) is UNIQUE, so this order has no ties to break.
const listTierOverridesQuery = `SELECT id, tenant_id, tool_or_verb, action_tier, builtin_tier, created_at, created_by ` +
	`FROM tier_overrides ORDER BY tool_or_verb`

// updateTierOverrideQuery does not touch created_by: unlike Policy/Agent
// (no such column exists there at all), TierOverride.CreatedBy identifies
// who ORIGINALLY authored this override, and an edit is not a new
// authorship — the same reason a Unix file's owner does not change when its
// contents are edited by someone with write access. Who made THIS change is
// still fully recorded, on the audit entry's own Actor field, exactly as it
// is for every other write in this file.
const updateTierOverrideQuery = `UPDATE tier_overrides SET tool_or_verb = $1, action_tier = $2, builtin_tier = $3 ` +
	`WHERE id = $4 RETURNING created_at, created_by`

const deleteTierOverrideQuery = `DELETE FROM tier_overrides WHERE id = $1 RETURNING tool_or_verb`

// loadTierOverridesQuery is listTierOverridesQuery's decision-facing
// sibling: the same table, ordered the same way, but selecting only the two
// columns a decision consumes. id, tenant_id, created_at, and created_by
// have no reader on that path (see this file's own package doc), and
// builtin_tier is deliberately excluded from it too — that column is a
// snapshot of the baseline compared against at write time, and the PDP
// recomputes the LIVE baseline instead, which is the entire point of
// re-validating on read.
const loadTierOverridesQuery = `SELECT tool_or_verb, action_tier FROM tier_overrides ORDER BY tool_or_verb`

// overrideBaseline computes the tier authz.ValidateOverride compares a
// proposed override against for key (a tier_overrides.tool_or_verb value —
// a tool name, a bare verb, or a "Tool:verb" composite, per
// internal/authz.lookupKeys): the resolution beneath the override, which is
// the tenant's own merged tool catalog first and the built-in classifier
// after it. authz.OverrideBaseline is where that rule actually lives; this
// method's whole job is supplying it the tenant's live catalog, read inside
// the caller's own transaction.
//
// Until Phase 14 Task 7 this was a pure function consulting
// authz.DefaultCatalog() and the verb table only, and its doc comment gave
// two reasons for excluding the tenant's tool_catalog. The first (that table
// was Task 4's scope, not Task 3's) is obsolete. The second was real: a
// NULL-tier row (Bash-shaped — "no fixed tier, classify per command") has no
// static tier to compare against. It is resolved rather than dodged now, by
// the same merge the decision path itself uses: BuildTierCatalog contributes
// no entry for such a row, so the key falls through to the built-in
// resolution — the previous behaviour — instead of the override being
// refused. See authz.OverrideBaseline's own doc comment for the ruling and
// the residual it leaves.
//
// Both the catalog AND the tenant's other override rows are read, in the
// caller's own transaction, because both are part of the resolution beneath
// this key: deriveTierByName probes overrides at every slot before any catalog
// lookup, so an existing tenant-wide "Bash" raise sits beneath a new
// "Bash:read" row and a write that ignored it would let the more specific row
// silently lower the broader one. Reading both here is what keeps this end's
// answer identical to the PDP's — the two must agree, or a row accepted at
// write time is dropped on every decision, which is a worse failure than
// refusing it outright.
func (s *Store) overrideBaseline(ctx context.Context, tx *sql.Tx, key string) (models.ActionTier, error) {
	entries, err := queryToolCatalogTx(ctx, tx)
	if err != nil {
		return models.ActionTierReasoning, err
	}
	overrides, err := queryTierOverridesTx(ctx, tx)
	if err != nil {
		return models.ActionTierReasoning, err
	}
	table := authz.TierTable{
		Catalog:   authz.BuildTierCatalog(entries, authz.DefaultCatalog()),
		Overrides: overrides,
	}
	return authz.OverrideBaseline(table, entries, key), nil
}

// LoadTierOverrides loads the tenant's tier_overrides rows as the map
// internal/authz.TierTable.Overrides is keyed by — spec §4.4's override step,
// which had no reader on the decision path at all until Phase 14 Task 7
// (migrations/000017_tier_overrides_serving_grant is the SELECT grant that
// makes this callable as stratium_app; the role holds nothing else on this
// table, and that absence is T6's enforcement).
//
// A map, not a slice: (tenant_id, tool_or_verb) is UNIQUE, so no key can
// appear twice and nothing is lost by keying on it here rather than at the
// caller. A tenant with no overrides — every tenant, until an operator
// writes one — is an ordinary, empty result.
//
// The rows are returned exactly as stored. Whether each one may be HONORED
// is decided by the caller, against the same tenant catalog it resolves
// tiers with: see pdpgrpc.Decide's own re-validation, and
// authz.TierTable.Overrides's doc comment for why that check cannot live
// here (this method has no catalog, and giving it one would put the
// raise-only rule in two places).
func (s *Store) LoadTierOverrides(ctx context.Context) (map[string]models.ActionTier, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	overrides, err := queryTierOverridesTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return overrides, nil
}

// queryTierOverridesTx runs loadTierOverridesQuery inside an already-open,
// already-tenant-scoped transaction — the same split queryToolCatalogTx
// (catalog.go) makes, and for the same second caller: overrideBaseline needs
// the tenant's other override rows to compute the resolution beneath a
// proposed one, in the SAME transaction the write then lands in.
func queryTierOverridesTx(ctx context.Context, tx *sql.Tx) (map[string]models.ActionTier, error) {
	rows, err := tx.QueryContext(ctx, loadTierOverridesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: load tier overrides: %w", err)
	}
	defer func() { _ = rows.Close() }()

	overrides := make(map[string]models.ActionTier)
	for rows.Next() {
		var key string
		var rawTier int64
		if err := rows.Scan(&key, &rawTier); err != nil {
			return nil, fmt.Errorf("store: scan tier override row: %w", err)
		}
		// The same fail-loudly discipline scanFullTierOverride applies: a
		// corrupt or out-of-range tier must error, never silently become
		// ActionTierReasoning and be honored as though this override really
		// was that innocuous.
		tier, err := models.ParseActionTier(int(rawTier))
		if err != nil {
			return nil, fmt.Errorf("store: tier override %q action_tier: %w", key, err)
		}
		overrides[key] = tier
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate tier override rows: %w", err)
	}
	return overrides, nil
}

// scanFullTierOverride scans one row (Get) or the current row of a
// *sql.Rows (List) into a models.TierOverride, sharing decode logic via
// rowScanner (store.go). action_tier/builtin_tier decode through
// models.ParseActionTier, the same fail-loudly discipline scanDelegation
// (store.go) applies to max_action_tier: a corrupt or out-of-range tier
// must error, never silently become ActionTierReasoning and read back as
// though this override really was that innocuous.
func scanFullTierOverride(row rowScanner) (models.TierOverride, error) {
	var t models.TierOverride
	var actionTier, builtinTierRaw int64
	if err := row.Scan(&t.ID, &t.TenantID, &t.ToolOrVerb, &actionTier, &builtinTierRaw, &t.CreatedAt, &t.CreatedBy); err != nil {
		return models.TierOverride{}, err
	}
	tier, err := models.ParseActionTier(int(actionTier))
	if err != nil {
		return models.TierOverride{}, fmt.Errorf("tier_override %s action_tier: %w", t.ID, err)
	}
	t.ActionTier = tier
	builtin, err := models.ParseActionTier(int(builtinTierRaw))
	if err != nil {
		return models.TierOverride{}, fmt.Errorf("tier_override %s builtin_tier: %w", t.ID, err)
	}
	t.BuiltinTier = builtin
	return t, nil
}

// CreateTierOverride computes t.ToolOrVerb's baseline — the resolution
// beneath the override (overrideBaseline, above) — calls
// authz.ValidateOverride against it — spec §4.4's raise-only rule, enforced
// by the one function written for it rather than reimplemented here — and,
// only if that succeeds, inserts t and audits its creation inside one
// transaction (N4).
//
// The baseline read shares that transaction, so it is the same catalog this
// write is committed against. A refused override therefore does open a
// transaction and read one table before refusing — it did not before Phase
// 14 Task 7, when the baseline was a pure function — but it still never
// reaches the INSERT, which is what "refused before persisting" has always
// meant here.
//
// t.ID, t.TenantID, t.BuiltinTier, t.CreatedAt, and t.CreatedBy are ignored
// on input and set authoritatively here: BuiltinTier specifically must never
// be caller-supplied — a tenant declaring its own floor would make the
// raise-only rule vacuous, exactly the "declare a destructive action
// harmless" hole server-side derivation exists to prevent (see
// models.TierOverride.BuiltinTier's own doc comment).
func (s *Store) CreateTierOverride(ctx context.Context, t models.TierOverride, actor string) (models.TierOverride, error) {
	if t.ToolOrVerb == "" {
		return models.TierOverride{}, fmt.Errorf("%w: tool_or_verb is required", ErrInvalidRequest)
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.TierOverride{}, err
	}
	defer func() { _ = tx.Rollback() }()

	baseline, err := s.overrideBaseline(ctx, tx, t.ToolOrVerb)
	if err != nil {
		return models.TierOverride{}, err
	}
	if err := authz.ValidateOverride(baseline, t.ActionTier); err != nil {
		return models.TierOverride{}, err
	}

	t.TenantID = s.tenantID
	t.BuiltinTier = baseline
	t.CreatedBy = actor

	row := tx.QueryRowContext(ctx, insertTierOverrideQuery,
		s.tenantID, t.ToolOrVerb, int64(t.ActionTier), int64(t.BuiltinTier), t.CreatedBy)
	if err := row.Scan(&t.ID, &t.CreatedAt); err != nil {
		if isUniqueViolation(err) {
			return models.TierOverride{}, fmt.Errorf("%w: tier override for %q", ErrAlreadyExists, t.ToolOrVerb)
		}
		return models.TierOverride{}, fmt.Errorf("store: insert tier override %q: %w", t.ToolOrVerb, err)
	}

	// ToolName/DeclaredTier/DerivedTier are the closest fit audit.Entry's
	// decision-shaped fields have for a tier-override write, the same
	// repurposing pdpgrpc/delegation.go's appendDelegationAudit already
	// documents for its own DeclaredTier/DerivedTier pair: ToolName carries
	// the overridden tool_or_verb (the field's name matches this table's own
	// concept directly, no stretch); DeclaredTier is what the operator
	// asked for, DerivedTier is the built-in baseline it was validated
	// against — "declared vs. derived" is exactly the shape this entry
	// needs, one step removed from a decision's own claim-vs-reality pair.
	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    t.CreatedAt,
		EventType:     eventTypeTierOverrideCreated,
		Actor:         actor,
		ToolName:      t.ToolOrVerb,
		DeclaredTier:  int16(t.ActionTier),  //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier
		DerivedTier:   int16(t.BuiltinTier), //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        t.ToolOrVerb,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.TierOverride{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.TierOverride{}, fmt.Errorf("store: commit: %w", err)
	}
	return t, nil
}

// GetTierOverride loads one tier_overrides row by id. ErrNotFound covers
// both "no such row" and "another tenant's row," indistinguishably, per the
// package doc.
func (s *Store) GetTierOverride(ctx context.Context, id uuid.UUID) (models.TierOverride, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.TierOverride{}, err
	}
	defer func() { _ = tx.Rollback() }()

	t, err := scanFullTierOverride(tx.QueryRowContext(ctx, getTierOverrideQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.TierOverride{}, fmt.Errorf("%w: tier override %s", ErrNotFound, id)
		}
		return models.TierOverride{}, fmt.Errorf("store: get tier override %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return models.TierOverride{}, fmt.Errorf("store: commit: %w", err)
	}
	return t, nil
}

// ListTierOverrides loads every tier override the tenant has. A tenant with
// none is an ordinary, empty result.
func (s *Store) ListTierOverrides(ctx context.Context) ([]models.TierOverride, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listTierOverridesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list tier overrides: %w", err)
	}
	defer func() { _ = rows.Close() }()

	overrides := make([]models.TierOverride, 0)
	for rows.Next() {
		t, err := scanFullTierOverride(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan tier override row: %w", err)
		}
		overrides = append(overrides, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate tier override rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return overrides, nil
}

// UpdateTierOverride re-validates the raise-only rule against t.ToolOrVerb's
// (possibly newly-supplied) baseline — the same ValidateOverride call
// CreateTierOverride makes, run fresh rather than trusting the row's
// existing builtin_tier column, so an update is held to the current
// baseline, not a possibly-stale one recorded at creation time. A
// PUT-shaped full replace, matching UpdatePolicy/UpdateAgent: the caller
// supplies both ToolOrVerb and ActionTier, and both may change together.
//
// id names the row; t.ID, t.TenantID, t.BuiltinTier, t.CreatedAt, and
// t.CreatedBy are ignored on input — CreatedBy specifically is never
// reassigned by an edit (see updateTierOverrideQuery's own comment).
// ErrNotFound if no row with id exists for this tenant.
//
// now is an explicit parameter here, unlike UpdatePolicy/UpdateAgent, which
// both reuse a RETURNING updated_at for their audit entry's OccurredAt:
// tier_overrides (migrations/000001_baseline.up.sql) has no updated_at
// column at all — created_at names authorship, not last-touched, and does
// not change on edit — so there is no row-level timestamp to read back and
// reuse here. A Go-side clock read is unavoidable for this one method, and
// it is injected rather than called inline for the same determinism
// authz.Request.Now and models.Approval.Verify's own now parameter require.
func (s *Store) UpdateTierOverride(
	ctx context.Context, id uuid.UUID, t models.TierOverride, actor string, now time.Time,
) (models.TierOverride, error) {
	if t.ToolOrVerb == "" {
		return models.TierOverride{}, fmt.Errorf("%w: tool_or_verb is required", ErrInvalidRequest)
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.TierOverride{}, err
	}
	defer func() { _ = tx.Rollback() }()

	baseline, err := s.overrideBaseline(ctx, tx, t.ToolOrVerb)
	if err != nil {
		return models.TierOverride{}, err
	}
	if err := authz.ValidateOverride(baseline, t.ActionTier); err != nil {
		return models.TierOverride{}, err
	}

	t.BuiltinTier = baseline
	row := tx.QueryRowContext(ctx, updateTierOverrideQuery, t.ToolOrVerb, int64(t.ActionTier), int64(t.BuiltinTier), id.String())
	if err := row.Scan(&t.CreatedAt, &t.CreatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.TierOverride{}, fmt.Errorf("%w: tier override %s", ErrNotFound, id)
		}
		if isUniqueViolation(err) {
			return models.TierOverride{}, fmt.Errorf("%w: tier override for %q", ErrAlreadyExists, t.ToolOrVerb)
		}
		return models.TierOverride{}, fmt.Errorf("store: update tier override %s: %w", id, err)
	}
	t.ID = id
	t.TenantID = s.tenantID

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeTierOverrideUpdated,
		Actor:         actor,
		ToolName:      t.ToolOrVerb,
		DeclaredTier:  int16(t.ActionTier),  //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier
		DerivedTier:   int16(t.BuiltinTier), //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        t.ToolOrVerb,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.TierOverride{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.TierOverride{}, fmt.Errorf("store: commit: %w", err)
	}
	return t, nil
}

// DeleteTierOverride deletes the id row and audits the deletion inside one
// transaction. No ValidateOverride call: removing an override reverts a tool
// to the resolution beneath it — the tenant's own tool_catalog entry where
// one exists, the built-in classification otherwise (authz.OverrideBaseline)
// — and since the row could only ever have been at or ABOVE that resolution,
// removing it can never lower anything. The raise-only rule has nothing to
// say about deletion, the same reasoning Task 2's own report gives for why
// stratium_pap holds DELETE on this table at all.
//
// Task 2's report words that as "reverts a tool to its built-in tier," which
// was accurate when the baseline was the built-in alone and is now one case
// of it.
//
// now is a parameter for the same reason DeletePolicy's/DeleteAgent's are: a
// DELETE leaves no row behind whose own timestamp the audit entry could
// reuse via RETURNING.
func (s *Store) DeleteTierOverride(ctx context.Context, id uuid.UUID, actor string, now time.Time) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var toolOrVerb string
	if err := tx.QueryRowContext(ctx, deleteTierOverrideQuery, id.String()).Scan(&toolOrVerb); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: tier override %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: delete tier override %s: %w", id, err)
	}

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeTierOverrideDeleted,
		Actor:         actor,
		ToolName:      toolOrVerb,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        toolOrVerb,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
