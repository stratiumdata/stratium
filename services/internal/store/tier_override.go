package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// Package doc for this file: the PAP's CRUD surface over the tier_overrides
// table (migrations/000001_baseline) — spec §4.4's raise-only tenant
// correction to a tool or verb's built-in action-tier classification.
// Nothing reads this table on the decision path through this package today
// (internal/authz.TierTable.Overrides is populated by whatever the PDP's own
// wiring loads it from — out of this phase's scope), so unlike policy.go and
// agent.go there is no sibling PDP-facing read to distinguish this file's
// methods from.

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

// builtinTier computes the built-in sensitivity tier ValidateOverride
// compares a proposed override against for key (a tier_overrides.tool_or_verb
// value — a tool name or a bare verb, per internal/authz.lookupKeys). It is
// not a reimplementation of BuiltinTier's own shell-command classifier
// (tier.go) — that classifier needs an actual RawInput, which an override
// target (a name, not one invocation) never has, and TASK 3's brief is
// explicit: "Call ValidateOverride; do not reimplement it," which this
// function honors by staying entirely upstream of ValidateOverride's own
// job (comparing two already-known tiers) rather than duplicating any part
// of it.
//
// Two, and only two, of DeriveTier's three name-keyed resolution steps are
// consulted, deliberately not all three:
//
//  1. authz.DefaultCatalog() — the fixed tool-name -> tier table (Read,
//     Write, ...). A key matching an entry here has a real, static built-in
//     tier, and an override claiming anything below it IS a lowering.
//  2. authz.BuiltinTier(Action{Verb: key}) — reached only through its
//     verb-table branch (verbTiers), since a bare key carries no RawInput
//     for the shell classifier to run against. A key matching a known verb
//     ("read", "write", "delete", ...) has a real, static built-in tier the
//     same way a catalogued tool name does.
//
// The catalog step DeriveTier itself also consults — a tenant's own
// tool_catalog rows (BuildTierCatalog, internal/authz/catalog.go) — is
// deliberately NOT reached here. That table is Task 4's own CRUD scope, not
// this task's, and more importantly its NULL-tier rows (Bash-shaped: "let
// BuiltinTier decide per command") have no single static tier to compare an
// override against at all — the whole reason DefaultCatalog() itself omits
// Bash (see that function's own doc comment). Reaching into a table this
// task does not write, for a value that would not answer the question
// asked, is not a shortcut worth taking.
//
// A key matching neither table — "Bash" among them, deliberately (both
// DefaultCatalog's and this function's own doc comments) — floors at
// models.ActionTierReasoning, ActionTier's own minimum. Nothing can be
// "lowered" below the lattice's floor, so an override on a name with no
// static built-in signal can never fail the raise-only check on that
// account; the check that actually protects a Bash-typed override from
// masking a genuinely destructive command happens per-invocation, at
// decision time, via DeriveTier's own evidence rule (tier.go's
// destructiveEvidence) — never here, and never by this function pretending
// to know what a not-yet-issued command will do.
func builtinTier(key string) models.ActionTier {
	if t, ok := authz.DefaultCatalog()[key]; ok {
		return t
	}
	if t, ok := authz.BuiltinTier(authz.Action{Verb: key}); ok {
		return t
	}
	return models.ActionTierReasoning
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

// CreateTierOverride computes t.ToolOrVerb's built-in tier (builtinTier,
// above), calls authz.ValidateOverride against it — Property 3 of Task 3,
// spec §4.4's raise-only rule, enforced by the one function written for it
// rather than reimplemented here — and, only if that succeeds, inserts t
// and audits its creation inside one transaction (N4).
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
	builtin := builtinTier(t.ToolOrVerb)
	if err := authz.ValidateOverride(builtin, t.ActionTier); err != nil {
		return models.TierOverride{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.TierOverride{}, err
	}
	defer func() { _ = tx.Rollback() }()

	t.TenantID = s.tenantID
	t.BuiltinTier = builtin
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
// (possibly newly-supplied) built-in tier — the same ValidateOverride call
// CreateTierOverride makes, run fresh rather than trusting the row's
// existing builtin_tier column, so an update is held to the current built-in
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
	builtin := builtinTier(t.ToolOrVerb)
	if err := authz.ValidateOverride(builtin, t.ActionTier); err != nil {
		return models.TierOverride{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.TierOverride{}, err
	}
	defer func() { _ = tx.Rollback() }()

	t.BuiltinTier = builtin
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
// transaction. No ValidateOverride call: removing an override reverts a
// tool to its built-in tier, never a lowering of anything — the raise-only
// rule has nothing to say about deletion, the identical reasoning Task 2's
// own report already gives for why stratium_pap holds DELETE on this table
// at all ("removing an override reverts a tool to its built-in tier, an
// ordinary, safe operation").
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
