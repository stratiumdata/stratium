package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// ToolCatalogEntry is defined in pkg/models, not here: see that file's own
// doc comment for why Task 2 moved it out of this package once internal/authz
// needed to resolve tiers and extract fields from a whole catalog, not just
// receive rows from this package's own loader.

// loadToolCatalogQuery loads every tool_catalog row RLS scopes the
// transaction to. id and tenant_id are both real columns
// (migrations/000013_tool_catalog) but neither is selected: id has no
// reader yet — this is the first load the table gets, and the table has no
// update-by-id or delete-by-id path for the PDP to ever need one (see the
// migration's own GRANT comment) — and tenant_id is redundant with the
// Store this method already runs through, the same reasoning
// loadAllPoliciesQuery (policy.go) applies to leaving its own tenant_id
// column unselected. Selecting either would be exactly the
// plumbed-but-never-populated field this project's house style rules out.
const loadToolCatalogQuery = `SELECT tool_name, action_tier, verb, resource_field, command_field ` +
	`FROM tool_catalog ORDER BY tool_name`

// scanToolCatalogRows scans every row of a loadToolCatalogQuery result —
// the same "map one row" / "run a query inside a transaction" split
// scanPolicyRows (policy.go) and scanAuditTail (audit.go) already keep
// separate in this package.
func scanToolCatalogRows(rows *sql.Rows) ([]models.ToolCatalogEntry, error) {
	entries := make([]models.ToolCatalogEntry, 0)
	for rows.Next() {
		var e models.ToolCatalogEntry
		var actionTier sql.NullInt64
		var resourceField, commandField sql.NullString

		if err := rows.Scan(&e.ToolName, &actionTier, &e.Verb, &resourceField, &commandField); err != nil {
			return nil, fmt.Errorf("scan tool catalog row: %w", err)
		}

		// action_tier is nullable (migrations/000014_tool_catalog_nullable_tier):
		// scanned through sql.NullInt64 into a pointer, the same discipline
		// scanDelegation applies to escalate_at (internal/store/store.go),
		// and for the same reason -- ActionTierReasoning is tier 0, so
		// decoding NULL into a bare (non-pointer) field would silently mean
		// "this tool is always harmless" instead of "no fixed tier; ask the
		// command classifier" (ToolCatalogEntry.ActionTier's own doc
		// comment). A non-NULL value still fails loudly on an out-of-range
		// tier, the same discipline scanDelegation and scanApproval already
		// apply to their own tier columns: a corrupt row must error, never
		// silently decode as ActionTierReasoning and read back as though
		// the tenant really did declare this tool harmless.
		if actionTier.Valid {
			tier, err := models.ParseActionTier(int(actionTier.Int64))
			if err != nil {
				return nil, fmt.Errorf("tool catalog %q action_tier: %w", e.ToolName, err)
			}
			e.ActionTier = &tier
		}

		if resourceField.Valid {
			v := resourceField.String
			e.ResourceField = &v
		}
		if commandField.Valid {
			v := commandField.String
			e.CommandField = &v
		}

		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate tool catalog rows: %w", err)
	}
	return entries, nil
}

// LoadToolCatalog loads the tenant's whole tool catalog, ordered by
// tool_name — the only selected column guaranteed unique per tenant (the
// UNIQUE (tenant_id, tool_name) constraint), so ordering by it is a
// complete, deterministic order with no ties to break, the same property
// loadAllPoliciesQuery gets from ORDER BY id.
//
// A tenant with no catalog rows — every tenant, until the control plane
// populates one — is an ordinary, empty result: a non-nil, zero-length
// slice and a nil error, never an error of its own. A caller resolving tier
// (spec §4.4.2 T1) falls back to the built-in map in exactly that case, the
// same "nothing configured" fallback LoadAllPolicies' own empty result
// already supports for the policy engines — but that fallback is that
// caller's decision to make, not this function's: LoadToolCatalog reports
// what the tenant has, nothing more.
func (s *Store) LoadToolCatalog(ctx context.Context) ([]models.ToolCatalogEntry, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, loadToolCatalogQuery)
	if err != nil {
		return nil, fmt.Errorf("store: load tool catalog: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries, err := scanToolCatalogRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: load tool catalog: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return entries, nil
}

// --- PAP CRUD (Task 4) ---
//
// Everything below is the PAP's admin-plane surface over this table (T1),
// named distinctly from LoadToolCatalog above for the same reason GetPolicy/
// ListPolicies are named distinctly from LoadAllPolicies (policy.go's own
// package doc): the two families read different shapes for different
// purposes. This family is also this table's first Go-level WRITER of any
// kind — LoadToolCatalog has been read-only since Task 2 — and the first
// reader of id and tenant_id: migrations/000013_tool_catalog's own comment
// named "no update-by-id or delete-by-id path... yet" as the reason neither
// column was selected before; this is that "yet."
//
// There is no DeleteToolCatalogEntry: migrations/000016_stratium_pap_role's
// own comment withholds DELETE on this table deliberately ("no delete
// caller in this phase... a tenant that no longer wants a tool specially
// classified can already correct the row via UPDATE"), and a Go method
// wrapping a grant the role does not hold would either dead-end at
// insufficient_privilege on every call or be a standing invitation to widen
// the grant to make it work — neither is worth adding for a verb this task
// never asks for.

// eventTypeToolCatalogCreated and eventTypeToolCatalogUpdated are
// audit_chain.event_type values for this table's two write operations (N4)
// — see policy.go's own comment on the identical constant shape.
const (
	eventTypeToolCatalogCreated = "tool_catalog_created"
	eventTypeToolCatalogUpdated = "tool_catalog_updated"
)

// insertToolCatalogQuery omits id from its column list -- see
// insertPolicyQuery's own doc comment (policy.go) for why: nothing here
// needs the id before this statement returns, so the schema's own DEFAULT
// uuid_generate_v4() generates it, read back via RETURNING.
const insertToolCatalogQuery = `INSERT INTO tool_catalog (tenant_id, tool_name, action_tier, verb, resource_field, command_field) ` +
	`VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`

const getToolCatalogEntryQuery = `SELECT id, tenant_id, tool_name, action_tier, verb, resource_field, command_field ` +
	`FROM tool_catalog WHERE id = $1`

// listToolCatalogEntriesQuery is loadToolCatalogQuery's admin-facing
// sibling: the same table, ordered the same way (ORDER BY tool_name — see
// that query's own doc comment for why it is a complete, tie-free order),
// but selecting id and tenant_id too, which the PAP's Get/Update-by-id
// routes need and the PDP's bulk decision-time read never has.
const listToolCatalogEntriesQuery = `SELECT id, tenant_id, tool_name, action_tier, verb, resource_field, command_field ` +
	`FROM tool_catalog ORDER BY tool_name`

const updateToolCatalogEntryQuery = `UPDATE tool_catalog SET tool_name = $1, action_tier = $2, verb = $3, resource_field = $4, command_field = $5 ` +
	`WHERE id = $6 RETURNING id`

// validateToolCatalogFields is the Go-side mirror of this table's two write
// constraints, checked proactively for a clean message before either ever
// reaches Postgres — the same discipline validateAgentFields (agent.go)
// holds trust_tier to:
//
//   - tool_name is required: NOT NULL and this table's own UNIQUE key
//     (tenant_id, tool_name), the same "empty string satisfies NOT NULL but
//     names nothing an admin screen could ever list usefully" reasoning
//     validatePolicyName gives its own required field.
//   - a fixed ActionTier or a CommandField, or both, must be present —
//     tool_catalog_tier_or_command_field (migrations/000014_tool_catalog_
//     nullable_tier). This mirror is not the only enforcement: isCheckViolation
//     below is what actually holds if this check is ever bypassed, weakened,
//     or simply wrong — see that function's own doc comment, and this
//     table's migration comment, "the constraint is the enforcement, not a
//     description of one."
//
// Verb is deliberately NOT required: ToolCatalogEntry.Verb's own doc comment
// (pkg/models) states plainly that nothing on the decision path consumes it
// yet, so there is no safety argument for gatekeeping it the way
// AllowedTools or Name are gated elsewhere in this package — an operator who
// does not care about it may simply leave it blank.
func validateToolCatalogFields(e models.ToolCatalogEntry) error {
	if e.ToolName == "" {
		return fmt.Errorf("%w: tool_name is required", ErrInvalidRequest)
	}
	if e.ActionTier == nil && e.CommandField == nil {
		return fmt.Errorf("%w: tool catalog entry must set an action_tier, a command_field, or both", ErrInvalidRequest)
	}
	return nil
}

// declaredTierForAudit converts a nullable catalog tier to audit_chain's
// plain int16 DeclaredTier column: -1 (matching noDenial's own established
// "not applicable" sentinel — see that constant's own doc comment) when the
// row fixes no tier at all, since 0 is ActionTierReasoning, a REAL tier, and
// would misrepresent a NULL-tier (Bash-shaped: "classify by command_field
// instead") row as one that declared REASONING rather than one that
// declared nothing.
func declaredTierForAudit(tier *models.ActionTier) int16 {
	if tier == nil {
		return -1
	}
	return int16(*tier) //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier
}

// scanFullToolCatalogEntry scans one row (Get) or the current row of a
// *sql.Rows (List) into a models.ToolCatalogEntry, sharing decode logic via
// rowScanner (store.go) — the admin-facing sibling of scanToolCatalogRows
// above, which cannot be reused directly: that function scans a *sql.Rows
// result with a five-column list (no id/tenant_id) built for its own
// multi-row loop, while every caller here needs the seven-column id/tenant_id
// shape through the single-row/multi-row rowScanner interface every other
// PAP CRUD scan* function in this package already uses.
func scanFullToolCatalogEntry(row rowScanner) (models.ToolCatalogEntry, error) {
	var e models.ToolCatalogEntry
	var actionTier sql.NullInt64
	var resourceField, commandField sql.NullString

	if err := row.Scan(&e.ID, &e.TenantID, &e.ToolName, &actionTier, &e.Verb, &resourceField, &commandField); err != nil {
		return models.ToolCatalogEntry{}, err
	}

	if actionTier.Valid {
		tier, err := models.ParseActionTier(int(actionTier.Int64))
		if err != nil {
			return models.ToolCatalogEntry{}, fmt.Errorf("tool catalog %s action_tier: %w", e.ID, err)
		}
		e.ActionTier = &tier
	}
	if resourceField.Valid {
		v := resourceField.String
		e.ResourceField = &v
	}
	if commandField.Valid {
		v := commandField.String
		e.CommandField = &v
	}
	return e, nil
}

// CreateToolCatalogEntry validates e (validateToolCatalogFields) and, only
// if that succeeds, inserts it and audits its creation inside one
// transaction (N4) — the same validate-then-write-and-audit shape every
// other PAP Create method in this package follows.
//
// e.ID and e.TenantID are ignored on input and set authoritatively here,
// matching CreatePolicy's identical treatment of its own caller-supplied
// identity fields.
func (s *Store) CreateToolCatalogEntry(ctx context.Context, e models.ToolCatalogEntry, actor string, now time.Time) (models.ToolCatalogEntry, error) {
	if err := validateToolCatalogFields(e); err != nil {
		return models.ToolCatalogEntry{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.ToolCatalogEntry{}, err
	}
	defer func() { _ = tx.Rollback() }()

	e.TenantID = s.tenantID

	// e.ActionTier/e.ResourceField/e.CommandField are all nilable pointers,
	// passed directly and unconverted -- the same treatment
	// insertDelegationQuery already gives d.EscalateAt/d.ParentDelegationID
	// (delegation.go's own doc comment): database/sql's default parameter
	// converter maps a nil pointer to SQL NULL and a non-nil one to its
	// pointee's value, so there is no separate nil-check-and-substitute step
	// to keep in sync with either field's own nullability contract.
	row := tx.QueryRowContext(ctx, insertToolCatalogQuery,
		s.tenantID, e.ToolName, e.ActionTier, e.Verb, e.ResourceField, e.CommandField)
	if err := row.Scan(&e.ID); err != nil {
		if isUniqueViolation(err) {
			return models.ToolCatalogEntry{}, fmt.Errorf("%w: tool catalog entry for %q", ErrAlreadyExists, e.ToolName)
		}
		if isCheckViolation(err) {
			return models.ToolCatalogEntry{}, fmt.Errorf("%w: tool catalog entry must set an action_tier, a command_field, or both", ErrInvalidRequest)
		}
		return models.ToolCatalogEntry{}, fmt.Errorf("store: insert tool catalog entry %q: %w", e.ToolName, err)
	}

	// ToolName/DeclaredTier are the closest fit audit.Entry's decision-shaped
	// fields have for this write, the same repurposing tier_override.go's own
	// CreateTierOverride audit entry already documents for its own
	// DeclaredTier/DerivedTier pair. DerivedTier is left unset (0): unlike a
	// tier override, there is no built-in baseline this write was validated
	// against to record there -- this is an ordinary configuration write,
	// closer to CreatePolicy's own audit shape than to CreateTierOverride's.
	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeToolCatalogCreated,
		Actor:         actor,
		ToolName:      e.ToolName,
		DeclaredTier:  declaredTierForAudit(e.ActionTier),
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        e.ToolName,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.ToolCatalogEntry{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.ToolCatalogEntry{}, fmt.Errorf("store: commit: %w", err)
	}
	return e, nil
}

// GetToolCatalogEntry loads one tool_catalog row by id. RLS scopes it to the
// tenant fixed at New; a row for another tenant, or no row at all, is
// ErrNotFound either way — the same indistinguishable-by-design guarantee
// every other Get method in this package gives (store.go's package doc).
func (s *Store) GetToolCatalogEntry(ctx context.Context, id uuid.UUID) (models.ToolCatalogEntry, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.ToolCatalogEntry{}, err
	}
	defer func() { _ = tx.Rollback() }()

	e, err := scanFullToolCatalogEntry(tx.QueryRowContext(ctx, getToolCatalogEntryQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ToolCatalogEntry{}, fmt.Errorf("%w: tool catalog entry %s", ErrNotFound, id)
		}
		return models.ToolCatalogEntry{}, fmt.Errorf("store: get tool catalog entry %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return models.ToolCatalogEntry{}, fmt.Errorf("store: commit: %w", err)
	}
	return e, nil
}

// ListToolCatalogEntries loads every tool catalog row the tenant has, with
// id and tenant_id populated (unlike LoadToolCatalog's bulk decision-time
// read). A tenant with none is an ordinary, empty result.
func (s *Store) ListToolCatalogEntries(ctx context.Context) ([]models.ToolCatalogEntry, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listToolCatalogEntriesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list tool catalog entries: %w", err)
	}
	defer func() { _ = rows.Close() }()

	entries := make([]models.ToolCatalogEntry, 0)
	for rows.Next() {
		e, err := scanFullToolCatalogEntry(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan tool catalog row: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate tool catalog rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return entries, nil
}

// UpdateToolCatalogEntry re-validates e the same way CreateToolCatalogEntry
// does, then replaces every mutable column of the id row and audits the
// change, inside one transaction — a PUT-shaped full replace, matching
// UpdatePolicy/UpdateAgent: the caller supplies every field
// CreateToolCatalogEntry accepts, so there is no separate partial-patch path
// and no way to fool the CHECK constraint by changing one field without the
// other.
//
// id names the row; e.ID and e.TenantID are ignored on input. ErrNotFound if
// no row with id exists for this tenant.
func (s *Store) UpdateToolCatalogEntry(
	ctx context.Context, id uuid.UUID, e models.ToolCatalogEntry, actor string, now time.Time,
) (models.ToolCatalogEntry, error) {
	if err := validateToolCatalogFields(e); err != nil {
		return models.ToolCatalogEntry{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.ToolCatalogEntry{}, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, updateToolCatalogEntryQuery,
		e.ToolName, e.ActionTier, e.Verb, e.ResourceField, e.CommandField, id.String())
	if err := row.Scan(&e.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ToolCatalogEntry{}, fmt.Errorf("%w: tool catalog entry %s", ErrNotFound, id)
		}
		if isUniqueViolation(err) {
			return models.ToolCatalogEntry{}, fmt.Errorf("%w: tool catalog entry for %q", ErrAlreadyExists, e.ToolName)
		}
		if isCheckViolation(err) {
			return models.ToolCatalogEntry{}, fmt.Errorf("%w: tool catalog entry must set an action_tier, a command_field, or both", ErrInvalidRequest)
		}
		return models.ToolCatalogEntry{}, fmt.Errorf("store: update tool catalog entry %s: %w", id, err)
	}
	e.TenantID = s.tenantID

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeToolCatalogUpdated,
		Actor:         actor,
		ToolName:      e.ToolName,
		DeclaredTier:  declaredTierForAudit(e.ActionTier),
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        e.ToolName,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.ToolCatalogEntry{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.ToolCatalogEntry{}, fmt.Errorf("store: commit: %w", err)
	}
	return e, nil
}
