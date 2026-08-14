package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"stratium/internal/policy"
	"stratium/pkg/audit"
	"stratium/pkg/models"
)

// loadAllPoliciesQuery loads every enabled policy for a tenant, regardless of
// language — what policy.Multi (internal/policy/multi.go) needs to discover
// which languages a tenant has authored before it knows which per-language
// groups to prepare, without asking one language at a time. No WHERE
// tenant_id clause, per the package doc: RLS is the only implementation of
// the tenant boundary. idx_policies_tenant_enabled indexes (tenant_id,
// enabled), so RLS's rewrite plus this query's own enabled = true still
// reaches that index. ORDER BY id makes the result deterministic across
// calls — an unordered load would give a compiled policy set an unstable
// identity, which makes any future cache key (see StoredPolicy.Version's own
// doc comment) meaningless and "why did this decision differ" unanswerable.
//
// policies.effect is deliberately not selected. Phase 4a Task 4 dropped it
// from StoredPolicy: no engine reads it — all four derive effect from the
// policy text — and it can actively disagree with that text (a row stored
// effect='deny' whose text says permit(...) still evaluates to ALLOW), so
// trusting this column at read time would let a PAP screen listing policies
// by policies.effect show the opposite of what the policy actually does. The
// database column itself stays: a future PAP write path may populate it. If
// one ever does, that write path must validate the value agrees with the
// policy text it is attached to before persisting, rather than this query
// trusting whatever was last written — the same discipline every engine's
// own Prepare already applies today by ignoring the column and parsing the
// text instead.
const loadAllPoliciesQuery = `SELECT id, name, language, policy_content, priority, version ` +
	`FROM policies WHERE enabled = true ORDER BY id`

// scanPolicyRows scans every row of a loadAllPoliciesQuery result into
// StoredPolicy. Kept as its own named function the same way scanDelegation
// (store.go) and scanAuditTail (audit.go) are: separating "map one row" from
// "run a query inside a transaction" reads better than interleaving them, a
// readability call this package makes for every multi-column scan regardless
// of how many callers a given query has.
func scanPolicyRows(rows *sql.Rows) ([]policy.StoredPolicy, error) {
	policies := make([]policy.StoredPolicy, 0)
	for rows.Next() {
		var p policy.StoredPolicy
		if err := rows.Scan(&p.ID, &p.Name, &p.Language, &p.Text, &p.Priority, &p.Version); err != nil {
			return nil, fmt.Errorf("scan policy row: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy rows: %w", err)
	}
	return policies, nil
}

// LoadAllPolicies loads the tenant's enabled policies across every language,
// ordered by id. A tenant with no policies at all is an ordinary, empty
// result, not an error: the caller gets a non-nil, zero-length slice and a
// nil error, prepares an empty policy set from it, and evaluates to zero
// verdicts — default-deny handles the rest downstream (see
// policy.PolicyEngine.Prepare's own doc comment).
//
// policies.policy_content is the policy text column; it maps to
// StoredPolicy.Text, not a same-named field.
//
// Priority is loaded but never ordered by. ORDER BY stays on id: priority is
// provenance only (spec Y7), so sorting the compiled set by it would suggest
// an evaluation order that authz.FoldVerdicts does not have, and would make
// the set's identity change whenever an operator renumbered policies without
// changing any of them.
func (s *Store) LoadAllPolicies(ctx context.Context) ([]policy.StoredPolicy, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, loadAllPoliciesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: load all policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	policies, err := scanPolicyRows(rows)
	if err != nil {
		return nil, fmt.Errorf("store: load all policies: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return policies, nil
}

// --- PAP CRUD (Task 3) ---
//
// Everything below is the PAP's admin-plane surface over this table:
// Create/Get/List/Update/Delete, named distinctly from LoadAllPolicies above
// (the PDP's own decision-path read, filtered to enabled=true and reduced to
// what an engine needs) so the two families never get mixed up by name —
// this family reads and writes the full row, every policy regardless of
// enabled, via models.Policy rather than policy.StoredPolicy.

// eventTypePolicyCreated, eventTypePolicyUpdated, and eventTypePolicyDeleted
// are audit_chain.event_type values for this table's three write operations
// (N4) — named the same way pdpgrpc/server.go's eventTypeDecision and
// pdpgrpc/delegation.go's eventTypeDelegationCreated already are, one
// constant per distinct kind of write rather than one shared "policy_write"
// value, so an auditor can tell a creation from a deletion without parsing
// Reason text.
const (
	eventTypePolicyCreated = "policy_created"
	eventTypePolicyUpdated = "policy_updated"
	eventTypePolicyDeleted = "policy_deleted"
)

// ErrUnknownLanguage indicates policies.language names a language no engine
// in the caller-supplied policy.Registry implements. Checked before Validate
// is even attempted, so a typo'd or unimplemented language reads as "we do
// not know this language," never as a validation failure of some sort.
var ErrUnknownLanguage = errors.New("store: no policy engine registered for this language")

// ErrInvalidEffect indicates policies.effect is neither "allow" nor "deny" —
// the Go-side mirror of the schema's own CHECK (effect IN ('allow','deny')),
// checked here so a bad value is refused with a clear message before ever
// reaching Postgres, rather than surfacing as an opaque constraint violation.
var ErrInvalidEffect = errors.New("store: policy effect must be \"allow\" or \"deny\"")

// ErrPolicyInvalid wraps every error validatePolicyText's own engine.
// Validate call returns — a syntax error, or the exact "syntactically
// valid but semantically dead" rejections Phase 4a added (a typo'd Rego
// package, an empty JSON "in" list, an out-of-vocabulary XACML tier value,
// a Cedar `in []` scope). Found live, not designed up front: without this
// sentinel, the underlying engine error (which wraps none of this
// package's own sentinels) fell through cmd/stratium-pap/respond.go's
// writeStoreError to its default case — 500 Internal Server Error — for
// exactly the property this task's own brief calls "the failure the PAP
// exists to prevent," which should read to an operator as "fix your
// policy" (400), never "something is broken here" (500).
// TestCreatePolicy_InvalidPolicyRefused_NothingPersisted
// (cmd/stratium-pap/policies_test.go) is what caught this.
var ErrPolicyInvalid = errors.New("store: policy failed validation")

// insertPolicyQuery omits id from its column list, unlike
// insertDelegationQuery/insertApprovalQuery (delegation.go, approval.go),
// which both bind a Go-generated uuid.New() explicitly: CreateDelegation
// needs d.ID before the INSERT even runs (chain_agent_ids, the
// self-referencing root_delegation_id for a root), and CreateApproval's own
// caller mints a token against a.ID from the same call. Nothing here needs
// the id for anything before this statement returns, so the schema's own
// DEFAULT uuid_generate_v4() (migrations/000001_baseline.up.sql) is left to
// generate it, read back via RETURNING alongside created_at/updated_at —
// one fewer value this package computes redundantly with what the database
// already commits to being authoritative for.
const insertPolicyQuery = `INSERT INTO policies (tenant_id, name, description, language, policy_content, effect, enabled) ` +
	`VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at, updated_at`

const getPolicyQuery = `SELECT id, tenant_id, name, description, language, policy_content, effect, version, enabled, created_at, updated_at ` +
	`FROM policies WHERE id = $1`

// listPoliciesQuery orders by name, the PAP admin screen's natural,
// human-facing order — unlike loadAllPoliciesQuery's ORDER BY id above,
// nothing downstream of this list gives compiled-set identity a reason to
// stay stable across calls, so there is no reason to prefer id here.
const listPoliciesQuery = `SELECT id, tenant_id, name, description, language, policy_content, effect, version, enabled, created_at, updated_at ` +
	`FROM policies ORDER BY name`

// updatePolicyQuery leaves version and updated_at to Postgres (version =
// version + 1, updated_at = NOW()) rather than binding either as a Go-side
// parameter, and returns both via RETURNING — the same reasoning
// CreatePolicy's own RETURNING created_at, updated_at follows: the row's own
// clock is authoritative, and reading it back in the same round trip is what
// lets the audit entry below reuse updated_at as OccurredAt exactly,
// with no separate, potentially skewed time.Now() call of its own.
const updatePolicyQuery = `UPDATE policies SET name = $1, description = $2, language = $3, policy_content = $4, ` +
	`effect = $5, enabled = $6, version = version + 1, updated_at = NOW() ` +
	`WHERE id = $7 RETURNING version, created_at, updated_at`

const deletePolicyQuery = `DELETE FROM policies WHERE id = $1 RETURNING name`

// validateEffect is the Go-side mirror of the schema's own CHECK constraint
// — see ErrInvalidEffect.
func validateEffect(effect string) error {
	if effect != "allow" && effect != "deny" {
		return fmt.Errorf("%w: got %q", ErrInvalidEffect, effect)
	}
	return nil
}

// validatePolicyName is the one field CreatePolicy/UpdatePolicy check that
// has no engine or CHECK constraint standing in for it: an empty name would
// insert cleanly into the NOT NULL name column (empty string is not NULL)
// and only surface later as a policy an admin screen lists with nothing to
// call it. Checked here, in the store layer, alongside validateEffect and
// validatePolicyText — this package's CRUD methods are the single place
// request-shape and domain validation both live for a write, so the HTTP
// handlers that call them (cmd/stratium-pap/policies.go) stay thin: decode,
// call, map the resulting error to a status.
func validatePolicyName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: policy name is required", ErrInvalidRequest)
	}
	return nil
}

// validatePolicyText looks up language in registry and runs text through
// that engine's own Validate — never reimplemented, never approximated.
// This is Property 2 of Task 3 (spec: "storing a policy that can never fire
// is exactly the failure the PAP exists to prevent"): all four engines
// implement Validate, and Phase 4a made each one strict enough to reject a
// policy that is syntactically valid but semantically dead (a Rego module
// with a typo'd package, a JSON "in": [], a Cedar `in []` scope, an XACML
// document naming an out-of-vocabulary tier) — see each engine's own
// Validate doc comment. Called from CreatePolicy and UpdatePolicy, both
// before beginTenantTx: a policy that fails here never causes a transaction
// to be opened at all, let alone a row to be written.
func validatePolicyText(ctx context.Context, registry policy.Registry, language, text string) error {
	engine, ok := registry[language]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownLanguage, language)
	}
	if err := engine.Validate(ctx, text); err != nil {
		// Wraps BOTH ErrPolicyInvalid (so an HTTP caller can answer 400,
		// not 500 — see that sentinel's own doc comment) and the engine's
		// own error (so its specific reason — which package, which
		// AttributeValue, which empty list — still reaches whoever reads
		// this error, engine text intact). Go's fmt.Errorf supports more
		// than one %w since 1.20; errors.Is/As can match either.
		return fmt.Errorf("%w: policy text failed validation: %w", ErrPolicyInvalid, err)
	}
	return nil
}

// scanFullPolicy scans one row (Get) or the current row of a *sql.Rows
// (List) into a models.Policy, sharing decode logic between the two via
// rowScanner (store.go) — description is nullable in the schema and, unlike
// the plain-string fields written directly (see CreatePolicy's own comment
// on why an unset Description writes as "" rather than NULL), a genuinely
// NULL row predating any PAP write must still decode to "" here, not error.
func scanFullPolicy(row rowScanner) (models.Policy, error) {
	var p models.Policy
	var description sql.NullString
	err := row.Scan(&p.ID, &p.TenantID, &p.Name, &description, &p.Language, &p.Text, &p.Effect,
		&p.Version, &p.Enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return models.Policy{}, err
	}
	if description.Valid {
		p.Description = description.String
	}
	return p, nil
}

// CreatePolicy validates p.Text against p.Language's own engine (see
// validatePolicyText) and, only if that succeeds, inserts p and audits its
// creation inside one transaction (N4): a policy that fails validation is
// never persisted, and a policy that IS persisted is never left unaudited,
// because the same commit covers both, and the same rollback undoes both.
//
// p.ID, p.TenantID, p.Version, p.CreatedAt, and p.UpdatedAt are ignored on
// input and set authoritatively here — the same treatment CreateDelegation
// gives d.RootDelegationID/d.Depth (delegation.go) and CreateApproval gives
// a.Status/a.RequestedAt (approval.go): there is no legitimate
// caller-supplied value for any of them on a brand-new row.
//
// actor is recorded on the audit entry only (Actor) — unlike TierOverride,
// the policies table itself has no created_by column to also carry it.
func (s *Store) CreatePolicy(ctx context.Context, registry policy.Registry, p models.Policy, actor string) (models.Policy, error) {
	if err := validatePolicyName(p.Name); err != nil {
		return models.Policy{}, err
	}
	if err := validateEffect(p.Effect); err != nil {
		return models.Policy{}, err
	}
	if err := validatePolicyText(ctx, registry, p.Language, p.Text); err != nil {
		return models.Policy{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Policy{}, err
	}
	defer func() { _ = tx.Rollback() }()

	p.TenantID = s.tenantID
	p.Version = 1

	row := tx.QueryRowContext(ctx, insertPolicyQuery,
		s.tenantID, p.Name, p.Description, p.Language, p.Text, p.Effect, p.Enabled)
	if err := row.Scan(&p.ID, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if isUniqueViolation(err) {
			return models.Policy{}, fmt.Errorf("%w: policy named %q", ErrAlreadyExists, p.Name)
		}
		return models.Policy{}, fmt.Errorf("store: insert policy %q: %w", p.Name, err)
	}

	// Decision/DeniedAtDepth/PolicySource/PolicyID are the closest fit
	// audit.Entry's decision-shaped fields have for a CRUD write — the same
	// repurposing pdpgrpc/delegation.go's appendDelegationAudit already
	// documents for DeclaredTier/DerivedTier: Decision is unconditionally
	// "ALLOW" and DeniedAtDepth unconditionally noDenial because this call
	// only ever reaches here after every refusal path above has already
	// returned; PolicySource/PolicyID exist precisely to identify "which
	// policy" and are reused for that literally, not as an analogy. Reason
	// carries the policy's own name, which nothing else on this entry
	// records.
	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    p.CreatedAt,
		EventType:     eventTypePolicyCreated,
		Actor:         actor,
		PolicySource:  p.Language,
		PolicyID:      p.ID.String(),
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        p.Name,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.Policy{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.Policy{}, fmt.Errorf("store: commit: %w", err)
	}
	return p, nil
}

// GetPolicy loads one policies row by id. RLS scopes it to the tenant fixed
// at New; a row for another tenant, or no row at all, is ErrNotFound either
// way — the same indistinguishable-by-design guarantee LoadAgent gives
// (store.go's package doc).
func (s *Store) GetPolicy(ctx context.Context, id uuid.UUID) (models.Policy, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Policy{}, err
	}
	defer func() { _ = tx.Rollback() }()

	p, err := scanFullPolicy(tx.QueryRowContext(ctx, getPolicyQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Policy{}, fmt.Errorf("%w: policy %s", ErrNotFound, id)
		}
		return models.Policy{}, fmt.Errorf("store: get policy %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return models.Policy{}, fmt.Errorf("store: commit: %w", err)
	}
	return p, nil
}

// ListPolicies loads every policy the tenant has, enabled or not — an admin
// screen needs to show a disabled policy so an operator can re-enable or fix
// it, unlike LoadAllPolicies above, which exists to feed a decision and so
// filters to enabled=true only. A tenant with no policies at all is an
// ordinary, empty result: a non-nil, zero-length slice and a nil error.
func (s *Store) ListPolicies(ctx context.Context) ([]models.Policy, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listPoliciesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	policies := make([]models.Policy, 0)
	for rows.Next() {
		p, err := scanFullPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan policy row: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate policy rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return policies, nil
}

// UpdatePolicy validates p.Text the same way CreatePolicy does, then
// replaces every mutable column of the id row and audits the change, inside
// one transaction. A PUT-shaped full replace, not a partial patch: the
// caller always supplies every field CreatePolicy accepts, so there is no
// separate "did policy_content change" branch deciding whether to
// re-validate — it always runs, which is simpler and cannot be fooled by a
// request that changes language without changing text (or vice versa).
//
// id names the row; p.ID, p.TenantID, p.Version, p.CreatedAt, and
// p.UpdatedAt are ignored on input, matching CreatePolicy. ErrNotFound if no
// row with id exists for this tenant (RLS makes "another tenant's row" and
// "no such row" indistinguishable, per the package doc).
func (s *Store) UpdatePolicy(
	ctx context.Context, registry policy.Registry, id uuid.UUID, p models.Policy, actor string,
) (models.Policy, error) {
	if err := validatePolicyName(p.Name); err != nil {
		return models.Policy{}, err
	}
	if err := validateEffect(p.Effect); err != nil {
		return models.Policy{}, err
	}
	if err := validatePolicyText(ctx, registry, p.Language, p.Text); err != nil {
		return models.Policy{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Policy{}, err
	}
	defer func() { _ = tx.Rollback() }()

	row := tx.QueryRowContext(ctx, updatePolicyQuery,
		p.Name, p.Description, p.Language, p.Text, p.Effect, p.Enabled, id.String())
	if err := row.Scan(&p.Version, &p.CreatedAt, &p.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.Policy{}, fmt.Errorf("%w: policy %s", ErrNotFound, id)
		}
		if isUniqueViolation(err) {
			return models.Policy{}, fmt.Errorf("%w: policy named %q", ErrAlreadyExists, p.Name)
		}
		return models.Policy{}, fmt.Errorf("store: update policy %s: %w", id, err)
	}
	p.ID = id
	p.TenantID = s.tenantID

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    p.UpdatedAt,
		EventType:     eventTypePolicyUpdated,
		Actor:         actor,
		PolicySource:  p.Language,
		PolicyID:      p.ID.String(),
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        p.Name,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.Policy{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.Policy{}, fmt.Errorf("store: commit: %w", err)
	}
	return p, nil
}

// DeletePolicy deletes the id row and audits the deletion inside one
// transaction. now is a parameter, not read from the ambient clock — the
// same determinism authz.Request.Now and models.Approval.Verify's own now
// parameter require — because unlike Create/Update, a DELETE leaves no row
// behind whose own DB-computed timestamp the audit entry could reuse via
// RETURNING.
//
// RETURNING name both confirms the row existed (ErrNotFound if not — RLS
// makes "another tenant's row" and "no such row" indistinguishable, per the
// package doc) and supplies the audit entry's Reason in the same round trip,
// without a separate SELECT before the DELETE.
func (s *Store) DeletePolicy(ctx context.Context, id uuid.UUID, actor string, now time.Time) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var name string
	if err := tx.QueryRowContext(ctx, deletePolicyQuery, id.String()).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: policy %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: delete policy %s: %w", id, err)
	}

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypePolicyDeleted,
		Actor:         actor,
		PolicyID:      id.String(),
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
