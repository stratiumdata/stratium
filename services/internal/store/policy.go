package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/models"
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
// policy text — so trusting this column at DECISION time would let a
// decision depend on a value no engine's own Prepare/Evaluate has ever
// verified. The database column itself stays, and Phase 14 Task 3's CRUD
// write path (CreatePolicy/UpdatePolicy, below) now populates it — validated
// at write time by validateEffectAgreement against cedar/json's own declared
// effect (refusing a mismatch outright) and constrained to a fixed, provably
// uninformative sentinel for rego/xacml, whose stored policies are not
// single-valued at all (see that function's own doc comment for the
// language-by-language basis). That write-time discipline is what makes the
// column SAFE for a display-only read path (GetPolicy/ListPolicies' own
// scanFullPolicy, which do select it, for an admin screen) — this decision
// path still does not select it, and must not start to: no engine has
// changed how it derives effect, only how honestly the column now describes
// what they already do.
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

// effectDeclarer is implemented by a policy.PolicyEngine whose language
// makes a stored policy's effect single-valued and mechanically derivable
// from its own text — cedar.Engine and jsonpolicy.Engine both implement it;
// rego.Engine and xacml.Engine do not, because a single stored policy in
// either language can itself define rules of BOTH effects, resolved only
// once real request data is known (see validateEffectAgreement's own doc
// comment for the empirical, language-by-language basis).
//
// Declared here, as a small interface satisfied structurally via a type
// assertion, rather than added as a method on policy.PolicyEngine itself:
// Prepare and Evaluate never need this, so forcing rego.Engine and
// xacml.Engine to grow a method they could only implement dishonestly
// (picking an arbitrary one of the two effects, or always erroring) would
// spread this package's own write-path concern into every engine's public
// surface for no reader of Prepare/Evaluate to ever call — the same "define
// the interface where it is used, not where it is implemented" call this
// codebase already makes for its other small interfaces.
type effectDeclarer interface {
	// DeclaredEffect parses text — already known to pass Validate by the
	// time this is called — and returns the single "allow"/"deny" value it
	// unconditionally declares.
	DeclaredEffect(text string) (string, error)
}

// multiValuedLanguageEffect is the one value policies.effect may hold for a
// language whose engine does not implement effectDeclarer (today: rego,
// xacml) — see validateEffectAgreement's own doc comment for why no
// operator-supplied value can be trusted there at all. "deny" specifically,
// not "allow": the same safe-direction default authz.Effect's own zero value
// already establishes for "no real information here" ("a leg that is never
// evaluated must deny rather than silently permit"), and jsonpolicy's and
// xacml's own effectOf fallbacks already pick it for the identical reason. A
// reader who ignores this doc comment and trusts the column anyway for one
// of these two languages is misled in the safe direction — believing a
// policy denies more than it actually does, never less.
const multiValuedLanguageEffect = "deny"

// ErrEffectMismatch indicates policies.effect disagrees with what the
// policy's own text unconditionally declares, for a language where that
// comparison is well-defined (see validateEffectAgreement). A stored policy
// whose declared column contradicts its text is exactly what let a PAP
// screen "show the opposite of what the policy actually does"
// (LoadAllPolicies' own doc comment) — refusing the write at the one place
// a human still has to agree with the machine is cheaper than ever
// discovering the disagreement downstream, on a screen an operator trusts.
var ErrEffectMismatch = errors.New("store: policy effect does not agree with policy text")

// ErrEffectNotDeclarable indicates a Create/Update call supplied an effect
// other than multiValuedLanguageEffect for a language whose engine does not
// implement effectDeclarer. Refusing anything else, rather than silently
// overwriting it with the sentinel, is deliberate: an operator who typed
// "allow" for a Rego or XACML policy believing it means something is told
// so immediately, at the one moment they can act on it — the same "say it
// explicitly, don't get a default for free" discipline
// ErrAllowedToolsRequired (agent.go) already holds a different field to,
// rather than this package quietly discarding input the caller believed
// was recorded.
var ErrEffectNotDeclarable = errors.New("store: policy language cannot declare a single effect from its text")

// validateEffectAgreement is Issue 1's write-time check: policies.effect
// must never be able to say something the policy text contradicts, for the
// reason LoadAllPolicies' own doc comment already gives for not trusting it
// at read time — except read-time silence cannot undo a bad row that
// already exists, and this refuses one before it is ever written.
//
// Determined empirically, by reading each engine's own Prepare/Evaluate (see
// this phase's own task report for the full per-language walkthrough), not
// assumed: a stored policy's effect is single-valued — one text, one
// effect, true for every request that ever matches it — in exactly two of
// the four languages this package validates against.
//
//   - Cedar: parseOne (cedar/engine.go) already requires text to be exactly
//     one policy STATEMENT, and Cedar's grammar begins every statement with
//     exactly one of the two mutually exclusive keywords "permit"/"forbid".
//     No Cedar text exists for which that keyword could read one way against
//     one request and the other way against a different one.
//   - JSON: the schema's own top-level "effect" key IS the declared value,
//     literally — see jsonpolicy's own package doc for the schema in full.
//   - Rego: a single module can define an "allow" rule and a "deny" rule as
//     two INDEPENDENT rules, each conditioned however its author wrote it —
//     rego/evaluate.go's own decision() reads both keys off one Eval call's
//     result, and that package's own doc comment states plainly that "a
//     policy defining both allow and deny as true resolves to a deny
//     verdict" PER REQUEST. Nothing about the text alone fixes which rule
//     fires for a request not yet known.
//   - XACML: a single <Policy> (one stored policy) may contain more than one
//     <Rule>, and each Rule carries its OWN Effect attribute independently,
//     combined only by deny-overrides when more than one actually matches
//     the SAME request (xacml/evaluate.go's compiledPolicy.evaluate) — a
//     Policy with one Permit-effect Rule scoped to one Target and one
//     Deny-effect Rule scoped to a different Target legitimately produces
//     Allow for some requests and Deny for others, from the identical
//     stored row.
//
// For the two single-valued languages, effect must equal exactly what the
// text declares (via effectDeclarer), or the write is refused
// (ErrEffectMismatch) — the column can no longer lie, because it is checked
// against the one thing it could ever disagree with.
//
// For the two that are not, the column cannot be a claim about that policy
// at all: no operator-supplied value could ever be validated against a text
// with no one true effect to compare it to, and silently accepting one
// anyway would leave exactly the "PAP screen shows the opposite of what the
// policy does" risk this function exists to close, just unenforced for two
// of four languages instead of all four. Rather than accept-and-trust (this
// package's own established treatment for values it cannot check further,
// e.g. Name), this rejects anything except the fixed sentinel
// multiValuedLanguageEffect (ErrEffectNotDeclarable) — see that constant's
// own doc comment for why "deny," and this function's own doc comment above
// for why refuse rather than silently overwrite. A future PAP screen
// (Task 6) must read this column as fact ONLY for cedar/json rows; for
// rego/xacml rows it is a constant placeholder, provably uninformative
// (every rego/xacml row's effect is, by construction, the identical value),
// and must never be displayed as that row's real behavior.
func validateEffectAgreement(registry policy.Registry, language, effect, text string) error {
	engine, ok := registry[language]
	if !ok {
		// validatePolicyText — called earlier by every caller of this
		// function, against the same (registry, language) pair — already
		// turns an unregistered language into ErrUnknownLanguage before this
		// is ever reached in practice. Returning nil rather than re-deriving
		// that same error here keeps this function's own contract to
		// exactly one question, "does effect agree with text," rather than
		// a second, independently-worded unknown-language check whose
		// message would need to be kept in sync with validatePolicyText's.
		return nil
	}

	declarer, ok := engine.(effectDeclarer)
	if !ok {
		if effect != multiValuedLanguageEffect {
			return fmt.Errorf(
				"%w: %s policies cannot declare a single effect (one stored policy can itself produce both allow and deny outcomes, depending on the request) — pass %q, the fixed placeholder a display screen must never read as this policy's actual behavior",
				ErrEffectNotDeclarable, language, multiValuedLanguageEffect)
		}
		return nil
	}

	declared, err := declarer.DeclaredEffect(text)
	if err != nil {
		// validatePolicyText already confirmed text passes this same
		// engine's Validate; a DeclaredEffect failure here would mean the
		// two disagree about what text is well-formed, which should be
		// unreachable in practice for either engine that implements this
		// interface today. Wrapped and returned, not ignored: silently
		// treating an error as "agreement confirmed" would be the exact
		// fail-open this whole function exists to refuse.
		return fmt.Errorf("store: determine declared effect: %w", err)
	}
	if declared != effect {
		return fmt.Errorf("%w: policy text declares %q, request says %q", ErrEffectMismatch, declared, effect)
	}
	return nil
}

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

const getPolicyQuery = `SELECT id, tenant_id, name, description, language, policy_content, effect, version, enabled, created_at, updated_at, protected ` +
	`FROM policies WHERE id = $1`

// listPoliciesQuery orders by name, the PAP admin screen's natural,
// human-facing order — unlike loadAllPoliciesQuery's ORDER BY id above,
// nothing downstream of this list gives compiled-set identity a reason to
// stay stable across calls, so there is no reason to prefer id here.
const listPoliciesQuery = `SELECT id, tenant_id, name, description, language, policy_content, effect, version, enabled, created_at, updated_at, protected ` +
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

// loadPolicyProtectedForUpdateQuery locks the row an editor's update is
// checked against: a protected policy is an admin's to change.
const loadPolicyProtectedForUpdateQuery = `SELECT protected FROM policies WHERE id = $1 FOR UPDATE`

// setPolicyProtectionQuery is the only statement that writes the protected
// column. updatePolicyQuery leaves it alone on purpose: a full replace that
// omitted the field must not be able to clear it.
const setPolicyProtectionQuery = `UPDATE policies SET protected = $1, updated_at = NOW() WHERE id = $2 RETURNING name`

const (
	eventTypePolicyProtected   = "policy_protected"
	eventTypePolicyUnprotected = "policy_unprotected"
)

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
		&p.Version, &p.Enabled, &p.CreatedAt, &p.UpdatedAt, &p.Protected)
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
	if err := validateEffectAgreement(registry, p.Language, p.Effect, p.Text); err != nil {
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
	ctx context.Context, registry policy.Registry, id uuid.UUID, p models.Policy, actor string, mayLoosen bool,
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
	if err := validateEffectAgreement(registry, p.Language, p.Effect, p.Text); err != nil {
		return models.Policy{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.Policy{}, err
	}
	defer func() { _ = tx.Rollback() }()

	// The stored flag, not the request's: protection is set through
	// SetPolicyProtection only, and a body cannot claim or clear it.
	var protected bool
	if !mayLoosen {
		if err := tx.QueryRowContext(ctx, loadPolicyProtectedForUpdateQuery, id.String()).Scan(&protected); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return models.Policy{}, fmt.Errorf("%w: policy %s", ErrNotFound, id)
			}
			return models.Policy{}, fmt.Errorf("store: load policy %s protection: %w", id, err)
		}
		if protected {
			return models.Policy{}, fmt.Errorf("%w: the policy is protected", ErrAdminRequired)
		}
	}

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

// SetPolicyProtection marks a policy protected or not. A protected policy can
// be changed or disabled only by an admin (UpdatePolicy's mayLoosen); deleting
// any policy already needs one. It is how an admin makes a rule an editor
// wrote, or one of their own, stay: an agent reservation, a forbid.
func (s *Store) SetPolicyProtection(
	ctx context.Context, id uuid.UUID, protected bool, actor string, now time.Time,
) (models.PolicyProtectionView, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.PolicyProtectionView{}, err
	}
	defer func() { _ = tx.Rollback() }()

	var name string
	if err := tx.QueryRowContext(ctx, setPolicyProtectionQuery, protected, id.String()).Scan(&name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.PolicyProtectionView{}, fmt.Errorf("%w: policy %s", ErrNotFound, id)
		}
		return models.PolicyProtectionView{}, fmt.Errorf("store: set policy %s protection: %w", id, err)
	}

	eventType := eventTypePolicyUnprotected
	if protected {
		eventType = eventTypePolicyProtected
	}
	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventType,
		Actor:         actor,
		PolicyID:      id.String(),
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        name,
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.PolicyProtectionView{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.PolicyProtectionView{}, fmt.Errorf("store: commit: %w", err)
	}
	return models.PolicyProtectionView{PolicyID: id, Protected: protected}, nil
}
