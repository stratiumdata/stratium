package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/classification"
	"github.com/stratiumdata/stratium/pkg/models"
)

// eventTypeResourceLabelRuleCreated, eventTypeResourceLabelRuleUpdated and
// eventTypeResourceLabelRuleDeleted are audit_chain.event_type values for this
// table's three write operations (N4) — the same three-constant shape
// policy.go, agent.go and tier_override.go each declare for their own tables.
const (
	eventTypeResourceLabelRuleCreated = "resource_label_rule_created"
	eventTypeResourceLabelRuleUpdated = "resource_label_rule_updated"
	eventTypeResourceLabelRuleDeleted = "resource_label_rule_deleted"
)

// loadResourceLabelRulesQuery loads every resource_label_rules row RLS scopes
// the transaction to (migrations/000019_resource_label_rules).
//
// No WHERE tenant_id, per this package's own doc: RLS is the only tenant
// boundary. id and tenant_id are real columns but neither is selected — id has
// no reader on the decision path, and tenant_id is redundant with the Store
// this method already runs through, the identical reasoning
// loadToolCatalogQuery and loadAllPoliciesQuery each give for their own
// unselected columns.
//
// And nothing else: no LIKE, no prefix predicate, no closest-match ordering.
// pkg/classification.Resolve takes the whole slice and does the matching
// itself; pushing any part of R5/R6 into SQL would be a second matcher
// alongside a tested one, free to disagree about case-sensitivity, ties, and
// the empty-prefix catch-all. The migration's own comment on the absent prefix
// index says the same thing from the schema's side.
//
// ORDER BY prefix, hierarchy, level — every selected column, in order, so the
// result is totally ordered by construction. What that buys is modest and
// worth stating precisely, because an earlier version of this comment
// overstated it twice:
//
//   - A deterministic slice for anything that consumes the whole set. Resolve
//     does not need it (its winner and its ambiguity verdict are both
//     order-independent), but a test can assert an exact slice against it, and
//     TestIntegration_ResourceLabelRules_RoundTrip does.
//   - Ordering on all three columns rather than prefix alone, because ordering
//     on prefix alone would be total only if prefix were unique — which is a
//     SCHEMA constraint, and this file is otherwise careful that a schema
//     constraint is not a runtime one (see validateResourceLabelRule below).
//     Leaning on UNIQUE (tenant_id, prefix) here would be that same mistake
//     eighty lines earlier: exactly in the three worlds this file keeps naming
//     — a stale read, an in-flight migration, a direct psql write — two rows
//     could share a prefix, and ORDER BY prefix would leave them in whatever
//     order the planner chose. Naming all three columns costs nothing and does
//     not depend on any constraint holding.
//
// What it does for two same-prefix rules splits in two, and the halves are
// easy to state as one sentence that is wrong:
//
//   - If they DISAGREE — a prefix carrying two answers — Resolve refuses the
//     ambiguity rather than picking by position, so there is no value here for
//     an order to stabilise.
//   - If they agree once casing is folded, Resolve keeps whichever arrived
//     first, and this clause does settle which that is. That is a side effect
//     of ordering on the columns, not the reason for it, and it is worth no
//     more weight than that: the two rows differ only in casing of strings the
//     decision compares case-insensitively.
const loadResourceLabelRulesQuery = `SELECT prefix, hierarchy, level ` +
	`FROM resource_label_rules ORDER BY prefix, hierarchy, level`

// insertResourceLabelRuleQuery omits id from its column list, letting the
// schema's own uuid_generate_v4() DEFAULT generate it, and reads it back via
// RETURNING — see insertPolicyQuery's own doc comment (policy.go) for the
// general form of that choice.
//
// The RETURNING clause is Task 5's own addition. Until the PAP had an
// update-by-id and a delete-by-id route there was no reader for the value, and
// this constant said so; now a create's own 201 response is where the operator
// gets the handle those two routes name, exactly as every sibling resource's
// create already does.
const insertResourceLabelRuleQuery = `INSERT INTO resource_label_rules (tenant_id, prefix, hierarchy, level) ` +
	`VALUES ($1,$2,$3,$4) RETURNING id`

// --- PAP CRUD (Task 5) ---
//
// The four queries below are the admin plane's surface over this table, named
// distinctly from loadResourceLabelRulesQuery above for the reason
// catalog.go's own PAP-CRUD block gives: the two families read different
// shapes for different purposes. This one selects id and tenant_id, which the
// decision path has never had a reader for; that one selects the three columns
// a match is made of and nothing else.
//
// None of them filters by tenant_id — RLS via beginTenantTx is the only tenant
// boundary in this package, and TestNoProductionQueryFiltersByTenantID checks
// that automatically for every query here, including these.

const getResourceLabelRuleQuery = `SELECT id, tenant_id, prefix, hierarchy, level ` +
	`FROM resource_label_rules WHERE id = $1`

// listResourceLabelRulesQuery orders by prefix, hierarchy, level for the same
// reason loadResourceLabelRulesQuery does: ordering on prefix alone would be
// total only if prefix were unique, and that is a schema constraint, not a
// runtime one. Unlike that query it could order on id instead — a genuine
// primary key — but an operator's list is read by a human, and prefix order is
// the order the rules are reasoned about in.
const listResourceLabelRulesQuery = `SELECT id, tenant_id, prefix, hierarchy, level ` +
	`FROM resource_label_rules ORDER BY prefix, hierarchy, level`

// updateResourceLabelRuleQuery is a full replace of all three operator-owned
// columns, matching every other Update* in this package. RETURNING id exists
// only to tell "no such row for this tenant" from "updated" — the id is
// already known to the caller — the identical trick updateToolCatalogEntryQuery
// uses, and the reason neither needs a separate rows-affected check.
// getResourceLabelRuleForUpdateQuery locks the row an editor's update is
// compared against (labelRuleLoosens), so the comparison and the write see
// the same rule.
const getResourceLabelRuleForUpdateQuery = getResourceLabelRuleQuery + ` FOR UPDATE`

const updateResourceLabelRuleQuery = `UPDATE resource_label_rules SET prefix = $1, hierarchy = $2, level = $3 ` +
	`WHERE id = $4 RETURNING id`

// deleteResourceLabelRuleQuery returns the whole rule, not just the prefix its
// siblings return (deletePolicyQuery returns a name, deleteTierOverrideQuery a
// tool_or_verb). Two readers need it: the audit entry names the rule that was
// removed in the same "%q -> %s/%s" form the create entry names the rule that
// was added, and DeleteResourceLabelRule's own blast-radius report resolves the
// deleted prefix against what survives.
const deleteResourceLabelRuleQuery = `DELETE FROM resource_label_rules WHERE id = $1 ` +
	`RETURNING prefix, hierarchy, level`

// LoadResourceLabelRules loads the tenant's whole set of resource labelling
// rules (spec §3.9.1 R4), the input pkg/classification.Resolve resolves a
// resource id against.
//
// A tenant with no rules — every tenant, until an operator registers one — is
// an ordinary, empty result: a non-nil, zero-length slice and a nil error,
// never an error of its own, exactly as LoadToolCatalog and LoadAllPolicies
// treat their own "nothing configured yet" case. It is emphatically not a
// reason to substitute a default label: R2/R7 make an unlabelled resource deny
// under any configured cap, and that denial is the designed behaviour, not a
// gap for this method to paper over.
func (s *Store) LoadResourceLabelRules(ctx context.Context) ([]classification.Rule, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rules, err := queryResourceLabelRulesTx(ctx, tx)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return rules, nil
}

// queryResourceLabelRulesTx runs loadResourceLabelRulesQuery inside an
// already-open, already-tenant-scoped transaction — the same split
// queryToolCatalogTx (catalog.go) and queryTierOverridesTx (tier_override.go)
// each make, and for the same kind of second caller: DeleteResourceLabelRule
// needs the rules that SURVIVE its own delete, read after it, in the
// transaction the delete lands in, so the blast radius it records is the one
// that was actually committed.
func queryResourceLabelRulesTx(ctx context.Context, tx *sql.Tx) ([]classification.Rule, error) {
	rows, err := tx.QueryContext(ctx, loadResourceLabelRulesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: load resource label rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	rules := make([]classification.Rule, 0)
	for rows.Next() {
		var r classification.Rule
		if err := rows.Scan(&r.Prefix, &r.Hierarchy, &r.Level); err != nil {
			return nil, fmt.Errorf("store: scan resource label rule: %w", err)
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate resource label rules: %w", err)
	}
	return rules, nil
}

// validateResourceLabelRule refuses a rule whose level is not a level of its
// hierarchy, checked against pkg/classification.Levels itself — the single
// source for what the hierarchies are (R8 keeps them hardcoded in Go because a
// tenant-defined hierarchy needs an ORDERING, which is its own subsystem). The
// migration's own comment records why this is here rather than in a CHECK
// constraint: a CHECK enumerating the ten (hierarchy, level) pairs would be a
// second copy of Levels that nothing links back to the first, and both of its
// drift directions are silent.
//
// What this buys is a good error at the point of the typo. It is NOT the
// enforcement, and R9 says so in as many words: the enforcement is that a
// label the system cannot rank never reaches a permissive branch, which is
// CheckCap's to hold. A stale read, an in-flight migration, and a store bug
// each hand the read path rows this function never saw, so nothing downstream
// may assume an unrankable hierarchy is impossible — the same line
// pkg/classification.Resolve's own doc comment draws about this table's
// uniqueness key.
//
// prefix is deliberately NOT required to be non-empty, and that is the one
// place this differs from every other validate* function in this package. The
// empty prefix is a prefix of every id, which makes a row carrying it R7's
// catch-all — the construct R7 says costs no mechanism, and the answer an
// operator needs when enabling a cap denies everything unmatched. A reflexive
// "required field" guard here would delete that capability outright.
//
// The hierarchy lookup folds case exactly as Index does, so an operator who
// writes "NATO" is not refused for a rule that will match perfectly well. The
// row is stored verbatim regardless; see the migration's own comment on why
// nothing normalises it on the way in.
func validateResourceLabelRule(rule classification.Rule) error {
	levels, ok := classification.Levels[strings.ToLower(rule.Hierarchy)]
	if !ok {
		return fmt.Errorf("%w: unknown classification hierarchy %q (known: %s)",
			ErrInvalidRequest, rule.Hierarchy, strings.Join(knownHierarchies(), ", "))
	}
	if classification.Index(rule.Hierarchy, rule.Level) < 0 {
		return fmt.Errorf("%w: level %q is not a level of hierarchy %q (known: %s)",
			ErrInvalidRequest, rule.Level, rule.Hierarchy, strings.Join(levels, ", "))
	}
	return nil
}

// knownHierarchies lists Levels' keys in a stable order, so the error above
// names the same set every time rather than in Go's randomised map order — an
// operator comparing two failures should not have to wonder whether the list
// itself changed.
func knownHierarchies() []string {
	return slices.Sorted(maps.Keys(classification.Levels))
}

// CreateResourceLabelRule validates rule (validateResourceLabelRule) and, only
// if that succeeds, inserts it and audits its creation inside one transaction
// (N4) — the same validate-then-write-and-audit shape every other PAP-facing
// Create method in this package follows.
//
// A duplicate prefix within the tenant is ErrAlreadyExists, not a generic
// failure, so an HTTP caller answers 409 rather than 500. That collision is
// this table's UNIQUE (tenant_id, prefix) doing the job the migration explains
// at length: one prefix carrying two answers is a configuration the decision
// path cannot consume, and its only symptom would be silent denial under that
// prefix. Note what the key does NOT distinguish — a second rule on the same
// prefix in a DIFFERENT hierarchy collides exactly like an identical one,
// which is the whole point of narrowing the key from the triple.
func (s *Store) CreateResourceLabelRule(
	ctx context.Context, rule models.ResourceLabelRule, actor string, now time.Time,
) (models.ResourceLabelRule, error) {
	if err := validateResourceLabelRule(rule.Rule()); err != nil {
		return models.ResourceLabelRule{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.ResourceLabelRule{}, err
	}
	defer func() { _ = tx.Rollback() }()

	rule.TenantID = s.tenantID
	row := tx.QueryRowContext(ctx, insertResourceLabelRuleQuery,
		s.tenantID, rule.Prefix, rule.Hierarchy, rule.Level)
	if err := row.Scan(&rule.ID); err != nil {
		if isUniqueViolation(err) {
			return models.ResourceLabelRule{}, fmt.Errorf("%w: resource label rule for prefix %q", ErrAlreadyExists, rule.Prefix)
		}
		return models.ResourceLabelRule{}, fmt.Errorf("store: insert resource label rule %q: %w", rule.Prefix, err)
	}

	// Reason carries the whole row (ruleAuditReason, below, shared with the
	// update and delete paths) because it is the only field on audit.Entry that
	// fits: this write has no tool, no action, and no tier to repurpose the
	// decision-shaped columns for, unlike CreateTierOverride and
	// CreateToolCatalogEntry which each document their own repurposing.
	//
	// Recording the prefix here is not the thing "never log a resource id"
	// rules out. That constraint is about decision-time resource ids in process
	// logs that may be shipped elsewhere; this is operator-authored
	// configuration, written to a per-tenant, RLS-scoped table whose entire
	// purpose is to record what an operator changed. An audit row that could
	// not name which rule was created would not be an audit row.
	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeResourceLabelRuleCreated,
		Actor:         actor,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        ruleAuditReason(rule),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.ResourceLabelRule{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.ResourceLabelRule{}, fmt.Errorf("store: commit: %w", err)
	}
	return rule, nil
}

// ruleAuditReason renders a rule for audit_chain.reason. Quoted (%q) rather
// than bare specifically so the catch-all is legible — an empty prefix would
// otherwise vanish from the record, leaving the one rule that matches
// everything as the one rule the audit row cannot name. Shared by all three
// write paths so a create, an update and a delete describe the same rule the
// same way, which is what makes the three entries readable as a sequence.
//
// The id is included, and this table needs it where its siblings do not.
// Elsewhere in this package the audit reason is a NAME that survives editing (a
// policy name, a tool_or_verb), so the chain reads as a history of one row. Here
// the reason is the rule itself, and migrations/000019 calls editing the prefix
// "exactly the field an operator corrects when a rule is wrong" — which is the
// reason this table carries a surrogate key at all. Without the id, an update
// that moved a prefix is indistinguishable in the chain from two unrelated
// rules, and "what happened to THIS rule" becomes unanswerable from the one
// record designed to answer it.
func ruleAuditReason(rule models.ResourceLabelRule) string {
	return fmt.Sprintf("%q -> %s/%s (%s)", rule.Prefix, rule.Hierarchy, rule.Level, rule.ID)
}

// GetResourceLabelRule loads one resource_label_rules row by id. RLS scopes it
// to the tenant fixed at New; a row for another tenant, or no row at all, is
// ErrNotFound either way — the same indistinguishable-by-design guarantee every
// other Get method in this package gives (store.go's package doc).
func (s *Store) GetResourceLabelRule(ctx context.Context, id uuid.UUID) (models.ResourceLabelRule, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.ResourceLabelRule{}, err
	}
	defer func() { _ = tx.Rollback() }()

	rule, err := scanResourceLabelRule(tx.QueryRowContext(ctx, getResourceLabelRuleQuery, id.String()))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ResourceLabelRule{}, fmt.Errorf("%w: resource label rule %s", ErrNotFound, id)
		}
		return models.ResourceLabelRule{}, fmt.Errorf("store: get resource label rule %s: %w", id, err)
	}

	if err := tx.Commit(); err != nil {
		return models.ResourceLabelRule{}, fmt.Errorf("store: commit: %w", err)
	}
	return rule, nil
}

// scanResourceLabelRule scans one row (Get) or the current row of a *sql.Rows
// (List) into a models.ResourceLabelRule, sharing decode logic via rowScanner
// (store.go) exactly as scanFullTierOverride does for its own table.
//
// No validation here, deliberately, and the omission is the same one
// LoadResourceLabelRules makes: a stale read, an in-flight migration and a
// direct psql write each put rows in this table that
// validateResourceLabelRule never saw, and an operator whose list silently
// omitted them could not correct what they cannot see. Reading a rule back is
// how you FIND a bad one; refusing to read it would hide it.
func scanResourceLabelRule(row rowScanner) (models.ResourceLabelRule, error) {
	var r models.ResourceLabelRule
	if err := row.Scan(&r.ID, &r.TenantID, &r.Prefix, &r.Hierarchy, &r.Level); err != nil {
		return models.ResourceLabelRule{}, err
	}
	return r, nil
}

// ListResourceLabelRules loads every rule the tenant has, ids included — the
// operator's own view of the set, and the only place the handles
// UpdateResourceLabelRule and DeleteResourceLabelRule name come from. A tenant
// with none is an ordinary, empty result.
//
// It is also, unglamorously, the whole of an operator's pre-flight view before
// a delete: see DeleteResourceLabelRule's own doc comment for why that is where
// the blast-radius question is answered rather than in a confirmation gate.
func (s *Store) ListResourceLabelRules(ctx context.Context) ([]models.ResourceLabelRule, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, listResourceLabelRulesQuery)
	if err != nil {
		return nil, fmt.Errorf("store: list resource label rules: %w", err)
	}
	defer func() { _ = rows.Close() }()

	rules := make([]models.ResourceLabelRule, 0)
	for rows.Next() {
		r, err := scanResourceLabelRule(rows)
		if err != nil {
			return nil, fmt.Errorf("store: scan resource label rule row: %w", err)
		}
		rules = append(rules, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate resource label rule rows: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
	}
	return rules, nil
}

// UpdateResourceLabelRule validates rule through validateResourceLabelRule —
// THE SAME FUNCTION CreateResourceLabelRule calls, not a second copy of its
// rule — and, only if that succeeds, replaces the id row's three
// operator-owned columns and audits the change inside one transaction (N4).
//
// That shared call is the whole point of this method's existence being flagged
// in Task 2's report as a ranked concern. The semantic half of validity lives
// in Go rather than in a schema CHECK precisely because a CHECK enumerating
// the ten (hierarchy, level) pairs would be a second copy of
// pkg/classification.Levels with two silent drift directions
// (migrations/000019's own comment). A second copy of the same rule inside
// this package, reached only by the update path, would be that identical
// defect one layer up — and it would be worse, because the two copies would
// share a test suite that could not tell which one it had exercised.
//
// A PUT-shaped full replace: prefix, hierarchy and level may all change
// together, matching UpdatePolicy/UpdateAgent/UpdateTierOverride/
// UpdateToolCatalogEntry. Editing the prefix is not a corner case here, it is
// the ordinary correction — migrations/000019 names it as the reason this
// table carries a surrogate id at all.
//
// A prefix that collides with another rule's is ErrAlreadyExists, not a
// generic failure, for the reason CreateResourceLabelRule's own doc comment
// gives: UNIQUE (tenant_id, prefix) refuses one prefix carrying two answers,
// and an HTTP caller should see 409 rather than 500.
//
// now is an explicit parameter for the reason UpdateTierOverride's is: this
// table has no updated_at column whose RETURNING value the audit entry could
// reuse (migrations/000019 declines created_at/created_by too, and says why),
// so the clock read is unavoidable and is injected rather than called inline.
func (s *Store) UpdateResourceLabelRule(
	ctx context.Context, id uuid.UUID, rule models.ResourceLabelRule, actor string, now time.Time, mayLoosen bool,
) (models.ResourceLabelRule, error) {
	if err := validateResourceLabelRule(rule.Rule()); err != nil {
		return models.ResourceLabelRule{}, err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return models.ResourceLabelRule{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if !mayLoosen {
		old, err := scanResourceLabelRule(tx.QueryRowContext(ctx, getResourceLabelRuleForUpdateQuery, id.String()))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return models.ResourceLabelRule{}, fmt.Errorf("%w: resource label rule %s", ErrNotFound, id)
			}
			return models.ResourceLabelRule{}, fmt.Errorf("store: load resource label rule %s: %w", id, err)
		}
		if reason := labelRuleLoosens(old, rule); reason != "" {
			return models.ResourceLabelRule{}, fmt.Errorf("%w: %s", ErrAdminRequired, reason)
		}
	}

	row := tx.QueryRowContext(ctx, updateResourceLabelRuleQuery, rule.Prefix, rule.Hierarchy, rule.Level, id.String())
	if err := row.Scan(&rule.ID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return models.ResourceLabelRule{}, fmt.Errorf("%w: resource label rule %s", ErrNotFound, id)
		}
		if isUniqueViolation(err) {
			return models.ResourceLabelRule{}, fmt.Errorf("%w: resource label rule for prefix %q", ErrAlreadyExists, rule.Prefix)
		}
		return models.ResourceLabelRule{}, fmt.Errorf("store: update resource label rule %s: %w", id, err)
	}
	rule.TenantID = s.tenantID

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeResourceLabelRuleUpdated,
		Actor:         actor,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        ruleAuditReason(rule),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return models.ResourceLabelRule{}, err
	}

	if err := tx.Commit(); err != nil {
		return models.ResourceLabelRule{}, fmt.Errorf("store: commit: %w", err)
	}
	return rule, nil
}

// DeleteResourceLabelRule deletes the id row and audits the deletion inside one
// transaction, recording WHAT THE DELETE DID TO THE PREFIX in the audit entry's
// own reason.
//
// # Deleting a rule is not neutral, and this is what is done about it
//
// Every other Delete* in this package removes something PERMISSIVE: a policy,
// an agent, a raise-only tier override. Removing a resource label is the
// opposite. R2/R7 make an unlabelled resource DENY under any configured cap, so
// deleting a rule can turn allows into denials for everything beneath its
// prefix, and deleting the empty-prefix catch-all does it tenant-wide.
//
// The delete is NOT gated on a confirmation flag, and that is a decision
// rather than an omission:
//
//   - There is no "off" value for a rule. Every row that exists MATCHES
//     something, so removal is the only way to un-label a subtree
//     (migrations/000019 says exactly this, as the reason stratium_pap holds
//     DELETE on this table at all where it does not on tool_catalog). A gate
//     would sit in front of the one sanctioned operation, not in front of a
//     mistake.
//   - No sibling DELETE route in this system takes one, and inventing a
//     query-parameter handshake for this table alone would put the surface an
//     operator learns out of step with itself.
//   - The window is bounded by the epoch, not by hope: migrations/000019
//     attaches bump_tenant_epoch() FOR EACH ROW on DELETE, so a PEP holding a
//     cached ALLOW under this prefix is made to re-ask rather than serving a
//     decision this delete invalidated.
//
// What replaces the gate is a RECORD, computed rather than assumed. After the
// DELETE, inside the same transaction, the surviving rules are read back and
// the deleted prefix is resolved against them with the same
// pkg/classification.Resolve the decision path uses — never a second matcher
// written for this report, which would be free to disagree about
// case-sensitivity, ties and the catch-all. The audit entry then names either
// the rule that now covers the prefix or the fact that none does.
//
// The claim that report makes is deliberately narrow, because the honest one
// is: it answers "what does THIS PREFIX resolve to now," not "what does
// everything beneath it resolve to now." A rule at a LONGER prefix
// (`/data/public/` beneath a deleted `/data/`) still covers its own subtree, so
// "no remaining rule matches this prefix" does not mean the whole subtree went
// dark. Saying more than that would put a false claim in the operator's record,
// which is the mistake pkg/classification.Match's own three separate fields
// exist to avoid.
//
// The operator's PRE-flight view is ListResourceLabelRules: the rule set is
// small, operator-authored, and returned whole by one GET, so "what else covers
// this prefix" is answerable before the delete by looking. This method's job is
// to make the answer durable afterwards, in the tamper-evident chain, where a
// one-time console warning would not be.
//
// now is a parameter for the reason DeleteTierOverride's is: a DELETE leaves no
// row behind whose own timestamp the audit entry could reuse via RETURNING.
func (s *Store) DeleteResourceLabelRule(ctx context.Context, id uuid.UUID, actor string, now time.Time) error {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var deleted models.ResourceLabelRule
	if err := tx.QueryRowContext(ctx, deleteResourceLabelRuleQuery, id.String()).
		Scan(&deleted.Prefix, &deleted.Hierarchy, &deleted.Level); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: resource label rule %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: delete resource label rule %s: %w", id, err)
	}

	// The id the caller named, not one read back: deleteResourceLabelRuleQuery
	// returns the three operator-owned columns and deliberately not the key it
	// was just given, so without this the reason would carry the zero UUID —
	// which reads as an id rather than as an absence, and is worse than omitting
	// it. RETURNING id would work equally well and cost a column; this costs a
	// line and cannot disagree with the WHERE clause.
	deleted.ID = id

	remaining, err := queryResourceLabelRulesTx(ctx, tx)
	if err != nil {
		return err
	}

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    now,
		EventType:     eventTypeResourceLabelRuleDeleted,
		Actor:         actor,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        ruleAuditReason(deleted) + "; " + prefixAftermath(remaining, deleted.Prefix, deleted.Hierarchy),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// prefixAftermath says what prefix resolves to against remaining — the blast
// radius of the delete that produced that set, in the words an operator reading
// the audit chain needs.
//
// Resolve, not a hand-rolled scan, so this report and the decision agree by
// construction: the "nothing matches" answer here is the same absence that
// makes CheckCap deny, and an ambiguous or lowered match is folded exactly as
// the decision path folds it.
//
// Both branches are about the prefix ITSELF, and the wording says so rather
// than generalising to the subtree — see DeleteResourceLabelRule's own doc
// comment for why that narrowness is the point.
//
// deletedHierarchy is the removed rule's, and is only ever compared against the
// survivor's: it is what turns "a different hierarchy is in this string
// somewhere" into a sentence naming the consequence.
func prefixAftermath(remaining []classification.Rule, prefix, deletedHierarchy string) string {
	match, ok := classification.Resolve(remaining, prefix)
	if !ok {
		return fmt.Sprintf("no remaining rule labels %q; ids under it that no longer-prefixed rule covers "+
			"are now unlabelled and deny under any configured cap", prefix)
	}
	aftermath := fmt.Sprintf("%q now resolves to %s/%s via %q",
		prefix, match.Rule.Hierarchy, match.Rule.Level, match.Rule.Prefix)
	// A survivor in a DIFFERENT hierarchy is legible from the string above —
	// both hierarchies are in it — but it is not the same event as a relabelling
	// within one, and it is the more dangerous of the two. CheckCap consults one
	// hierarchy per resource, so a cap in the DELETED rule's hierarchy now says
	// nothing at all about ids under this prefix: they do not resolve lower, they
	// leave the ordering that cap was written against. That is the hazard
	// classification.Match.SwitchedHierarchyFrom exists to surface on the
	// decision path, named here for the same reason and reported separately for
	// the same reason — calling it a lowering would assert an ordering between
	// two hierarchies that does not exist.
	if !strings.EqualFold(deletedHierarchy, match.Rule.Hierarchy) {
		aftermath += fmt.Sprintf("; that is a different hierarchy from the deleted rule's %s, so a %s cap no "+
			"longer constrains anything under this prefix", deletedHierarchy, deletedHierarchy)
	}
	return aftermath
}
