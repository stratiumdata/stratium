package store

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"stratium/pkg/audit"
	"stratium/pkg/classification"
)

// eventTypeResourceLabelRuleCreated is audit_chain.event_type for a write to
// resource_label_rules (N4) — the same constant shape policy.go, agent.go,
// tier_override.go and catalog.go each declare for their own tables.
const eventTypeResourceLabelRuleCreated = "resource_label_rule_created"

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
// It does NOT stabilise which of two same-prefix rules Resolve reports. Two
// such rules disagree (a prefix carrying two answers), and Resolve refuses
// ambiguity rather than picking by position — so there is no value here for an
// order to stabilise. Where casing alone differs, this clause does now settle
// it, but that is a side effect of ordering on the columns, not the reason for
// it.
const loadResourceLabelRulesQuery = `SELECT prefix, hierarchy, level ` +
	`FROM resource_label_rules ORDER BY prefix, hierarchy, level`

// insertResourceLabelRuleQuery omits id, letting the schema's own
// uuid_generate_v4() DEFAULT generate it: nothing here needs the value back,
// so there is no RETURNING clause either — see insertPolicyQuery's own doc
// comment (policy.go) for the general form of that choice.
const insertResourceLabelRuleQuery = `INSERT INTO resource_label_rules (tenant_id, prefix, hierarchy, level) ` +
	`VALUES ($1,$2,$3,$4)`

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

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit: %w", err)
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
func (s *Store) CreateResourceLabelRule(ctx context.Context, rule classification.Rule, actor string, now time.Time) error {
	if err := validateResourceLabelRule(rule); err != nil {
		return err
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, insertResourceLabelRuleQuery,
		s.tenantID, rule.Prefix, rule.Hierarchy, rule.Level); err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: resource label rule for prefix %q", ErrAlreadyExists, rule.Prefix)
		}
		return fmt.Errorf("store: insert resource label rule %q: %w", rule.Prefix, err)
	}

	// Reason carries the whole row, quoted, because it is the only field on
	// audit.Entry that fits: this write has no tool, no action, and no tier to
	// repurpose the decision-shaped columns for, unlike CreateTierOverride and
	// CreateToolCatalogEntry which each document their own repurposing. Quoted
	// (%q) rather than bare specifically so the catch-all is legible — an empty
	// prefix would otherwise vanish from the record, leaving the one rule that
	// matches everything as the one rule the audit row cannot name.
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
		Reason:        fmt.Sprintf("%q -> %s/%s", rule.Prefix, rule.Hierarchy, rule.Level),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}
