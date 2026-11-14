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

	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/classification"
	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
)

// eventTypeAgentCapsSet and eventTypeAgentCapsCleared are audit_chain.event_type
// values for this file's two write operations, kept here rather than folded
// into agent.go's own three-constant block (eventTypeAgentCreated et al.):
// every other domain file in this package (catalog.go, resource_label.go,
// tier_override.go, delegation.go) already declares its own event type
// constants next to the methods that use them, not centralized in agent.go,
// and these two are this file's writes, not agent.go's.
const (
	eventTypeAgentCapsSet     = "agent_caps_set"
	eventTypeAgentCapsCleared = "agent_caps_cleared"
)

// ErrNoCatchAllRule is returned when a cap names a hierarchy that has no
// empty-prefix ("") label rule. It wraps ErrConflict, not ErrInvalidRequest:
// the request is well formed, and what is wrong is the tenant's current state
// (respond.go's writeStoreError draws exactly that line — see
// cmd/stratium-pap/respond.go:88-98). Co-located here rather than in store.go
// for the same reason ErrAllowedToolsRequired lives in agent.go, not
// store.go: it is this file's own error, produced by no other.
var ErrNoCatchAllRule = fmt.Errorf("%w: no catch-all label rule", ErrConflict)

// ErrClassificationCapsRequired is returned when a PUT would leave caps empty
// (nil, an absent/misspelled classification_caps key, or an explicit {}).
// Wraps ErrInvalidRequest, not ErrConflict: unlike ErrNoCatchAllRule this is
// not about the tenant's current state, it is a structurally malformed
// request, the same category ErrAllowedToolsRequired (agent.go) is for the
// identical hazard on AllowedTools. An empty caps map is enforcement OFF
// (classification.CheckCap ALLOWs whenever len(caps)==0), and the whole
// justification for classification-caps being a sub-resource, not a field on
// PUT /v1/agents/{id}, is that turning enforcement off cannot happen by
// omission -- only DELETE does that. Enforced in SetAgentClassificationCaps
// itself (below), not only in cmd/stratium-pap's handler, so the store
// refuses this for every caller, not just the one route that exists today.
var ErrClassificationCapsRequired = fmt.Errorf(
	"%w: classification_caps must be a non-empty map; "+
		"DELETE /v1/agents/{id}/classification-caps to turn enforcement off instead",
	ErrInvalidRequest)

// validateClassificationCaps rejects anything classification.CheckCap could not
// act on. Levels come from classification.Levels rather than a local list so
// there is one definition of what a hierarchy contains. Hierarchy lookup folds
// case exactly as validateResourceLabelRule's own does (resource_label.go),
// so an operator who writes "NATO" is not refused for a cap that will match
// perfectly well once stored -- classification.Index folds the same way.
//
// It also rejects two keys that fold to the SAME hierarchy under different
// casing, e.g. {"nato":"SECRET","NATO":"CONFIDENTIAL"}: each key alone
// passes the checks above, but classification.lookupCap (pkg/classification/
// classification.go) scans case-insensitively and treats two differently-
// cased keys with different values as ambiguous, and CheckCap DENIES
// ambiguous caps unconditionally. Accepting that combination here would make
// this function's own doc comment a lie -- it claims to reject anything
// CheckCap could not act on, and an unconditional deny is exactly that.
func validateClassificationCaps(caps map[string]string) error {
	seen := make(map[string]string, len(caps)) // folded hierarchy -> first key seen with that fold
	for hierarchy, level := range caps {
		folded := strings.ToLower(hierarchy)
		levels, ok := classification.Levels[folded]
		if !ok {
			return fmt.Errorf("%w: unknown classification hierarchy %q (known: %s)",
				ErrInvalidRequest, hierarchy, strings.Join(knownHierarchies(), ", "))
		}
		if classification.Index(hierarchy, level) < 0 {
			return fmt.Errorf("%w: %q is not a level in hierarchy %q (levels: %s)",
				ErrInvalidRequest, level, hierarchy, strings.Join(levels, ", "))
		}
		if prior, dup := seen[folded]; dup {
			return fmt.Errorf(
				"%w: %q and %q both name hierarchy %q under different casing; "+
					"classification.CheckCap treats that as ambiguous and denies -- use one key per hierarchy",
				ErrInvalidRequest, prior, hierarchy, folded)
		}
		seen[folded] = hierarchy
	}
	return nil
}

// normalizeClassificationCaps lowercases every hierarchy key. Called only
// after validateClassificationCaps has already rejected case-duplicate keys
// (above), so two distinct caller keys can never collide and silently drop
// one here. Persisting the lowercase form -- not whatever casing the caller
// sent -- is what keeps a stored cap's key comparing equal, by plain map
// lookup, to catchAllLevels' own lowercase-folded keys (that function's own
// doc comment): without this, a cap keyed "NATO" against a rule stored as
// "nato" would find no catch-all, and SetAgentClassificationCaps would 409 a
// request that classification.CheckCap (which folds case internally) would
// actually have enforced correctly.
func normalizeClassificationCaps(caps map[string]string) map[string]string {
	out := make(map[string]string, len(caps))
	for hierarchy, level := range caps {
		out[strings.ToLower(hierarchy)] = level
	}
	return out
}

// sortedKeys returns caps' keys in sorted order. Go's map iteration order is
// randomised; without this, which uncovered hierarchy SetAgentClassificationCaps
// names first in ErrNoCatchAllRule (below) would vary run to run for a caller
// with more than one, turning a deterministic refusal into a flaky-looking one.
func sortedKeys(caps map[string]string) []string {
	keys := make([]string, 0, len(caps))
	for k := range caps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// renderCaps is the audit entry's Reason for a caps write: a compact,
// deterministic (sorted) rendering, so two writes of the identical caps
// produce byte-identical audit text and an operator reading the chain does
// not need to parse JSON to see what changed. {} (ClearAgentClassificationCaps,
// or an explicitly empty Set) renders as the literal empty-braces form rather
// than an empty string, so the reason column is never blank.
func renderCaps(caps map[string]string) string {
	if len(caps) == 0 {
		return "classification_caps={}"
	}
	parts := make([]string, 0, len(caps))
	for _, h := range sortedKeys(caps) {
		parts = append(parts, fmt.Sprintf("%s=%s", h, caps[h]))
	}
	return "classification_caps={" + strings.Join(parts, ", ") + "}"
}

// allowUncoveredNote is appended to renderCaps' output when the write used
// ?allow_uncovered=true -- the spec's Risks section requires that override to
// "appear in the audit entry" because it is this call's most dangerous path
// (it bypasses the guard that otherwise refuses a cap with no catch-all rule,
// which denies every resource no rule matches). Without this, the audited
// Reason for an overridden write and a normally-guarded one are byte-
// identical, and an auditor reading the chain cannot tell which happened.
func allowUncoveredNote(allowUncovered bool) string {
	if !allowUncovered {
		return ""
	}
	return " (allow_uncovered=true)"
}

// SetAgentClassificationCaps replaces the agent's caps and returns the view
// callers need to understand what they just did. caps must be non-empty:
// this is PUT, and the entire justification for classification-caps being a
// sub-resource rather than a field on PUT /v1/agents/{id} is that enforcement
// cannot be turned off by omission -- only DELETE
// (ClearAgentClassificationCaps) does that. A nil map, an absent/misspelled
// classification_caps key (both decode to nil), and an explicit {} are all
// refused with ErrClassificationCapsRequired before anything else runs, no
// exception for allowUncovered -- that flag only ever widens what a
// non-empty cap is allowed to do, never substitutes for one.
//
// It also refuses a cap for a hierarchy with no catch-all rule unless
// allowUncovered: with a cap set and no rule matching, classification.CheckCap
// denies every resource whose label cannot be resolved, so the un-guarded
// version of this call is a foot-gun that looks like a success.
//
// now is not forwarded to the write (see updateAgentCapsQuery's own doc
// comment) -- kept as a parameter only so this and ClearAgentClassificationCaps
// present the same shape to their HTTP-routes caller.
func (s *Store) SetAgentClassificationCaps(
	ctx context.Context, id uuid.UUID, caps map[string]string,
	allowUncovered bool, actor string, now time.Time,
) (models.AgentCapsView, error) {
	if len(caps) == 0 {
		return models.AgentCapsView{}, ErrClassificationCapsRequired
	}
	if err := validateClassificationCaps(caps); err != nil {
		return models.AgentCapsView{}, err
	}
	caps = normalizeClassificationCaps(caps)

	catchAll, err := s.catchAllLevels(ctx)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	if !allowUncovered {
		for _, hierarchy := range sortedKeys(caps) {
			if catchAll[hierarchy] == nil {
				// resource_label_rules is UNIQUE (tenant_id, prefix), not
				// (tenant_id, prefix, hierarchy) -- migrations/000019's own
				// comment records why. At most one prefix:"" rule can exist
				// per tenant, in ONE hierarchy, so a cap naming more than one
				// hierarchy can never have a catch-all satisfied for all of
				// them at once: this branch is the ONLY reachable outcome for
				// a multi-hierarchy cap without the override, not merely one
				// case among several, and the message says so rather than
				// leaving an operator to rediscover it by trial.
				multiHierarchyNote := ""
				if len(caps) > 1 {
					multiHierarchyNote = "; resource_label_rules allows only ONE catch-all " +
						"(prefix \"\") rule per tenant, in one hierarchy, so a cap naming " +
						"more than one hierarchy can never satisfy this guard for all of " +
						"them -- ?allow_uncovered=true is the only route"
				}
				return models.AgentCapsView{}, fmt.Errorf(
					"%w for hierarchy %q; a cap without one denies every resource no rule matches. "+
						"POST /v1/resource-label-rules with prefix \"\" first, or pass ?allow_uncovered=true%s",
					ErrNoCatchAllRule, hierarchy, multiHierarchyNote)
			}
		}
	}

	if err := s.writeAgentCaps(ctx, id, caps, allowUncovered, actor); err != nil {
		return models.AgentCapsView{}, err
	}
	return s.agentCapsView(ctx, id, caps, catchAll)
}

// ClearAgentClassificationCaps sets the map back to {}, which turns
// classification enforcement OFF for delegations issued from now on. It is a
// distinct verb precisely so that turning enforcement off cannot happen by
// omitting a field from a request body.
//
// now is accepted for signature symmetry with SetAgentClassificationCaps
// (both take the request's timestamp as a parameter, the shape a later
// HTTP-routes task calls with) but is not forwarded to writeAgentCaps: see
// updateAgentCapsQuery's own doc comment for why the write uses Postgres's
// clock, not this one.
func (s *Store) ClearAgentClassificationCaps(ctx context.Context, id uuid.UUID, actor string, now time.Time) error {
	return s.writeAgentCaps(ctx, id, map[string]string{}, false, actor)
}

// updateAgentCapsQuery leaves updated_at to Postgres (NOW()), returned via
// RETURNING -- the identical reasoning updateAgentQuery's own doc comment
// (agent.go) gives: the row's own persisted clock is authoritative, and
// that RETURNING value becomes the audit entry's OccurredAt below, so there
// is exactly one clock in play for this column, not two. Binding a caller-
// supplied now here instead (as an earlier version of this query did) put
// this column's writer out of step with UpdateAgent's own -- one used NOW(),
// the other a Go-side timestamp that could skew from it -- for no benefit,
// since RETURNING already hands the authoritative value back.
const updateAgentCapsQuery = `UPDATE agents SET classification_caps = $2, updated_at = NOW() WHERE id = $1 RETURNING updated_at`

// loadAgentCapsForUpdateQuery reads the caps this write is about to replace,
// and locks the row until the transaction ends. See its resource-constraints
// twin, loadAgentConstraintsForUpdateQuery (agent_constraints.go), for the
// full reasoning -- the lock is what keeps the containment verdict
// (containment_audit.go) from being computed against a baseline some
// concurrent writer has already replaced.
const loadAgentCapsForUpdateQuery = `SELECT classification_caps FROM agents WHERE id = $1 FOR UPDATE`

// writeAgentCaps is SetAgentClassificationCaps and ClearAgentClassificationCaps's
// shared write path: replace classification_caps and audit the change in the
// SAME transaction (N4 -- see CreateAgent's own doc comment, agent.go), inside
// one beginTenantTx.
//
// The audit event type is derived from caps itself, len(caps) == 0 means
// eventTypeAgentCapsCleared, never eventTypeAgentCapsSet -- regardless of
// which exported method got here. SetAgentClassificationCaps can no longer
// reach this function with an empty caps map (it refuses one itself, before
// ever calling here -- ErrClassificationCapsRequired), so today the only
// caller that can produce eventTypeAgentCapsCleared is
// ClearAgentClassificationCaps' own explicit {} -- kept as a derivation
// rather than a caller-supplied "eventType" parameter anyway, so a future
// caller cannot get this wrong by passing the wrong constant.
//
// allowUncovered is not part of the event type: it only ever affects the
// Reason text (allowUncoveredNote, below), never which event fired.
func (s *Store) writeAgentCaps(ctx context.Context, id uuid.UUID, caps map[string]string, allowUncovered bool, actor string) error {
	eventType := eventTypeAgentCapsSet
	if len(caps) == 0 {
		eventType = eventTypeAgentCapsCleared
	}

	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	capsJSON, err := json.Marshal(caps)
	if err != nil {
		return fmt.Errorf("store: marshal classification_caps: %w", err)
	}

	// Captured INSIDE this transaction and BEFORE the UPDATE below, under the
	// row lock, so the comparison cannot race another writer.
	var beforeJSON []byte
	if err := tx.QueryRowContext(ctx, loadAgentCapsForUpdateQuery, id.String()).Scan(&beforeJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: load agent %s classification caps: %w", id, err)
	}
	var stored map[string]string
	if err := json.Unmarshal(beforeJSON, &stored); err != nil {
		return fmt.Errorf("store: unmarshal classification_caps: %w", err)
	}
	// Folded for the reason GetAgentClassificationCaps folds the same column:
	// caps written by THIS API are already lowercase, but a row written some
	// other way can carry any casing, and `caps` on the other side of the
	// comparison is always normalized. Without the fold a hierarchy stored as
	// "NATO" would look absent from the new caps, and every write to that row
	// would be recorded as dropping it.
	before := normalizeClassificationCaps(stored)

	var updatedAt time.Time
	row := tx.QueryRowContext(ctx, updateAgentCapsQuery, id.String(), capsJSON)
	if err := row.Scan(&updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return fmt.Errorf("store: update agent %s classification caps: %w", id, err)
	}

	entry := audit.Entry{
		TenantID:      s.tenantID,
		OccurredAt:    updatedAt,
		EventType:     eventType,
		Actor:         actor,
		AgentID:       &id,
		Decision:      "ALLOW",
		DeniedAtDepth: noDenial,
		Reason:        renderCaps(caps) + allowUncoveredNote(allowUncovered),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
		return err
	}

	if err := s.recordWideningTx(ctx, tx, id, actor, updatedAt,
		permset.Set{ClassificationCaps: before},
		permset.Set{ClassificationCaps: caps}); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// GetAgentClassificationCaps returns the same advisory view
// SetAgentClassificationCaps returns, without changing anything -- for an
// operator who wants to see the consequences (CatchAll, UnsatisfiableTools,
// LiveDelegations) of the agent's CURRENT caps before deciding whether to act,
// not only after.
//
// The stored row is folded through normalizeClassificationCaps the same way
// Set folds its input before persisting: agent.ClassificationCaps is
// whatever casing was last WRITTEN, which for every row this API itself
// wrote is already lowercase, but a row written some other way (direct SQL,
// a row predating this normalization) can carry any casing. catchAllLevels'
// own keys are always lowercase (that function's own doc comment), so
// without this fold a hierarchy stored as "NATO" would look up CatchAll
// under the wrong case and report CatchAll["NATO"] = nil -- a false
// "everything under nato denies" reading of a cap that in fact resolves
// fine. Folding here keeps GET and PUT reporting identically for the same
// underlying row.
func (s *Store) GetAgentClassificationCaps(ctx context.Context, id uuid.UUID) (models.AgentCapsView, error) {
	agent, err := s.GetAgent(ctx, id)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	caps := normalizeClassificationCaps(agent.ClassificationCaps)
	catchAll, err := s.catchAllLevels(ctx)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	return s.agentCapsView(ctx, id, caps, catchAll)
}

// unsatisfiableTools returns the tools that can never satisfy ANY
// classification cap, because they produce no resource for
// classification.CheckCap to label at all -- not "denied by THIS cap,"
// denied by any cap whatsoever, the instant one is set. Two distinct causes
// produce that same no-resource outcome, and this function reports both:
//
//   - a catalog row with no resource_field (the tool is known, but declares
//     no single resource-shaped argument), and
//   - for a RESTRICTED agent (len(allowedTools) > 0) only, a tool in
//     allowedTools with NO catalog row at all -- equally resource-less at
//     decision time, and, because allowedTools is a finite, known list,
//     enumerable here the same way the first case is.
//
// An UNRESTRICTED agent's (allowedTools == []) uncatalogued tools are NOT
// included: unlike a restricted allowlist, "every tool the catalog does not
// yet know about" has no finite enumeration to scan, so this function can
// only warn about the catalog rows it can see. That is a real, permanent gap
// in this advisory for unrestricted agents, not an oversight -- callers must
// not read an unrestricted agent's empty-looking result here as "every tool
// is satisfiable."
//
// allowedTools == [] means EVERY tool, not none: store.ErrAllowedToolsRequired
// says so verbatim (agent.go), and internal/authz/agent.go's allowlist check
// applies only when len(AllowedTools) > 0. So an empty slice here must WIDEN
// the catalog-row check to the whole catalog, never narrow it to nothing --
// narrowing would silence this warning for exactly the agents with the
// widest reach, the agents a warning about unsatisfiable tools matters most
// for.
func unsatisfiableTools(allowedTools []string, catalog []models.ToolCatalogEntry) []string {
	unrestricted := len(allowedTools) == 0
	held := make(map[string]bool, len(allowedTools))
	for _, t := range allowedTools {
		held[t] = true
	}

	out := map[string]bool{}
	inCatalog := make(map[string]bool, len(catalog))
	for _, e := range catalog {
		inCatalog[e.ToolName] = true
		// A resource_field yields an id directly; a command_field yields one
		// per path the command names (internal/authz.ShellResourceIDs, added
		// 2026-08-28). Either shape can produce something to label, so
		// neither is unsatisfiable. Before that change this tested
		// ResourceField alone, which reported Bash as unable to satisfy any
		// cap -- true then, false now, and read by operators as guidance
		// (docs/default-posture.md §4).
		if e.ResourceField != nil || e.CommandField != nil {
			continue
		}
		if unrestricted || held[e.ToolName] {
			out[e.ToolName] = true
		}
	}
	if !unrestricted {
		for t := range held {
			if !inCatalog[t] {
				out[t] = true
			}
		}
	}

	result := make([]string, 0, len(out))
	for t := range out {
		result = append(result, t)
	}
	sort.Strings(result)
	return result
}

// catchAllLevels maps each hierarchy to the level its empty-prefix rule
// resolves to, or leaves it absent where no such rule exists. A prefix of ""
// matches every resource id (R7's catch-all -- see ResourceLabelRule.Prefix's
// own doc comment, pkg/models/resource_label.go), which is exactly the rule
// SetAgentClassificationCaps' catch-all guard is checking for.
//
// Keys are folded to lowercase: rule hierarchies are stored VERBATIM
// (validateResourceLabelRule's own doc comment, resource_label.go, explains
// why nothing normalises them on the way in), but caps are normalized to
// lowercase before this map is ever consulted (normalizeClassificationCaps).
// Without the same fold here, a rule stored as "NATO" would produce a key
// this map's caller -- keyed "nato" -- can never look up: a spurious 409 for
// SetAgentClassificationCaps, and a misleading nil in AgentCapsView.CatchAll
// for a hierarchy that in fact has a catch-all rule.
func (s *Store) catchAllLevels(ctx context.Context) (map[string]*string, error) {
	rules, err := s.ListResourceLabelRules(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]*string{}
	for _, r := range rules {
		if r.Prefix == "" {
			level := r.Level
			out[strings.ToLower(r.Hierarchy)] = &level
		}
	}
	return out, nil
}

// countLiveDelegationsQuery counts delegations neither revoked nor expired --
// migrations/000001_baseline's own idx_delegations_active partial index on
// (tenant_id, expires_at) WHERE revoked = false covers exactly this
// predicate, so RLS's tenant_id rewrite plus this WHERE clause is an index
// lookup, not a scan. now() is Postgres's clock, not a caller-supplied
// time.Time: GetAgentClassificationCaps takes no `now` parameter (it changes
// nothing, so it stamps nothing), and using the database's own clock for
// both callers of agentCapsView keeps "live" meaning the same instant
// regardless of which one asks.
const countLiveDelegationsQuery = `SELECT COUNT(*) FROM delegations WHERE agent_id = $1 AND revoked = false AND expires_at > now()`

// countLiveDelegations answers agentCapsView's LiveDelegations field: the
// delegations THIS cap change does not affect (Delegation.ClassificationCaps
// is copied at issuance and never re-read from the agent row), which is why
// AgentCapsView's own doc comment calls the count a warning, not a
// confirmation.
func (s *Store) countLiveDelegations(ctx context.Context, agentID uuid.UUID) (int, error) {
	tx, err := s.beginTenantTx(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()

	var count int
	if err := tx.QueryRowContext(ctx, countLiveDelegationsQuery, agentID.String()).Scan(&count); err != nil {
		return 0, fmt.Errorf("store: count live delegations for agent %s: %w", agentID, err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return count, nil
}

// agentCapsView assembles the advisory response every classification-caps
// write (and read) returns. It loads the agent fresh (for AllowedTools --
// unsatisfiableTools needs the CURRENT allowlist, not whatever the caller of
// SetAgentClassificationCaps happened to have in hand), the tool catalog, and
// the live-delegation count, then builds the view around the caps and
// catchAll the caller already has (Set's just-validated new caps and the
// catchAll it already computed to gate them; Get's caps read straight off the
// agent row).
//
// CatchAll is restricted to the hierarchies actually named in caps, not the
// tenant's whole label-rule configuration: this response describes what THIS
// cap does, not an unrelated audit of every hierarchy the tenant has ever
// configured a rule for.
func (s *Store) agentCapsView(
	ctx context.Context, id uuid.UUID, caps map[string]string, catchAll map[string]*string,
) (models.AgentCapsView, error) {
	agent, err := s.GetAgent(ctx, id)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	catalog, err := s.ListToolCatalogEntries(ctx)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	liveDelegations, err := s.countLiveDelegations(ctx, id)
	if err != nil {
		return models.AgentCapsView{}, err
	}

	restrictedCatchAll := make(map[string]*string, len(caps))
	for h := range caps {
		restrictedCatchAll[h] = catchAll[h]
	}

	return models.AgentCapsView{
		AgentID:            id,
		ClassificationCaps: caps,
		CatchAll:           restrictedCatchAll,
		UnsatisfiableTools: unsatisfiableTools(agent.AllowedTools, catalog),
		LiveDelegations:    liveDelegations,
		Applies:            "at next issuance",
	}, nil
}
