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

	"stratium/pkg/audit"
	"stratium/pkg/classification"
	"stratium/pkg/models"
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

// SetAgentClassificationCaps replaces the agent's caps and returns the view
// callers need to understand what they just did. It refuses a cap for a
// hierarchy with no catch-all rule unless allowUncovered: with a cap set and no
// rule matching, classification.CheckCap denies every resource whose label
// cannot be resolved, so the un-guarded version of this call is a foot-gun that
// looks like a success.
//
// now is not forwarded to the write (see updateAgentCapsQuery's own doc
// comment) -- kept as a parameter only so this and ClearAgentClassificationCaps
// present the same shape to their HTTP-routes caller.
func (s *Store) SetAgentClassificationCaps(
	ctx context.Context, id uuid.UUID, caps map[string]string,
	allowUncovered bool, actor string, now time.Time,
) (models.AgentCapsView, error) {
	if caps == nil {
		caps = map[string]string{}
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
				return models.AgentCapsView{}, fmt.Errorf(
					"%w for hierarchy %q; a cap without one denies every resource no rule matches. "+
						"POST /v1/resource-label-rules with prefix \"\" first, or pass ?allow_uncovered=true",
					ErrNoCatchAllRule, hierarchy)
			}
		}
	}

	if err := s.writeAgentCaps(ctx, id, caps, actor); err != nil {
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
	return s.writeAgentCaps(ctx, id, map[string]string{}, actor)
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

// writeAgentCaps is SetAgentClassificationCaps and ClearAgentClassificationCaps's
// shared write path: replace classification_caps and audit the change in the
// SAME transaction (N4 -- see CreateAgent's own doc comment, agent.go), inside
// one beginTenantTx.
//
// The audit event type is derived from caps itself, len(caps) == 0 means
// eventTypeAgentCapsCleared, never eventTypeAgentCapsSet -- regardless of
// which exported method got here. SetAgentClassificationCaps called with nil
// or {} is a second off-switch (classification.CheckCap allows everything
// once len(caps) == 0, the same as ClearAgentClassificationCaps' own
// explicit {}), and an auditor grepping the chain for agent_caps_cleared to
// find every moment enforcement went off must not miss the ones that came
// through Set. There is deliberately no separate "eventType" parameter for a
// caller to get this wrong through.
func (s *Store) writeAgentCaps(ctx context.Context, id uuid.UUID, caps map[string]string, actor string) error {
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
		Reason:        renderCaps(caps),
	}
	if err := s.appendAuditTx(ctx, tx, entry); err != nil {
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
func (s *Store) GetAgentClassificationCaps(ctx context.Context, id uuid.UUID) (models.AgentCapsView, error) {
	agent, err := s.GetAgent(ctx, id)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	catchAll, err := s.catchAllLevels(ctx)
	if err != nil {
		return models.AgentCapsView{}, err
	}
	return s.agentCapsView(ctx, id, agent.ClassificationCaps, catchAll)
}

// unsatisfiableTools returns the catalog entries that can never satisfy ANY
// classification cap, because they declare no resource_field and so produce
// no resource for classification.CheckCap to label at all -- not "denied by
// THIS cap," denied by any cap whatsoever, the instant one is set.
//
// allowedTools == [] means EVERY tool, not none: store.ErrAllowedToolsRequired
// says so verbatim (agent.go), and internal/authz/agent.go's allowlist check
// applies only when len(AllowedTools) > 0. So an empty slice here must WIDEN
// the check to the whole catalog, never narrow it to nothing -- narrowing
// would silence this warning for exactly the agents with the widest reach,
// the agents a warning about unsatisfiable tools matters most for.
func unsatisfiableTools(allowedTools []string, catalog []models.ToolCatalogEntry) []string {
	unrestricted := len(allowedTools) == 0
	held := make(map[string]bool, len(allowedTools))
	for _, t := range allowedTools {
		held[t] = true
	}

	var out []string
	for _, e := range catalog {
		if e.ResourceField != nil {
			continue
		}
		if unrestricted || held[e.ToolName] {
			out = append(out, e.ToolName)
		}
	}
	sort.Strings(out)
	return out
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
