// Package authz is the single place a Stratium authorization decision is
// computed. It is pure: no database handles, no network clients, no ambient
// clock. Callers load the data and pass it in; authz decides.
//
// Every enforcement surface — gRPC proxy, MCP, hooks, Envoy ext-authz —
// reaches this code through the PDP. Nothing else may compute a decision.
// Three parallel implementations drifting apart is the specific failure this
// package exists to prevent.
//
// TierTable.Catalog (tier.go) is seeded by DefaultCatalog (catalog.go) with
// tool names — "Read", "Write", "WebFetch" — that are Claude Code's names,
// not a framework-agnostic vocabulary, even though this package's stated job
// is to serve any agent framework. That mismatch is a deliberate, temporary
// trade, not an oversight: a catalog nobody populates leaves the
// tool-input-has-no-verb defect exactly where it was (see DeriveTier's and
// BuiltinTier's doc comments), and the failure mode of shipping the trade is
// silent rather than loud — a tool name this catalog does not recognize
// simply falls through to BuiltinTier or the tenant's UnknownTier floor,
// same as before the catalog existed, never an error. The eventual home for
// this table is a database-backed, per-tenant catalog; DefaultCatalog is the
// seed it starts from, not the end state.
package authz

import (
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/pkg/models"
)

// Effect is the outcome of a decision, or of one leg of it.
type Effect int

const (
	// EffectDeny is the zero value deliberately: a leg that is never evaluated
	// must deny rather than silently permit. Do not reorder these.
	EffectDeny Effect = iota
	EffectAllow
	EffectEscalate
)

func (e Effect) String() string {
	switch e {
	case EffectAllow:
		return "ALLOW"
	case EffectEscalate:
		return "ESCALATE"
	default:
		return "DENY"
	}
}

// LegResult is one leg's contribution to the compound decision.
type LegResult struct {
	Effect Effect
	Reason string
}

// PolicyVerdict is one policy's answer about the principal. It is plain data:
// the engines produce it, authz consumes it, and no engine dependency enters
// this package.
type PolicyVerdict struct {
	Effect Effect
	Reason string

	// Source names the engine or grant model — "cedar", "rego", "xacml",
	// "json", "entitlement". Recorded for provenance.
	Source string

	// PolicyID identifies the specific policy or entitlement row.
	PolicyID string

	// Priority is recorded for audit and debugging and is NOT consulted by the
	// fold. Deny-overrides makes priority security-irrelevant (spec §3.3 Y7);
	// ordering by it here would reinstate the bug class Y7 removed.
	Priority int

	// UnevaluatedPolicyIDs carries the policy ids a language could not
	// evaluate — no registered engine for it, or its engine's own Prepare
	// call failed for the whole batch. Populated only on that kind of
	// verdict (internal/policy's orphanVerdicts/prepareFailureVerdicts);
	// empty on every ordinary, engine-produced verdict.
	//
	// This is a health fact about the deployment ("this language could not
	// run"), not a decision — it must not be mistaken for one by inflating
	// it into extra deny verdicts (that was tried and reverted: PolicyID is
	// singular, so N ids could only ever produce one queryable PolicyID
	// per verdict no matter how the N were split, and FoldVerdicts' own
	// tie-break on (Source, PolicyID) means an orphaned language's verdict
	// routinely loses to any other verdict present anyway — see Decide's own
	// aggregation of this field for why the fact still needs to survive that
	// loss). Carried on the verdict so Decide can aggregate it across the
	// whole slice regardless of which single verdict FoldVerdicts picks.
	UnevaluatedPolicyIDs []string
}

// Action describes what the agent is attempting.
type Action struct {
	Tool     string // "Bash", "Read", "mcp__stripe__create_refund"
	Verb     string // "read", "write", "delete"
	RawInput string // the actual command or path, used for derivation

	// NormalizedInput is a caller-supplied, best-effort extraction from
	// RawInput (e.g. a PEP pulling "ls -la" out of {"command":"ls -la"}).
	// BuiltinTier classifies both and combines them by evidence: a positive
	// destructive-or-external match on RawInput always wins, otherwise a
	// NormalizedInput that positively classifies is used, otherwise
	// RawInput's own result (including its default). An extraction that
	// under-reports, or is left empty, can only fail to raise the tier — it
	// can never lower RawInput below what a destructive or external match on
	// RawInput alone would produce. See BuiltinTier's doc comment.
	NormalizedInput string

	// DeclaredTier is what the caller claims. It never derives the tier — it is
	// only cross-checked against the derived value (C1, C2, C3).
	DeclaredTier *models.ActionTier
}

// Principal is the human on whose behalf the agent acts.
type Principal struct {
	Subject    string
	Attributes map[string]string
}

// AgentInfo is the acting agent's registry record, reduced to what a decision
// needs.
type AgentInfo struct {
	ID           uuid.UUID
	TrustTier    models.AgentTrustTier
	Enabled      bool
	Suspended    bool
	AllowedTools []string

	// ClassificationCaps is the template a ROOT delegation's caps are copied
	// from at issuance. It is NOT consulted at decision time -- the decision
	// reads the delegation's own caps (internal/authz/delegation.go) -- so a
	// change here never affects a delegation already issued.
	ClassificationCaps map[string]string

	// ResourceConstraints is the template a ROOT delegation's constraints are
	// copied from at issuance (internal/pdpgrpc/delegation.go), the same way
	// ClassificationCaps above is. It is NOT consulted at decision time -- the
	// decision reads the delegation's own constraints
	// (checkResourceConstraints) -- so a change here never affects a
	// delegation already issued.
	ResourceConstraints map[string]string
}

// Request is a complete decision input. Chain is ordered root-first, with the
// acting delegation last.
type Request struct {
	TenantID  string
	Principal Principal
	Agent     AgentInfo
	Chain     []*models.Delegation
	Action    Action
	Resource  map[string]string

	// ResourceIDs are every identity this call resolved to: the catalogued
	// resource field's own id, plus one per path a command_field tool's
	// command names (ShellResourceIDs). The delegation leg's id_prefix
	// constraint is evaluated against every member — see
	// satisfiesIDPrefix for why every, not any.
	//
	// Separate from Resource rather than a key inside it: Resource is a map
	// of single-valued attributes the policy engines also read, and R1
	// strips two of its keys unconditionally. A multi-valued identity does
	// not fit that shape and must not be smuggled into it.
	ResourceIDs []string

	// Now is injected so decisions are deterministic and testable.
	Now time.Time

	// PrincipalVerdicts are the policy engines' per-policy verdicts, evaluated
	// before this call and combined by FoldVerdicts. A nil or empty slice
	// folds to deny (default-deny), so a caller that forgets to evaluate it
	// denies rather than permitting.
	PrincipalVerdicts []PolicyVerdict
}

// Result is the compound decision.
type Result struct {
	Effect      Effect
	DerivedTier models.ActionTier

	Principal  LegResult
	Agent      LegResult
	Delegation LegResult

	// Deciding names the verdict Principal.Reason was attributed to, or nil
	// when the decision was default-deny with no verdict at all. That case
	// is real (an empty PrincipalVerdicts slice folds to deny) and must not
	// be papered over with a zero-value verdict: "no policy spoke" and "a
	// policy denied" are different facts an auditor needs told apart.
	Deciding *PolicyVerdict

	// UnevaluatedPolicyIDs is every PolicyVerdict.UnevaluatedPolicyIDs
	// value across req.PrincipalVerdicts, aggregated, sorted, and
	// deduplicated — not just Deciding's own, so an orphaned or
	// unprepared language's ids are reported even when some other verdict
	// (a Cedar deny, say) wins FoldVerdicts' tie-break and decides the
	// outcome instead. Sorted so it is deterministic across calls — the
	// audit hash chain commits to this value (pkg/audit.Entry.Hash), and a
	// value that reordered itself between two runs over the same facts
	// would make two honest chains diverge.
	UnevaluatedPolicyIDs []string

	// DeniedAtDepth is the chain depth at which a denial occurred, or -1.
	DeniedAtDepth int
	DeniedLeg     string
	Reason        string
}
