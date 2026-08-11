package policy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"stratium/internal/authz"
)

// AllPolicySource loads every enabled policy for a tenant across every
// language in one call — what Multi needs to discover which languages a
// tenant has authored before it can decide which per-language groups to
// prepare. store.LoadAllPolicies is the production implementation.
//
// A separate interface from PolicySource (configured.go), not an added
// method on it: every existing PolicySource — Configured's, and every test
// double across this codebase — loads one language at a time and has no
// reason to also answer "give me everything." Bolting that requirement onto
// every existing caller of Configured to serve Multi's different need would
// be the same unrequested-abstraction mistake in reverse. *store.Store
// satisfies both interfaces structurally, with no adapter either way.
type AllPolicySource interface {
	LoadAllPolicies(ctx context.Context) ([]StoredPolicy, error)
}

// Registry maps policies.language to the engine that evaluates it. A
// language present in a tenant's policies but absent from Registry is an
// orphan — see PrepareAll — never silently skipped.
type Registry map[string]PolicyEngine

// Multi evaluates a tenant's policies across every registered engine. It is
// the multi-language successor to Configured (configured.go): where
// Configured loads and prepares exactly one PolicyEngine's language, Multi
// loads every language a tenant has authored in one call and prepares each
// group with whatever engine Registry has for it, so a tenant free to author
// Cedar, Rego, JSON, and XACML policies side by side gets all of them
// evaluated — or, for a language nothing is registered for, an honest deny
// naming it (D10) rather than that language's policies silently never
// running.
//
// Multi satisfies PrincipalPolicy (Evaluate) directly. It also exposes
// PrepareAll, which PrincipalPolicy does not declare: pdpgrpc's
// CreateDelegation gate needs a CompiledPolicySet it can probe many times
// over for one grant request (see Probe in probe.go), the same gap
// Configured left open that used to force pdpgrpc to hold a second, raw
// PolicySource/PolicyEngine pair alongside its PrincipalPolicy just to
// rebuild one itself. NewMulti returns Multi itself, not the PrincipalPolicy
// interface, specifically so a caller that needs PrepareAll — pdpgrpc's
// NewServer — can reach it without a type assertion.
type Multi struct {
	source  AllPolicySource
	engines Registry
}

var _ PrincipalPolicy = Multi{}

// NewMulti returns a Multi backed by source and engines. Both are required:
// like Configured, Multi cannot be built with zero arguments, so it cannot
// be a hardcoded, zero-configuration bypass any more than Configured can —
// see TestNoExportedConstructorAllows in policy_test.go for how the no-allow
// guard accounts for that.
func NewMulti(source AllPolicySource, engines Registry) Multi {
	return Multi{source: source, engines: engines}
}

// PrepareAll groups the tenant's policies by language, prepares each group
// with its registered engine, and returns a CompiledPolicySet spanning all
// of them. Decide's principal leg (Evaluate, below) and pdpgrpc's
// delegation-creation gate both call this — the gate needs its own compiled
// set to probe repeatedly per grant request, Evaluate needs one set per
// decision, and grouping-then-preparing is identical work either way (see
// PolicyEngine's own doc comment on why that compile step must happen once,
// not per request).
//
// The returned CompiledPolicySet is nil only when err reports that loading
// the tenant's policies failed outright — in which case nothing is known
// about what languages even exist, so there is nothing to fall back to.
// Every other failure this method can encounter — a language with no
// registered engine, or a registered engine's own Prepare call failing — is
// folded into the returned set as a deny verdict for that specific language,
// rather than aborting the whole call: a Rego engine that cannot compile
// must not silence a Cedar forbid that prepared just fine.
//
// err is still non-nil, alongside a fully usable set, when one or more
// languages failed to *prepare* — never when a language simply has no
// registered engine; that is not an error, only ever a deny verdict (see
// orphanVerdict). This asymmetry is deliberate: Evaluate (below) treats a
// non-nil set as sufficient regardless of err, because the failure is
// already recorded as that language's deny verdict inside it and
// deny-overrides means nothing is lost by proceeding — but pdpgrpc's
// delegation-creation gate treats any non-nil err as blocking (see
// delegation.go's CreateDelegation), preserving the pre-Multi distinction
// between "we could not even check" (Internal) and "we checked, the answer
// is no" (PermissionDenied) for the higher-stakes question of whether to
// hand out more authority. Decide's audit trail and CreateDelegation's grant
// gate read the same failure differently on purpose; both readings are safe
// because deny-overrides makes the embedded verdict harmless to include
// either way.
func (m Multi) PrepareAll(ctx context.Context) (CompiledPolicySet, error) {
	policies, err := m.source.LoadAllPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: load all policies: %w", err)
	}

	byLanguage := make(map[string][]StoredPolicy)
	for _, p := range policies {
		byLanguage[p.Language] = append(byLanguage[p.Language], p)
	}
	languages := make([]string, 0, len(byLanguage))
	for lang := range byLanguage {
		languages = append(languages, lang)
	}
	// Sorted once, here, so multiSet.Evaluate never has to: every call reads
	// entries in the same fixed order, which is what makes its output
	// deterministic across calls (see multiSet.Evaluate's own doc comment).
	sort.Strings(languages)

	entries := make([]languageEntry, 0, len(languages))
	var prepareFailures []string
	for _, lang := range languages {
		langPolicies := byLanguage[lang]
		engine, ok := m.engines[lang]
		if !ok {
			entries = append(entries, languageEntry{language: lang, verdict: orphanVerdict(lang, langPolicies)})
			continue
		}
		set, err := engine.Prepare(ctx, langPolicies)
		if err != nil {
			entries = append(entries, languageEntry{language: lang, verdict: prepareFailureVerdict(lang, err)})
			prepareFailures = append(prepareFailures, fmt.Sprintf("%s: %s", lang, err))
			continue
		}
		entries = append(entries, languageEntry{language: lang, set: set})
	}

	result := multiSet{entries: entries}
	if len(prepareFailures) > 0 {
		return result, fmt.Errorf("policy: preparing policies: %s", strings.Join(prepareFailures, "; "))
	}
	return result, nil
}

// Evaluate decides the principal leg by preparing the tenant's full,
// multi-language policy set and evaluating it once. It is a thin wrapper
// around PrepareAll and the resulting set's own Evaluate — see PrepareAll's
// doc comment for why a non-nil err alongside a non-nil set is treated as
// already handled rather than re-reported here.
func (m Multi) Evaluate(ctx context.Context, in EvaluationInput) []authz.PolicyVerdict {
	set, err := m.PrepareAll(ctx)
	if set == nil {
		return []authz.PolicyVerdict{{
			Effect: authz.EffectDeny,
			Source: "none",
			Reason: fmt.Sprintf("principal: loading policies: %s", err),
		}}
	}

	verdicts, err := set.Evaluate(ctx, in)
	if err != nil {
		// multiSet.Evaluate is built to never actually return a non-nil
		// error — every failure mode it can encounter is already folded
		// into a deny verdict within its returned slice (see multiSet.
		// Evaluate's own doc comment). This exists only as a fail-closed
		// backstop should that invariant ever break, consistent with every
		// other failure path in this package denying rather than trusting
		// a slice to carry a fact it might not.
		return []authz.PolicyVerdict{{
			Effect: authz.EffectDeny,
			Source: "none",
			Reason: fmt.Sprintf("principal: evaluating policies: %s", err),
		}}
	}
	return verdicts
}

// languageEntry is one language's contribution to a multiSet, fixed at
// PrepareAll time. Exactly one of set/verdict is populated: set for a
// language with a registered engine that prepared successfully — Evaluate
// calls it fresh on every multiSet.Evaluate call, since only the actual
// decision input can determine what it says; verdict for a language whose
// contribution is already fully known before any EvaluationInput exists (no
// registered engine, or Prepare itself failed) and would not change by
// recomputing it per call.
type languageEntry struct {
	language string
	set      CompiledPolicySet
	verdict  *authz.PolicyVerdict
}

// multiSet is Multi's CompiledPolicySet. entries is built once by
// PrepareAll, in sorted-by-language order, and never mutated afterward —
// which is what makes multiSet safe for the concurrent Evaluate calls
// CompiledPolicySet's own contract requires: every call only reads entries,
// and each sub-engine's own set is required to be concurrency-safe by that
// same contract.
type multiSet struct {
	entries []languageEntry
}

var _ CompiledPolicySet = multiSet{}

// Evaluate concatenates every language's contribution in entries' fixed
// order — languages sorted (see PrepareAll) — and, within a prepared
// language's own contribution, sorted here by PolicyID, because an
// individual engine's own iteration order is not guaranteed to be stable
// (Cedar's, for one, documents that its own follows Go's randomised map
// order). Without that second sort, the same tenant's same policies could
// report a different audit reason on two calls that changed nothing, which
// is untestable and unexplainable — the property this method exists to
// guarantee.
//
// A sub-engine's own Evaluate failing is caught per language, converted to a
// deny verdict naming that language, and does not stop the loop: a Rego
// outage must not silence a Cedar forbid that evaluated just fine — the same
// principle PrepareAll applies to a Prepare failure. This is why this
// method's own error return is, in practice, always nil; see Multi.Evaluate
// for the one defensive exception.
//
// Zero entries means PrepareAll loaded no policies for this tenant in any
// language — a distinct, more specific fact than "every language's policies
// were consulted and none matched," which is FoldVerdicts' own generic
// default-deny text downstream. Configured (configured.go) drew the same
// distinction for its one language; this is that same reasoning applied
// tenant-wide, with the language dropped from the message because the
// absence is no longer one language's.
func (s multiSet) Evaluate(ctx context.Context, in EvaluationInput) ([]authz.PolicyVerdict, error) {
	if len(s.entries) == 0 {
		return []authz.PolicyVerdict{{
			Effect: authz.EffectDeny,
			Source: "none",
			Reason: "principal: no policies configured for this tenant",
		}}, nil
	}

	var verdicts []authz.PolicyVerdict
	for _, e := range s.entries {
		if e.verdict != nil {
			verdicts = append(verdicts, *e.verdict)
			continue
		}

		vs, err := e.set.Evaluate(ctx, in)
		if err != nil {
			verdicts = append(verdicts, authz.PolicyVerdict{
				Effect: authz.EffectDeny,
				Source: e.language,
				Reason: fmt.Sprintf("principal: evaluating %s policies: %s", e.language, err),
			})
			continue
		}
		sort.Slice(vs, func(i, j int) bool { return vs[i].PolicyID < vs[j].PolicyID })
		verdicts = append(verdicts, vs...)
	}
	return verdicts, nil
}

// orphanVerdict is the single deny verdict a language with policies but no
// registered engine contributes — D10: an operator who authored a policy in
// a language this deployment cannot run must learn it from a denial, naming
// every policy id left unevaluated, not from a system that behaves as though
// they never wrote it.
func orphanVerdict(language string, policies []StoredPolicy) *authz.PolicyVerdict {
	ids := make([]string, len(policies))
	for i, p := range policies {
		ids[i] = p.ID
	}
	return &authz.PolicyVerdict{
		Effect: authz.EffectDeny,
		Source: language,
		Reason: fmt.Sprintf("principal: no %s engine registered; cannot evaluate policy IDs %s", language, strings.Join(ids, ", ")),
	}
}

// prepareFailureVerdict is the single deny verdict a language contributes
// when its registered engine's Prepare call itself fails — the same
// "preparing %s policies" wording Configured's own denyf uses for the
// one-language case, so the two failure modes read the same way in an audit
// log whether a tenant has one engine or four.
func prepareFailureVerdict(language string, err error) *authz.PolicyVerdict {
	return &authz.PolicyVerdict{
		Effect: authz.EffectDeny,
		Source: language,
		Reason: fmt.Sprintf("principal: preparing %s policies: %s", language, err),
	}
}
