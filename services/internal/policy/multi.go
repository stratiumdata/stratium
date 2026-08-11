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
//
// Multi routes purely by map key (see PrepareAll) and never itself calls an
// engine's Language() to cross-check — NewMulti validates once, at
// construction, that every key agrees with its own engine's Language()
// instead, so a typo'd key (Registry{"rego": xacml.New()}) cannot silently
// route one language's policies to the wrong engine.
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
//
// Panics if any Registry entry's key disagrees with its own engine's
// Language() (see Registry's own doc comment on why nothing downstream
// would otherwise catch that). NewMulti is called once, at startup, to wire
// a static configuration — never per request — so a mistake here is a
// wiring bug, not a runtime condition, and failing loudly immediately beats
// silently misattributing every verdict the mismatched engine produces
// later. A returned error was the other option, and it remains available:
// the no-allow guard used to see only single-value returns, which made an
// error return cost this constructor its coverage, but that was a hole in
// the guard rather than a constraint on constructors and has been fixed.
// The panic stands on its own merits — this is the canonical Go case for
// one, a static wiring mistake detectable before the process serves any
// traffic, in the shape of regexp.MustCompile — not because a signature
// forced it.
func NewMulti(source AllPolicySource, engines Registry) Multi {
	for key, engine := range engines {
		if lang := engine.Language(); lang != key {
			panic(fmt.Sprintf("policy: NewMulti: Registry key %q does not match its engine's Language() %q", key, lang))
		}
	}
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
// folded into the returned set as one deny verdict per policy in that
// specific language, rather than aborting the whole call: a Rego engine that
// cannot compile must not silence a Cedar forbid that prepared just fine.
//
// err is still non-nil, alongside a fully usable set, when one or more
// languages failed to *prepare* — never when a language simply has no
// registered engine; that is not an error, only ever a deny verdict per
// policy (see orphanVerdicts). This asymmetry is deliberate: Evaluate
// (below) treats a non-nil set as sufficient regardless of err, because the
// failure is already recorded as that language's deny verdicts inside it and
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
			entries = append(entries, languageEntry{language: lang, verdicts: orphanVerdicts(lang, langPolicies)})
			continue
		}
		set, err := engine.Prepare(ctx, langPolicies)
		if err != nil {
			entries = append(entries, languageEntry{language: lang, verdicts: prepareFailureVerdicts(lang, langPolicies, err)})
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
// PrepareAll time. Exactly one of set/verdicts is populated: set for a
// language with a registered engine that prepared successfully — Evaluate
// calls it fresh on every multiSet.Evaluate call, since only the actual
// decision input can determine what it says; verdicts for a language whose
// contribution is already fully known before any EvaluationInput exists (no
// registered engine, or Prepare itself failed) and would not change by
// recomputing it per call.
//
// Plural, not a single verdict: an orphaned or prepare-failed language
// denies once per unevaluated policy (see orphanVerdicts and
// prepareFailureVerdicts below), the same one-verdict-per-policy shape
// every registered engine's own Evaluate already follows, so
// audit_chain.policy_id stays populated and queryable on exactly these
// denials instead of every id but one living only inside free-text Reason.
type languageEntry struct {
	language string
	set      CompiledPolicySet
	verdicts []authz.PolicyVerdict
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
// The sort runs on a copy appended into verdicts, never on the slice a
// sub-engine's Evaluate handed back: CompiledPolicySet's own contract
// (engine.go) requires the *set* to be goroutine-safe, not the slice a call
// to Evaluate returns, and it says nothing about that slice being freshly
// allocated per call. An engine that precomputes and reuses one backing
// array across calls (plausible for a cache — see Task 6) would have that
// array mutated by two concurrent Decides sorting it at once: a data race,
// and interleaved verdict order landing in the audit trail. Sorting
// verdicts' own tail after appending avoids touching the sub-engine's slice
// at all.
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
		if len(e.verdicts) > 0 {
			verdicts = append(verdicts, e.verdicts...)
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
		start := len(verdicts)
		verdicts = append(verdicts, vs...)
		sort.Slice(verdicts[start:], func(i, j int) bool {
			return verdicts[start+i].PolicyID < verdicts[start+j].PolicyID
		})
	}
	return verdicts, nil
}

// orphanVerdicts is one deny verdict per policy stored in a language with no
// registered engine — D10: an operator who authored a policy in a language
// this deployment cannot run must learn it from a denial naming that exact
// policy, not from a system that behaves as though they never wrote it.
//
// One verdict per policy, not one verdict naming every policy: PolicyID is
// singular (authz.PolicyVerdict), so a single verdict for N orphaned
// policies can only ever populate it with one of them (or leave it empty,
// which is what this function used to do) — audit_chain.policy_id stays
// unqueryable either way, with every id living only inside free-text
// Reason. Splitting into N verdicts, each carrying its own PolicyID, is what
// makes every orphaned policy individually queryable, and is harmless under
// deny-overrides: N denies fold to the same outcome one would, FoldVerdicts
// simply has more equally-valid candidates to pick a stable attribution
// from (see authz.FoldVerdicts' own tie-break).
//
// Sorted by PolicyID before returning, the same defensive-determinism
// reasoning multiSet.Evaluate applies to a sub-engine's own output (see that
// method's doc comment): AllPolicySource makes no ordering promise in its
// interface, so this does not lean on store.LoadAllPolicies' own ORDER BY id
// happening to hold today, or on every other implementation of the interface
// (test doubles included) doing the same.
func orphanVerdicts(language string, policies []StoredPolicy) []authz.PolicyVerdict {
	verdicts := make([]authz.PolicyVerdict, len(policies))
	for i, p := range policies {
		verdicts[i] = authz.PolicyVerdict{
			Effect:   authz.EffectDeny,
			Source:   language,
			PolicyID: p.ID,
			Reason:   fmt.Sprintf("principal: no %s engine registered; cannot evaluate policy ID %s", language, p.ID),
		}
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].PolicyID < verdicts[j].PolicyID })
	return verdicts
}

// prepareFailureVerdicts is one deny verdict per policy stored in a language
// whose registered engine's Prepare call itself failed for the whole batch —
// the same "preparing %s policies" wording Configured's own denyf used for
// the one-language case, so the two failure modes read the same way in an
// audit log whether a tenant has one engine or four.
//
// One verdict per policy, the same shape orphanVerdicts uses above, and for
// the same underlying reason rather than a coincidental resemblance: every
// engine in this tree stops at its first bad policy and returns a single
// error for the whole Prepare call (see e.g. cedar.Engine.Prepare's own doc
// comment), so every policy in policies is equally unevaluated when this
// fires — not only whichever one err's own text happens to name. err's text
// is shared verbatim across every returned verdict, because there is
// exactly one underlying failure to report, while PolicyID differs per
// verdict — so audit_chain.policy_id is queryable for every one of them,
// not only whichever id happened to reach the free-text Reason first.
func prepareFailureVerdicts(language string, policies []StoredPolicy, err error) []authz.PolicyVerdict {
	verdicts := make([]authz.PolicyVerdict, len(policies))
	for i, p := range policies {
		verdicts[i] = authz.PolicyVerdict{
			Effect:   authz.EffectDeny,
			Source:   language,
			PolicyID: p.ID,
			Reason:   fmt.Sprintf("principal: preparing %s policies: %s", language, err),
		}
	}
	sort.Slice(verdicts, func(i, j int) bool { return verdicts[i].PolicyID < verdicts[j].PolicyID })
	return verdicts
}
