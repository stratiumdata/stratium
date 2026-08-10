package policy

import (
	"context"
	"fmt"

	"stratium/internal/authz"
)

// PolicySource loads a tenant's policies for one language. *store.Store
// satisfies it: store already imports this package for policy.StoredPolicy
// (see internal/store/policy.go), so this package cannot import store back
// without a cycle. The interface is declared here, where it is consumed —
// the same pattern pdpgrpc.Store uses for its own store dependency, so
// *store.Store needs no adapter to satisfy either.
type PolicySource interface {
	LoadPolicies(ctx context.Context, language string) ([]StoredPolicy, error)
}

// configured is PrincipalPolicy backed by a real PolicyEngine. There is
// deliberately no cache: every Evaluate call loads the tenant's policies
// from source and prepares them fresh (see Prepare's own doc comment and the
// Phase 2c plan's "caching is deliberately out of scope" — Task 5 measures
// the real compile-versus-evaluate cost before any cache gets designed
// around a guessed ratio).
type configured struct {
	source PolicySource
	engine PolicyEngine
}

// Configured returns a PrincipalPolicy backed by engine, loading its
// tenant's policies from source on every Evaluate call. It is the
// counterpart to Unconfigured: where Unconfigured always denies because
// there is nothing to consult, Configured consults a real, tenant-authored
// policy set and can legitimately return an allow — the two constructors
// are how this package tells "no policy engine wired" and "a policy engine
// decided" apart in the audit trail.
//
// Both arguments are required: Configured cannot be called with zero
// arguments, so — unlike a hardcoded bypass — it can never allow without a
// caller first wiring in something real policy data could come from. See
// TestNoExportedConstructorAllows in policy_test.go for how the no-allow
// guard accounts for that.
func Configured(source PolicySource, engine PolicyEngine) PrincipalPolicy {
	return configured{source: source, engine: engine}
}

// Evaluate loads, prepares, and evaluates — fail-closed at every step. A
// failure at any stage denies with a reason naming the engine's language, so
// an operator can tell "cedar broke" from "a cedar policy denied."
func (c configured) Evaluate(ctx context.Context, in EvaluationInput) []authz.PolicyVerdict {
	policies, err := c.source.LoadPolicies(ctx, c.engine.Language())
	if err != nil {
		return c.denyf("loading %s policies: %s", c.engine.Language(), err)
	}
	if len(policies) == 0 {
		// Exactly one verdict, not zero — the same reasoning as Unconfigured's
		// own doc comment: FoldVerdicts folds an empty slice to deny too, but
		// with its generic "default deny: no policy verdict allowed" text.
		// "This tenant has authored no policies yet" is a different, more
		// specific fact an auditor needs told apart from "policies exist and
		// were consulted, none matched" — which *does* fall through to
		// FoldVerdicts' generic text below, deliberately: the engine already
		// ran and had nothing to say, and describing that is FoldVerdicts'
		// job, not this method's to redo.
		return c.denyf("no %s policies configured for this tenant", c.engine.Language())
	}

	set, err := c.engine.Prepare(ctx, policies)
	if err != nil {
		return c.denyf("preparing %s policies: %s", c.engine.Language(), err)
	}

	verdicts, err := set.Evaluate(ctx, in)
	if err != nil {
		return c.denyf("evaluating %s policies: %s", c.engine.Language(), err)
	}
	return verdicts
}

// denyf builds the single-verdict, fail-closed shape every error path above
// returns: Source is the engine's own language, never "none" — a real
// engine ran, or tried to, which is a different fact than Unconfigured's
// "no engine at all" from an auditor's point of view.
func (c configured) denyf(format string, args ...any) []authz.PolicyVerdict {
	return []authz.PolicyVerdict{{
		Effect: authz.EffectDeny,
		Source: c.engine.Language(),
		Reason: "principal: " + fmt.Sprintf(format, args...),
	}}
}
