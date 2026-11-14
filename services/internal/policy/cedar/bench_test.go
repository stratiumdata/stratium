package cedar

import (
	"context"
	"fmt"
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
)

// syntheticPolicies builds n well-formed, distinct Cedar policies, each
// scoped to a principal that never matches benchPrincipal below. That keeps
// BenchmarkEvaluate honest: every policy still costs a real per-policy
// Authorize call (parse the request, walk the scope, fail the match)
// instead of however Cedar might short-circuit the cheapest possible
// "permit(principal, action, resource)" statement — this should cost what a
// tenant's non-trivial policy set costs, not the cheapest one imaginable.
func syntheticPolicies(n int) []policy.StoredPolicy {
	policies := make([]policy.StoredPolicy, n)
	for i := range policies {
		id := fmt.Sprintf("bench-%d", i)
		policies[i] = policy.StoredPolicy{
			ID:   id,
			Name: id,
			Text: fmt.Sprintf(`permit(principal == User::"bench-user-%d", action, resource);`, i),
		}
	}
	return policies
}

// benchPrincipal matches syntheticPolicies' first entry (bench-user-0) when
// n >= 1, so BenchmarkEvaluate always does the work of producing exactly one
// verdict, not the (cheaper) work of matching nothing at all.
const benchPrincipal = "bench-user-0"

var benchSizes = []int{1, 10, 100}

// BenchmarkPrepare measures Prepare's compile-once cost in isolation: the
// timer starts after the policy fixtures are built, so only parsing and
// PolicySet construction are measured.
func BenchmarkPrepare(b *testing.B) {
	ctx := context.Background()
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("policies=%d", n), func(b *testing.B) {
			policies := syntheticPolicies(n)
			engine := New()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := engine.Prepare(ctx, policies); err != nil {
					b.Fatalf("Prepare: %v", err)
				}
			}
		})
	}
}

// BenchmarkEvaluate measures Evaluate's per-decision cost against an
// already-prepared set: Prepare runs once before the timer starts, exactly
// the "compile once, evaluate many" split policy.PolicyEngine's doc comment
// describes — this is the cost every decision after the first actually
// pays.
func BenchmarkEvaluate(b *testing.B) {
	ctx := context.Background()
	for _, n := range benchSizes {
		b.Run(fmt.Sprintf("policies=%d", n), func(b *testing.B) {
			policies := syntheticPolicies(n)
			engine := New()
			set, err := engine.Prepare(ctx, policies)
			if err != nil {
				b.Fatalf("Prepare: %v", err)
			}
			in := policy.EvaluationInput{Principal: authz.Principal{Subject: benchPrincipal}}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := set.Evaluate(ctx, in); err != nil {
					b.Fatalf("Evaluate: %v", err)
				}
			}
		})
	}
}
