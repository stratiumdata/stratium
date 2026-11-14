package jsonpolicy

import (
	"context"
	"fmt"
	"testing"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
)

// syntheticPolicies builds n well-formed, distinct JSON policies, each
// matching a principal attribute that never matches benchAttrValue below
// except at index 0 — the same shape cedar/bench_test.go and
// rego/bench_test.go use, so BenchmarkEvaluate costs a real per-policy match
// tree walk that fails, not whatever this engine could short-circuit for the
// emptiest possible policy. subject.attr, not a direct subject match: this
// schema has no way to match Principal.Subject itself (see the package doc's
// "input mapping" section) — subject.attr indexes Principal.Attributes,
// which is what benchIn (below) populates.
func syntheticPolicies(n int) []policy.StoredPolicy {
	policies := make([]policy.StoredPolicy, n)
	for i := range policies {
		id := fmt.Sprintf("bench-%d", i)
		policies[i] = policy.StoredPolicy{
			ID:   id,
			Name: id,
			Text: fmt.Sprintf(`{"effect": "allow", "match": {"subject": {"attr": "bench_id", "equals": "bench-user-%d"}}}`, i),
		}
	}
	return policies
}

// benchAttrValue matches syntheticPolicies' first entry (bench-user-0) when
// n >= 1, so BenchmarkEvaluate always does the work of producing exactly one
// verdict, not the (cheaper) work of matching nothing at all.
const benchAttrValue = "bench-user-0"

var benchSizes = []int{1, 10, 100}

// BenchmarkPrepare measures Prepare's compile-once cost in isolation: the
// timer starts after the policy fixtures are built, so only parseDoc's
// per-policy validation and match-tree construction are measured.
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
			in := policy.EvaluationInput{Principal: authz.Principal{Attributes: map[string]string{"bench_id": benchAttrValue}}}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := set.Evaluate(ctx, in); err != nil {
					b.Fatalf("Evaluate: %v", err)
				}
			}
		})
	}
}
