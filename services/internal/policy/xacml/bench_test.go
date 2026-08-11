package xacml

import (
	"context"
	"fmt"
	"testing"

	"stratium/internal/authz"
	"stratium/internal/policy"
)

// syntheticPolicies builds n well-formed, distinct XACML policies, each
// targeted at a subject-id that never matches benchPrincipal below except at
// index 0 — the same shape cedar/bench_test.go and rego/bench_test.go use,
// so BenchmarkEvaluate costs a real per-policy Target match that fails, not
// whatever this engine could short-circuit for a Target-less, always-Permit
// policy.
func syntheticPolicies(n int) []policy.StoredPolicy {
	policies := make([]policy.StoredPolicy, n)
	for i := range policies {
		id := fmt.Sprintf("bench-%d", i)
		policies[i] = policy.StoredPolicy{
			ID:   id,
			Name: id,
			Text: fmt.Sprintf(`<Policy PolicyId=%q RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">bench-user-%d</AttributeValue>
          <AttributeDesignator AttributeId="subject-id" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId=%q Effect="Permit"/>
</Policy>`, id, i, id+"-rule"),
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
// timer starts after the policy fixtures are built, so only
// parseAndValidate's per-policy XML parse and structural/semantic
// validation are measured.
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
