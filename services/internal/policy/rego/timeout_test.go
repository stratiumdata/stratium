package rego

import (
	"context"
	"testing"
	"time"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
)

type fixedSource []policy.StoredPolicy

func (f fixedSource) LoadAllPolicies(context.Context) ([]policy.StoredPolicy, error) { return f, nil }

// A policy that would run for a very long time is stopped at the evaluation
// deadline, and the result is a deny, not an allow and not a hang.
func TestEvaluate_PolicyPastTheDeadlineDenies(t *testing.T) {
	slow := policy.StoredPolicy{ID: "slow", Name: "slow", Language: "rego", Text: `package stratium.policy

allow if {
	count([1 | some i in numbers.range(1, 20000); some j in numbers.range(1, 20000)]) > 0
}`}
	multi := policy.NewMulti(fixedSource{slow}, policy.Registry{"rego": New()}).
		WithEvalTimeout(100 * time.Millisecond)

	start := time.Now()
	verdicts := multi.Evaluate(context.Background(), policy.EvaluationInput{})
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Evaluate took %s, want it stopped near the 100ms deadline", elapsed)
	}
	if len(verdicts) != 1 || verdicts[0].Effect != authz.EffectDeny {
		t.Fatalf("got %+v, want exactly one deny verdict", verdicts)
	}
}
