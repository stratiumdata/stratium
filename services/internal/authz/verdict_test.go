package authz

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestFoldVerdicts(t *testing.T) {
	tests := []struct {
		name       string
		verdicts   []PolicyVerdict
		wantEffect Effect
	}{
		{
			name:       "empty slice denies",
			verdicts:   []PolicyVerdict{},
			wantEffect: EffectDeny,
		},
		{
			name:       "nil slice denies",
			verdicts:   nil,
			wantEffect: EffectDeny,
		},
		{
			name: "single deny denies",
			verdicts: []PolicyVerdict{
				{Effect: EffectDeny, Source: "cedar", PolicyID: "p1"},
			},
			wantEffect: EffectDeny,
		},
		{
			name: "single allow allows",
			verdicts: []PolicyVerdict{
				{Effect: EffectAllow, Source: "cedar", PolicyID: "p1"},
			},
			wantEffect: EffectAllow,
		},
		{
			name: "allow + deny denies",
			verdicts: []PolicyVerdict{
				{Effect: EffectAllow, Source: "cedar", PolicyID: "p1"},
				{Effect: EffectDeny, Source: "rego", PolicyID: "p2"},
			},
			wantEffect: EffectDeny,
		},
		{
			name: "allow + escalate escalates",
			verdicts: []PolicyVerdict{
				{Effect: EffectAllow, Source: "cedar", PolicyID: "p1"},
				{Effect: EffectEscalate, Source: "rego", PolicyID: "p2"},
			},
			wantEffect: EffectEscalate,
		},
		{
			name: "deny + escalate denies",
			verdicts: []PolicyVerdict{
				{Effect: EffectEscalate, Source: "cedar", PolicyID: "p1"},
				{Effect: EffectDeny, Source: "rego", PolicyID: "p2"},
			},
			wantEffect: EffectDeny,
		},
		{
			// Y7: priority is recorded for audit only and must never let a
			// higher-priority allow beat a lower-priority deny.
			name: "priority does not change the outcome",
			verdicts: []PolicyVerdict{
				{Effect: EffectAllow, Source: "cedar", PolicyID: "high", Priority: 100},
				{Effect: EffectDeny, Source: "rego", PolicyID: "low", Priority: 1},
			},
			wantEffect: EffectDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := FoldVerdicts(tt.verdicts)
			if got.Effect != tt.wantEffect {
				t.Fatalf("FoldVerdicts(%+v) effect = %v, want %v", tt.verdicts, got.Effect, tt.wantEffect)
			}
		})
	}
}

// A bare escalate — no accompanying allow — must escalate rather than fall
// through to default-deny, and the reason must come from the escalate
// verdict itself, not the generic default-deny text. This is the defect the
// step reorder fixes: escalate is checked before default-deny.
func TestFoldVerdicts_BareEscalateEscalates(t *testing.T) {
	escalate := PolicyVerdict{Effect: EffectEscalate, Source: "xacml", PolicyID: "p1", Reason: "needs approval"}

	leg, got := FoldVerdicts([]PolicyVerdict{escalate})
	if leg.Effect != EffectEscalate {
		t.Fatalf("bare escalate must escalate, got %v", leg.Effect)
	}
	if leg.Reason != escalate.Reason {
		t.Fatalf("reason = %q, want the escalate verdict's reason %q (not default-deny text)", leg.Reason, escalate.Reason)
	}
	// reflect.DeepEqual, not !=: PolicyVerdict's []string field
	// (UnevaluatedPolicyIDs) makes it non-comparable with ==.
	if got == nil || !reflect.DeepEqual(*got, escalate) {
		t.Fatalf("decided = %+v, want %+v", got, escalate)
	}
}

// The *PolicyVerdict FoldVerdicts returns identifies which verdict decided
// the outcome: non-nil whenever a specific verdict is decisive, nil only for
// default-deny, where no verdict decided anything.
func TestFoldVerdicts_ReturnsDecidingVerdict(t *testing.T) {
	deny := PolicyVerdict{Effect: EffectDeny, Source: "cedar", PolicyID: "p1", Reason: "cedar says no"}
	allow := PolicyVerdict{Effect: EffectAllow, Source: "rego", PolicyID: "p2", Reason: "rego allows"}
	escalate := PolicyVerdict{Effect: EffectEscalate, Source: "xacml", PolicyID: "p3", Reason: "needs approval"}

	// reflect.DeepEqual throughout this test, not !=: PolicyVerdict's
	// []string field (UnevaluatedPolicyIDs) makes it non-comparable with ==.
	t.Run("deny is attributed", func(t *testing.T) {
		leg, got := FoldVerdicts([]PolicyVerdict{allow, deny})
		if got == nil || !reflect.DeepEqual(*got, deny) {
			t.Fatalf("decided = %+v, want %+v", got, deny)
		}
		if leg.Reason != deny.Reason {
			t.Fatalf("leg reason = %q, want %q", leg.Reason, deny.Reason)
		}
	})

	t.Run("allow is attributed", func(t *testing.T) {
		leg, got := FoldVerdicts([]PolicyVerdict{allow})
		if got == nil || !reflect.DeepEqual(*got, allow) {
			t.Fatalf("decided = %+v, want %+v", got, allow)
		}
		if leg.Reason != allow.Reason {
			t.Fatalf("leg reason = %q, want %q", leg.Reason, allow.Reason)
		}
	})

	t.Run("escalate is attributed", func(t *testing.T) {
		leg, got := FoldVerdicts([]PolicyVerdict{allow, escalate})
		if got == nil || !reflect.DeepEqual(*got, escalate) {
			t.Fatalf("decided = %+v, want %+v", got, escalate)
		}
		if leg.Reason != escalate.Reason {
			t.Fatalf("leg reason = %q, want %q", leg.Reason, escalate.Reason)
		}
	})

	t.Run("default-deny attributes to no verdict", func(t *testing.T) {
		_, got := FoldVerdicts(nil)
		if got != nil {
			t.Fatalf("decided = %+v, want nil", got)
		}
	})
}

// Several denies must attribute to the same verdict regardless of the order
// FoldVerdicts receives them in — the PDP builds this slice from multiple
// engines, so input order is not guaranteed stable across runs.
func TestFoldVerdicts_DenyAttributionIsOrderIndependent(t *testing.T) {
	verdicts := []PolicyVerdict{
		{Effect: EffectDeny, Source: "rego", PolicyID: "p3", Reason: "rego says no"},
		{Effect: EffectDeny, Source: "cedar", PolicyID: "p2", Reason: "cedar p2 says no"},
		{Effect: EffectDeny, Source: "cedar", PolicyID: "p1", Reason: "cedar p1 says no"},
		{Effect: EffectAllow, Source: "cedar", PolicyID: "p0"},
	}
	want := verdicts[2] // ("cedar","p1") sorts before ("cedar","p2") and ("rego","p3")

	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 20; i++ {
		shuffled := append([]PolicyVerdict(nil), verdicts...)
		rng.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })

		leg, decided := FoldVerdicts(shuffled)
		if leg.Effect != EffectDeny {
			t.Fatalf("shuffle %d: effect = %v, want DENY", i, leg.Effect)
		}
		if leg.Reason != want.Reason {
			t.Fatalf("shuffle %d: reason = %q, want %q", i, leg.Reason, want.Reason)
		}
		// reflect.DeepEqual, not !=: PolicyVerdict's []string field
		// (UnevaluatedPolicyIDs) makes it non-comparable with ==.
		if decided == nil || !reflect.DeepEqual(*decided, want) {
			t.Fatalf("shuffle %d: decided = %+v, want %+v", i, decided, want)
		}
	}
}
