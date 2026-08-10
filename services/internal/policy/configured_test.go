package policy

import (
	"context"
	"errors"
	"strings"
	"testing"

	"stratium/internal/authz"
)

// stubSource is a PolicySource test double. gotLang, if set, records the
// language LoadPolicies was actually called with, so a test can assert
// Configured passes the engine's own Language() through rather than a
// hardcoded string.
type stubSource struct {
	policies []StoredPolicy
	err      error
	gotLang  *string
}

func (s stubSource) LoadPolicies(_ context.Context, language string) ([]StoredPolicy, error) {
	if s.gotLang != nil {
		*s.gotLang = language
	}
	return s.policies, s.err
}

// stubEngine is a PolicyEngine test double. gotPolicies, if set, records what
// Prepare was actually called with.
type stubEngine struct {
	language    string
	prepareErr  error
	set         CompiledPolicySet
	gotPolicies *[]StoredPolicy
}

func (s stubEngine) Language() string { return s.language }

func (s stubEngine) Prepare(_ context.Context, policies []StoredPolicy) (CompiledPolicySet, error) {
	if s.gotPolicies != nil {
		*s.gotPolicies = policies
	}
	if s.prepareErr != nil {
		return nil, s.prepareErr
	}
	return s.set, nil
}

func (stubEngine) Validate(context.Context, string) error { return nil }

// stubSet is a CompiledPolicySet test double.
type stubSet struct {
	verdicts []authz.PolicyVerdict
	err      error
}

func (s stubSet) Evaluate(context.Context, EvaluationInput) ([]authz.PolicyVerdict, error) {
	return s.verdicts, s.err
}

func TestConfigured_LoadsPreparesAndEvaluates(t *testing.T) {
	stored := []StoredPolicy{{ID: "p1", Effect: "allow"}, {ID: "p2", Effect: "deny"}}
	want := []authz.PolicyVerdict{
		{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "p1"},
		{Effect: authz.EffectDeny, Source: "cedar", PolicyID: "p2"},
	}
	var gotLang string
	var gotPolicies []StoredPolicy
	engine := stubEngine{language: "cedar", set: stubSet{verdicts: want}, gotPolicies: &gotPolicies}
	source := stubSource{policies: stored, gotLang: &gotLang}

	got := Configured(source, engine).Evaluate(context.Background(), EvaluationInput{})

	if gotLang != "cedar" {
		t.Errorf("LoadPolicies called with language %q, want %q (engine.Language(), not a hardcoded string)", gotLang, "cedar")
	}
	if len(gotPolicies) != len(stored) {
		t.Fatalf("Prepare called with %d policies, want %d", len(gotPolicies), len(stored))
	}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Evaluate() = %+v, want %+v (verdicts must pass through unchanged)", got, want)
	}
}

// TestConfigured_CanReturnAllowFromEngine is the positive control for the
// claim Configured's own doc comment makes: it can legitimately allow. A
// provider that silently clamped every verdict to deny would also pass every
// other test in this file, so this one exists specifically to prove the
// plumbing does not do that.
func TestConfigured_CanReturnAllowFromEngine(t *testing.T) {
	allow := []authz.PolicyVerdict{{Effect: authz.EffectAllow, Source: "cedar", PolicyID: "permit-1", Reason: "matched"}}
	engine := stubEngine{language: "cedar", set: stubSet{verdicts: allow}}
	source := stubSource{policies: []StoredPolicy{{ID: "permit-1", Effect: "allow"}}}

	got := Configured(source, engine).Evaluate(context.Background(), EvaluationInput{})
	if len(got) != 1 || got[0].Effect != authz.EffectAllow {
		t.Fatalf("Evaluate() = %+v, want exactly one EffectAllow verdict (Configured must not clamp a real engine's allow)", got)
	}
}

func TestConfigured_NoPoliciesDeniesNamingTheEngine(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies []StoredPolicy
	}{
		{"nil", nil},
		{"empty", []StoredPolicy{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine := stubEngine{language: "cedar"}
			got := Configured(stubSource{policies: tc.policies}, engine).Evaluate(context.Background(), EvaluationInput{})
			if len(got) != 1 {
				t.Fatalf("Evaluate() with no policies = %d verdicts, want exactly 1 (not zero — see Unconfigured's own doc comment on why)", len(got))
			}
			v := got[0]
			if v.Effect != authz.EffectDeny {
				t.Errorf("Effect = %v, want EffectDeny", v.Effect)
			}
			if v.Source != "cedar" {
				t.Errorf("Source = %q, want %q (a real engine ran; this is not the Unconfigured case)", v.Source, "cedar")
			}
			if !strings.Contains(v.Reason, "no cedar policies") {
				t.Errorf("Reason = %q, want it to name the engine and the empty policy set", v.Reason)
			}
		})
	}
}

func TestConfigured_FailurePathsDenyAndNameTheEngine(t *testing.T) {
	wantErr := errors.New("boom")
	tests := map[string]struct {
		source stubSource
		engine stubEngine
	}{
		"load fails":     {stubSource{err: wantErr}, stubEngine{language: "cedar"}},
		"prepare fails":  {stubSource{policies: []StoredPolicy{{ID: "p1"}}}, stubEngine{language: "cedar", prepareErr: wantErr}},
		"evaluate fails": {stubSource{policies: []StoredPolicy{{ID: "p1"}}}, stubEngine{language: "cedar", set: stubSet{err: wantErr}}},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := Configured(tc.source, tc.engine).Evaluate(context.Background(), EvaluationInput{})
			if len(got) != 1 {
				t.Fatalf("Evaluate() = %d verdicts, want exactly 1", len(got))
			}
			v := got[0]
			if v.Effect != authz.EffectDeny {
				t.Errorf("Effect = %v, want EffectDeny (must fail closed)", v.Effect)
			}
			if v.Source != "cedar" {
				t.Errorf("Source = %q, want %q", v.Source, "cedar")
			}
			if !strings.Contains(v.Reason, wantErr.Error()) {
				t.Errorf("Reason = %q, want it to contain the underlying error %q", v.Reason, wantErr.Error())
			}
		})
	}
}
