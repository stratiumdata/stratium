package permset

import (
	"testing"
	"time"

	"stratium/pkg/models"
)

func grantBase() Set {
	return Set{
		Tools:               []string{"Read", "Write"},
		MaxTier:             models.ActionTierExternalComms,
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{},
		ExpiresAt:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
	}
}

// TestGrantWidens_DisagreesWithContainsExactlyOnIntroducedKeys is the whole
// reason this function exists, and it asserts BOTH sides on the same input:
// Contains refuses an introduced key (a deliberate delegation-SHAPE rule),
// while as a grant diff that same change NARROWS, because an absent cap or
// constraint means unrestricted.
//
// If this test ever passes with the two answers agreeing, either Contains
// stopped enforcing the shape rules or GrantWidens stopped neutralising
// them. Both are defects, and neither should be fixed by relaxing this test.
func TestGrantWidens_DisagreesWithContainsExactlyOnIntroducedKeys(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after func(Set) Set
	}{
		{
			name: "first classification cap",
			after: func(s Set) Set {
				s.ClassificationCaps = map[string]string{"nato": "SECRET"}
				return s
			},
		},
		{
			name: "first resource constraint",
			after: func(s Set) Set {
				s.ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace/"}
				return s
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := grantBase()
			after := tc.after(grantBase())

			if reason := Contains(before, after); reason == "" {
				t.Fatal("Contains must still refuse an introduced key — that shape rule is deliberate")
			}
			if reason := GrantWidens(before, after); reason != "" {
				t.Errorf("GrantWidens said the grant widened: %q\n"+
					"introducing a restriction NARROWS a grant — an absent cap or constraint key "+
					"means unrestricted", reason)
			}
		})
	}
}

// TestGrantWidens_StillNamesEveryRealWidening is the other half. Neutralising
// the introduce rule must not neutralise anything else, and a test that only
// checked the suppressed case would pass against a function that returned ""
// unconditionally.
func TestGrantWidens_StillNamesEveryRealWidening(t *testing.T) {
	capped := grantBase()
	capped.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"}

	scoped := grantBase()
	scoped.ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace/"}

	for _, tc := range []struct {
		name          string
		before, after Set
	}{
		{
			name:   "a cap is dropped",
			before: capped,
			after:  grantBase(),
		},
		{
			name:   "a cap level is raised",
			before: capped,
			after: func() Set {
				s := grantBase()
				s.ClassificationCaps = map[string]string{"nato": "SECRET"}
				return s
			}(),
		},
		{
			name:   "a constraint is dropped",
			before: scoped,
			after:  grantBase(),
		},
		{
			name:   "a prefix moves sideways",
			before: scoped,
			after: func() Set {
				s := grantBase()
				s.ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace-evil/"}
				return s
			}(),
		},
		{
			name:   "the tool allowlist is emptied",
			before: grantBase(),
			after: func() Set {
				s := grantBase()
				s.Tools = []string{}
				return s
			}(),
		},
		{
			name:   "the tier ceiling is raised",
			before: grantBase(),
			after: func() Set {
				s := grantBase()
				s.MaxTier = models.ActionTierDestructive
				return s
			}(),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := GrantWidens(tc.before, tc.after); reason == "" {
				t.Error("GrantWidens returned no reason for a real widening")
			}
		})
	}
}

// TestGrantWidens_UnchangedAndNarrowingAreSilent pins the condition the audit
// write depends on: only a widening records anything.
func TestGrantWidens_UnchangedAndNarrowingAreSilent(t *testing.T) {
	base := grantBase()

	if reason := GrantWidens(base, base); reason != "" {
		t.Errorf("an unchanged grant reported %q", reason)
	}

	narrower := grantBase()
	narrower.Tools = []string{"Read"}
	narrower.MaxTier = models.ActionTierReadOnly
	if reason := GrantWidens(base, narrower); reason != "" {
		t.Errorf("a narrowing grant reported %q", reason)
	}
}

// TestGrantWidens_DoesNotMutateItsArguments matters because FromDelegation
// shares its maps with the source Delegation: a pre-fill that wrote into
// `before` would corrupt a live record, and every assertion above would
// still pass.
func TestGrantWidens_DoesNotMutateItsArguments(t *testing.T) {
	before := grantBase()
	before.ClassificationCaps = map[string]string{"nato": "SECRET"}
	after := grantBase()
	after.ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace/"}

	beforeCaps := len(before.ClassificationCaps)
	beforeConstraints := len(before.ResourceConstraints)
	afterCaps := len(after.ClassificationCaps)

	_ = GrantWidens(before, after)

	if len(before.ClassificationCaps) != beforeCaps || len(before.ResourceConstraints) != beforeConstraints {
		t.Errorf("GrantWidens mutated `before`: caps %d->%d, constraints %d->%d",
			beforeCaps, len(before.ClassificationCaps), beforeConstraints, len(before.ResourceConstraints))
	}
	if len(after.ClassificationCaps) != afterCaps {
		t.Errorf("GrantWidens mutated `after`: caps %d->%d", afterCaps, len(after.ClassificationCaps))
	}
}
