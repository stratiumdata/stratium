package permset

import (
	"testing"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
)

func baseSet() Set {
	esc := models.ActionTierExternalComms
	return Set{
		Tools:               []string{"Read", "Write"},
		MaxTier:             models.ActionTierExternalComms,
		EscalateAt:          &esc,
		ClassificationCaps:  map[string]string{"nato": "SECRET"},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
		ExpiresAt:           time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC),
	}
}

// TestContains_FrozenReasons pins Contains to the reason strings
// models.ScopeNarrows -- the pre-move implementation this package replaced,
// deleted when ScopeNarrows moved into permset -- produced on 2026-09-15,
// captured mechanically rather than transcribed. These strings reach an
// operator through store.CreateDelegation's wrapped error, so they are API.
//
// WHEN THIS FAILS: you changed a containment rule or a reason string. Both
// are user-visible. Neither is a refactor.
func TestContains_FrozenReasons(t *testing.T) {
	cases := []struct {
		name string
		mut  func(outer, inner *Set)
		want string // <- pasted verbatim from Step 1's mechanical capture
	}{
		{"valid_identical", func(o, i *Set) {}, ""},
		{"tier_wider", func(o, i *Set) { i.MaxTier = models.ActionTierDestructive },
			"child max_action_tier DESTRUCTIVE exceeds parent EXTERNAL_COMMS"},
		{"escalate_introduced", func(o, i *Set) { o.EscalateAt = nil },
			"child introduces escalate_at EXTERNAL_COMMS which parent leaves unset"},
		{"escalate_dropped", func(o, i *Set) { i.EscalateAt = nil },
			"child drops parent escalate_at EXTERNAL_COMMS"},
		{"escalate_raised", func(o, i *Set) {
			e := models.ActionTierDestructive
			i.EscalateAt = &e
			i.MaxTier = models.ActionTierDestructive
			o.MaxTier = models.ActionTierDestructive
		}, "child escalate_at DESTRUCTIVE exceeds parent EXTERNAL_COMMS"},
		{"escalate_lowered", func(o, i *Set) { e := models.ActionTierReadOnly; i.EscalateAt = &e }, ""},
		{"tools_unrestricted", func(o, i *Set) { i.Tools = nil },
			"child has no tool restriction while parent restricts tools"},
		{"tools_extra", func(o, i *Set) { i.Tools = []string{"Read", "Bash"} },
			"child tool Bash not in parent approved_tools"},
		{"caps_omitted", func(o, i *Set) { i.ClassificationCaps = map[string]string{} },
			"child does not cap hierarchy nato which parent caps at SECRET"},
		{"caps_child_unknown", func(o, i *Set) { i.ClassificationCaps = map[string]string{"nato": "BOGUS"} },
			"child cap BOGUS is not a known level in hierarchy nato"},
		{"caps_parent_unknown", func(o, i *Set) { o.ClassificationCaps = map[string]string{"nato": "BOGUS"} },
			"parent cap BOGUS is not a known level in hierarchy nato"},
		{"caps_widened", func(o, i *Set) { o.ClassificationCaps = map[string]string{"nato": "CONFIDENTIAL"} },
			"child cap SECRET exceeds parent cap CONFIDENTIAL in hierarchy nato"},
		{"caps_introduced", func(o, i *Set) { i.ClassificationCaps["acme"] = "SECRET" },
			"child caps hierarchy acme which parent does not cap"},
		{"rc_dropped", func(o, i *Set) { i.ResourceConstraints = map[string]string{} },
			"child drops parent resource constraint id_prefix=/workspace/"},
		{"rc_sideways", func(o, i *Set) { i.ResourceConstraints[models.ResourceIDPrefixKey] = "/workspace-evil/" },
			"child resource constraint id_prefix=/workspace-evil/ is not within parent id_prefix=/workspace/"},
		{"rc_deeper", func(o, i *Set) { i.ResourceConstraints[models.ResourceIDPrefixKey] = "/workspace/sub/" }, ""},
		{"rc_other_key_differs", func(o, i *Set) { o.ResourceConstraints["env"] = "prod"; i.ResourceConstraints["env"] = "dev" },
			"child resource constraint env=dev differs from parent env=prod"},
		{"rc_introduced", func(o, i *Set) { i.ResourceConstraints["env"] = "dev" },
			"child constrains resource key env which parent does not constrain"},
		{"expiry_longer", func(o, i *Set) { i.ExpiresAt = i.ExpiresAt.Add(time.Hour) },
			"child expires_at exceeds parent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outer, inner := baseSet(), baseSet()
			tc.mut(&outer, &inner)
			if got := Contains(outer, inner); got != tc.want {
				t.Errorf("Contains() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestContains_EscalateAtPresenceIsAsymmetric is called out separately
// because it is the rule most likely to be "fixed" by a future reader.
// Introducing escalate_at genuinely NARROWS and is rejected anyway, so that
// a child's shape is derivable from its parent's fixed set of dimensions
// rather than from which hop first introduced one (spec section 4.3.1).
func TestContains_EscalateAtPresenceIsAsymmetric(t *testing.T) {
	read := models.ActionTierReadOnly

	introduced, in := baseSet(), baseSet()
	introduced.EscalateAt = nil
	if Contains(introduced, in) == "" {
		t.Error("a child introducing escalate_at must be rejected")
	}

	o, dropped := baseSet(), baseSet()
	dropped.EscalateAt = nil
	if Contains(o, dropped) == "" {
		t.Error("a child dropping escalate_at must be rejected")
	}

	o2, lowered := baseSet(), baseSet()
	lowered.EscalateAt = &read
	if reason := Contains(o2, lowered); reason != "" {
		t.Errorf("a child lowering escalate_at narrows and must be accepted: %s", reason)
	}
}

// TestContains_EscalateAtMayBeOmittedOnlyWhereUnreachable pins the one
// exception to the drop rule. A child whose own ceiling sits below the
// parent's threshold can never reach the escalate band, so leaving the field
// unset says the same thing the parent's value would. Without the exception
// such a child must carry a threshold at or below its own ceiling, which
// makes a worker handed LESS authority escalate MORE than its parent.
//
// The boundary is MaxTier < EscalateAt, strictly. At equality the child can
// reach the band, and omitting the field would let it act there unattended.
func TestContains_EscalateAtMayBeOmittedOnlyWhereUnreachable(t *testing.T) {
	destructive := models.ActionTierDestructive
	external := models.ActionTierExternalComms

	for _, tc := range []struct {
		name          string
		parentMax     models.ActionTier
		parentEsc     *models.ActionTier
		childMax      models.ActionTier
		wantContained bool
	}{
		{"child ceiling below the threshold may omit it",
			models.ActionTierDestructive, &destructive, models.ActionTierExternalComms, true},
		{"child ceiling far below the threshold may omit it",
			models.ActionTierDestructive, &destructive, models.ActionTierReadOnly, true},
		{"child ceiling AT the threshold may not omit it",
			models.ActionTierDestructive, &destructive, models.ActionTierDestructive, false},
		{"child ceiling above a lower threshold may not omit it",
			models.ActionTierDestructive, &external, models.ActionTierExternalComms, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outer, inner := baseSet(), baseSet()
			outer.MaxTier, outer.EscalateAt = tc.parentMax, tc.parentEsc
			inner.MaxTier, inner.EscalateAt = tc.childMax, nil

			got := Contains(outer, inner)
			if tc.wantContained && got != "" {
				t.Errorf("want contained, got %q", got)
			}
			if !tc.wantContained && got != "child drops parent escalate_at "+tc.parentEsc.String() {
				t.Errorf("want the frozen drop reason, got %q", got)
			}
		})
	}
}
