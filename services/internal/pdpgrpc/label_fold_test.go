package pdpgrpc

import (
	"testing"

	"stratium/pkg/classification"
)

// The fold labelResource applies when a command-field tool yields several
// resource identities (internal/authz.ShellResourceIDs). Design of record:
// docs/superpowers/specs/2026-08-28-shell-resource-identity-design.md.
//
// Every case here is a fail-closed rule. The single-id cases are included
// deliberately rather than assumed: this fold replaced a one-id signature, and
// the whole of R4's existing safety argument rests on those behaving exactly
// as they did before.
func TestLabelResource_Fold(t *testing.T) {
	rules := []classification.Rule{
		{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
		{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"},
		{Prefix: "/ts/", Hierarchy: "nato", Level: "TOP-SECRET"},
	}

	cases := []struct {
		name             string
		rules            []classification.Rule
		ids              []string
		wantLevel        string
		wantHierarchy    string
		wantNoLabelAtAll bool
	}{
		{
			name:  "no ids leaves the resource unlabelled, exactly as before",
			rules: rules, ids: nil, wantNoLabelAtAll: true,
		},
		{
			name:  "one id labels from its own rule",
			rules: rules, ids: []string{"/tmp/notes.txt"},
			wantLevel: "UNCLASSIFIED", wantHierarchy: "nato",
		},
		{
			// THE property. A command naming a benign path and a secret one
			// must be labelled by the secret one, or a decoy buys a
			// permissive label while the command still reads the secret.
			name:  "the strictest of several wins",
			rules: rules, ids: []string{"/tmp/notes.txt", "/secret/plans.txt"},
			wantLevel: "SECRET", wantHierarchy: "nato",
		},
		{
			name:  "and wins regardless of source order",
			rules: rules, ids: []string{"/secret/plans.txt", "/tmp/notes.txt"},
			wantLevel: "SECRET", wantHierarchy: "nato",
		},
		{
			name:  "the strictest of three",
			rules: rules, ids: []string{"/tmp/a", "/ts/b", "/secret/c"},
			wantLevel: "TOP-SECRET", wantHierarchy: "nato",
		},
		{
			// Without a catch-all a member can resolve to nothing, and the
			// maximum of a set containing an unknown is unknowable. An
			// unknowable maximum must not read as the maximum of the rest:
			// that is bypass-by-omission, one level up from the attribute.
			name:             "an unresolvable member denies rather than folding to the rest",
			rules:            []classification.Rule{{Prefix: "/secret/", Hierarchy: "nato", Level: "SECRET"}},
			ids:              []string{"/secret/plans.txt", "/elsewhere/x"},
			wantNoLabelAtAll: true,
		},
		{
			// Not erased, and not skipped: an unrankable label always denies
			// at CheckCap, so it is the strictest member of any set -- and it
			// denies naming the typo. TestDecide_UnknownHierarchyInARule
			// DeniesAndNamesIt guards the reason text end to end.
			name: "an unrankable rule wins the fold so the denial can name it",
			rules: []classification.Rule{
				{Prefix: "", Hierarchy: "nato", Level: "UNCLASSIFIED"},
				{Prefix: "/typo/", Hierarchy: "nato-typo", Level: "SECRET"},
			},
			ids:           []string{"/tmp/ok.txt", "/typo/x"},
			wantLevel:     "SECRET",
			wantHierarchy: "nato-typo",
		},
		{
			// Conservative interim (design §Risks): the resource map holds
			// exactly one (classification, hierarchy) pair, and widening it
			// touches R1's stripping guarantee. Deny until that is designed.
			name: "paths spanning two hierarchies deny",
			rules: []classification.Rule{
				{Prefix: "/n/", Hierarchy: "nato", Level: "SECRET"},
				{Prefix: "/c/", Hierarchy: "commercial", Level: "INTERNAL"},
			},
			ids:              []string{"/n/a", "/c/b"},
			wantNoLabelAtAll: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := labelResource(tc.rules, map[string]string{}, tc.ids)

			level := got[classification.AttrClassification]
			hierarchy := got[classification.AttrHierarchy]

			if tc.wantNoLabelAtAll {
				if level != "" || hierarchy != "" {
					t.Fatalf("labelResource(%v) wrote %s/%s, want no label at all -- an unevaluable "+
						"cap must deny, never read as satisfied", tc.ids, hierarchy, level)
				}
				return
			}
			if level != tc.wantLevel || hierarchy != tc.wantHierarchy {
				t.Fatalf("labelResource(%v) = %s/%s, want %s/%s",
					tc.ids, hierarchy, level, tc.wantHierarchy, tc.wantLevel)
			}
		})
	}
}

// TestLabelResource_StillStripsCallerSuppliedLabels guards R1 across the
// signature change: the two keys the PDP owns are removed from the caller's
// map before anything is written, whatever the id count.
func TestLabelResource_StillStripsCallerSuppliedLabels(t *testing.T) {
	caller := map[string]string{
		classification.AttrClassification: "UNCLASSIFIED",
		classification.AttrHierarchy:      "nato",
		"unrelated":                       "kept",
	}

	// No ids: nothing to label with, so the caller's claim must simply be gone.
	got := labelResource(nil, caller, nil)
	if got[classification.AttrClassification] != "" || got[classification.AttrHierarchy] != "" {
		t.Fatalf("labelResource kept a caller-supplied label: %v -- this is the cheapest possible "+
			"bypass and R1 forecloses it", got)
	}
	if got["unrelated"] != "kept" {
		t.Error("labelResource dropped an unrelated caller attribute")
	}
}
