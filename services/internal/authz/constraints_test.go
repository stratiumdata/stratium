package authz

import (
	"strings"
	"testing"
)

func TestHasDotDotSegment(t *testing.T) {
	cases := map[string]bool{
		"/workspace/src/main.go":   false,
		"/workspace/../etc/shadow": true,
		"/workspace/a/../b.txt":    true,
		"../etc/shadow":            true,
		"..":                       true,
		// A segment, not a substring: these are ordinary names.
		"/workspace/..hidden/x": false,
		"/workspace/a..b.txt":   false,
		"":                      false,
	}
	for id, want := range cases {
		if got := hasDotDotSegment(id); got != want {
			t.Errorf("hasDotDotSegment(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestSatisfiesIDPrefix(t *testing.T) {
	const prefix = "/workspace/"

	t.Run("every id under the prefix satisfies", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix([]string{"/workspace/a.txt", "/workspace/src/b.go"}, prefix)
		if !ok {
			t.Fatalf("satisfiesIDPrefix denied (%s), want satisfied", reason)
		}
	})

	t.Run("one id outside denies and names it", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix([]string{"/workspace/a.txt", "/etc/shadow"}, prefix)
		if ok {
			t.Fatal("satisfiesIDPrefix allowed a set containing an id outside the prefix")
		}
		if !strings.Contains(reason, "/etc/shadow") {
			t.Errorf("reason = %q, want it to name the offending id", reason)
		}
	})

	// The safety property: a decoy inside the prefix adds an obligation, it
	// never relieves one. Order must not matter either.
	t.Run("a decoy cannot rescue an id outside the prefix", func(t *testing.T) {
		for _, ids := range [][]string{
			{"/workspace/ok.txt", "/etc/shadow"},
			{"/etc/shadow", "/workspace/ok.txt"},
		} {
			if ok, _ := satisfiesIDPrefix(ids, prefix); ok {
				t.Fatalf("satisfiesIDPrefix(%v) allowed; a decoy just bought access outside the scope", ids)
			}
		}
	})

	t.Run("a traversal segment denies even under the prefix", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix([]string{"/workspace/../etc/shadow"}, prefix)
		if ok {
			t.Fatal("satisfiesIDPrefix allowed a traversal escape; HasPrefix alone does not stop this")
		}
		if !strings.Contains(reason, "..") {
			t.Errorf("reason = %q, want it to name the traversal segment", reason)
		}
	})

	t.Run("no ids at all denies as unevaluable", func(t *testing.T) {
		ok, reason := satisfiesIDPrefix(nil, prefix)
		if ok {
			t.Fatal("satisfiesIDPrefix allowed an empty id set; unevaluable must not read as satisfied")
		}
		if !strings.Contains(reason, "cannot be evaluated") {
			t.Errorf("reason = %q, want the uncheckable wording, distinct from an outside-the-scope denial", reason)
		}
	})
}
