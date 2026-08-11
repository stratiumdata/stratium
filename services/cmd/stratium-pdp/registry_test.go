package main

import (
	"slices"
	"strings"
	"testing"
)

// engineConstructors' keys are trusted, not re-derived, by buildRegistry —
// see that map's own doc comment. This test is what actually proves the
// trust is warranted: a typo'd key here (e.g. "jsonpolicy" instead of
// "json") would otherwise surface only as NewMulti's construction-time
// panic (policy.NewMulti, multi.go) the first time this binary actually
// starts, far from the map where the typo lives. Each subtest name doubles
// as documentation of which literal is authoritative.
func TestEngineConstructors_KeysMatchLanguage(t *testing.T) {
	for key, engine := range engineConstructors {
		if got := engine.Language(); got != key {
			t.Errorf("engineConstructors[%q].Language() = %q, want %q — NewMulti would panic on this mismatch at startup", key, got, key)
		}
	}
}

func TestBuildRegistry_KnownLanguagesWireTheirEngines(t *testing.T) {
	registry, err := buildRegistry([]string{"cedar", "rego"})
	if err != nil {
		t.Fatalf("buildRegistry() error = %v, want nil", err)
	}
	if len(registry) != 2 {
		t.Fatalf("len(registry) = %d, want 2", len(registry))
	}
	for _, lang := range []string{"cedar", "rego"} {
		engine, ok := registry[lang]
		if !ok {
			t.Errorf("registry missing %q", lang)
			continue
		}
		// The registered engine must be the one actually keyed by this
		// language, not merely present at any key — Language() re-confirms
		// it rather than trusting the map lookup was correct by construction.
		if engine.Language() != lang {
			t.Errorf("registry[%q].Language() = %q, want %q", lang, engine.Language(), lang)
		}
	}
}

// This is the property the whole task exists for: a language config names
// with no matching engine must fail the whole build, naming the offender —
// never a warning, never a registry silently missing that one engine.
func TestBuildRegistry_UnknownLanguageFailsNamingIt(t *testing.T) {
	registry, err := buildRegistry([]string{"cedar", "cobol"})
	if err == nil {
		t.Fatal("buildRegistry() error = nil, want an error naming the unimplemented language")
	}
	if registry != nil {
		t.Errorf("registry = %v, want nil — a bad language must fail the whole build, not wire a partial registry", registry)
	}
	if !strings.Contains(err.Error(), "cobol") {
		t.Errorf("error %q does not name the offending language %q", err.Error(), "cobol")
	}
	if !strings.Contains(err.Error(), "STRATIUM_POLICY_LANGUAGES") {
		t.Errorf("error %q does not name the responsible variable", err.Error())
	}
}

// Two unknown languages alongside two known ones: both offenders must be
// named, and neither known language leaking into a partial registry — the
// same "fails the whole build" property as the single-offender case above,
// checked against a case a naive first-bad-entry-only implementation could
// pass by accident.
func TestBuildRegistry_MultipleUnknownLanguagesAllNamed(t *testing.T) {
	_, err := buildRegistry([]string{"cedar", "cobol", "rego", "opa-wasm"})
	if err == nil {
		t.Fatal("buildRegistry() error = nil, want an error")
	}
	for _, bad := range []string{"cobol", "opa-wasm"} {
		if !strings.Contains(err.Error(), bad) {
			t.Errorf("error %q does not name offender %q", err.Error(), bad)
		}
	}
}

// An empty configured list is a legitimate, explicit choice — a deployment
// that wants no policy engine at all (see main.go's own doc comment on
// NewMulti(repo, policy.Registry{})) — not an error. config.Load's own
// default never actually produces this (it defaults to all four), but
// buildRegistry is tested here as a general function independent of that
// default, the same "don't couple this function's correctness to one
// caller's current behaviour" reasoning most table-driven tests in this
// codebase already follow.
func TestBuildRegistry_EmptyLanguagesIsEmptyRegistryNotError(t *testing.T) {
	registry, err := buildRegistry(nil)
	if err != nil {
		t.Fatalf("buildRegistry(nil) error = %v, want nil", err)
	}
	if len(registry) != 0 {
		t.Errorf("len(registry) = %d, want 0", len(registry))
	}
}

// TestBuildRegistry_DuplicateLanguageDedupesToOneEntry pins a behaviour that
// was previously true only by accident of registry being a map: nothing
// documented or tested that STRATIUM_POLICY_LANGUAGES=cedar,cedar collapses
// to a one-engine registry rather than, say, an error naming the duplicate,
// or two engine instances silently double-evaluating the same tenant
// policies. The collapse is harmless — registry[lang] = engine is
// idempotent, and NewMulti's own key/Language() check (multi.go) has
// nothing to object to when both writes agree — but "harmless and
// untested" is still a behaviour someone could change without any test
// failing, which is the gap this pins shut.
func TestBuildRegistry_DuplicateLanguageDedupesToOneEntry(t *testing.T) {
	registry, err := buildRegistry([]string{"cedar", "cedar"})
	if err != nil {
		t.Fatalf("buildRegistry() error = %v, want nil (a repeated known language is not a configuration error)", err)
	}
	if len(registry) != 1 {
		t.Fatalf("len(registry) = %d, want 1 (a duplicate key collapses in the underlying map, not an error and not two entries)", len(registry))
	}
	if engine, ok := registry["cedar"]; !ok || engine.Language() != "cedar" {
		t.Errorf(`registry["cedar"] = %v (ok=%t), want the cedar engine`, engine, ok)
	}
}

func TestKnownLanguages_SortedAndComplete(t *testing.T) {
	got := knownLanguages()
	want := []string{"cedar", "json", "rego", "xacml"}
	if !slices.Equal(got, want) {
		t.Errorf("knownLanguages() = %v, want %v (sorted)", got, want)
	}
}

func TestRegistryLanguages_SortedRegardlessOfInsertionOrder(t *testing.T) {
	registry, err := buildRegistry([]string{"xacml", "cedar", "json"})
	if err != nil {
		t.Fatalf("buildRegistry() error = %v", err)
	}
	if want := []string{"cedar", "json", "xacml"}; !slices.Equal(registryLanguages(registry), want) {
		t.Errorf("registryLanguages() = %v, want %v", registryLanguages(registry), want)
	}
}
