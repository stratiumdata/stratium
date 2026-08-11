package main

import (
	"fmt"
	"sort"
	"strings"

	"stratium/internal/policy"
	"stratium/internal/policy/cedar"
	"stratium/internal/policy/jsonpolicy"
	"stratium/internal/policy/rego"
	"stratium/internal/policy/xacml"
)

// engineConstructors is every policy engine this binary ships, keyed by the
// same string its own Language() returns. This is the single place that
// pairing is made: buildRegistry (below) trusts these keys rather than each
// engine's own Language(), so NewMulti's own construction-time consistency
// check (policy.Registry's doc comment — it panics if a Registry key ever
// disagrees with its engine's Language()) can never fire from a name learned
// here. Each engine holds no state (see its own New()), so constructing all
// four eagerly costs nothing and needs no lazy wrapper.
var engineConstructors = map[string]policy.PolicyEngine{
	"cedar": cedar.New(),
	"json":  jsonpolicy.New(),
	"rego":  rego.New(),
	"xacml": xacml.New(),
}

// buildRegistry turns a deployment's configured language list
// (config.Config.PolicyLanguages) into a policy.Registry, failing loudly on
// any name this build has no engine for — the same fail-fast rule
// internal/config already applies to required config with no default
// (STRATIUM_DATABASE_URL, STRATIUM_TENANT_ID), extended here to a value that
// does have a default but whose entries must still name something real. An
// operator who mistypes a language, or names one this build does not yet
// ship, learns it at startup, never from a policy that silently never
// evaluates — D10's failure mode one layer up, from configuration instead
// of a single tenant's data (see policy.Multi's own orphanVerdict for the
// per-tenant case this configuration-level check sits above).
//
// Returns a nil Registry alongside the error on any failure: a deployment
// that named one bad language among three good ones still refuses to start
// with a partially-wired registry, rather than serving a hobbled process
// silently missing an engine its operator believes is present.
func buildRegistry(languages []string) (policy.Registry, error) {
	registry := make(policy.Registry, len(languages))
	var unknown []string
	for _, lang := range languages {
		engine, ok := engineConstructors[lang]
		if !ok {
			unknown = append(unknown, lang)
			continue
		}
		registry[lang] = engine
	}
	if len(unknown) > 0 {
		quoted := make([]string, len(unknown))
		for i, lang := range unknown {
			quoted[i] = fmt.Sprintf("%q", lang)
		}
		return nil, fmt.Errorf("STRATIUM_POLICY_LANGUAGES names %s with no engine in this build (known: %s)",
			strings.Join(quoted, ", "), strings.Join(knownLanguages(), ", "))
	}
	return registry, nil
}

// knownLanguages is engineConstructors' key set, sorted so buildRegistry's
// error text — and the startup log line in main.go — reads the same on
// every run instead of following Go's randomised map iteration order.
func knownLanguages() []string {
	names := make([]string, 0, len(engineConstructors))
	for lang := range engineConstructors {
		names = append(names, lang)
	}
	sort.Strings(names)
	return names
}

// registryLanguages is registry's own key set, sorted the same way
// knownLanguages is — used for the startup log line so it reports exactly
// what got wired, derived from the registry itself rather than re-stating
// cfg.PolicyLanguages (which, unlike registry's keys, could in principle
// list a duplicate).
func registryLanguages(registry policy.Registry) []string {
	names := make([]string, 0, len(registry))
	for lang := range registry {
		names = append(names, lang)
	}
	sort.Strings(names)
	return names
}
