package main

import (
	"stratium/internal/policy"
	"stratium/internal/policy/cedar"
	"stratium/internal/policy/jsonpolicy"
	"stratium/internal/policy/rego"
	"stratium/internal/policy/xacml"
)

// newPolicyRegistry returns every policy engine this binary ships, keyed by
// language -- always all four, unconditionally. Unlike
// cmd/stratium-pdp/registry.go's own buildRegistry, which wires a
// deployment-configured SUBSET of engines (STRATIUM_POLICY_LANGUAGES) to
// actually serve decisions with, the PAP has no equivalent configuration
// and needs none: policies.language's own CHECK constraint
// (migrations/000001_baseline.up.sql) already fixes the vocabulary to
// exactly these four, and CreatePolicy/UpdatePolicy's job (internal/store/
// policy.go) is to validate whatever language an operator's policy
// declares against ITS OWN engine, regardless of which subset the PDP
// happens to be configured to run today -- an operator authoring a Rego
// policy the PDP is not yet configured to serve should still be told at
// write time whether that policy is well formed, not learn only "we do not
// evaluate rego here" from an entirely different, unrelated process. Each
// engine holds no state (see its own New()), so constructing all four
// eagerly costs nothing and needs no lazy wrapper.
func newPolicyRegistry() policy.Registry {
	return policy.Registry{
		"cedar": cedar.New(),
		"json":  jsonpolicy.New(),
		"rego":  rego.New(),
		"xacml": xacml.New(),
	}
}
