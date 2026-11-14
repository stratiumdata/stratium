package rego

import (
	"testing"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/pkg/models"
)

// fullyPopulatedEvaluationInput sets every EvaluationInput field buildInput
// reads, including at least one entry in each of the three tenant-open maps
// (principal.attributes, resource, delegation.classification_caps) so
// TestInputSchema_DeclaresExactlyWhatBuildInputProduces actually walks into
// them rather than vacuously skipping an empty map. A fixed UUID, not
// uuid.New(): matches policytest's own probeInputs reasoning — every other
// value here is a stable literal, and a fixture that differs run to run
// makes a failure harder to reproduce than it needs to be.
func fullyPopulatedEvaluationInput() policy.EvaluationInput {
	return policy.EvaluationInput{
		Principal:   authz.Principal{Subject: "drift-probe-subject", Attributes: map[string]string{"dept": "eng"}},
		Action:      authz.Action{Tool: "Bash"},
		DerivedTier: models.ActionTierDestructive,
		Resource:    map[string]string{"id": "res-1", "classification": "restricted"},
		Agent: authz.AgentInfo{
			ID:           uuid.MustParse("a5f1c2d3-0000-4000-8000-000000000099"),
			TrustTier:    models.TrustTierCertified,
			Enabled:      true,
			Suspended:    true,
			AllowedTools: []string{"drift-probe-tool-a", "drift-probe-tool-b"},
		},
		Delegation: policy.DelegationContext{
			Depth:              2,
			MaxActionTier:      models.ActionTierExternalComms,
			ClassificationCaps: map[string]string{"pii": "restricted"},
			Purpose:            "quarterly-close",
		},
	}
}

// TestInputSchema_DeclaresExactlyWhatBuildInputProduces is the drift guard
// the task brief asks for in place of generating schema.go's schema
// directly from input.go (judged impractical for a single hand-maintained
// document this size — see schema.go's package comment): it walks a fully
// populated buildInput output and fails the moment it finds a key that is
// not declared in schemaDoc at the matching path, so a field added to
// buildInput, agentDoc, or delegationDoc without a matching schema.go edit
// fails this test rather than silently going unchecked by both
// checkComparisonTypes and inputSchemaSet — exactly the "drift is silent in
// the dangerous direction" failure the task brief warns about.
//
// It also collects every path where the walk stopped because schemaDoc
// declares no "properties" there, and asserts that set is exactly the three
// deliberately open tenant maps schema.go's package comment names: no fewer
// (one of the three accidentally closed would start rejecting real
// tenant-supplied keys, the over-rejection this task is warned against) and
// no more (a fourth object accidentally left open would silently stop
// checking everything under it — the same drift this test otherwise exists
// to catch, just one level up, and the kind of gap a plain "every key is
// declared" walk would miss on its own).
func TestInputSchema_DeclaresExactlyWhatBuildInputProduces(t *testing.T) {
	built := buildInput(fullyPopulatedEvaluationInput())

	openPaths := map[string]bool{}
	var walk func(path string, node any, schemaNode map[string]any)
	walk = func(path string, node any, schemaNode map[string]any) {
		keys, get, isMap := mapEntries(node)
		if !isMap {
			return // a leaf value (string, int, bool, []string, ...): nothing further to check
		}

		props, hasProps := schemaNode["properties"].(map[string]any)
		if !hasProps {
			openPaths[path] = true
			return
		}

		for _, k := range keys {
			childSchema, declared := props[k].(map[string]any)
			if !declared {
				t.Errorf("buildInput produces key %q at input.%s, but schema.go's input schema does not declare it there — "+
					"either input.go grew a field schema.go was not updated for, or the two have otherwise drifted",
					k, joinPath(path, k))
				continue
			}
			walk(joinPath(path, k), get(k), childSchema)
		}
	}
	walk("", built, schemaDoc)

	wantOpen := map[string]bool{
		"principal.attributes":           true,
		"resource":                       true,
		"delegation.classification_caps": true,
	}
	for p := range wantOpen {
		if !openPaths[p] {
			t.Errorf("expected input.%s to be a deliberately open tenant map (no declared \"properties\"), but the schema declares "+
				"properties there — see schema.go's package comment for why this field must stay open", p)
		}
	}
	for p := range openPaths {
		if !wantOpen[p] {
			t.Errorf("input.%s has no declared \"properties\" in the schema and was not expected to be open — an accidentally-open "+
				"object silently stops checking everything under it, the same drift this test exists to catch", p)
		}
	}
}

func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// mapEntries returns node's keys and a lookup accessor when node is one of
// the two concrete map shapes buildInput, agentDoc, and delegationDoc
// actually produce (map[string]any for nested structured objects,
// map[string]string for the tenant-open leaves); isMap is false for
// anything else (a leaf: string, int, bool, []string), including an
// interface value wrapping one of those two map types with zero entries —
// callers must check isMap, not len(keys), to tell "an empty map" apart
// from "not a map at all."
func mapEntries(node any) (keys []string, get func(string) any, isMap bool) {
	switch m := node.(type) {
	case map[string]any:
		for k := range m {
			keys = append(keys, k)
		}
		return keys, func(k string) any { return m[k] }, true
	case map[string]string:
		for k := range m {
			keys = append(keys, k)
		}
		return keys, func(k string) any { return m[k] }, true
	default:
		return nil, nil, false
	}
}
