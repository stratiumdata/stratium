package authz

import (
	"fmt"
	"maps"
	"testing"

	"stratium/pkg/models"
)

// propertyCatalog is the tenant configuration every case below is generated
// against. Names are chosen to be adversarial rather than realistic: colons in
// tool_name AND in verb (both are unvalidated TEXT columns), mixed case in
// verbs (lookupKeys lowercases its verb slot and nothing else), and tiers
// spread so that a missed candidate shows up as a tier difference rather than
// a coincidence.
func propertyEntries() []models.ToolCatalogEntry {
	tier := func(t models.ActionTier) *models.ActionTier { return &t }
	return []models.ToolCatalogEntry{
		{ToolName: "Bash", ActionTier: nil, CommandField: strPtr("command"), Verb: "read"},
		{ToolName: "danger", ActionTier: tier(models.ActionTierDestructive), Verb: "write"},
		{ToolName: "svc", ActionTier: tier(models.ActionTierReadOnly), Verb: "index:delete"},
		{ToolName: "svc:index", ActionTier: tier(models.ActionTierDestructive), Verb: "delete"},
		{ToolName: "X", ActionTier: tier(models.ActionTierReadOnly), Verb: "y"},
		{ToolName: "X:y", ActionTier: tier(models.ActionTierDestructive), Verb: ""},
		{ToolName: "Foo", ActionTier: tier(models.ActionTierDestructive), Verb: "Purge"},
	}
}

// propertyOverrides are rows already stored for the tenant. A baseline
// computed for one key must account for the others: deriveTierByName probes
// overrides at EVERY slot before any catalog lookup, so a sibling row really
// is part of the resolution beneath this one.
func propertyOverrides() map[string]models.ActionTier {
	return map[string]models.ActionTier{
		"Bash":  models.ActionTierDestructive,
		"write": models.ActionTierInternalModify,
	}
}

// TestOverrideBaseline_Property is the generated counterpart to the curated
// table tests: it does not enumerate attack shapes, it enumerates INPUTS and
// lets lookupKeys produce the shapes.
//
// The action is built with ExtractFromCatalog + ApplyExtraction — the real
// functions Decide uses — rather than by setting Verb directly. That is the
// point: Action.Verb has exactly one production writer (extract.go), and its
// value is the tenant's tool_catalog.verb for that tool, so the verb a tool
// can actually arrive with is not free. Building the action any other way
// would bake this test's own assumption about the action space into it, which
// is the blindness three rounds of review have kept finding.
func TestOverrideBaseline_Property(t *testing.T) {
	entries := propertyEntries()
	catalog := BuildTierCatalog(entries, DefaultCatalog())
	overrides := propertyOverrides()

	// Tool names to probe: every catalogued name, every override key, every
	// split of every override key and catalogued name, plus names that are in
	// neither. Generated from the fixture, not hand-listed per case.
	names := map[string]bool{"Read": true, "Write": true, "unknown-tool": true, ":": true, "": true}
	add := func(s string) {
		names[s] = true
		for i := 1; i < len(s)-1; i++ {
			if s[i] == ':' {
				names[s[:i]] = true
				names[s[i+1:]] = true
			}
		}
	}
	for _, e := range entries {
		add(e.ToolName)
		add(e.Verb)
	}
	for k := range overrides {
		add(k)
	}

	for name := range names {
		for _, raw := range []string{"", "ls -la", `{"command":"ls; cat /etc/hosts"}`} {
			action := Action{Tool: name, RawInput: raw}
			action, _ = ApplyExtraction(ExtractFromCatalog(entries, action), action, nil)

			// The NAME-KEYED resolution: what overrides, the catalog, and the
			// verb table say, with BuiltinTier's classification of
			// caller-supplied RawInput excluded. That exclusion is the bound
			// OverrideBaseline documents and
			// TestOverrideBaseline_RawInputClassificationIsNotBounded pins;
			// RawInput is free text, so maximising over it would floor every
			// key at DESTRUCTIVE. Verb survives the clear because extraction
			// copies it from the catalog row, not from the input.
			nameKeyed := action
			nameKeyed.RawInput, nameKeyed.NormalizedInput = "", ""

			for _, key := range lookupKeys(action) {
				// The resolution beneath an override on key: every other
				// stored row still applies, this one does not.
				others := maps.Clone(overrides)
				delete(others, key)
				beneath, err := deriveTierByName(TierTable{Catalog: catalog, Overrides: others}, nameKeyed)
				if err != nil {
					continue
				}
				table := TierTable{Catalog: catalog, Overrides: overrides}
				if got := OverrideBaseline(table, entries, key); got < beneath {
					t.Errorf("OverrideBaseline(%q) = %s, but %s resolves %s beneath it\n"+
						"    an override on %q at %s would be ACCEPTED and would LOWER that call",
						key, got, describe(nameKeyed), beneath, key, got)
				}
			}
		}
	}
}

func describe(a Action) string {
	return fmt.Sprintf("{Tool:%q Verb:%q RawInput:%q}", a.Tool, a.Verb, a.RawInput)
}

// TestOverrideBaseline_RawInputClassificationIsNotBounded pins the one thing
// OverrideBaseline deliberately does NOT bound, so that it is a stated
// property rather than a gap someone rediscovers.
//
// An override on a name replaces per-invocation classification for the calls
// it matches. That is what an override IS — and it cannot be bounded the way
// the name-keyed resolution is, because RawInput is free text from the PEP:
// the maximum of BuiltinTier over all possible RawInput is DESTRUCTIVE, so
// requiring the baseline to cover it would refuse every override anyone could
// ever write.
//
// The second half is the compensating control, and it is why the first half is
// tolerable: DeriveTier's evidence rule re-raises a destructive raw input
// above ANY override, unconditionally. A tenant can blunt the classifier's
// lower tiers with an override; it cannot use one to hide `rm -rf /`.
func TestOverrideBaseline_RawInputClassificationIsNotBounded(t *testing.T) {
	catalog := BuildTierCatalog(nil, DefaultCatalog())
	table := TierTable{Catalog: catalog}
	const tool = "uncatalogued-tool"

	// The baseline for a name nothing catalogues is the floor, so an override
	// at the floor is accepted...
	baseline := OverrideBaseline(table, nil, tool)
	if baseline != models.ActionTierReasoning {
		t.Fatalf("OverrideBaseline(%q) = %s, want REASONING", tool, baseline)
	}
	if err := ValidateOverride(baseline, models.ActionTierReasoning); err != nil {
		t.Fatalf("an override at the baseline must be accepted: %v", err)
	}

	// ...and it does lower what the command classifier would have said for a
	// benign command. This is the residual, asserted rather than described.
	withOverride := TierTable{Catalog: catalog, Overrides: map[string]models.ActionTier{tool: models.ActionTierReasoning}}
	benign := Action{Tool: tool, RawInput: "ls -la"}
	if got, _ := DeriveTier(table, benign); got != models.ActionTierReadOnly {
		t.Fatalf("without the override, %q derives %s, want READ_ONLY", benign.RawInput, got)
	}
	if got, _ := DeriveTier(withOverride, benign); got != models.ActionTierReasoning {
		t.Errorf("DeriveTier with the override = %s, want REASONING — if this now resolves higher, the "+
			"residual OverrideBaseline documents has been closed and its doc comment must say so", got)
	}

	// The compensating control: evidence still binds above the override.
	hostile := Action{Tool: tool, RawInput: "rm -rf /"}
	if got, _ := DeriveTier(withOverride, hostile); got != models.ActionTierDestructive {
		t.Errorf("DeriveTier(%q) with a REASONING override = %s, want DESTRUCTIVE — an override must never "+
			"be able to hide destructive raw input (destructiveEvidence, §4.4.1)", hostile.RawInput, got)
	}
}
