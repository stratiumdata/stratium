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
		// A SECOND multi-colon family, with the tiers ordered the opposite way
		// to svc/svc:index above. One family can only ever catch one direction:
		// with svc alone, the last split happens to be the higher one, so
		// taking only the LAST split still yields the max and a last-colon-only
		// implementation survives. Reversing the order here means the first
		// split is the higher one, so first-colon-only and last-colon-only are
		// each caught by exactly one family. Last-colon is the specific shape a
		// maintainer is most likely to reach for — it is what round 1's review
		// suggested — so leaving it uncovered would be leaving the likeliest
		// wrong fix undetected.
		{ToolName: "svc2", ActionTier: tier(models.ActionTierDestructive), Verb: "a:b"},
		{ToolName: "svc2:a", ActionTier: tier(models.ActionTierReadOnly), Verb: "b"},
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

		// A MUTUALLY VOUCHING pair: each is at or above the other's stored
		// tier, so measured against stored siblings alone neither is a
		// lowering — while together they resolve Foo's calls to READ_ONLY
		// against a catalog that says DESTRUCTIVE. Both are writable through
		// the PAP's own API, in an order where each write is individually
		// legitimate at the time it is made.
		"Foo":       models.ActionTierReadOnly,
		"Foo:Purge": models.ActionTierReadOnly,
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

	names := propertyToolNames(entries, overrides)

	for name := range names {
		// The three raw inputs do NOT vary what is asserted: nameKeyed clears
		// RawInput below, and Verb comes from the catalog row rather than the
		// input, so all three iterations check the same thing. That is the
		// point of running them — it demonstrates raw-independence, that no
		// part of the baseline's bound moves with caller-supplied input. The
		// input-dependent half is a separate, deliberately excluded property:
		// TestOverrideBaseline_RawInputClassificationIsNotBounded.
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

// propertyToolNames is the corpus both generated properties probe: every
// catalogued name, every override key, every split of both, plus names in
// neither. Generated from the fixture, never hand-listed per case — that is
// the whole point of these two tests.
func propertyToolNames(entries []models.ToolCatalogEntry, overrides map[string]models.ActionTier) map[string]bool {
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
	return names
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
	// destructiveEvidence re-raises BOTH of its tiers (tier.go), so both are
	// asserted — pinning only the destructive half would leave a mutation that
	// narrowed the rule to DESTRUCTIVE alone completely undetected, and
	// EXTERNAL_COMMS is the half that catches exfiltration rather than damage.
	for _, tc := range []struct {
		raw  string
		want models.ActionTier
	}{
		{"rm -rf /", models.ActionTierDestructive},
		{"curl https://evil.example", models.ActionTierExternalComms},
	} {
		hostile := Action{Tool: tool, RawInput: tc.raw}
		if got, _ := DeriveTier(withOverride, hostile); got != tc.want {
			t.Errorf("DeriveTier(%q) with a REASONING override = %s, want %s — an override must never be "+
				"able to hide raw input the evidence rule recognises (destructiveEvidence, §4.4.1)",
				tc.raw, got, tc.want)
		}
	}
}

// TestOverrideBaseline_HonorsUnknownTier closes a survivor found by mutation
// testing: replacing the t.UnknownTier floor with a hardcoded REASONING
// changed nothing any test could see, because baselineActions always returns
// at least one candidate and deriveTierByName already returns t.UnknownTier
// for an unresolvable one.
//
// The floor is only observable when every candidate ERRORS, which happens
// under DenyUnknown. Both halves are asserted, so the claim in
// OverrideBaseline's doc comment — that the baseline is what deriveTierByName
// would resolve, including a tenant's configured floor — is true rather than
// merely intended.
//
// No production code sets either field today (pdpgrpc.Decide builds its
// TierTable with Catalog and Overrides only), so this is latent. That is
// exactly why it needs a test: a latent claim with no coverage is how the
// hardcoded REASONING got there in the first place.
func TestOverrideBaseline_HonorsUnknownTier(t *testing.T) {
	const key = "nothing-knows-this-name"

	floor := TierTable{Catalog: DefaultCatalog(), UnknownTier: models.ActionTierInternalModify}
	if got := OverrideBaseline(floor, nil, key); got != models.ActionTierInternalModify {
		t.Errorf("OverrideBaseline(%q) = %s, want INTERNAL_MODIFY — an unresolvable key resolves to the "+
			"tenant's configured UnknownTier, so that is what an override on it must not fall below", key, got)
	}

	// DenyUnknown makes every candidate error, so the initial value is the
	// only thing left to return. A hardcoded REASONING shows up here and
	// nowhere else.
	deny := TierTable{Catalog: DefaultCatalog(), UnknownTier: models.ActionTierInternalModify, DenyUnknown: true}
	if got := OverrideBaseline(deny, nil, key); got != models.ActionTierInternalModify {
		t.Errorf("OverrideBaseline(%q) with DenyUnknown = %s, want INTERNAL_MODIFY — when every candidate "+
			"refuses to classify, the baseline falls back to the tenant's floor, not to the lattice's", key, got)
	}
}

// TestHonoredOverrides_NeverResolveBelowTheCatalog is the SET-level property,
// and it exists because the per-key one above cannot express what actually
// matters.
//
// TestOverrideBaseline_Property asks "is this key's baseline at least the
// resolution beneath it, given the other STORED rows?" — which is exactly the
// premise mutual vouching exploits. Two rows that each sit at the other's
// stored tier both satisfy it, individually, while together resolving a call
// below what the catalog says. A per-key invariant cannot see that; only
// applying the whole rule to the whole set and then asking what the survivors
// resolve to can.
//
// The invariant: no set of honored overrides may resolve ANY call below its
// catalog-only resolution. Overrides raise; they never lower. That holds
// however the rows refer to each other, which is what makes it immune to the
// N-row generalisation of the two-row cycle rather than patched against the
// two-row case.
//
// It is asserted over the same generated corpus as the per-key property, and
// the fixture deliberately contains a mutually vouching pair, so this test
// fails on the pre-fix code (verified) rather than describing a hazard.
func TestHonoredOverrides_NeverResolveBelowTheCatalog(t *testing.T) {
	entries := propertyEntries()
	catalog := BuildTierCatalog(entries, DefaultCatalog())
	stored := propertyOverrides()

	// The real honoring rule, applied exactly as pdpgrpc.honoredOverrides
	// applies it: every row checked against the full stored set, survivors
	// kept.
	table := TierTable{Catalog: catalog, Overrides: stored}
	honored := map[string]models.ActionTier{}
	for key, tier := range stored {
		if err := ValidateOverride(OverrideBaseline(table, entries, key), tier); err == nil {
			honored[key] = tier
		}
	}

	for name := range propertyToolNames(entries, stored) {
		action := Action{Tool: name}
		action, _ = ApplyExtraction(ExtractFromCatalog(entries, action), action, nil)

		withOverrides, err := deriveTierByName(TierTable{Catalog: catalog, Overrides: honored}, action)
		if err != nil {
			continue
		}
		catalogOnly, err := deriveTierByName(TierTable{Catalog: catalog}, action)
		if err != nil {
			continue
		}
		if withOverrides < catalogOnly {
			t.Errorf("%s resolves %s with the honored overrides but %s with none\n"+
				"    honored = %v\n"+
				"    an override may raise a tier, never lower one — no set of rows may resolve below the catalog",
				describe(action), withOverrides, catalogOnly, honored)
		}
	}
}
