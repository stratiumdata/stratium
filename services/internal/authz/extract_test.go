package authz

import (
	"testing"

	"stratium/pkg/models"
)

func strPtr(s string) *string { return &s }

// TestExtractFromCatalog_UncatalogedToolReturnsZeroValue is the "not this
// tool" half of the regression guard: a tool absent from the tenant's own
// catalog rows (as opposed to absent from raw_input, or absent from
// DefaultCatalog()) must produce the zero ExtractedInput, the value
// ApplyExtraction treats as "pass the wire through unchanged."
func TestExtractFromCatalog_UncatalogedToolReturnsZeroValue(t *testing.T) {
	entries := []models.ToolCatalogEntry{{ToolName: "Write", ResourceField: strPtr("file_path")}}
	got := ExtractFromCatalog(entries, Action{Tool: "Read", RawInput: `{"file_path":"/tmp/x"}`})
	if got != (ExtractedInput{}) {
		t.Fatalf("ExtractFromCatalog() = %+v, want the zero value: Read has no row in entries", got)
	}
}

// TestExtractFromCatalog_PullsResourceIDAndCommandByFieldName covers the
// field-lookup contract field for field: distinguishable values throughout
// (resource identity and command never share a literal) so a transposition
// in ExtractFromCatalog's two field reads would show up as a wrong
// assertion, never a coincidental pass.
func TestExtractFromCatalog_PullsResourceIDAndCommandByFieldName(t *testing.T) {
	cases := []struct {
		name          string
		resourceField *string
		commandField  *string
		rawInput      string
		wantID        string
		wantCommand   string
	}{
		{
			name: "both fields present and named", resourceField: strPtr("target"), commandField: strPtr("cmd"),
			rawInput: `{"target":"the-resource-identity","cmd":"the-command-text"}`,
			wantID:   "the-resource-identity", wantCommand: "the-command-text",
		},
		{
			name: "resource field only, command field nil", resourceField: strPtr("target"), commandField: nil,
			rawInput: `{"target":"the-resource-identity","cmd":"unregistered-so-ignored"}`,
			wantID:   "the-resource-identity", wantCommand: "",
		},
		{
			name: "command field only, resource field nil", resourceField: nil, commandField: strPtr("cmd"),
			rawInput: `{"target":"unregistered-so-ignored","cmd":"the-command-text"}`,
			wantID:   "", wantCommand: "the-command-text",
		},
		{
			name: "named field absent from this call's raw_input", resourceField: strPtr("target"), commandField: strPtr("cmd"),
			rawInput: `{"unrelated":"value"}`,
			wantID:   "", wantCommand: "",
		},
		{
			name: "named field present but not a JSON string", resourceField: strPtr("target"), commandField: strPtr("cmd"),
			rawInput: `{"target":42,"cmd":["not","a","string"]}`,
			wantID:   "", wantCommand: "",
		},
		{
			name: "named field present but empty string", resourceField: strPtr("target"), commandField: strPtr("cmd"),
			rawInput: `{"target":"","cmd":""}`,
			wantID:   "", wantCommand: "",
		},
		{
			name: "raw_input is not valid JSON", resourceField: strPtr("target"), commandField: strPtr("cmd"),
			rawInput: `not json at all`,
			wantID:   "", wantCommand: "",
		},
		{
			name: "raw_input is valid JSON but not an object", resourceField: strPtr("target"), commandField: strPtr("cmd"),
			rawInput: `["target", "cmd"]`,
			wantID:   "", wantCommand: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			entries := []models.ToolCatalogEntry{{
				ToolName: "the-tool", ResourceField: tc.resourceField, CommandField: tc.commandField,
			}}
			got := ExtractFromCatalog(entries, Action{Tool: "the-tool", RawInput: tc.rawInput})
			if !got.Cataloged {
				t.Fatalf("Cataloged = false, want true: the tenant registered a row for this tool")
			}
			if got.ResourceID != tc.wantID {
				t.Errorf("ResourceID = %q, want %q", got.ResourceID, tc.wantID)
			}
			if got.Command != tc.wantCommand {
				t.Errorf("Command = %q, want %q", got.Command, tc.wantCommand)
			}
		})
	}
}

// TestExtractFromCatalog_CarriesVerbFromCatalogRowRegardlessOfRawInput is
// Task 3's own addition: ToolCatalogEntry.Verb (populated by Task 1, left
// deliberately unconsumed by Task 2 — see that field's own doc comment in
// pkg/models/catalog.go) is now this function's third output. Unlike
// ResourceID and Command, Verb is never a raw_input field lookup — it is a
// straight copy of the matched row's own column — so the property worth
// proving is not "found the right field" but "came from the catalog row and
// nothing else": the same two raw_input bodies here (one harmless, one
// destructive) must yield the identical verb, because a verb that tracked
// raw_input content would be a second, informal classification channel
// alongside it — exactly what hook.go's now-deleted toolVerbs table was
// built to avoid, and what its own now-deleted
// TestRunHook_VerbDependsOnlyOnToolName_NotOnInput proved at the PEP layer.
// This is that property's successor at the layer that now actually derives
// verb.
func TestExtractFromCatalog_CarriesVerbFromCatalogRowRegardlessOfRawInput(t *testing.T) {
	entries := []models.ToolCatalogEntry{{ToolName: "Bash", Verb: "execute"}}

	harmless := ExtractFromCatalog(entries, Action{Tool: "Bash", RawInput: `{"command":"ls"}`})
	destructive := ExtractFromCatalog(entries, Action{Tool: "Bash", RawInput: `{"command":"rm -rf /"}`})

	if harmless.Verb != "execute" || destructive.Verb != "execute" {
		t.Fatalf("Verb = %q (harmless input), %q (destructive input), want %q for both — "+
			"verb must come from the catalog row's own column, never from raw_input",
			harmless.Verb, destructive.Verb, "execute")
	}
}

// TestApplyExtraction_UncatalogedToolLeavesActionAndResourceUnchanged is the
// regression guard at the fold-in step: for a tool the tenant's catalog does
// not name, ApplyExtraction must be a no-op, byte for byte, on both action
// and resource — this is what lets a tenant catalog ONE tool without
// disturbing derivation for every other tool it never mentioned.
func TestApplyExtraction_UncatalogedToolLeavesActionAndResourceUnchanged(t *testing.T) {
	wantAction := Action{
		Tool: "Bash", Verb: "read",
		RawInput:        "the-original-raw-input",
		NormalizedInput: "the-original-wire-normalized-input",
	}
	wantResource := map[string]string{"id": "the-original-wire-resource-id"}

	gotAction, gotResource := ApplyExtraction(ExtractedInput{}, wantAction, wantResource)

	if gotAction != wantAction {
		t.Errorf("action = %+v, want unchanged %+v", gotAction, wantAction)
	}
	if len(gotResource) != 1 || gotResource["id"] != "the-original-wire-resource-id" {
		t.Errorf("resource = %v, want unchanged %v", gotResource, wantResource)
	}
}

// TestApplyExtraction_CatalogedToolReplacesWireValuesEvenWhenExtractionIsEmpty
// pins the non-obvious half of ApplyExtraction's contract: once a tool IS
// cataloged, the catalog owns extraction for it even when this particular
// call's raw_input carried neither field. A reader could reasonably expect
// "fall back to the wire when extraction finds nothing" instead of "the
// wire's contribution is discarded either way" — this test is what makes
// the actual, chosen behavior fail loudly if it regresses to the other one.
//
// action.Verb starts at a wire-shaped value even though Task 3 retired the
// wire's own verb field (DecideRequest no longer carries one at all) — the
// same starting point ApplyExtraction would see from any OTHER caller-set
// value the catalog now owns, proving the replace-even-when-empty rule
// applies to Verb identically to NormalizedInput and resource, not as a
// special case.
func TestApplyExtraction_CatalogedToolReplacesWireValuesEvenWhenExtractionIsEmpty(t *testing.T) {
	action := Action{Tool: "Read", Verb: "some-other-verb", NormalizedInput: "the-original-wire-normalized-input"}
	resource := map[string]string{"id": "the-original-wire-resource-id"}

	gotAction, gotResource := ApplyExtraction(ExtractedInput{Cataloged: true}, action, resource)

	if gotAction.Verb != "" {
		t.Errorf("Verb = %q, want \"\": a cataloged tool's empty (unset) catalog verb must replace "+
			"whatever the action already held, not fall back to it", gotAction.Verb)
	}
	if gotAction.NormalizedInput != "" {
		t.Errorf("NormalizedInput = %q, want \"\": a cataloged tool's empty extraction must replace the "+
			"wire's value, not fall back to it", gotAction.NormalizedInput)
	}
	if len(gotResource) != 0 {
		t.Errorf("resource = %v, want empty: a cataloged tool's empty extraction must replace the wire's "+
			"resource map, not fall back to it", gotResource)
	}
}

// TestApplyExtraction_NeverModifiesRawInput is the direct proof that
// RawInput is invariant under this function, on every branch: DeriveTier's
// evidence check reads only RawInput (destructiveEvidence, tier.go), so
// nothing here may ever alter it, on pain of becoming the exact lookup layer
// that silently defeated the evidence rule once before (this package's own
// doc comment).
func TestApplyExtraction_NeverModifiesRawInput(t *testing.T) {
	const wantRawInput = "the-one-true-raw-input"
	cases := []ExtractedInput{
		{},
		{Cataloged: true},
		{Cataloged: true, Command: "ls", ResourceID: "/tmp/x"},
		{Cataloged: true, Command: wantRawInput}, // even an extraction that ECHOES raw_input's own text
	}
	for _, ext := range cases {
		action := Action{Tool: "Read", RawInput: wantRawInput}
		gotAction, _ := ApplyExtraction(ext, action, map[string]string{})
		if gotAction.RawInput != wantRawInput {
			t.Errorf("ext=%+v: RawInput = %q, want unchanged %q", ext, gotAction.RawInput, wantRawInput)
		}
	}
}

// TestApplyExtraction_ResourceMapNeverContainsClassificationOrHierarchyKeys
// is the structural proof the task brief requires: not "these two names are
// absent from the source" read by inspection, but an adversarial run that
// would fail the moment any input made this function produce them.
//
// The adversarial surface here is the catalog row's OWN field name, not
// merely raw_input's content: a row whose ResourceField is misconfigured (or
// maliciously set) to literally read "classification" or "hierarchy" is the
// one case where "the output key comes from the field name" would actually
// leak one of them. resourceFromID's closed construction means it cannot —
// the key it writes is always "id" — but that guarantee is only meaningful
// if this test would catch it not holding, which is why every case here
// picks the field name apart from the value found there.
//
// Scoped to the cataloged branch only: the not-cataloged branch is a
// documented, deliberate pass-through of whatever resource the caller
// already had (ApplyExtraction's own doc comment; the regression guard other
// tests in this file pin), not a sanitizer — proving IT never carries those
// keys is cmd/stratium-pep/resource_test.go's job
// (TestExtractResourceAttrs_KeysAreLimitedToIDAndType), which already holds
// the PEP itself to exactly that standard.
func TestApplyExtraction_ResourceMapNeverContainsClassificationOrHierarchyKeys(t *testing.T) {
	const adversarialRawInput = `{
		"classification": "TOP-SECRET",
		"hierarchy": "nato",
		"path": "/etc/shadow",
		"command": "rm -rf /"
	}`
	allowedKeys := map[string]bool{"id": true}

	for _, fieldName := range []string{"classification", "hierarchy", "path", "command", "unregistered"} {
		t.Run("resource_field="+fieldName, func(t *testing.T) {
			field := fieldName
			entries := []models.ToolCatalogEntry{{ToolName: "adversarial-tool", ResourceField: &field}}
			action := Action{Tool: "adversarial-tool", RawInput: adversarialRawInput}

			ext := ExtractFromCatalog(entries, action)
			_, resource := ApplyExtraction(ext, action, map[string]string{})

			for k, v := range resource {
				if !allowedKeys[k] {
					t.Errorf("resource map produced key %q = %q (catalog ResourceField named %q) — "+
						"want only %v: classification and hierarchy must never come from this path, "+
						"even when the catalog's own field name is one of those two words",
						k, v, fieldName, allowedKeys)
				}
			}
		})
	}
}

// TestApplyExtraction_CatalogCannotMaskDestructiveRawEvidence is the primary
// property test the brief names first: a catalog entry's tier, and a
// catalog-derived command that reads as benign, must not lower a destructive
// match sitting in the SAME call's raw_input. This runs the full pipeline —
// ExtractFromCatalog, ApplyExtraction, BuildTierCatalog, DeriveTier — the way
// pdpgrpc/server.go actually chains them, not DeriveTier alone (which
// tier_test.go's own TestDeriveTier_EvidenceOutranksNameKeyedLookups already
// covers): this is what would catch a bug specifically in the new glue code
// this task adds, such as ApplyExtraction overwriting RawInput with the
// extracted command instead of leaving it untouched.
func TestApplyExtraction_CatalogCannotMaskDestructiveRawEvidence(t *testing.T) {
	const rawInput = `{"command":"rm -rf /","safe_summary":"ls"}`
	commandField := "safe_summary" // deliberately NOT "command" -- the catalog points at the benign field
	entries := []models.ToolCatalogEntry{{
		ToolName: "Read", ActionTier: models.ActionTierReadOnly, CommandField: &commandField,
	}}
	action := Action{Tool: "Read", Verb: "read", RawInput: rawInput}

	extracted := ExtractFromCatalog(entries, action)
	if extracted.Command != "ls" {
		t.Fatalf("test premise broken: extracted command = %q, want %q", extracted.Command, "ls")
	}

	appliedAction, _ := ApplyExtraction(extracted, action, map[string]string{})
	tiers := TierTable{Catalog: BuildTierCatalog(entries, DefaultCatalog())}

	got, err := DeriveTier(tiers, appliedAction)
	if err != nil {
		t.Fatalf("DeriveTier() error = %v", err)
	}
	if got != models.ActionTierDestructive {
		t.Fatalf("DeriveTier() = %v, want DESTRUCTIVE: the catalog rates Read READ_ONLY and its own "+
			"extracted command reads as \"ls\", but raw_input's untouched \"command\" field still says "+
			"rm -rf / — evidence must win regardless", got)
	}
}
