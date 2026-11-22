// extract.go is the PDP's own field extraction (spec §4.4.2 T2/T3): pulling
// a tool call's resource identity, command, and verb out of raw_input and
// the tenant's own tool_catalog row for that tool. It replaces the PEP-side
// extraction cmd/stratium-pep/normalize.go, resource.go, and hook.go's
// toolVerbs table used to perform — Task 3 (spec §4.4.2 T3) deleted all
// three outright once this file could derive everything they did, itself,
// from data the PDP already trusts. This file draws the identical boundary
// they did — a schema map, never a policy: it may look up WHICH field or
// column holds a value, by name, but may never inspect what a value MEANS —
// because moving WHERE extraction runs does not change WHAT it is allowed to
// do (spec §3.9 R1/R3). A PEP willing to mislabel a call was equally willing
// to extract wrongly (Phase 3b's original argument for why raw_input travels
// unconditionally, never replaced); a catalog row is tenant-authored
// configuration, not a per-call claim, but the boundary this file must not
// cross is the same one regardless of who is asking it to extract: this file
// answers "which field/column", never "what does it mean".
//
// Structurally simpler than its PEP-side predecessors, not merely relocated:
// normalizedInputFields/resourceIDFields each named a tool's field with a
// short-circuiting LIST of candidate spellings ({"file_path", "path"}),
// because a hardcoded table had to guess which one a given tool used. A
// tool_catalog row does not guess — an operator names exactly one field per
// concern when the row is written — so this file needs no fallback list, no
// firstNamedField-style walk, and no third near-identical table
// (resourceFieldTypes) naming a resource TYPE by field name: ToolCatalogEntry
// (pkg/models) carries no type column, so this file cannot emit one and does
// not try to. toolVerbs' verb guess needed no fallback list — one tool name,
// one label — but it still needed a whole second table keyed on a Claude
// Code-specific vocabulary; ToolCatalogEntry.Verb replaces it with one more
// column on the row this file already reads.
package authz

import (
	"encoding/json"

	"github.com/stratiumdata/stratium/pkg/models"
)

// ExtractedInput is what a's catalog row, if any, contributes for one tool
// call. Cataloged distinguishes "the tenant registered this tool, but this
// particular call carried neither field" (Cataloged true, both strings
// empty) from "the tenant never registered this tool at all" (the zero
// value) — ApplyExtraction treats the two differently, so collapsing them
// into a single "found nothing" signal would lose the distinction its caller
// actually needs.
//
// Verb is not a raw_input field lookup like ResourceID and Command — it is
// the matched row's own Verb column, copied straight through. Task 2 left
// ToolCatalogEntry.Verb unconsumed by design (that field's own doc comment
// in pkg/models/catalog.go), deferring the decision to Task 3: retire
// DecideRequest.verb (the PEP-computed field it replaces) alongside
// normalized_input, and have the PDP derive it here instead, keyed on the
// same tool-name match ResourceID/Command already use. The alternative —
// leave DecideRequest.verb on the wire with nothing left to populate it,
// now that cmd/stratium-pep's toolVerbs table is deleted — is exactly the
// plumbed-but-unconsumed shape this project's house style rules out, just
// moved from "a catalog column nothing reads" to "a wire field nothing
// sends."
type ExtractedInput struct {
	Cataloged  bool
	Verb       string
	ResourceID string
	Command    string
	// Patch is the text of a patch-style edit, set only through an alias
	// (ExtractAliased). Its file paths are the call's resource identities.
	Patch string
}

// ExtractFromCatalog looks up a.Tool among entries — a tenant's own
// tool_catalog rows, never DefaultCatalog(), which carries tiers only and
// registers no field name at all — and, when found, pulls the resource
// identity and command out of a.RawInput using that row's ResourceField and
// CommandField, and copies the row's Verb straight through.
//
// Field lookup only, never value inspection, for ResourceID and Command: the
// only two case analyses here are on a field NAME drawn from the catalog
// row, and neither ever asks what the matched field's VALUE means beyond "is
// this a non-empty JSON string" — so this function has no path that could
// read a "classification" or "hierarchy" attribute out of raw_input,
// regardless of what the catalog row names or what raw_input contains (spec
// §3.9 R3). A field that is absent, present but not a JSON string, or
// present but empty all read as "this call did not carry it" — the same
// convention cmd/stratium-pep's now-deleted firstNamedField applied at the
// edge, kept here because the question has not changed, only which table
// answers it. Verb needs no such case analysis at all: it is not read out of
// a.RawInput by name, it is the matched row's own column, so there is no
// field-presence question to get wrong and no way for it to vary with what a
// given call's raw_input happens to contain (see
// TestExtractFromCatalog_CarriesVerbFromCatalogRowRegardlessOfRawInput).
//
// entries is scanned linearly rather than indexed by tool name first: a
// tenant's catalog is expected to hold tens of rows, not thousands, this
// runs once per decision, and UNIQUE(tenant_id, tool_name)
// (migrations/000013_tool_catalog) guarantees at most one match — indexing
// would add a map build on every call to save a scan too short to matter.
func ExtractFromCatalog(entries []models.ToolCatalogEntry, a Action) ExtractedInput {
	for _, e := range entries {
		if e.ToolName != a.Tool {
			continue
		}
		out := ExtractedInput{Cataloged: true, Verb: e.Verb}
		obj := parseJSONObject(a.RawInput)
		if e.ResourceField != nil {
			out.ResourceID = jsonStringField(obj, *e.ResourceField)
		}
		if e.CommandField != nil {
			out.Command = jsonStringField(obj, *e.CommandField)
		}
		return out
	}
	return ExtractedInput{}
}

// ApplyExtraction folds ext onto action and resource, producing the values
// DeriveTier and the policy/delegation legs should see. It returns new
// values rather than mutating its arguments, matching this codebase's
// general immutability discipline (e.g. DefaultCatalog's fresh-map-per-call
// rule) and leaving a caller that still needs the original wire-supplied
// action or resource — for an audit entry describing what actually arrived,
// say — free to keep them.
//
// Not cataloged (the tenant registered no row for a.Tool): action and
// resource pass through completely unchanged. This is the regression guard
// — a tenant with no catalog rows, or a call to a tool the tenant's catalog
// does not name, must derive identically to how it did before this function
// existed — and it holds per TOOL, not only for a tenant with zero rows
// overall: TestDecide_CatalogDerivesReadOnlyForBareReadCall
// (pdpgrpc/server_test.go), predating this task, depends on exactly this
// branch for a tool its fixture never catalogs. Task 3 retired
// DecideRequest.verb and normalized_input from the wire entirely, so for an
// uncataloged tool action.Verb and action.NormalizedInput now simply start,
// and stay, at Go's own zero value "" — there is no wire value left for this
// branch to preserve or discard either way, which is a stronger form of the
// same regression guard, not a weaker one: nothing upstream of this function
// can smuggle a claimed verb or normalized form past it for a tool the
// tenant never registered.
//
// Cataloged: the catalog OWNS this tool's extraction from here, even where
// it found nothing. ext.Verb (possibly "") replaces action.Verb, ext.Command
// (possibly "") replaces action.NormalizedInput, and ext.ResourceID
// (possibly "") becomes the entire resource map via resourceFromID,
// discarding whatever action/resource already held. Replacing rather than
// merging is deliberate, for two reasons: it is what "field extraction moves
// from the PEP to the PDP" (spec §4.4.2 T2/T3) means for a tool the tenant
// has actually registered — the PDP's own, verified reading of raw_input (or,
// for Verb, the tenant's own registered column) is authoritative for that
// tool, not a supplement to a claim a caller already made — and it is what
// makes "the PDP never infers a classification" hold by construction rather
// than by care: resourceFromID's output can only ever be {} or {"id": v}, so
// nothing a caller sent, however it was produced, can ride along into a
// decision for a cataloged tool.
//
// action.RawInput is never touched, on either branch. RawInput is the one
// field DeriveTier's evidence check (destructiveEvidence, tier.go) reads,
// and it must see exactly what the caller sent — not a value this function
// derived from it — or the catalog becomes exactly the kind of lookup layer
// that silently defeated the evidence rule once before (see this package's
// own doc comment). Evidence therefore binds regardless of what ext
// contains or which branch below runs, and regardless of whether a caller
// applies this extraction before or after building tiers: nothing in this
// function's control flow can prevent DeriveTier, called afterward, from
// seeing the true RawInput.
func ApplyExtraction(ext ExtractedInput, action Action, resource map[string]string) (Action, map[string]string) {
	if !ext.Cataloged {
		return action, resource
	}
	action.Verb = ext.Verb
	action.NormalizedInput = ext.Command
	return action, resourceFromID(ext.ResourceID)
}

// resourceFromID is the only place a catalog-derived resource map is built.
// One parameter, one branch, one possible key: unlike a general-purpose
// map-merge, which could carry a "classification" or "hierarchy" key in from
// anywhere upstream without this function's own diff ever mentioning it,
// this function cannot be edited into producing either without the change
// saying so in the literal it touches. See
// TestApplyExtraction_ResourceMapNeverContainsClassificationOrHierarchyKeys
// for the adversarial proof, including the case where a catalog row's own
// ResourceField is literally named "classification" — even then, the key
// this function writes is "id", never the field name that produced the
// value.
func resourceFromID(id string) map[string]string {
	if id == "" {
		return map[string]string{}
	}
	return map[string]string{"id": id}
}

// parseJSONObject decodes s as a JSON object, returning nil on any failure —
// invalid JSON, or valid JSON that is not an object (a bare string, a
// number, an array). A nil map is a safe, inert result: every subsequent
// obj[field] lookup in jsonStringField below simply misses, the same way an
// absent field does.
func parseJSONObject(s string) map[string]json.RawMessage {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal([]byte(s), &obj)
	return obj
}

// jsonStringField reads field out of obj, returning "" unless the field is
// present with a non-empty JSON string value — present-but-not-a-string and
// present-but-empty both read as absent, matching firstNamedField's contract
// (cmd/stratium-pep/normalize.go) exactly, because a value this function
// will not vouch for and an attribute that was never sent must be
// indistinguishable to every caller downstream.
func jsonStringField(obj map[string]json.RawMessage, field string) string {
	raw, ok := obj[field]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}
