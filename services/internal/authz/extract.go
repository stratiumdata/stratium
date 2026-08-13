// extract.go is the PDP's own field extraction (spec §4.4.2 T2): pulling a
// tool call's resource identity and command out of raw_input by the field
// names a tenant's tool_catalog row registered for that tool. It replaces
// the PEP-side extraction cmd/stratium-pep/normalize.go and resource.go
// perform today (Task 3 deletes that code); this file draws the identical
// boundary theirs did — a schema map, never a policy — because moving WHERE
// extraction runs does not change WHAT it is allowed to do: see resource.go's
// own package doc for the classification boundary this file must not cross
// either (spec §3.9 R1/R3).
//
// Structurally simpler than its PEP-side predecessors, not merely relocated:
// normalizedInputFields/resourceIDFields each name a tool's field with a
// short-circuiting LIST of candidate spellings ({"file_path", "path"}),
// because a hardcoded table had to guess which one a given tool used. A
// tool_catalog row does not guess — an operator names exactly one field per
// concern when the row is written — so this file needs no fallback list, no
// firstNamedField-style walk, and no third near-identical table
// (resourceFieldTypes) naming a resource TYPE by field name: ToolCatalogEntry
// (pkg/models) carries no type column, so this file cannot emit one and does
// not try to.
package authz

import (
	"encoding/json"

	"stratium/pkg/models"
)

// ExtractedInput is what a's catalog row, if any, contributes for one tool
// call. Cataloged distinguishes "the tenant registered this tool, but this
// particular call carried neither field" (Cataloged true, both strings
// empty) from "the tenant never registered this tool at all" (the zero
// value) — ApplyExtraction treats the two differently, so collapsing them
// into a single "found nothing" signal would lose the distinction its caller
// actually needs.
type ExtractedInput struct {
	Cataloged  bool
	ResourceID string
	Command    string
}

// ExtractFromCatalog looks up a.Tool among entries — a tenant's own
// tool_catalog rows, never DefaultCatalog(), which carries tiers only and
// registers no field name at all — and, when found, pulls the resource
// identity and command out of a.RawInput using that row's ResourceField and
// CommandField.
//
// Field lookup only, never value inspection: the only two case analyses here
// are on a field NAME drawn from the catalog row, and neither ever asks what
// the matched field's VALUE means beyond "is this a non-empty JSON string" —
// so this function has no path that could read a "classification" or
// "hierarchy" attribute out of raw_input, regardless of what the catalog row
// names or what raw_input contains (spec §3.9 R3). A field that is absent,
// present but not a JSON string, or present but empty all read as "this call
// did not carry it" — the same convention firstNamedField
// (cmd/stratium-pep/normalize.go) used at the edge, kept here because the
// question has not changed, only which table answers it.
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
		out := ExtractedInput{Cataloged: true}
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
// overall: TestDecide_NormalizedInputReachesDerivation and
// TestDecide_CatalogDerivesReadOnlyForBareReadCall (pdpgrpc/server_test.go),
// both predating this task, depend on exactly this branch for tools their
// fixtures never catalog.
//
// Cataloged: the catalog OWNS this tool's extraction from here, even where
// it found nothing. ext.Command (possibly "") replaces
// action.NormalizedInput, and ext.ResourceID (possibly "") becomes the
// entire resource map via resourceFromID, discarding whatever the wire
// carried. Replacing rather than merging is deliberate, for two reasons: it
// is what "field extraction moves from the PEP to the PDP" (spec §4.4.2 T2)
// means for a tool the tenant has actually registered — the PDP's own,
// verified reading of raw_input is authoritative for that tool, not a
// supplement to a claim the PEP already made — and it is what makes "the PDP
// never infers a classification" hold by construction rather than by care:
// resourceFromID's output can only ever be {} or {"id": v}, so nothing the
// wire sent, however it was produced, can ride along into a decision for a
// cataloged tool.
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
