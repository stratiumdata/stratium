// resource.go extracts DecideRequest.resource -- a resource identifier, by
// field name only -- from a tool call's arguments. See normalize.go's
// package doc for the boundary shared here: a schema map is not a policy.
// This file draws that boundary somewhere higher-stakes than normalize.go
// does, because resource is the one input pkg/classification.CheckCap reads
// (the "classification" and "hierarchy" keys) to decide what a delegation
// permits an agent to touch. A PEP that ever populated either key would be a
// PEP asserting its own classification over its own request -- spec defect
// D1, and with higher stakes than the original: D1 was a client asserting a
// tier the server re-derived anyway and cross-checked, while a
// classification the server has no other source for would simply be
// believed (Phase 7 plan, ruling R1). This file extracts an identifier, and,
// only where a field's own NAME says so unambiguously, a coarse type; it
// never reads a field's VALUE for anything beyond "is this a non-empty
// string", and it has no branch that could produce "classification" or
// "hierarchy" -- see TestExtractResourceAttrs_KeysAreLimitedToIDAndType
// (resource_test.go) for the structural proof, not just this comment.
package main

import "encoding/json"

// resourceIDFields names, for a known Claude Code tool, the tool_input
// field(s) that identify the resource being acted on -- checked in order,
// first one present with a non-empty string value wins, the same rule
// normalizedInputFields (normalize.go) applies for a different question.
//
// Today this table is identical, tool for tool and field for field, to
// normalizedInputFields: for every tool below, "what text should
// classification read" and "what resource does this call name" happen to
// have the same answer. Kept as a second, separately-named table anyway
// rather than one shared map: the two questions are not the same question,
// only coincidentally aligned for Claude Code's current built-in tool set,
// and collapsing them risks a future tool -- most plausibly an MCP tool,
// where this package has far less control over argument shape -- silently
// inheriting one table's field choice for the other table's purpose. This is
// the THIRD near-identical per-tool table in this package now (after this
// one, normalizedInputFields, and hook.go's toolVerbs); the task report
// flags whether that is one design question or three rather than resolving
// it unilaterally here.
var resourceIDFields = map[string][]string{
	"Bash":  {"command"},
	"Read":  {"file_path", "path"},
	"Write": {"file_path", "path"},
	"Edit":  {"file_path", "path"},
	"Glob":  {"pattern"},
	"Grep":  {"pattern"},
}

// resourceFieldTypes names, for a subset of resourceIDFields' own field
// names, the resource type that field name -- never its value -- makes
// unambiguous. Only "file_path" and "path" qualify: both names, in every
// tool that carries them here, come from Claude Code's own tool schema
// naming a filesystem path, so labelling the resource "file" reads off the
// field's name alone. "command" and "pattern" are deliberately absent: a
// shell command string or a glob/regex pattern is an argument TO the action,
// not a kind of resource, and inventing one from either field name would be
// exactly the "what does this tool mean" conditional the package doc
// forbids.
var resourceFieldTypes = map[string]string{
	"file_path": "file",
	"path":      "file",
}

// extractResourceAttrs pulls a resource identifier out of toolInput for
// toolName, structured like extractNormalizedInput (normalize.go) and
// failing the same way it does: empty input, an unrecognized tool, a
// tool_input that is not a JSON object, every candidate field missing, or a
// field present but not a non-empty JSON string, all produce an empty map --
// never an error, and never, by itself, a reason to deny. Tasks 2 and 3
// decide what an empty resource map means; this function does not pre-empt
// them.
//
// The returned map holds at most "id" and "type" -- see the package doc for
// why "classification" and "hierarchy" can never appear, structurally: this
// function has no case analysis on any field's VALUE, only on which of a
// fixed, known field NAME (resourceIDFields) was present, and the only
// second key it can ever add (resourceFieldTypes) is looked up by that same
// closed set of names.
func extractResourceAttrs(toolName string, toolInput json.RawMessage) map[string]string {
	fields := resourceIDFields[toolName]
	if len(fields) == 0 {
		return map[string]string{}
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(toolInput, &obj); err != nil {
		return map[string]string{}
	}

	field, value, ok := firstNamedField(obj, fields)
	if !ok {
		return map[string]string{}
	}

	attrs := map[string]string{"id": value}
	if t, ok := resourceFieldTypes[field]; ok {
		attrs["type"] = t
	}
	return attrs
}
