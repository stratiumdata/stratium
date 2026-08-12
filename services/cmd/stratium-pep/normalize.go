// normalize.go extracts DecideRequest.normalized_input from tool_input by
// field name only. See hook.go's package doc for the boundary this must not
// cross: this is a schema map ("the shell tool's argument lives under
// .command"), never a policy ("this text looks like rm -rf"). If this table
// ever grows a conditional on what a field's value means, that is
// classification, and classification belongs in internal/authz.BuiltinTier
// alone (spec defect D1).
package main

import "encoding/json"

// normalizedInputFields names, for a known Claude Code tool, the
// tool_input field(s) that hold a best-effort normalized string —
// checked in order, first one present with a non-empty string value wins.
// A tool absent from this map is an honest "unknown": extractNormalizedInput
// returns "" and BuiltinTier classifies raw_input alone — coarse, but
// correct (see hook.go's package doc), exactly like an unrecognized tool
// name in toolVerbs.
var normalizedInputFields = map[string][]string{
	"Bash":  {"command"},           // shell tools
	"Read":  {"file_path", "path"}, // file tools
	"Write": {"file_path", "path"},
	"Edit":  {"file_path", "path"},
	"Glob":  {"pattern"}, // search tools
	"Grep":  {"pattern"},
}

// extractNormalizedInput pulls toolName's normalized field out of toolInput,
// by name only, never by inspecting what the value contains. Empty input, an
// unrecognized tool, a tool_input that is not a JSON object, a missing
// field, or a field whose value is not a JSON string all produce "".
//
// "" is always a safe result, never a lossy one: BuiltinTier treats an empty
// NormalizedInput as no evidence, which can only fail to raise the derived
// tier, never lower it below what raw_input alone would classify — see
// tier.go's BuiltinTier doc comment for the combining rule this leans on.
func extractNormalizedInput(toolName string, toolInput json.RawMessage) string {
	fields := normalizedInputFields[toolName]
	if len(fields) == 0 {
		return ""
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(toolInput, &obj); err != nil {
		return ""
	}

	_, value, _ := firstNamedField(obj, fields)
	return value
}

// firstNamedField walks fields against obj, in order, and returns the name
// and value of the first one present with a non-empty JSON string value.
// Shared by extractNormalizedInput above and extractResourceAttrs
// (resource.go): both ask the identical structural question -- "which of
// these named fields holds this tool's one relevant argument" -- for two
// different downstream purposes (what text to classify, vs. what resource
// this call names), so sharing the walk costs nothing a second copy would
// have bought, and a JSON-shape edge case (present-but-not-a-string, present
// but empty) only needs handling once.
func firstNamedField(obj map[string]json.RawMessage, fields []string) (name, value string, ok bool) {
	for _, f := range fields {
		raw, present := obj[f]
		if !present {
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			continue // present but not a JSON string -- not this hook's to interpret
		}
		if s != "" {
			return f, s, true
		}
	}
	return "", "", false
}
