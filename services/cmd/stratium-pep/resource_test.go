package main

import (
	"encoding/json"
	"maps"
	"testing"
)

func TestExtractResourceAttrs(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		toolInput string
		want      map[string]string
	}{
		{"Bash command becomes id, no type", "Bash", `{"command":"ls -la"}`,
			map[string]string{"id": "ls -la"}},
		{"Read file_path becomes id with type file", "Read", `{"file_path":"/tmp/notes.txt"}`,
			map[string]string{"id": "/tmp/notes.txt", "type": "file"}},
		{"Write file_path becomes id with type file", "Write", `{"file_path":"/tmp/out.txt","content":"hello"}`,
			map[string]string{"id": "/tmp/out.txt", "type": "file"}},
		{"Edit file_path becomes id with type file", "Edit", `{"file_path":"/tmp/x.go","old_string":"a","new_string":"b"}`,
			map[string]string{"id": "/tmp/x.go", "type": "file"}},
		{"Glob pattern becomes id, no type", "Glob", `{"pattern":"**/*.go"}`,
			map[string]string{"id": "**/*.go"}},
		{"Grep pattern becomes id, no type", "Grep", `{"pattern":"TODO","path":"."}`,
			map[string]string{"id": "TODO"}},
		{"Read falls back to path when file_path absent, still type file", "Read", `{"path":"/tmp/fallback.txt"}`,
			map[string]string{"id": "/tmp/fallback.txt", "type": "file"}},
		{"Read prefers file_path over path when both present", "Read", `{"file_path":"/tmp/a.txt","path":"/tmp/b.txt"}`,
			map[string]string{"id": "/tmp/a.txt", "type": "file"}},

		{"unrecognized tool sends empty map", "WebFetch", `{"url":"https://example.com"}`, map[string]string{}},
		{"recognized tool, field absent, sends empty map", "Bash", `{"description":"no command key"}`, map[string]string{}},
		{"recognized tool, field not a string, sends empty map", "Bash", `{"command":123}`, map[string]string{}},
		{"recognized tool, field is empty string, sends empty map", "Bash", `{"command":""}`, map[string]string{}},
		{"malformed tool_input JSON sends empty map", "Bash", `not json`, map[string]string{}},
		{"tool_input is a JSON array, not an object, sends empty map", "Bash", `["ls -la"]`, map[string]string{}},
		{"empty tool_input sends empty map", "Bash", ``, map[string]string{}},
		{"empty object sends empty map", "Read", `{}`, map[string]string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractResourceAttrs(tt.tool, json.RawMessage(tt.toolInput))
			if !maps.Equal(got, tt.want) {
				t.Errorf("extractResourceAttrs(%q, %s) = %v, want %v", tt.tool, tt.toolInput, got, tt.want)
			}
		})
	}
}

// The table looks up WHERE a resource's identity lives, never WHAT it means.
// Write's tool_input carries a "content" field that could itself contain
// text shaped like a path -- extraction must never read it, only file_path.
// If this ever changed to also consider "content", that would be exactly
// the classification creep normalize.go's package doc warns against, now
// aimed at resource identity instead of normalized text.
func TestExtractResourceAttrs_IgnoresFieldsOutsideTheSchemaMap(t *testing.T) {
	const toolInput = `{"file_path":"/tmp/out.txt","content":"/etc/shadow"}`
	got := extractResourceAttrs("Write", json.RawMessage(toolInput))
	want := map[string]string{"id": "/tmp/out.txt", "type": "file"}
	if !maps.Equal(got, want) {
		t.Fatalf("extractResourceAttrs() = %v, want only file_path's value %v -- content must never be read", got, want)
	}
}

// "sends an empty resource map, and is not an error" is the literal
// contract the task brief states for an unrecognized tool. A nil map would
// satisfy every len()-based check here too, but DecideRequest.resource is a
// plain field callers (hook.go, mcp_authorize.go) assign this return value
// to directly -- checking non-nil keeps that assignment honest rather than
// relying on Go's own "nil map marshals like an empty one" behavior to
// paper over the difference.
func TestExtractResourceAttrs_UnrecognizedToolSendsEmptyMapNotNilNotError(t *testing.T) {
	// Deliberately includes recognized field names (command, file_path) in the
	// input: an unrecognized TOOL must still yield nothing, even when the
	// input shape would have satisfied a recognized tool's own field list.
	const toolInput = `{"command":"ls","file_path":"/etc/shadow"}`
	for _, tool := range []string{"WebFetch", "WebSearch", "Task", "mcp__server__method", "", "NotARealTool"} {
		t.Run(tool, func(t *testing.T) {
			got := extractResourceAttrs(tool, json.RawMessage(toolInput))
			if got == nil {
				t.Fatal("extractResourceAttrs() = nil, want a non-nil empty map")
			}
			if len(got) != 0 {
				t.Fatalf("extractResourceAttrs(%q, ...) = %v, want empty -- an unrecognized tool must never guess an identifier",
					tool, got)
			}
		})
	}
}

// type is populated only where the FIELD NAME itself makes the resource
// kind unambiguous (file_path, path -> "file"); command and pattern are
// deliberately absent from resourceFieldTypes. Checked by key PRESENCE, not
// merely an empty string, because a mutation that set attrs["type"] = ""
// would pass an empty-string check while still adding a key nothing asked
// for.
func TestExtractResourceAttrs_TypeOmittedWhenFieldNameIsAmbiguous(t *testing.T) {
	tests := []struct {
		tool      string
		toolInput string
	}{
		{"Bash", `{"command":"ls -la"}`},
		{"Glob", `{"pattern":"**/*.go"}`},
		{"Grep", `{"pattern":"TODO"}`},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			attrs := extractResourceAttrs(tt.tool, json.RawMessage(tt.toolInput))
			if _, ok := attrs["type"]; ok {
				t.Errorf("extractResourceAttrs(%q, ...) = %v, want no \"type\" key -- %s's field name does not say what kind of resource this is",
					tt.tool, attrs, tt.tool)
			}
			if attrs["id"] == "" {
				t.Errorf("extractResourceAttrs(%q, ...) = %v, want a non-empty id", tt.tool, attrs)
			}
		})
	}
}

// allowedResourceKeys is the complete, closed set of keys
// extractResourceAttrs may ever produce. classification and hierarchy are
// conspicuously absent: those are the two keys pkg/classification.CheckCap
// reads to cap what a delegation may touch, and a PEP that ever set either
// would be deciding its own classification (spec D1; see the package doc).
var allowedResourceKeys = map[string]bool{"id": true, "type": true}

// TestExtractResourceAttrs_KeysAreLimitedToIDAndType is the structural proof
// the task requires: not "these two names are absent" read off the source by
// inspection, but a test that fails the moment any code path produces them.
// Checking the result against an ALLOWLIST, rather than only denying
// "classification" and "hierarchy" by name, is deliberate: it also catches
// any OTHER unexpected key a future edit might introduce, not just a
// mutation that happens to spell one of these two specific names.
//
// adversarialInput supplies every field name this package's tables ever
// look up, PLUS "classification" and "hierarchy" directly by name, exactly
// as a careless or hostile tool_input might -- proving those two names are
// never picked up even when they are sitting right there in the input,
// under their own name, for every tool this package recognizes (and two it
// does not, where the check holds vacuously over an empty map).
func TestExtractResourceAttrs_KeysAreLimitedToIDAndType(t *testing.T) {
	const adversarialInput = `{
		"command": "rm -rf /",
		"file_path": "/etc/shadow",
		"path": "/etc/shadow",
		"pattern": "*.go",
		"classification": "TOP-SECRET",
		"hierarchy": "nato"
	}`

	tools := make([]string, 0, len(resourceIDFields)+2)
	for tool := range resourceIDFields {
		tools = append(tools, tool)
	}
	tools = append(tools, "WebFetch", "unknown_tool") // unrecognized: holds vacuously over {}

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			attrs := extractResourceAttrs(tool, json.RawMessage(adversarialInput))
			for k, v := range attrs {
				if !allowedResourceKeys[k] {
					t.Errorf("extractResourceAttrs(%q, ...) produced key %q = %q, want only keys in %v -- "+
						"classification and hierarchy in particular must NEVER come from a PEP",
						tool, k, v, allowedResourceKeys)
				}
			}
		})
	}
}
