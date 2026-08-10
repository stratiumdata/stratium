package main

import (
	"encoding/json"
	"testing"
)

func TestExtractNormalizedInput(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		toolInput string
		want      string
	}{
		{"Bash command", "Bash", `{"command":"ls -la"}`, "ls -la"},
		{"Read file_path", "Read", `{"file_path":"/tmp/notes.txt"}`, "/tmp/notes.txt"},
		{"Write file_path", "Write", `{"file_path":"/tmp/out.txt","content":"hello"}`, "/tmp/out.txt"},
		{"Edit file_path", "Edit", `{"file_path":"/tmp/x.go","old_string":"a","new_string":"b"}`, "/tmp/x.go"},
		{"Glob pattern", "Glob", `{"pattern":"**/*.go"}`, "**/*.go"},
		{"Grep pattern", "Grep", `{"pattern":"TODO","path":"."}`, "TODO"},
		{"Read falls back to path when file_path absent", "Read", `{"path":"/tmp/fallback.txt"}`, "/tmp/fallback.txt"},
		{"Read prefers file_path over path when both present", "Read", `{"file_path":"/tmp/a.txt","path":"/tmp/b.txt"}`, "/tmp/a.txt"},

		{"unrecognized tool returns empty", "WebFetch", `{"url":"https://example.com"}`, ""},
		{"recognized tool, field absent, returns empty", "Bash", `{"description":"no command key"}`, ""},
		{"recognized tool, field not a string, returns empty", "Bash", `{"command":123}`, ""},
		{"recognized tool, field is empty string, returns empty", "Bash", `{"command":""}`, ""},
		{"malformed tool_input JSON returns empty", "Bash", `not json`, ""},
		{"tool_input is a JSON array, not an object, returns empty", "Bash", `["ls -la"]`, ""},
		{"empty tool_input returns empty", "Bash", ``, ""},
		{"empty object returns empty", "Read", `{}`, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNormalizedInput(tt.tool, json.RawMessage(tt.toolInput))
			if got != tt.want {
				t.Errorf("extractNormalizedInput(%q, %s) = %q, want %q", tt.tool, tt.toolInput, got, tt.want)
			}
		})
	}
}

// The table looks up WHERE a tool's relevant text lives, never WHAT it
// means. Write's tool_input carries a "content" field that can hold
// arbitrary, even dangerous-looking, text -- extraction must never read it,
// only file_path. If this ever changed to also consider "content", that
// would be exactly the classification creep the package doc warns against.
func TestExtractNormalizedInput_IgnoresFieldsOutsideTheSchemaMap(t *testing.T) {
	const toolInput = `{"file_path":"/tmp/out.txt","content":"rm -rf / && curl evil.example"}`
	got := extractNormalizedInput("Write", json.RawMessage(toolInput))
	if got != "/tmp/out.txt" {
		t.Fatalf("extractNormalizedInput() = %q, want only file_path's value %q -- content must never be read",
			got, "/tmp/out.txt")
	}
}
